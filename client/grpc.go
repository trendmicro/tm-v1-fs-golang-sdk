package client

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	gmd "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/trendmicro/tm-v1-fs-golang-sdk/client/base"
)

const (
	_envvarAuthKeyNotRequired = "TM_AM_AUTH_KEY_NOT_REQUIRED" // Set to 1 and Client SDK will not send auth key to server; set to 0 or leave empty to disable.
	_envvarServerAddr         = "TM_AM_SERVER_ADDR"           // <host FQDN>:<port no>
	_envvarDisableTLS         = "TM_AM_DISABLE_TLS"           // Set to 1 to not use TLS for client-server communication; set to 0 or leave empty otherwise.
	_envvarDisableCertVerify  = "TM_AM_DISABLE_CERT_VERIFY"   // Set to 1 to not disable server certificate check by client; set to 0 or leave empty otherwise.

	appNameHTTPHeader = "tm-app-name"
	appNameV1FS       = "V1FS"

	maxTagsListSize = 8
	maxTagSize      = 63
)

type LogLevel int
type LoggerCallback func(level LogLevel, levelStr string, format string, a ...interface{})

var currentLogLevel LogLevel = LogLevelOff
var userLogger LoggerCallback = nil

/////////////////////////////////////////////////
//
// AMaaS Client I/O interface and implementations
//
/////////////////////////////////////////////////

type AmaasClientReader interface {
	Identifier() string
	DataSize() (int64, error)
	ReadBytes(offset int64, length int32) ([]byte, error)
	Close()
	Hash(algorithm string) (string, error)
}

// File reader implementation

type AmaasClientFileReader struct {
	fileName string
	fd       *os.File
}

func InitFileReader(fileName string) (*AmaasClientFileReader, error) {

	reader := new(AmaasClientFileReader)

	fd, err := os.Open(fileName)
	if err != nil {
		logMsg(LogLevelError, MSG("MSG_ID_ERR_OPEN_FILE"), fileName, err)
		return nil, err
	}

	reader.fileName = fileName
	reader.fd = fd

	return reader, nil
}

func (reader *AmaasClientFileReader) Identifier() string {
	return reader.fileName
}

func (reader *AmaasClientFileReader) DataSize() (int64, error) {

	fi, err := reader.fd.Stat()
	if err != nil {
		return 0, err
	}

	return fi.Size(), nil
}

func (reader *AmaasClientFileReader) Hash(algorithm string) (string, error) {
	var h hash.Hash

	switch strings.ToLower(algorithm) {
	case "sha256":
		h = sha256.New()
	case "sha1":
		h = sha1.New()
	default:
		return "", fmt.Errorf(MSG("MSG_ID_ERR_UNSUPPORTED_ALGORITHM"), algorithm)
	}

	if _, err := io.Copy(h, reader.fd); err != nil {
		return "", err
	}

	_, err := reader.fd.Seek(0, 0)
	if err != nil {
		return "", err
	}

	hashValue := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s:%s", algorithm, hashValue), nil
}

func (reader *AmaasClientFileReader) ReadBytes(offset int64, length int32) ([]byte, error) {

	b := make([]byte, length)

	if retrLen, err := reader.fd.ReadAt(b, offset); err != nil {
		if err == io.EOF {
			msg := fmt.Sprintf(MSG("MSG_ID_ERR_RETRIEVE_DATA"), length, retrLen)
			logMsg(LogLevelError, msg)
		} else {
			b = nil
		}
	}

	return b, nil
}

func (reader *AmaasClientFileReader) Close() {
	reader.fd.Close()
	reader.fd = nil
}

type AmaasClientBufferReader struct {
	identifier string
	buffer     []byte
}

// Memory buffer reader implementation

func InitBufferReader(memBuffer []byte, identifier string) (*AmaasClientBufferReader, error) {

	reader := new(AmaasClientBufferReader)

	reader.buffer = memBuffer
	reader.identifier = identifier

	return reader, nil
}

func (reader *AmaasClientBufferReader) Identifier() string {
	return reader.identifier
}

func (reader *AmaasClientBufferReader) DataSize() (int64, error) {

	return int64(len(reader.buffer)), nil
}

func (reader *AmaasClientBufferReader) ReadBytes(offset int64, length int32) ([]byte, error) {

	// We don't copy/clone the slice for optimal efficiency. Assumption is that the caller who
	// receives the returned slice won't do any modification to the slice and alter the
	// underlying backing array data.

	buffer_length := len(reader.buffer)
	if (offset + int64(length)) > int64(buffer_length) {
		return reader.buffer[offset:], io.EOF
	}

	return reader.buffer[offset : offset+int64(length)], nil
}

func (reader *AmaasClientBufferReader) Close() {
	reader.buffer = nil
}

// return hash value of buffer
func (reader *AmaasClientBufferReader) Hash(algorithm string) (string, error) {
	var h hash.Hash

	switch strings.ToLower(algorithm) {
	case "sha256":
		h = sha256.New()
	case "sha1":
		h = sha1.New()
	default:
		return "", fmt.Errorf(MSG("MSG_ID_ERR_UNSUPPORTED_ALGORITHM"), algorithm)
	}

	if _, err := h.Write(reader.buffer); err != nil {
		return "", err
	}

	hashValue := hex.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s:%s", algorithm, hashValue), nil
}

///////////////////////////////////////
//
// AMaaS Client layer related functions
//
///////////////////////////////////////

type AmaasClient struct {
	conn         *grpc.ClientConn
	isC1Token    bool
	authKey      string
	addr         string
	useTLS       bool
	verifyCert   bool
	timeoutSecs  int
	disableCache bool
	appName      string
	archHandler  AmaasClientArchiveHandler
}

func scanRun(ctx context.Context, cancel context.CancelFunc, c pb.ScanClient, dataReader AmaasClientReader, disableCache bool, tags []string) (string, error) {

	defer cancel()

	var stream pb.Scan_RunClient
	var err error
	var hashSha256 string

	// Validate the tags parameter
	if tags != nil {
		if err := validateTags(tags); err != nil {
			return "", err
		}
	}

	// Where certificate and connections related checks first happen, so many different
	// error conditions can be returned here.

	if stream, err = c.Run(ctx); err != nil {
		logMsg(LogLevelError, MSG("MSG_ID_ERR_SETUP_STREAM"), err)
		return makeFailedScanJSONResp(), sanitizeGRPCError(err)
	}

	defer func(stream pb.Scan_RunClient) {
		err := stream.CloseSend()
		if err != nil {
			panic(err)
		}
	}(stream)

	size, _ := dataReader.DataSize()

	if !disableCache {
		hashSha256, _ = dataReader.Hash("sha256")
	}

	hashSha1, _ := dataReader.Hash("sha1")

	if err = runInitRequest(stream, dataReader.Identifier(), int32(size), hashSha256, hashSha1, tags); err != nil {
		return makeFailedScanJSONResp(), err
	}

	var result string
	var totalUpload int32

	if result, totalUpload, err = runUploadLoop(stream, dataReader); err != nil {
		return makeFailedScanJSONResp(), err
	}

	logMsg(LogLevelDebug, MSG("MSG_ID_DEBUG_UPLOADED_BYTES"), totalUpload)

	return result, nil
}

func runInitRequest(stream pb.Scan_RunClient, identifier string, dataSize int32, hashSha256 string, hashSha1 string, tags []string) error {

	if err := stream.Send(&pb.C2S{Stage: pb.Stage_STAGE_INIT,
		FileName: identifier, RsSize: dataSize, FileSha256: hashSha256, FileSha1: hashSha1, Tags: tags}); err != nil {
		err = sanitizeGRPCError(err)
		logMsg(LogLevelError, MSG("MSG_ID_ERR_INIT"), err)
		return err
	}

	return nil
}

func runUploadLoop(stream pb.Scan_RunClient, dataReader AmaasClientReader) (result string, totalUpload int32, overallErr error) {

	result = ""
	totalUpload = 0
	overallErr = nil

	for {
		in, err := stream.Recv()

		if err != nil {
			if err == io.EOF {
				logMsg(LogLevelDebug, MSG("MSG_ID_DEBUG_CLOSED_CONN"))

			} else {

				msg := fmt.Sprintf(MSG("MSG_ID_ERR_RECV"), err.Error())
				logMsg(LogLevelError, msg)
				overallErr = sanitizeGRPCError(err)
				return
			}
			break
		}

		// TBD: Might be useful to add some checks to make sure message stage
		// and command values are coherent. Within the runUploadLoop(), stage
		// should really just be STAGE_RUN.

		switch in.Cmd {

		case pb.Command_CMD_QUIT:

			logMsg(LogLevelDebug, MSG("MSG_ID_DEBUG_QUIT"))
			result = in.Result
			return

		case pb.Command_CMD_RETR:

			logMsg(LogLevelDebug, MSG("MSG_ID_DEBUG_RETR"), in.Offset, in.Length)

			totalUpload += in.Length

			if buf, err := dataReader.ReadBytes(int64(in.Offset), in.Length); err != nil && err != io.EOF {

				msg := fmt.Sprintf(MSG("MSG_ID_ERR_RETR_DATA"), err.Error())
				logMsg(LogLevelError, msg)
				overallErr = makeInternalError(msg)
				return

			} else {

				if err := stream.Send(&pb.C2S{
					Stage:  pb.Stage_STAGE_RUN,
					Offset: in.Offset,
					Chunk:  buf}); err != nil {

					msg := fmt.Sprintf(MSG("MSG_ID_ERR_SEND_DATA"), err.Error())
					logMsg(LogLevelError, msg)
					overallErr = makeInternalError(msg)
					return
				}
			}

		default:

			msg := fmt.Sprintf(MSG("MSG_ID_ERR_UNKNOWN_CMD"), in.Cmd)
			logMsg(LogLevelError, msg)
			overallErr = makeInternalError(msg)
			return
		}
	}

	return
}

func (ac *AmaasClient) bufferScanRun(buffer []byte, identifier string, tags []string) (string, error) {

	if ac.conn == nil {
		return "", makeInternalError(MSG("MSG_ID_ERR_CLIENT_NOT_READY"))
	}

	bufferReader, err := InitBufferReader(buffer, identifier)
	if err != nil {
		return "", makeInternalError(fmt.Sprintf(MSG("MSG_ID_ERR_CLIENT_ERROR"), err.Error()))
	}
	defer bufferReader.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(ac.timeoutSecs))

	ctx = ac.buildAuthContext(ctx)

	ctx = ac.buildAppNameContext(ctx)

	return scanRun(ctx, cancel, pb.NewScanClient(ac.conn), bufferReader, ac.disableCache, tags)
}

func (ac *AmaasClient) fileScanRun(fileName string, tags []string) (string, error) {

	if ac.conn == nil {
		return "", makeInternalError(MSG("MSG_ID_ERR_CLIENT_NOT_READY"))
	}

	if ac.archHandler.archHandlingEnabled() {
		return ac.archHandler.fileScanRun(fileName)
	}

	return ac.fileScanRunNormalFile(fileName, tags)
}

func (ac *AmaasClient) fileScanRunNormalFile(fileName string, tags []string) (string, error) {

	fileReader, err := InitFileReader(fileName)
	if err != nil {
		return "", makeInternalError(fmt.Sprintf(MSG("MSG_ID_ERR_CLIENT_ERROR"), err.Error()))
	}
	defer fileReader.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(ac.timeoutSecs))

	ctx = ac.buildAuthContext(ctx)

	ctx = ac.buildAppNameContext(ctx)

	return scanRun(ctx, cancel, pb.NewScanClient(ac.conn), fileReader, ac.disableCache, tags)
}

func (ac *AmaasClient) setupComm() error {
	var err error

	if ac.authKey != "" {
		ac.isC1Token = isC1Token(ac.authKey)
	}

	if ac.conn == nil {
		if ac.useTLS {
			ac.conn, err = grpc.Dial(ac.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: !ac.verifyCert})))
		} else {
			ac.conn, err = grpc.Dial(ac.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (ac *AmaasClient) buildAuthContext(ctx context.Context) context.Context {
	newCtx := ctx
	if ac.authKey != "" {
		if ac.isC1Token {
			newCtx = gmd.AppendToOutgoingContext(ctx, "Authorization", fmt.Sprintf("Bearer %s", ac.authKey))
		} else {
			if isExplicitAPIKey(ac.authKey) {
				newCtx = gmd.AppendToOutgoingContext(ctx, "Authorization", ac.authKey)
			} else {
				newCtx = gmd.AppendToOutgoingContext(ctx, "Authorization", fmt.Sprintf("ApiKey %s", ac.authKey))
			}
		}
	}
	return newCtx
}

func (ac *AmaasClient) buildAppNameContext(ctx context.Context) context.Context {
	newCtx := ctx
	if len(ac.appName) > 0 {
		newCtx = gmd.AppendToOutgoingContext(ctx, appNameHTTPHeader, ac.appName)
	}
	return newCtx
}

////////////////////////////////////////////////
//
// Cloud One and client related helper functions
//
////////////////////////////////////////////////

func checkAuthKey(authKey string) (string, error) {

	envAuthKeyNotRequired := os.Getenv(_envvarAuthKeyNotRequired)

	if envAuthKeyNotRequired != "" && envAuthKeyNotRequired != "0" {
		return "", nil
	}

	var auth string = authKey

	envAuthKey := os.Getenv(_envvarAuthKey)

	if authKey == "" && envAuthKey == "" {
		return "", makeInternalError(MSG("MSG_ID_ERR_MISSING_AUTH"))
	} else if envAuthKey != "" {
		auth = envAuthKey
	}
	return auth, nil
}

func isExplicitAPIKey(auth string) bool {
	return strings.HasPrefix(strings.ToLower(auth), "apikey")
}

func isC1Token(auth string) bool {

	//for now, we may only support apikey, not customer token or service token
	return false

	// if isExplicitAPIKey(auth) {
	// 	return false
	// }

	// keySplitted := strings.Split(auth, ".")
	// if len(keySplitted) != 3 { // The JWT should contain three parts
	// 	return false
	// }

	// jsonFirstPart, err := base64.StdEncoding.DecodeString(keySplitted[0])
	// if err != nil {
	// 	return false
	// }

	// var firstPart struct {
	// 	Alg string `json:"alg"`
	// }
	// err = json.Unmarshal(jsonFirstPart, &firstPart)
	// if err != nil || firstPart.Alg == "" { // The first part should have the attribute "alg"
	// 	return false
	// }

	// return true
}

// deprecated
// func isC1APIKey(auth string) bool {
// 	return strings.HasPrefix(auth, "tmc") || isExplicitAPIKey(auth)
// }

func identifyServerAddr(region string) (string, error) {
	envOverrideAddr := os.Getenv(_envvarServerAddr)

	if envOverrideAddr != "" {
		return envOverrideAddr, nil
	}

	fqdn, err := getServiceFQDN(region)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%d", fqdn, _defaultCommPort), nil
}

func retrieveTLSSettings() (useTLS bool, verifyCert bool) {
	envDisableTLS := os.Getenv(_envvarDisableTLS)
	envDisableCertVerify := os.Getenv(_envvarDisableCertVerify)

	return (envDisableTLS == "" || envDisableTLS == "0"), (envDisableCertVerify == "" || envDisableCertVerify == "0")
}

func getDefaultScanTimeout() (int, error) {
	envScanTimeoutSecs := os.Getenv(_envvarScanTimeoutSecs)

	if envScanTimeoutSecs != "" {
		if val, err := strconv.Atoi(envScanTimeoutSecs); err != nil {
			return 0, fmt.Errorf(MSG("MSG_ID_ERR_ENVVAR_PARSING"), _envvarScanTimeoutSecs)
		} else {
			return val, nil
		}
	}

	return _defaultTimeoutSecs, nil
}

func getServiceFQDN(targetRegion string) (string, error) {

	// ensure the region exists in v1 or c1
	region := targetRegion
	if !slices.Contains(AllRegions, region) {
		return "", fmt.Errorf(MSG("MSG_ID_ERR_INVALID_REGION"), region, AllRegions)
	}
	// if it is a V1 region, map it to a C1 region
	if slices.Contains(V1Regions, region) {
		regionClone := ""
		exists := false
		// Make sure the v1 region is part of the cloudone.SupportedV1Regions and cloudone.V1ToC1RegionMapping lists
		if regionClone, exists = V1ToC1RegionMapping[region]; !exists || !slices.Contains(SupportedV1Regions, region) {
			return "", fmt.Errorf(MSG("MSG_ID_ERR_INVALID_REGION"), region, AllRegions)
		}
		region = regionClone
	}

	mapping := map[string]string{
		C1_US_REGION: "antimalware.us-1.cloudone.trendmicro.com",
		C1_IN_REGION: "antimalware.in-1.cloudone.trendmicro.com",
		C1_DE_REGION: "antimalware.de-1.cloudone.trendmicro.com",
		C1_SG_REGION: "antimalware.sg-1.cloudone.trendmicro.com",
		C1_AU_REGION: "antimalware.au-1.cloudone.trendmicro.com",
		C1_JP_REGION: "antimalware.jp-1.cloudone.trendmicro.com",
		C1_GB_REGION: "antimalware.gb-1.cloudone.trendmicro.com",
		C1_CA_REGION: "antimalware.ca-1.cloudone.trendmicro.com",
	}

	fqdn, exists := mapping[region]
	if !exists {
		return "", fmt.Errorf(MSG("MSG_ID_ERR_INVALID_REGION"), region, AllRegions)
	}
	return fqdn, nil
}

//////////////////////////////////////
//
// Logging and error related functions
//
//////////////////////////////////////

func getLogLevel() LogLevel {
	envLogLevel := os.Getenv(_envvarLogLevel)
	if envLogLevel != "" {
		if val, err := strconv.Atoi(envLogLevel); err == nil {
			return LogLevel(val)
		}
	}
	return LogLevelOff
}

var level2strMap = map[LogLevel]string{
	LogLevelOff:     "OFF",
	LogLevelFatal:   "FATAL",
	LogLevelError:   "ERROR",
	LogLevelWarning: "WARNING",
	LogLevelInfo:    "INFO",
	LogLevelDebug:   "DEBUG",
}

func logMsg(level LogLevel, format string, a ...interface{}) {

	// This function never be invoked with level = LogLevelOff
	if level <= LogLevelOff {
		log.Panicf(MSG("MSG_ID_WARNING_LOG_LEVEL"),
			level2strMap[LogLevelWarning], format)
	}

	if level <= currentLogLevel {
		levelStr := level2strMap[level]
		if userLogger != nil {
			userLogger(level, levelStr, format, a...)
		} else {
			format = fmt.Sprintf("[%s] %s", levelStr, format)
			log.Printf(format, a...)
		}
	}
}

func makeFailedScanJSONResp() string {
	// Only failed a scan completes successfully will the returned JSON response be valid,
	// so a failed scan response can be anything, so just return empty string for now.

	return ""
}

func makeInternalError(msg string) error {
	return status.Error(codes.Internal, msg)
}

func sanitizeGRPCError(err error) error {

	st, _ := status.FromError(err)

	// The following codes are based on https://pkg.go.dev/google.golang.org/grpc/codes#section-sourcefiles

	logMsg(LogLevelDebug, MSG("MSG_ID_DEBUG_GRPC_ERROR"), st.Code(), st.Message())

	switch st.Code() {

	// OK is returned on success.
	case codes.OK:

	// Canceled indicates the operation was canceled (typically by the caller).
	//
	// The gRPC framework will generate this error code when cancellation
	// is requested.
	case codes.Canceled:

	// Unknown error. An example of where this error may be returned is
	// if a Status value received from another address space belongs to
	// an error-space that is not known in this address space. Also
	// errors raised by APIs that do not return enough error information
	// may be converted to this error.
	//
	// The gRPC framework will generate this error code in the above two
	// mentioned cases.
	case codes.Unknown:

		return status.Error(st.Code(), MSG("MSG_ID_ERR_UNKNOWN_ERROR"))

	// InvalidArgument indicates client specified an invalid argument.
	// Note that this differs from FailedPrecondition. It indicates arguments
	// that are problematic regardless of the state of the system
	// (e.g., a malformed file name).
	//
	// This error code will not be generated by the gRPC framework.
	case codes.InvalidArgument: /* NOT GENERATED BY THE GRPC FRAMEWORK */

	// DeadlineExceeded means operation expired before completion.
	// For operations that change the state of the system, this error may be
	// returned even if the operation has completed successfully. For
	// example, a successful response from a server could have been delayed
	// long enough for the deadline to expire.
	//
	// The gRPC framework will generate this error code when the deadline is
	// exceeded.
	case codes.DeadlineExceeded:
		return status.Error(st.Code(), MSG("MSG_ID_ERR_TIMEOUT"))
	// NotFound means some requested entity (e.g., file or directory) was
	// not found.
	//
	// This error code will not be generated by the gRPC framework.
	case codes.NotFound: /* NOT GENERATED BY THE GRPC FRAMEWORK */

	// AlreadyExists means an attempt to create an entity failed because one
	// already exists.
	//
	// This error code will not be generated by the gRPC framework.
	case codes.AlreadyExists: /* NOT GENERATED BY THE GRPC FRAMEWORK */

	// PermissionDenied indicates the caller does not have permission to
	// execute the specified operation. It must not be used for rejections
	// caused by exhausting some resource (use ResourceExhausted
	// instead for those errors). It must not be
	// used if the caller cannot be identified (use Unauthenticated
	// instead for those errors).
	//
	// This error code will not be generated by the gRPC core framework,
	// but expect authentication middleware to use it.
	case codes.PermissionDenied: /* NOT GENERATED BY THE GRPC FRAMEWORK */

		return status.Error(st.Code(), MSG("MSG_ID_ERR_NO_PERMISSION"))

	// ResourceExhausted indicates some resource has been exhausted, perhaps
	// a per-user quota, or perhaps the entire file system is out of space.
	//
	// This error code will be generated by the gRPC framework in
	// out-of-memory and server overload situations, or when a message is
	// larger than the configured maximum size.
	case codes.ResourceExhausted:

	// FailedPrecondition indicates operation was rejected because the
	// system is not in a state required for the operation's execution.
	// For example, directory to be deleted may be non-empty, an rmdir
	// operation is applied to a non-directory, etc.
	//
	// A litmus test that may help a service implementor in deciding
	// between FailedPrecondition, Aborted, and Unavailable:
	//  (a) Use Unavailable if the client can retry just the failing call.
	//  (b) Use Aborted if the client should retry at a higher-level
	//      (e.g., restarting a read-modify-write sequence).
	//  (c) Use FailedPrecondition if the client should not retry until
	//      the system state has been explicitly fixed. E.g., if an "rmdir"
	//      fails because the directory is non-empty, FailedPrecondition
	//      should be returned since the client should not retry unless
	//      they have first fixed up the directory by deleting files from it.
	//  (d) Use FailedPrecondition if the client performs conditional
	//      REST Get/Update/Delete on a resource and the resource on the
	//      server does not match the condition. E.g., conflicting
	//      read-modify-write on the same resource.
	//
	// This error code will not be generated by the gRPC framework.
	case codes.FailedPrecondition: /* NOT GENERATED BY THE GRPC FRAMEWORK */

	// Aborted indicates the operation was aborted, typically due to a
	// concurrency issue like sequencer check failures, transaction aborts,
	// etc.
	//
	// See litmus test above for deciding between FailedPrecondition,
	// Aborted, and Unavailable.
	//
	// This error code will not be generated by the gRPC framework.
	case codes.Aborted: /* NOT GENERATED BY THE GRPC FRAMEWORK */

	// OutOfRange means operation was attempted past the valid range.
	// E.g., seeking or reading past end of file.
	//
	// Unlike InvalidArgument, this error indicates a problem that may
	// be fixed if the system state changes. For example, a 32-bit file
	// system will generate InvalidArgument if asked to read at an
	// offset that is not in the range [0,2^32-1], but it will generate
	// OutOfRange if asked to read from an offset past the current
	// file size.
	//
	// There is a fair bit of overlap between FailedPrecondition and
	// OutOfRange. We recommend using OutOfRange (the more specific
	// error) when it applies so that callers who are iterating through
	// a space can easily look for an OutOfRange error to detect when
	// they are done.
	//
	// This error code will not be generated by the gRPC framework.
	case codes.OutOfRange: /* NOT GENERATED BY THE GRPC FRAMEWORK */

	// Unimplemented indicates operation is not implemented or not
	// supported/enabled in this service.
	//
	// This error code will be generated by the gRPC framework. Most
	// commonly, you will see this error code when a method implementation
	// is missing on the server. It can also be generated for unknown
	// compression algorithms or a disagreement as to whether an RPC should
	// be streaming.
	case codes.Unimplemented:

		return status.Error(st.Code(), MSG("MSG_ID_ERR_INCOMPATIBLE_SDK"))

	// Internal errors. Means some invariants expected by underlying
	// system has been broken. If you see one of these errors,
	// something is very broken.
	//
	// This error code will be generated by the gRPC framework in several
	// internal error conditions.
	case codes.Internal:

	// Unavailable indicates the service is currently unavailable.
	// This is a most likely a transient condition and may be corrected
	// by retrying with a backoff. Note that it is not always safe to retry
	// non-idempotent operations.
	//
	// See litmus test above for deciding between FailedPrecondition,
	// Aborted, and Unavailable.
	//
	// This error code will be generated by the gRPC framework during
	// abrupt shutdown of a server process or network connection.
	case codes.Unavailable:

		desc := st.Message()

		if strings.Contains(desc, "transport: authentication handshake failed: x509") {
			return status.Error(codes.Internal, MSG("MSG_ID_ERR_CERT_VERIFY"))
		} else if strings.Contains(desc, "http2: frame too large") {
			return status.Error(codes.Internal, MSG("MSG_ID_ERR_TLS_REQUIRED"))
		} else if strings.Contains(desc, "unexpected HTTP status code received from server: 429") {
			return status.Error(codes.Internal, MSG("MSG_ID_ERR_RATE_LIMIT_EXCEEDED"))
		}

		return status.Error(st.Code(), "Anti-Malware Service is not reachable")

	// DataLoss indicates unrecoverable data loss or corruption.
	//
	// This error code will not be generated by the gRPC framework.
	case codes.DataLoss: /* NOT GENERATED BY THE GRPC FRAMEWORK */

	// Unauthenticated indicates the request does not have valid
	// authentication credentials for the operation.
	//
	// The gRPC framework will generate this error code when the
	// authentication metadata is invalid or a Credentials callback fails,
	// but also expect authentication middleware to generate it.
	case codes.Unauthenticated:

		return status.Error(st.Code(), MSG("MSG_ID_ERR_KEY_AUTH_FAILED"))
	}

	return status.Error(codes.Internal, st.Message())
}

//////////////////////////////////////////////////////////////
//
// Publicly unsupported API provided for legacy internal tools
//
//////////////////////////////////////////////////////////////

func NewClientInternal(key string, addr string, useTLS bool) (*AmaasClient, error) {

	ac := &AmaasClient{}

	ac.authKey = key
	ac.addr = addr
	ac.useTLS = useTLS
	ac.verifyCert = false

	ac.appName = appNameV1FS

	var err error

	if ac.timeoutSecs, err = getDefaultScanTimeout(); err != nil {
		return nil, err
	}

	if err = ac.archHandler.initHandler(ac); err != nil {
		return nil, err
	}

	if err = ac.setupComm(); err != nil {
		return nil, err
	}

	return ac, nil
}

func (ac *AmaasClient) SetCacheDisable() {
	ac.disableCache = true
}

func validateTags(tags []string) error {
	if len(tags) == 0 {
		return errors.New("tags cannot be empty")
	}

	if len(tags) > maxTagsListSize {
		return fmt.Errorf("too many tags, maximum is %d", maxTagsListSize)
	}

	for _, tag := range tags {
		if len(tag) > maxTagSize {
			return fmt.Errorf("tag length cannot exceed %d", maxTagSize)
		}
		if tag == "" {
			return errors.New("each tag cannot be empty")
		}
	}
	return nil
}
