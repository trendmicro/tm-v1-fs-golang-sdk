package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
)

const (
	_defaultCommPort    = 443 // Port used by AMaaS Client to communicate with server.
	_defaultTimeoutSecs = 300 // 5 minutes
)

const (
	_envvarAuthKey         = "TM_AM_AUTH_KEY"          // Can be API key or token; SDK will auto-detect
	_envvarScanTimeoutSecs = "TM_AM_SCAN_TIMEOUT_SECS" // Number of seconds before scan request timeout; default is 180 seconds.
	_envvarLogLevel        = "TM_AM_LOG_LEVEL"         // Can be used to override program's current log level
)

const (
	LogLevelOff     LogLevel = iota
	LogLevelFatal   LogLevel = 1
	LogLevelError   LogLevel = 2
	LogLevelWarning LogLevel = 3
	LogLevelInfo    LogLevel = 4
	LogLevelDebug   LogLevel = 5
)

type AmaasClientReader interface {
	// Return the identifier of the data source. For example, name of the file being read.
	Identifier() string

	// Return the total size of the data source.
	DataSize() (int64, error)

	// Return requested number of bytes from the data source starting at the specified offset.
	ReadBytes(offset int64, length int32) ([]byte, error)
}

func NewClient(key string, region string) (c *AmaasClient, e error) {

	ac := &AmaasClient{digest: true}

	ac.appName = appNameV1FS

	var err error

	if ac.authKey, err = checkAuthKey(key); err != nil {
		return nil, err
	}

	if ac.addr, err = identifyServerAddr(region); err != nil {
		return nil, err
	}

	ac.useTLS, ac.verifyCert = retrieveTLSSettings()

	if ac.timeoutSecs, err = getDefaultScanTimeout(); err != nil {
		return nil, err
	}

	if err = ac.archHandler.initHandler(ac); err != nil {
		return nil, err
	}

	if err = ac.setupComm(); err != nil {
		return nil, err
	}

	// TBD: We might want to do a hello/ping here against the target server so we can assess
	// service connectivity and access before user actually calls ScanFile().

	return ac, nil
}

//
// The Destroy() function should only be called after all ScanFile() invocations have completed.
//

func (ac *AmaasClient) Destroy() {

	if ac.conn != nil {
		ac.conn.Close()
		ac.conn = nil
	}
}

//
// The ScanFile(), ScanBuffer() and ScanReader() functions are thread-safe and can be invoked by multiple threads,
// but all file scans must complete before Destroy() can be invoked.

// If your application utilizes ScanReader() for scanning, it's advisable to deactivate digest feature by SetDigestDisable().
// This is because the Digest feature requires the entire file to be read/feteched.
//
// For instance, scanning a cloud-based file requires downloading the entire file locally for digest calculation.
// It increases network usage and processing time.
//

func (ac *AmaasClient) ScanFile(filePath string, tags []string) (resp string, e error) {
	ctx := context.Background()
	currentLogLevel = getLogLevel()
	return ac.fileScanRun(ctx, filePath, tags)
}

func (ac *AmaasClient) ScanFileWithContext(ctx context.Context, filePath string, tags []string) (resp string, e error) {
	currentLogLevel = getLogLevel()
	return ac.fileScanRun(ctx, filePath, tags)
}

func (ac *AmaasClient) ScanBuffer(buffer []byte, identifier string, tags []string) (resp string, e error) {
	ctx := context.Background()
	currentLogLevel = getLogLevel()
	return ac.bufferScanRun(ctx, buffer, identifier, tags)
}

func (ac *AmaasClient) ScanBufferWithContext(ctx context.Context, buffer []byte, identifier string, tags []string) (resp string, e error) {
	currentLogLevel = getLogLevel()
	return ac.bufferScanRun(ctx, buffer, identifier, tags)
}

func (ac *AmaasClient) ScanReader(reader AmaasClientReader, tags []string) (resp string, e error) {
	ctx := context.Background()
	currentLogLevel = getLogLevel()
	return ac.readerScanRun(ctx, reader, tags)
}

func (ac *AmaasClient) ScanReaderWithContext(ctx context.Context, reader AmaasClientReader, tags []string) (resp string, e error) {
	currentLogLevel = getLogLevel()
	return ac.readerScanRun(ctx, reader, tags)
}

func (ac *AmaasClient) DumpConfig() (output string) {
	return fmt.Sprintf("%+v", ac)
}

func SetLoggingLevel(level LogLevel) {
	currentLogLevel = level
}

func ConfigLoggingCallback(f func(level LogLevel, levelStr string, format string, a ...interface{})) {
	userLogger = f
}

func (ac *AmaasClient) GetTimeoutSetting() int {
	return ac.timeoutSecs
}

func (ac *AmaasClient) GetConnection() *grpc.ClientConn {
	return ac.conn
}

func (ac *AmaasClient) ConfigAuth(ctx context.Context) context.Context {
	return ac.buildAuthContext(ctx)
}

func (ac *AmaasClient) SetAppName(appName string) {
	ac.appName = appName
}

func (ac *AmaasClient) GetAppName() string {
	return ac.appName
}

func (ac *AmaasClient) ConfigAppName(ctx context.Context) context.Context {
	return ac.buildAppNameContext(ctx)
}
