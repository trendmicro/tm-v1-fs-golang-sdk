package client

import (
	"context"
	"fmt"
	"io"

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

// config holds the configuration for creating an AmaasClient.
type config struct {
	Key            string
	Region         string
	V1Direct       bool
	Digest         bool
	PML            bool
	Feedback       bool
	Verbose        bool
	ActiveContent  bool
	CloudAccountID string
}

// Option is a functional option for configuring config.
type Option func(*config) error

// WithDigest sets whether to calculate file digest during scan.
func WithDigest(digest bool) Option {
	return func(cfg *config) error {
		cfg.Digest = digest
		return nil
	}
}

// WithPML enables PML feature.
func WithPML(pml bool) Option {
	return func(cfg *config) error {
		cfg.PML = pml
		return nil
	}
}

// WithFeedback enables feedback feature.
func WithFeedback(feedback bool) Option {
	return func(cfg *config) error {
		cfg.Feedback = feedback
		return nil
	}
}

// WithVerbose enables verbose output.
func WithVerbose(verbose bool) Option {
	return func(cfg *config) error {
		cfg.Verbose = verbose
		return nil
	}
}

// WithActiveContent enables active content feature.
func WithActiveContent(activeContent bool) Option {
	return func(cfg *config) error {
		cfg.ActiveContent = activeContent
		return nil
	}
}

// WithCloudAccountID sets the cloud account ID.
func WithCloudAccountID(cloudAccountID string) Option {
	return func(cfg *config) error {
		if cloudAccountID == "" {
			cfg.CloudAccountID = cloudAccountID
			return nil
		}

		// Calculate the total tag length with "cloudAccountId=" prefix
		cloudAccountTag := fmt.Sprintf("cloudAccountId=%s", cloudAccountID)
		if len(cloudAccountTag) > maxTagSize {
			return fmt.Errorf("cloudAccountID tag 'cloudAccountId=%s' exceeds maximum tag size of %d characters", cloudAccountID, maxTagSize)
		}

		cfg.CloudAccountID = cloudAccountID
		return nil
	}
}

// WithV1Direct configures whether to connect directly to Vision One (V1) endpoint.
// When enabled, V1 regions will use V1 FQDN directly.
// When disabled (default), V1 regions will be routed through Cloud One (C1) endpoint.
func WithV1Direct(v1Direct bool) Option {
	return func(cfg *config) error {
		cfg.V1Direct = v1Direct
		return nil
	}
}

// newDefaultConfig creates a new config with default values.
func newDefaultConfig(key string, region string) *config {
	return &config{
		Key:    key,
		Region: region,
		Digest: true,
	}
}

// initFromConfig initializes the AmaasClient from the given config and applies defaults.
func (ac *AmaasClient) initFromConfig(cfg *config) error {
	var err error

	// Validate and transform key
	if ac.authKey, err = checkAuthKey(cfg.Key); err != nil {
		return err
	}

	// Transform region to server address
	if ac.addr, err = identifyServerAddr(cfg.Region, cfg.V1Direct); err != nil {
		return err
	}

	// Apply config values
	ac.digest = cfg.Digest
	ac.pml = cfg.PML
	ac.feedback = cfg.Feedback
	ac.verbose = cfg.Verbose
	ac.activeContent = cfg.ActiveContent
	ac.cloudAccountID = cfg.CloudAccountID
	// Apply defaults for internal settings
	ac.appName = appNameV1FS
	ac.useTLS, ac.verifyCert = retrieveTLSSettings()

	if ac.timeoutSecs, err = getDefaultScanTimeout(); err != nil {
		return err
	}

	return nil
}

func NewClient(key string, region string) (c *AmaasClient, e error) {
	return NewClientWithOptions(key, region)
}

func NewClientWithOptions(key string, region string, opts ...Option) (c *AmaasClient, e error) {

	// Create config with defaults
	cfg := newDefaultConfig(key, region)

	// Apply options to config
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	// Create client and initialize from config
	ac := &AmaasClient{}

	if err := ac.initFromConfig(cfg); err != nil {
		return nil, err
	}

	if err := ac.archHandler.initHandler(ac); err != nil {
		return nil, err
	}

	if err := ac.setupComm(); err != nil {
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

func ConfigLoggingCallback(f func(level LogLevel, levelStr string, format string, a ...any)) {
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

func (ac *AmaasClient) EncodeFile(ctx context.Context, src string, dst string) (e error) {
	currentLogLevel = getLogLevel()
	return ac.fileEncodeRun(ctx, src, dst)
}

func (ac *AmaasClient) EncodeReader(ctx context.Context, reader AmaasClientReader, writer io.WriterAt) (e error) {
	currentLogLevel = getLogLevel()
	return ac.readerEncodeRun(ctx, reader, writer)
}

func (ac *AmaasClient) DecodeFile(ctx context.Context, src string, dst string) (e error) {
	currentLogLevel = getLogLevel()
	return ac.fileDecodeRun(ctx, src, dst)
}

func (ac *AmaasClient) DecodeReader(ctx context.Context, reader AmaasClientReader, writer io.Writer) (e error) {
	currentLogLevel = getLogLevel()
	return ac.readerDecodeRun(ctx, reader, writer)
}
