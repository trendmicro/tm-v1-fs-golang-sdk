package client

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
)

const (
	_defaultCommPort    = 443 // Port used by AMaaS Client to communicate with server.
	_defaultTimeoutSecs = 180 // 3 minutes
)

const (
	_envvarAuthKey         = "TM_AM_AUTH_KEY"          // Can be API key or token; SDK will auto-detect
	_envvarScanTimeoutSecs = "TM_AM_SCAN_TIMEOUT_SECS" // Number of seconds before scan request timeout; default is 180 seconds.
	_envvarLogLevel        = "TM_AM_LOG_LEVEL"         // Can be used to override program's current log level
)

const (
	LogLevelOff     LogLevel = 0
	LogLevelFatal            = 1
	LogLevelError            = 2
	LogLevelWarning          = 3
	LogLevelInfo             = 4
	LogLevelDebug            = 5
)

func NewClient(key string, region string) (c *AmaasClient, e error) {

	ac := &AmaasClient{}

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
// The ScanFile() and ScanBuffer() functions are thread-safe and can be invoked by multiple threads,
// but all file scans must complete before Destroy() can be invoked.
//

func (ac *AmaasClient) ScanFile(filePath string) (resp string, e error) {
	currentLogLevel = getLogLevel()
	return ac.fileScanRun(filePath)
}

func (ac *AmaasClient) ScanBuffer(buffer []byte, identifier string) (resp string, e error) {
	currentLogLevel = getLogLevel()
	return ac.bufferScanRun(buffer, identifier)
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
