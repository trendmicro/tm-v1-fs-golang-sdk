package client

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

//
// API key related tests
//

func TestCheckAuthKeyEmpty(t *testing.T) {

	os.Setenv(_envvarAuthKey, "")
	os.Setenv(_envvarAuthKeyNotRequired, "")

	key, err := checkAuthKey("")

	assert.NotNil(t, err)
	assert.Equal(t, "", key)

	// Set TM_AM_AUTH_KEY_NOT_REQUIRED to "0" has same effect as empty
	os.Setenv(_envvarAuthKeyNotRequired, "0")

	key, err = checkAuthKey("")

	assert.NotNil(t, err)
	assert.Equal(t, "", key)
}

func TestCheckAuthKeyEmptyWithOverride(t *testing.T) {

	os.Setenv(_envvarAuthKey, "")
	os.Setenv(_envvarAuthKeyNotRequired, "1")

	key, err := checkAuthKey("")

	assert.Nil(t, err)
	assert.Equal(t, "", key)
}

const someAPIKey = "tmcmockapikey"

func TestCheckAuthKeyNonEmptyValidAPIKey(t *testing.T) {

	os.Setenv(_envvarAuthKey, "")
	os.Setenv(_envvarAuthKeyNotRequired, "")

	key, err := checkAuthKey(someAPIKey)

	assert.Nil(t, err)
	assert.Equal(t, someAPIKey, key)
}

func TestCheckAuthKeyNonEmptyValidJWT(t *testing.T) {

	os.Setenv(_envvarAuthKey, "")
	os.Setenv(_envvarAuthKeyNotRequired, "")

	someJWT, _ := generateJwtToken()

	key, err := checkAuthKey(someJWT)

	assert.Nil(t, err)
	assert.Equal(t, someJWT, key)
}

func TestCheckAuthKeyNonEmptyEnvVarOverride(t *testing.T) {

	someEnvVarSetAuthKey, _ := generateJwtToken()

	os.Setenv(_envvarAuthKey, someEnvVarSetAuthKey)
	os.Setenv(_envvarAuthKeyNotRequired, "")

	const someKey = "some-string-as-api-key"
	key, err := checkAuthKey(someKey)

	assert.Nil(t, err)
	assert.Equal(t, someEnvVarSetAuthKey, key)

	// Set TM_AM_AUTH_KEY_NOT_REQUIRED to "0" has same effect as empty
	os.Setenv(_envvarAuthKeyNotRequired, "0")

	key, err = checkAuthKey(someKey)

	assert.Nil(t, err)
	assert.Equal(t, someEnvVarSetAuthKey, key)
}

//
// Service FQDN related tests
//

func TestGetServiceFQDNEmpty(t *testing.T) {

	fqdn, _ := getServiceFQDN("")
	assert.Equal(t, "", fqdn)
}

func TestGetServiceFQDNGarbage(t *testing.T) {

	fqdn, _ := getServiceFQDN("blah blah okay")
	assert.Equal(t, "", fqdn)
}

func TestGetServiceFQDNMapping(t *testing.T) {

	var inputs = []string{
		"us-1",
		"in-1",
		"de-1",
		"sg-1",
		"au-1",
		"jp-1",
		"gb-1",
		"ca-1",
		"trend-us-1",
	}

	for _, region := range inputs {
		expected := fmt.Sprintf("antimalware.%s.cloudone.trendmicro.com", region)
		fqdn, _ := getServiceFQDN(region)

		assert.Equal(t, expected, fqdn)
	}
}

func TestGetServiceFQDNMappingVisionOne(t *testing.T) {

	var inputs = map[string]string{
		"us-1": "us-east-1",
		"in-1": "ap-south-1",
		"de-1": "eu-central-1",
		"sg-1": "ap-southeast-1",
		"au-1": "ap-southeast-2",
		"jp-1": "ap-northeast-1",
		// "gb-1": "",
		// "ca-1": "",
		// "trend-us-1": "",
	}

	for c1, v1 := range inputs {
		expected := fmt.Sprintf("antimalware.%s.cloudone.trendmicro.com", c1)
		fqdn, _ := getServiceFQDN(v1)

		assert.Equal(t, expected, fqdn)
	}
}

//
// Server address retrieval related tests
//

func TestIdServerAddressEmpty(t *testing.T) {

	os.Setenv(_envvarServerAddr, "")

	addr, err := identifyServerAddr("")

	assert.NotNil(t, err)
	assert.Equal(t, "", addr)
}

func TestIdServerAddressEmptyWithOverride(t *testing.T) {

	const testAddr = "this.is.a.fake.server.address:123"
	os.Setenv(_envvarServerAddr, testAddr)

	addr, err := identifyServerAddr("")

	assert.Nil(t, err)
	assert.Equal(t, testAddr, addr)
}

func TestIdServerAddressGarbage(t *testing.T) {

	os.Setenv(_envvarServerAddr, "")

	addr, err := identifyServerAddr("blah blah blah")

	assert.NotNil(t, err)
	assert.Equal(t, "", addr)
}

func TestIdServerAddressValid(t *testing.T) {

	os.Setenv(_envvarServerAddr, "")

	addr, err := identifyServerAddr("us-east-1")
	fqdn, _ := getServiceFQDN("us-east-1")
	expected := fmt.Sprintf("%s:%d", fqdn, _defaultCommPort)

	assert.Nil(t, err)
	assert.Equal(t, expected, addr)
}

func TestIdServerAddressValidWithOverride(t *testing.T) {

	const testAddr = "this.is.a.fake.server.address:123"
	os.Setenv(_envvarServerAddr, testAddr)

	addr, err := identifyServerAddr("us-east-1")

	assert.Nil(t, err)
	assert.Equal(t, testAddr, addr)
}

//
// TLS settings related tests
//

func TestRetrieveTLSSettings(t *testing.T) {

	os.Setenv(_envvarDisableTLS, "")
	os.Setenv(_envvarDisableCertVerify, "")

	useTLS, verifyCert := retrieveTLSSettings()

	assert.Equal(t, true, useTLS)
	assert.Equal(t, true, verifyCert)

	os.Setenv(_envvarDisableTLS, "0")
	os.Setenv(_envvarDisableCertVerify, "0")

	useTLS, verifyCert = retrieveTLSSettings()

	assert.Equal(t, true, useTLS)
	assert.Equal(t, true, verifyCert)

	os.Setenv(_envvarDisableTLS, "1")
	os.Setenv(_envvarDisableCertVerify, "1")

	useTLS, verifyCert = retrieveTLSSettings()

	assert.Equal(t, false, useTLS)
	assert.Equal(t, false, verifyCert)
}

//
// Scan timeout related tests
//

func TestGetDefaultScanTimeout(t *testing.T) {

	os.Setenv(_envvarScanTimeoutSecs, "")

	timeout, err := getDefaultScanTimeout()

	assert.Nil(t, err)
	assert.Equal(t, _defaultTimeoutSecs, timeout)
}

func TestGetDefaultScanTimeoutWithOverride(t *testing.T) {

	os.Setenv(_envvarScanTimeoutSecs, "what-the-heck")

	_, err := getDefaultScanTimeout()

	assert.NotNil(t, err)

	os.Setenv(_envvarScanTimeoutSecs, "1000")

	timeout, err := getDefaultScanTimeout()

	assert.Nil(t, err)
	assert.Equal(t, 1000, timeout)

	os.Setenv(_envvarScanTimeoutSecs, "123")

	timeout, err = getDefaultScanTimeout()

	assert.Nil(t, err)
	assert.Equal(t, 123, timeout)
}

//
// Logging facility related tests
//

func TestLogMsgWithNonOffLevel(t *testing.T) {

	triggered := false

	defer func() {
		triggered = true
	}()

	logMsg(LogLevelFatal, "TestLogMsgWithNonOffLevel: LogLevelFatal")
	logMsg(LogLevelError, "TestLogMsgWithNonOffLevel: LogLevelError")
	logMsg(LogLevelWarning, "TestLogMsgWithNonOffLevel: LogLevelWarning")
	logMsg(LogLevelInfo, "TestLogMsgWithNonOffLevel: LogLevelInfo")
	logMsg(LogLevelDebug, "TestLogMsgWithNonOffLevel: LogLevelDebug")

	assert.Equal(t, false, triggered)
}

func TestLogMsgWithOffLevel(t *testing.T) {

	triggered := false

	defer func() {
		triggered = true

		r := recover()
		assert.NotNil(t, r)
	}()

	logMsg(LogLevelOff, "TestLogMsgWithNonOffLevel: LogLevelOff")

	assert.Equal(t, true, triggered)
}

var CBTriggeredFlag bool = false

func LoggingCallback(level LogLevel, levelStr string, format string, a ...interface{}) {
	CBTriggeredFlag = true
}

func TestLoggingWithError(t *testing.T) {

	ConfigLoggingCallback(LoggingCallback)

	CBTriggeredFlag = false

	// We're just using InitFileReader() to trigger error conditions and error logging.
	reader, err := InitFileReader("some-file-that-doesnt-exist")
	assert.Nil(t, reader)
	assert.NotNil(t, err)

	SetLoggingLevel(LogLevelOff)
	reader, err = InitFileReader("some-file-that-doesnt-exist")
	assert.Nil(t, reader)
	assert.NotNil(t, err)
	assert.Equal(t, false, CBTriggeredFlag)

	// With log level at FATAL, callback should NOT be triggered
	// even when there is an error from a file open failure.

	SetLoggingLevel(LogLevelFatal)
	reader, err = InitFileReader("some-file-that-doesnt-exist")
	assert.Nil(t, reader)
	assert.NotNil(t, err)
	assert.Equal(t, false, CBTriggeredFlag)

	// With log level at ERROR, callback should be triggered
	// when there is an error from a file open failure.

	SetLoggingLevel(LogLevelError)
	reader, err = InitFileReader("some-file-that-doesnt-exist")
	assert.Nil(t, reader)
	assert.NotNil(t, err)
	assert.Equal(t, true, CBTriggeredFlag)

	CBTriggeredFlag = false

	// With log level at ERROR, callback should  be triggered
	// when there is an error from a file open failure.

	SetLoggingLevel(LogLevelWarning)
	reader, err = InitFileReader("some-file-that-doesnt-exist")
	assert.Nil(t, reader)
	assert.NotNil(t, err)
	assert.Equal(t, true, CBTriggeredFlag)

	CBTriggeredFlag = false

	// With log level at INFO, callback should  be triggered
	// when there is an error from a file open failure.

	SetLoggingLevel(LogLevelInfo)
	reader, err = InitFileReader("some-file-that-doesnt-exist")
	assert.Nil(t, reader)
	assert.NotNil(t, err)
	assert.Equal(t, true, CBTriggeredFlag)
}

func TestLoggingWithNonDebugLevel(t *testing.T) {

	if os.Getenv("CI") != "" {
		t.Skip("Skipping this test in slower CI environment")
	}

	ConfigLoggingCallback(LoggingCallback)

	CBTriggeredFlag = false

	// With log level at OFF, callback should not be triggered.

	SetLoggingLevel(LogLevelOff)
	TestRunUploadLoopNormalForFileReader(t)
	assert.Equal(t, false, CBTriggeredFlag)

	// With log level at FATAL, callback should not be triggered.

	SetLoggingLevel(LogLevelFatal)
	TestRunUploadLoopNormalForFileReader(t)
	assert.Equal(t, false, CBTriggeredFlag)

	// With log level at ERROR, callback should not be triggered.

	SetLoggingLevel(LogLevelError)
	TestRunUploadLoopNormalForFileReader(t)
	assert.Equal(t, false, CBTriggeredFlag)

	// With log level at WARNING, callback should not be triggered.

	SetLoggingLevel(LogLevelWarning)
	TestRunUploadLoopNormalForFileReader(t)
	assert.Equal(t, false, CBTriggeredFlag)

	// With log level at INFO, callback should not be triggered.

	SetLoggingLevel(LogLevelInfo)
	TestRunUploadLoopNormalForFileReader(t)
	assert.Equal(t, false, CBTriggeredFlag)
}

func TestLoggingWithDebugLevel(t *testing.T) {

	if os.Getenv("CI") != "" {
		t.Skip("Skipping this test in slower CI environment")
	}

	ConfigLoggingCallback(LoggingCallback)
	CBTriggeredFlag = false

	// Callback should only be triggered when level is at DEBUG

	SetLoggingLevel(LogLevelDebug)
	TestRunUploadLoopNormalForFileReader(t)
	assert.Equal(t, true, CBTriggeredFlag)
}

func TestBufferClientSha256(t *testing.T) {

	data := []byte("dummy")
	client, _ := InitBufferReader(data, "test")
	assert.NotNil(t, client)
	r, _ := client.Hash("sha256")
	assert.NotEmpty(t, r)
}

func TestBufferClientSha1(t *testing.T) {

	data := []byte("dummy")
	client, _ := InitBufferReader(data, "test")
	assert.NotNil(t, client)
	r, _ := client.Hash("sha1")
	assert.NotEmpty(t, r)
}

func TestFileClientSha1WithUnsupportedAlgo(t *testing.T) {

	data := []byte("dummy")
	client, _ := InitBufferReader(data, "test")
	assert.NotNil(t, client)
	r, err := client.Hash("sha224")
	assert.Empty(t, r)
	assert.NotNil(t, err)
	assert.Error(t, err, "Unsupported algorithm for calculating the hash: sha224")
}

func TestFileClientSha256(t *testing.T) {

	file_path, _ := os.Executable()
	client, _ := InitFileReader(file_path)
	assert.NotNil(t, client)
	r, _ := client.Hash("sha256")
	assert.NotEmpty(t, r)
}

func TestFileClientSha1(t *testing.T) {

	file_path, _ := os.Executable()
	client, _ := InitFileReader(file_path)
	assert.NotNil(t, client)
	r, _ := client.Hash("sha1")
	assert.NotEmpty(t, r)
}

func TestFileClientSha256WithUnsupportedAlgo(t *testing.T) {

	file_path, _ := os.Executable()
	client, _ := InitFileReader(file_path)
	assert.NotNil(t, client)
	r, err := client.Hash("sha224")
	assert.Empty(t, r)
	assert.NotNil(t, err)
	assert.Error(t, err, "Unsupported algorithm for calculating the hash: sha224")
}

func TestCheckAuthKey(t *testing.T) {
	tcs := []struct {
		testCase       string
		input          string
		expectedResult string
		expectedError  bool
	}{
		{
			testCase:       "c1 key",
			input:          "tmcDummy",
			expectedResult: "tmcDummy",
			expectedError:  false,
		},
		{
			testCase:       "explicit key",
			input:          "Apikey Dummy",
			expectedResult: "Apikey Dummy",
			expectedError:  false,
		},
		{
			testCase:       "any key",
			input:          "Dummy key",
			expectedResult: "Dummy key",
			expectedError:  false,
		},
		{
			testCase:       "empty key",
			input:          "",
			expectedResult: "",
			expectedError:  true,
		},
	}

	for _, tc := range tcs {
		os.Unsetenv("TM_AM_AUTH_KEY")
		t.Run(tc.testCase, func(t *testing.T) {
			result, err := checkAuthKey(tc.input)
			if tc.expectedError {
				assert.NotNil(t, err)
			} else {
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}

}

func generateJwtToken() (string, error) {
	// Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return ss, nil
}
