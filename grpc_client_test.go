package client

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
		"ae-1": "me-central-1",
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

type MockAmassClientReader struct {
	size int64
}

func NewMockAmassClientReader(size int64) *MockAmassClientReader {
	return &MockAmassClientReader{size: size}
}

func (m *MockAmassClientReader) Identifier() string {
	return "MockAmassClientReader"
}

func (m *MockAmassClientReader) DataSize() (int64, error) {
	return m.size, nil
}

func (m *MockAmassClientReader) ReadBytes(offset int64, length int32) ([]byte, error) {
	if offset < 0 || offset >= m.size {
		return nil, fmt.Errorf("Invalid offset: %d", offset)
	}

	// always return an array filled with zero
	return make([]byte, length), nil
}

func TestGetHashValue(t *testing.T) {

	reader := NewMockAmassClientReader(1024*1024 - 301)
	sha1, sha256, _ := getHashValue(reader)
	assert.Equal(t, "sha1:5e944e68476189d048e74673b02a62dc42118cc8", sha1)
	assert.Equal(t, "sha256:5746a33a622bbfd8d32a6398bbc04e90b3269787b17a9740b95e04a641a47935", sha256)

	reader = NewMockAmassClientReader(1024*1024 - 1)
	sha1, sha256, _ = getHashValue(reader)
	assert.Equal(t, "sha1:24f30d3b09e9056c6b9f6dfd6f386c6828fd63c3", sha1)
	assert.Equal(t, "sha256:ca7ed0c4a8e67cbdc461c4cb0d286d2fabbd9f0c41a7f42b665f72ebaa8aec56", sha256)

	reader = NewMockAmassClientReader(1024*1024 + 0)
	sha1, sha256, _ = getHashValue(reader)
	assert.Equal(t, "sha1:3b71f43ff30f4b15b5cd85dd9e95ebc7e84eb5a3", sha1)
	assert.Equal(t, "sha256:30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58", sha256)

	reader = NewMockAmassClientReader(1024*1024 + 1)
	sha1, sha256, _ = getHashValue(reader)
	assert.Equal(t, "sha1:a84d35eda74338bd79a432f77d73f8ab5eb91902", sha1)
	assert.Equal(t, "sha256:2cb74edba754a81d121c9db6833704a8e7d417e5b13d1a19f4a52f007d644264", sha256)

	reader = NewMockAmassClientReader(1024*1024 + 244)
	sha1, sha256, _ = getHashValue(reader)
	assert.Equal(t, "sha1:5f054033c49f65dce7ca3d30519663db572b040c", sha1)
	assert.Equal(t, "sha256:e8b900132db114bbe70361feb988e5f3b59c88f936b3e8fe924d448f0689f42c", sha256)
}

func TestGetHashValueWithBufferReader(t *testing.T) {
	data := []byte("dummy")
	reader, _ := InitBufferReader(data, "test")
	sha1, sha256, _ := getHashValue(reader)
	assert.Equal(t, "sha1:829c3804401b0727f70f73d4415e162400cbe57b", sha1)
	assert.Equal(t, "sha256:b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259", sha256)

	data = []byte("dummy1234567890")
	reader, _ = InitBufferReader(data, "test")
	sha1, sha256, _ = getHashValue(reader)
	assert.Equal(t, "sha1:84901b8dc51ff505905443f863d6b6e8e6eca1f3", sha1)
	assert.Equal(t, "sha256:e47a0a4d0e7da5ab6a5e331a0400157b09c44926224e9357308805ade4ae8141", sha256)
}

func TestGetHashValueWithFileReader(t *testing.T) {
	dat := createTestDat("test.*.dat")
	assert.NotNil(t, dat)
	defer os.Remove(dat.Filename())

	reader, _ := InitFileReader(dat.Filename())
	sha1, sha256, _ := getHashValue(reader)
	assert.Equal(t, dat.Sha1(), sha1)
	assert.Equal(t, dat.Sha256(), sha256)
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
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		Issuer:    "test",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	return ss, nil
}

//
// CloudAccountID related tests
//

func TestSetCloudAccountIDValid(t *testing.T) {
	ac := &AmaasClient{}

	// Test with AWS account ID (12 digits)
	err := ac.SetCloudAccountID("633537927402")
	assert.Nil(t, err)
	assert.Equal(t, "633537927402", ac.cloudAccountID)

	// Test with Azure UUID-v4 (36 characters)
	err = ac.SetCloudAccountID("a47ac10b-58cc-4372-a567-0e02b2c3d479")
	assert.Nil(t, err)
	assert.Equal(t, "a47ac10b-58cc-4372-a567-0e02b2c3d479", ac.cloudAccountID)

	// Test with exactly 48 characters (63 - 15 for "cloudAccountId=")
	longButValid := "123456789012345678901234567890123456789012345678"
	err = ac.SetCloudAccountID(longButValid)
	assert.Nil(t, err)
	assert.Equal(t, longButValid, ac.cloudAccountID)
}

func TestSetCloudAccountIDTooLong(t *testing.T) {
	ac := &AmaasClient{}

	// Test with string longer than 48 characters (49 chars)
	tooLong := "1234567890123456789012345678901234567890123456789"
	err := ac.SetCloudAccountID(tooLong)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum tag size of 63 characters")
	assert.Equal(t, "", ac.cloudAccountID)
}

func TestSetCloudAccountIDEmpty(t *testing.T) {
	ac := &AmaasClient{}

	// Test with empty string (should be allowed)
	err := ac.SetCloudAccountID("")
	assert.Nil(t, err)
	assert.Equal(t, "", ac.cloudAccountID)
}

func TestAppendCloudAccountIDToTagsWithEmpty(t *testing.T) {
	ac := &AmaasClient{}
	ac.cloudAccountID = ""

	// Test with nil tags
	result := ac.appendCloudAccountIDToTags(nil)
	assert.Nil(t, result)

	// Test with empty tags slice
	tags := []string{}
	result = ac.appendCloudAccountIDToTags(tags)
	assert.Equal(t, tags, result)

	// Test with existing tags
	tags = []string{"tag1", "tag2"}
	result = ac.appendCloudAccountIDToTags(tags)
	assert.Equal(t, tags, result)
}

func TestAppendCloudAccountIDToTagsWithValue(t *testing.T) {
	ac := &AmaasClient{}
	ac.cloudAccountID = "633537927402"

	// Test with nil tags
	result := ac.appendCloudAccountIDToTags(nil)
	expected := []string{"cloudAccountId=633537927402"}
	assert.Equal(t, expected, result)

	// Test with empty tags slice
	tags := []string{}
	result = ac.appendCloudAccountIDToTags(tags)
	expected = []string{"cloudAccountId=633537927402"}
	assert.Equal(t, expected, result)

	// Test with existing tags
	tags = []string{"tag1", "tag2"}
	result = ac.appendCloudAccountIDToTags(tags)
	expected = []string{"tag1", "tag2", "cloudAccountId=633537927402"}
	assert.Equal(t, expected, result)
}

func TestAppendCloudAccountIDToTagsImmutability(t *testing.T) {
	ac := &AmaasClient{}
	ac.cloudAccountID = "633537927402"

	// Test that original tags slice is not modified
	originalTags := []string{"tag1", "tag2"}
	originalTagsCopy := make([]string, len(originalTags))
	copy(originalTagsCopy, originalTags)

	result := ac.appendCloudAccountIDToTags(originalTags)

	// Original slice should remain unchanged
	assert.Equal(t, originalTagsCopy, originalTags)
	// Result should contain cloudAccountID
	expected := []string{"tag1", "tag2", "cloudAccountId=633537927402"}
	assert.Equal(t, expected, result)
}

func TestCloudAccountIDIntegrationWithScanMethods(t *testing.T) {
	// Create a mock AmaasClient with connection set to nil (to trigger early return)
	ac := &AmaasClient{
		conn: nil,
	}

	// Set cloudAccountID
	err := ac.SetCloudAccountID("633537927402")
	assert.Nil(t, err)

	// Test ScanFile with cloudAccountID
	_, err = ac.ScanFile("nonexistent.txt", []string{"tag1"})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Client is not ready")

	// Test ScanBuffer with cloudAccountID
	_, err = ac.ScanBuffer([]byte("test"), "buffer", []string{"tag1"})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Client is not ready")

	// Test ScanReader with cloudAccountID
	bufferReader, _ := InitBufferReader([]byte("test"), "reader")
	_, err = ac.ScanReader(bufferReader, []string{"tag1"})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Client is not ready")

	bufferReader.Close()
}

func TestAppendCloudAccountIDToTagsTooLong(t *testing.T) {
	ac := &AmaasClient{}
	
	// Set a cloudAccountID that would make the tag too long (49 characters)
	ac.cloudAccountID = "1234567890123456789012345678901234567890123456789" // 49 chars
	
	// Test with existing tags - should skip the cloudAccountID
	tags := []string{"tag1", "tag2"}
	result := ac.appendCloudAccountIDToTags(tags)
	
	// Should return original tags unchanged (cloudAccountID skipped due to length)
	assert.Equal(t, tags, result)
}
