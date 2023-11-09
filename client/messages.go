package client

var messageMap = map[string]string{
	"MSG_ID_ERR_OPEN_FILE":           "Cannot open file %s: %v",
	"MSG_ID_ERR_RETRIEVE_DATA":       "Attempted to read %d bytes but only retrieved %d",
	"MSG_ID_ERR_SETUP_STREAM":        "Failed to setup stream: %v",
	"MSG_ID_DEBUG_UPLOADED_BYTES":    "Uploaded %d bytes",
	"MSG_ID_ERR_INIT":                "Failed to send init msg: %v",
	"MSG_ID_DEBUG_CLOSED_CONN":       "Server closed connection",
	"MSG_ID_ERR_RECV":                "Failed to recv: %v",
	"MSG_ID_DEBUG_QUIT":              "Received QUIT command, exiting...\n",
	"MSG_ID_DEBUG_RETR":              "Received RETR command, offset: %d, length: %d",
	"MSG_ID_ERR_RETR_DATA":           "Failed to retrieve data from file: %s",
	"MSG_ID_ERR_SEND_DATA":           "Failed to send data chunk: %s",
	"MSG_ID_ERR_UNKNOWN_CMD":         "Received unknown command from server: %d",
	"MSG_ID_ERR_CLIENT_NOT_READY":    "Client is not ready to carry out scans, possibly due to invocation of Destroy()",
	"MSG_ID_ERR_CLIENT_ERROR":        "Client is not ready to carry out scans, due to %s",
	"MSG_ID_ERR_MISSING_AUTH":        "Must provide an API key to use the client",
	"MSG_ID_ERR_INVALID_AUTH":        "Invalid authorization key provided. Please provide a valid API key or token",
	"MSG_ID_ERR_UNKNOWN_AUTH":        "Internal error: unable to determine authorization key type",
	"MSG_ID_ERR_INVALID_REGION":      "%s is not a supported region",
	"MSG_ID_ERR_ENVVAR_PARSING":      "Cannot parse value specified by environment variable %s",
	"MSG_ID_WARNING_LOG_LEVEL":       "[%s] logMsg() invoked with level = LogLevelOff and format = %s",
	"MSG_ID_DEBUG_GRPC_ERROR":        "Received gRPC status code: %d, msg: %s",
	"MSG_ID_ERR_UNKNOWN_ERROR":       "Ecountered an unknown error",
	"MSG_ID_ERR_NO_PERMISSION":       "API key does not have permission to access the service",
	"MSG_ID_ERR_INCOMPATIBLE_SDK":    "Client SDK not compatible with the Anti-malware  Service - please upgrade",
	"MSG_ID_ERR_CERT_VERIFY":         "Server certificate verification failed",
	"MSG_ID_ERR_TLS_REQUIRED":        "Use of TLS for client-server communication required but not detected",
	"MSG_ID_ERR_KEY_AUTH_FAILED":     "Authorization key cannot be authenticated",
	"MSG_ID_ERR_RATE_LIMIT_EXCEEDED": "Too many requests. HTTP Status: 429; Exceeds rate limit",
	"MSG_ID_DEBUG_AH_EXAM_FILE":      "fileScanRunWithArchHandling(%s): examining file #%d \"%s\", size %d -> %d",
	"MSG_ID_DEBUG_AH_DIR_SKIP":       "..... is a directory, skipping to next file in archive",
	"MSG_ID_DEBUG_AH_ZIP_FILE":       "Encounted another ZIP file %s... recursively handle it",
	"MSG_ID_DEBUG_AH_NEW_ROUTINE":    "Create a new goroutine to do scan file \"%s\".....",
	"MSG_ID_ERR_AH_GOROUTINE_ERR":    "File scanning inside goroutine encountered error",
	"MSG_ID_DEBUG_QUEUE_STATUS":      "A job removed from work queue, queue status len %d / cap %d",
	"MSG_ID_DEBUG_QUEUE_ERR":         "Unexpected value read from queue: %d",
}

func MSG(id string) string {
	return messageMap[id]
}
