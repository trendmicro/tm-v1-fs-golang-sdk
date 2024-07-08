package client

type ScanResult2Client struct {
	ScannerVersion string          `json:"scannerVersion"`
	SchemaVersion  string          `json:"schemaVersion"`
	ScanResult     int32           `json:"scanResult"`
	ScanId         string          `json:"scanId"`
	ScanTimestamp  string          `json:"scanTimestamp"`
	FileName       string          `json:"fileName"`
	FoundMalwares  []MalwareDetail `json:"foundMalwares"`
	FoundErrors    []ErrMsg        `json:"foundErrors,omitempty"`
	FileSha1       string          `json:"fileSHA1,omitempty"`
	FileSha256     string          `json:"fileSHA256,omitempty"`
}

type MalwareDetail struct {
	FileName    string `json:"fileName"`
	MalwareName string `json:"malwareName"`
	Engine      string `json:"engine,omitempty"`
}

type ErrMsg struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
