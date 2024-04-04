//go: clientside_archive_handling

package client

type AmaasClientArchiveHandler struct {
}

func (ah *AmaasClientArchiveHandler) initHandler(ac *AmaasClient) error {
	return nil
}

func (ah *AmaasClientArchiveHandler) archHandlingEnabled() bool {
	return false
}

func (ah *AmaasClientArchiveHandler) fileScanRun(fileName string) (string, error) {
	return "", nil
}
