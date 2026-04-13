//go: clientside_archive_handling

package client

type AmaasClientArchiveHandler struct {
}

func (ah *AmaasClientArchiveHandler) initHandler(_ *AmaasClient) error {
	return nil
}

func (ah *AmaasClientArchiveHandler) archHandlingEnabled() bool {
	return false
}

func (ah *AmaasClientArchiveHandler) fileScanRun(_ string) (string, error) {
	return "", nil
}
