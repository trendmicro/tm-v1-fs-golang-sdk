package main

/*
This is an example of a test program that can execute a scan on an Azure Blob
Storage blob. It will return an array of AMaaS scan results as part of its
JSON output.

The AzureBlobReader implements the same reader contract as the scan-s3obj
example: GetProperties for the blob size and ranged DownloadStream calls for
partial reads. A small fixed read-ahead window coalesces the scan engine's
sequential small reads (4 KB units) into one ranged GET per window, which
matters when the client runs far from the storage account; the extra traffic
is bounded by the window size, and only portions of the blob are ever fetched.

Authentication: pass -sas_token for SAS token auth (dev/test), otherwise
DefaultAzureCredential is used (az login, managed identity, environment).
*/

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

func main() {
	var (
		accountURL string
		container  string
		blobName   string
		sasToken   string

		grpcAddr string
		apiKey   string
		tls      bool
		caCert   string
		region   string
		pml      bool
		feedback bool
		verbose  bool

		activeContent bool
		tag           string
		digest        bool
	)

	flag.StringVar(&accountURL, "accounturl", "", "storage account URL, e.g. https://ACCOUNT.blob.core.windows.net")
	flag.StringVar(&container, "container", "", "Azure blob container name")
	flag.StringVar(&blobName, "blob", "", "Azure blob name")
	flag.StringVar(&sasToken, "sas_token", "", "blob service SAS token; omit to use DefaultAzureCredential")

	flag.StringVar(&grpcAddr, "addr", "", "the address to connect to for GRPC")
	flag.StringVar(&apiKey, "apikey", "", "API key for service authentication")
	flag.BoolVar(&tls, "tls", false, "enable server TLS by client for GRPC.")
	flag.StringVar(&region, "region", "", "the region to connect to")
	flag.BoolVar(&pml, "pml", false, "enable predictive machine learning detection")
	flag.BoolVar(&feedback, "feedback", false, "enable SPN feedback")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose scan result")
	flag.BoolVar(&activeContent, "active-content", false, "enable/disable active content detection")
	flag.StringVar(&tag, "tag", "", "tags to be used for scanning. separated by comma.")
	flag.StringVar(&caCert, "ca_cert", "", "CA certificate for self hosted AMaaS server")
	flag.BoolVar(&digest, "digest", false, "enable digest calculation. it might increase network traffic for cloud file.")

	flag.Parse()

	ac, err := newScanClient(apiKey, region, grpcAddr, caCert, tls)
	if err != nil {
		log.Fatalf("Unable to create AMaaS scan client object. error: %v", err)
	}

	if pml {
		ac.SetPMLEnable()
	}

	if feedback {
		ac.SetFeedbackEnable()
	}

	if verbose {
		ac.SetVerboseEnable()
	}

	if activeContent {
		ac.SetActiveContentEnable()
	}

	if !digest {
		// disable digest calculation to reduce network traffic if file is on cloud
		ac.SetDigestDisable()
	}

	var tags []string
	if tag != "" {
		tags = strings.Split(tag, ",")
	}

	reader, err := NewAzureBlobReader(context.Background(), accountURL, container, blobName, sasToken)
	if err != nil {
		log.Fatalf("Unable to create Azure blob reader. error: %v", err)
	}

	result, err := ac.ScanReader(reader, tags)
	if err != nil {
		log.Fatalf("Unable to scan reader. error: %v", err)
	}

	fmt.Printf("%v", result)
}

// newScanClient creates the scan client from either a File Security region or
// a self hosted gRPC address; the two are mutually exclusive.
func newScanClient(apiKey, region, addr, caCert string, tls bool) (*amaasclient.AmaasClient, error) {
	switch {
	case region != "" && addr != "":
		return nil, errors.New("both region and addr are specified. please specify only one")
	case region != "":
		return amaasclient.NewClient(apiKey, region)
	case addr != "":
		return amaasclient.NewClientInternal(apiKey, addr, tls, caCert)
	default:
		return nil, errors.New("neither region nor addr is specified. please specify one")
	}
}

// readAheadBytes bounds the extra data fetched per ranged GET. It caps both
// the reader's memory use and the traffic wasted when the scan stops early.
const readAheadBytes = 256 * 1024

type AzureBlobReader struct {
	client     *blob.Client
	identifier string
	size       int64
	window     []byte // last ranged download, served to sequential reads without a new GET
	windowOff  int64  // blob offset of window[0]
}

func NewAzureBlobReader(ctx context.Context, accountURL, container, blobName, sasToken string) (*AzureBlobReader, error) {
	accountURL = strings.TrimSuffix(accountURL, "/")

	u, err := url.Parse(accountURL)
	if err != nil {
		return nil, fmt.Errorf("invalid storage account URL %q: %v", accountURL, err)
	}

	client, err := newBlobClient(accountURL, container, blobName, sasToken)
	if err != nil {
		return nil, err
	}

	props, err := client.GetProperties(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get blob properties: %w", err)
	}

	if props.ContentLength == nil {
		return nil, errors.New("unable to get blob size from Azure Storage")
	}

	return &AzureBlobReader{
		client:     client,
		identifier: fmt.Sprintf("azure://%s/%s/%s", u.Host, container, blobName),
		size:       *props.ContentLength,
		windowOff:  -1,
	}, nil
}

// newBlobClient returns a blob client backed by the SAS token when given,
// otherwise by DefaultAzureCredential (az login, managed identity, env vars).
func newBlobClient(accountURL, container, blobName, sasToken string) (*blob.Client, error) {
	blobURL := fmt.Sprintf("%s/%s/%s", accountURL, container, blobName)

	if sasToken != "" {
		return blob.NewClientWithNoCredential(blobURL+"?"+strings.TrimPrefix(sasToken, "?"), nil)
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create DefaultAzureCredential: %w", err)
	}

	return blob.NewClient(blobURL, cred, nil)
}

// AzureBlobReader implements [amaasclient.AmaasClientReader].
func (r *AzureBlobReader) Identifier() string {
	return r.identifier
}

func (r *AzureBlobReader) DataSize() (int64, error) {
	return r.size, nil
}

func (r *AzureBlobReader) ReadBytes(offset int64, length int32) (data []byte, err error) {
	if end := offset + int64(length); offset >= r.windowOff && end <= r.windowOff+int64(len(r.window)) {
		return r.window[offset-r.windowOff : end-r.windowOff], nil
	}

	// Fetch the requested range plus a read-ahead tail, so the engine's
	// sequential reads cost one ranged GET per window instead of per request.
	fetchLen := int64(length)
	if rest := r.size - offset; fetchLen < readAheadBytes && rest > fetchLen {
		fetchLen = min(readAheadBytes, rest)
	}

	resp, err := r.client.DownloadStream(context.Background(), &blob.DownloadStreamOptions{
		Range: blob.HTTPRange{
			Offset: offset,
			Count:  fetchLen,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("download blob range: %w", err)
	}
	defer resp.Body.Close()

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading blob body: %w", err)
	}

	r.window = data
	r.windowOff = offset

	return data[:min(int64(length), int64(len(data)))], nil
}
