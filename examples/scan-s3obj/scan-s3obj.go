package main

/*
This is an example of a test program that can execute a scan on a HTTP URL.
It will return an array of AMaaS scan results as part of its JSON output.
*/

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

func main() {
	var (
		bucketRegion string
		bucket       string
		key          string

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

	flag.StringVar(&bucketRegion, "bucketregion", "us-west-2", "region for S3 bucket")
	flag.StringVar(&bucket, "bucket", "", "S3 bucket name")
	flag.StringVar(&key, "key", "", "S3 object key")

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

	reader, err := NewS3ClientReader(context.Background(), bucketRegion, bucket, key)
	if err != nil {
		log.Fatalf("Unable to create S3 client reader. error: %v", err)
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

type S3ClientReader struct {
	client *s3.Client
	bucket string
	key    string
	size   int64
}

func NewS3ClientReader(ctx context.Context, bucketRegion, bucket, key string) (*S3ClientReader, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(bucketRegion))
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	attr, err := client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket: &bucket,
		Key:    &key,
		ObjectAttributes: []types.ObjectAttributes{
			types.ObjectAttributesObjectSize,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("get object attributes: %w", err)
	}

	if attr.ObjectSize == nil {
		return nil, errors.New("unable to get object size from S3")
	}

	return &S3ClientReader{
		client: client,
		bucket: bucket,
		key:    key,
		size:   *attr.ObjectSize,
	}, nil
}

// S3ClientReader implements [amaasclient.AmaasClientReader].
func (r *S3ClientReader) Identifier() string {
	return fmt.Sprintf("s3://%s/%s", r.bucket, r.key)
}

func (r *S3ClientReader) DataSize() (int64, error) {
	return r.size, nil
}

func (r *S3ClientReader) ReadBytes(offset int64, length int32) (data []byte, err error) {
	rng := fmt.Sprintf("bytes=%d-%d", offset, offset+int64(length)-1)

	output, err := r.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &r.bucket,
		Key:    &r.key,
		Range:  &rng,
	})
	if err != nil {
		return nil, fmt.Errorf("get object: %w", err)
	}
	defer output.Body.Close()

	data, err = io.ReadAll(output.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading S3 object body: %w", err)
	}

	return data, nil
}
