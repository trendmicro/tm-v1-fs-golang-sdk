package main

/*
This is an example of a test program that can execute a scan on a HTTP URL.
It will return an array of AMaaS scan results as part of its JSON output.
*/

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func main() {

	var bucketregion string
	var bucket string
	var key string

	var grpcAddr string
	var apiKey string
	var tls bool
	var caCert string
	var region string
	var pml bool
	var feedback bool
	var verbose bool
	var tag string
	var digest bool

	flag.StringVar(&bucketregion, "bucketregion", "us-west-2", "region for S3 bucket")
	flag.StringVar(&bucket, "bucket", "", "S3 bucket name")
	flag.StringVar(&key, "key", "", "S3 object key")

	flag.StringVar(&grpcAddr, "addr", "", "the address to connect to for GRPC")
	flag.StringVar(&apiKey, "apikey", "", "API key for service authentication")
	flag.BoolVar(&tls, "tls", false, "enable server TLS by client for GRPC.")
	flag.StringVar(&region, "region", "", "the region to connect to")
	flag.BoolVar(&pml, "pml", false, "enable predictive machine learning detection")
	flag.BoolVar(&feedback, "feedback", false, "enable SPN feedback")
	flag.BoolVar(&verbose, "verbose", false, "enable verbose scan result")
	flag.StringVar(&tag, "tag", "", "tags to be used for scanning. separated by comma.")
	flag.StringVar(&caCert, "ca_cert", "", "CA certificate for self hosted AMaaS server")
	flag.BoolVar(&digest, "digest", false, "enable digest calculation. it might increase network traffic for cloud file.")

	flag.Parse()

	var ac *amaasclient.AmaasClient
	var err error

	if region != "" && grpcAddr != "" {
		log.Fatal("Both region and addr are specified. Please specify only one.")
	} else if region != "" {
		ac, err = amaasclient.NewClient(apiKey, region)
		if err != nil {
			log.Fatalf("Unable to create AMaaS scan client object. error: %v", err)
		}
	} else if grpcAddr != "" {
		ac, err = amaasclient.NewClientInternal(apiKey, grpcAddr, tls, caCert)
		if err != nil {
			log.Fatalf("Unable to create AMaaS scan client object. error: %v", err)
		}
	} else {
		log.Fatal("Neither region nor addr is specified. Please specify one.")
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

	if !digest {
		// disable digest calculation to reduce network traffic if file is on cloud
		ac.SetDigestDisable()
	}

	var tagsArray []string
	if tag != "" {
		tagsArray = strings.Split(tag, ",")
	}

	reader, err := NewS3ClientReader(context.Background(), bucketregion, bucket, key)
	if err != nil {
		log.Fatalf("Unable to create S3 client reader. error: %v", err)
	}

	result, err := ac.ScanReader(reader, tagsArray)
	if err != nil {
		log.Fatalf("Unable to scan reader. error: %v", err)
	}

	fmt.Printf("%v", result)

	os.Exit(0)
}

type S3ClientReader struct {
	client *s3.Client
	bucket string
	key    string
	size   int64
}

func NewS3ClientReader(ctx context.Context, bucketregion, bucket, key string) (*S3ClientReader, error) {
	// load default config from environment with specified region
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(bucketregion))
	if err != nil {
		return nil, err
	}
	defer ctx.Done()

	// create S3 client with given config
	client := s3.NewFromConfig(cfg)

	attr, err := client.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket: &bucket,
		Key:    &key,
		ObjectAttributes: []types.ObjectAttributes{
			types.ObjectAttributesObjectSize,
		},
	})
	if err != nil {
		return nil, err
	}

	if attr.ObjectSize == nil {
		return nil, fmt.Errorf("unable to get object size from S3")
	}

	return &S3ClientReader{
		client: client,
		bucket: bucket,
		key:    key,
		size:   *attr.ObjectSize,
	}, nil
}

// S3ClientReader implements AmaasClientReader
func (r *S3ClientReader) Identifier() string {
	return fmt.Sprintf("s3://%s/%s", r.bucket, r.key)
}

func (r *S3ClientReader) DataSize() (int64, error) {
	return r.size, nil
}

func (r *S3ClientReader) ReadBytes(offset int64, length int32) ([]byte, error) {
	var rng string = fmt.Sprintf("bytes=%d-%d", offset, offset+int64(length)-1)

	output, err := r.client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: &r.bucket,
		Key:    &r.key,
		Range:  &rng,
	})
	if err != nil {
		return nil, err
	}
	defer output.Body.Close()

	bytes, err := io.ReadAll(output.Body)
	if err != nil && err != io.EOF {
		bytes = nil
	}

	return bytes, err
}
