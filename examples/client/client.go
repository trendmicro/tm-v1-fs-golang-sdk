package main

import (
	"flag"
	"log"
	"os"
	"strings"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

var (
	addr     = flag.String("addr", "", "the address to connect to")
	apiKey   = flag.String("apikey", "", "API key for service authentication")
	fileName = flag.String("filename", os.Args[0], "file to scan")
	tls      = flag.Bool("tls", false, "enable/disable TLS")
	region   = flag.String("region", "", "the region to connect to")
	pml      = flag.Bool("pml", false, "enable/disable predictive machine learning detection")
	feedback = flag.Bool("feedback", false, "enable/disable SPN feedback")
	verbose  = flag.Bool("verbose", false, "enable/disable verbose scan result")
	tag      = flag.String("tag", "", "tags to be used for scanning")
	digest   = flag.Bool("digest", true, "enable/disable digest calculation")
	caCert   = flag.String("ca_cert", "", "CA certificate for self hosted AMaaS server")
)

func main() {
	flag.Parse()

	var client *amaasclient.AmaasClient
	var err error

	if *region != "" && *addr != "" {
		log.Fatal("Both region and addr are specified. Please specify only one.")
	} else if *region != "" {
		client, err = amaasclient.NewClient(*apiKey, *region)
		if err != nil {
			log.Fatalf("Unable to create AMaaS scan client object. error: %v", err)
		}
	} else if *addr != "" {
		client, err = amaasclient.NewClientInternal(*apiKey, *addr, *tls, *caCert)
		if err != nil {
			log.Fatalf("Unable to create AMaaS scan client object. error: %v", err)
		}
	} else {
		log.Fatal("Neither region nor addr is specified. Please specify one.")
	}

	if *pml {
		client.SetPMLEnable()
	}

	if *feedback {
		client.SetFeedbackEnable()
	}

	if *verbose {
		client.SetVerboseEnable()
	}

	if !*digest {
		client.SetDigestDisable()
	}

	var tagsArray []string
	if *tag != "" {
		tagsArray = strings.Split(*tag, ",")
	}

	result, err := client.ScanFile(*fileName, tagsArray)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Printf("%s\n", result)

	client.Destroy()
}
