package main

import (
	"flag"
	"log"
	"strings"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

var (
	addr          = flag.String("addr", "", "the address to connect to")
	apiKey        = flag.String("apikey", "", "API key for service authentication")
	filenameFlag  = flag.String("filename", "", "file to scan (optional, can also be specified as the last argument)")
	tls           = flag.Bool("tls", false, "enable/disable TLS")
	region        = flag.String("region", "", "the region to connect to")
	pml           = flag.Bool("pml", false, "enable/disable predictive machine learning detection")
	feedback      = flag.Bool("feedback", false, "enable/disable SPN feedback")
	verbose       = flag.Bool("verbose", false, "enable/disable verbose scan result")
	activeContent = flag.Bool("active-content", false, "enable/disable active content detection")
	tag           = flag.String("tag", "", "tags to be used for scanning")
	digest        = flag.Bool("digest", true, "enable/disable digest calculation")
	caCert        = flag.String("ca_cert", "", "CA certificate for self hosted AMaaS server")
)

func main() {
	flag.Parse()

	fileName := getFileName()
	if fileName == "" {
		log.Fatal("Please specify a file to scan using either -filename flag or as the last argument")
	}

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

	if *activeContent {
		client.SetActiveContentEnable()
	}

	if !*digest {
		client.SetDigestDisable()
	}

	var tagsArray []string
	if *tag != "" {
		tagsArray = strings.Split(*tag, ",")
	}

	result, err := client.ScanFile(fileName, tagsArray)
	if err != nil {
		log.Fatal(err.Error())
	}

	log.Printf("%s\n", result)

	client.Destroy()
}

func getFileName() string {
	var fileName string

	args := flag.Args()

	if len(args) > 0 {
		fileName = args[len(args)-1]
	}

	if *filenameFlag != "" {
		fileName = *filenameFlag
	}

	return fileName
}
