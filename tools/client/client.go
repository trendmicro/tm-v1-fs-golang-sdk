package main

import (
	"flag"
	"log"
	"os"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

var (
	addr      = flag.String("addr", "", "the address to connect to")
	apiKey    = flag.String("apikey", "", "API key for service authentication")
	fileName  = flag.String("filename", os.Args[0], "file to scan")
	enableTLS = flag.Bool("tls", false, "enable TLS")
	region    = flag.String("region", "", "the region to connect to")
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
		client, err = amaasclient.NewClientInternal(*apiKey, *addr, *enableTLS)
		if err != nil {
			log.Fatalf("Unable to create AMaaS scan client object. error: %v", err)
		}
	} else {
		log.Fatal("Neither region nor addr is specified. Please specify one.")
	}

	result, err := client.ScanFile(*fileName, nil)
	if err != nil {
		log.Fatalf(err.Error())
	}

	log.Printf("%s\n", result)

	client.Destroy()
}
