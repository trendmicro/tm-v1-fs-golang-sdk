package main

/*
This is an example of a test program that can execute multiple testcases/tests in a single
execution. It will return an array of AMaaS scan results as part of its JSON output.
*/

import (
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	amaasclient "github.com/trendmicro/tm-v1-fs-golang-sdk"
)

/*
	TBD: This should also be turned into a module to avoid mistakes from being made when
	developing a large number of tests.
*/

type ScanResult struct {
	Id         string    `json:"id"`
	StartTime  time.Time `json:"scan_starttime"`
	EndTime    time.Time `json:"scan_endtime"`
	Test       string    `json:"test"`
	TestPassed bool      `json:"test_passed"`
	Data       string    `json:"data"`
}

type OverallTestResult struct {
	StartTime    time.Time    `json:"starttime"`
	EndTime      time.Time    `json:"endtime"`
	Passed       bool         `json:"overall_passed"`
	CombinedData []ScanResult `json:"combined_scan_results"`
}

func main() {

	var scanGoodFiles bool
	var scanInParallel bool
	var path string
	var grpcAddr string
	var apiKey string
	var tls bool
	var caCert string
	var fileList []string
	var region string
	var pml bool
	var feedback bool
	var verbose bool
	var activeContent bool
	var tag string
	var digest bool

	flag.StringVar(&path, "path", "", "Path of file or directory to scan.")
	flag.BoolVar(&scanGoodFiles, "good", false, "Specify if scanning good/non-malicious files.")
	flag.BoolVar(&scanInParallel, "parallel", false, "Specify if scanning of files should happen in parallel")

	flag.StringVar(&grpcAddr, "addr", "", "the address to connect to for GRPC")
	flag.StringVar(&apiKey, "apikey", "", "API key for service authentication")
	flag.BoolVar(&tls, "tls", false, "enable/disable server authentication by client for GRPC")
	flag.StringVar(&region, "region", "", "the region to connect to")
	flag.BoolVar(&pml, "pml", false, "enable/disable predictive machine learning detection")
	flag.BoolVar(&feedback, "feedback", false, "enable/disable SPN feedback")
	flag.BoolVar(&verbose, "verbose", false, "enable/disable verbose scan result")
	flag.BoolVar(&activeContent, "active-content", false, "enable/disable active content detection")
	flag.StringVar(&tag, "tag", "", "tags to be used for scanning")
	flag.StringVar(&caCert, "ca_cert", "", "CA certificate for self hosted AMaaS server")
	flag.BoolVar(&digest, "digest", true, "enable/disable verbose scan result")

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

	if path == "" {
		log.Fatal("The name of a file or directory to be scanned must be specified as parameter to the -path/--path flag.")
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		log.Fatalf("The path %s does not appear to be a valid one.", path)
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
		ac.SetDigestDisable()
	}

	var tagsArray []string
	if tag != "" {
		tagsArray = strings.Split(tag, ",")
	}

	if fileInfo.IsDir() {

		files, err := os.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {
			if strings.HasPrefix(f.Name(), ".") {
				continue
			}

			filePath := path + "/" + f.Name()

			fileInfo, err := os.Stat(filePath)
			if err != nil || fileInfo.IsDir() {
				continue
			}

			fileList = append(fileList, filePath)
		}
	} else {
		fileList = append(fileList, path)
	}

	var tr OverallTestResult
	if scanInParallel {
		tr = scanFileListInParallel(fileList, scanGoodFiles, ac, tagsArray)
	} else {
		tr = scanFileListInSequence(fileList, scanGoodFiles, ac, tagsArray)
	}

	jsonData, _ := json.Marshal(tr)
	ac.Destroy()

	fmt.Println(string(jsonData))

	os.Exit(0)
}

func scanFileListInSequence(fileList []string, scanGoodFiles bool, scanner *amaasclient.AmaasClient, tags []string) OverallTestResult {

	var tr OverallTestResult
	tr.Passed = true
	tr.StartTime = time.Now()

	for i := 0; i < len(fileList); i++ {
		filename := fileList[i]
		log.Printf("Scanning file %s ...\n", filename)

		var sr ScanResult
		sr.Id = hash(filename)

		sr.StartTime = time.Now()

		jsonResult, err := scanner.ScanFile(fileList[i], tags)
		if err != nil {
			log.Print(err.Error())
		}

		sr.EndTime = time.Now()

		sr.Data = jsonResult
		sr.Test = fmt.Sprintf("%s: amaasclient.Scan(\"%s\")", strings.Join(os.Args, " "), filename)
		sr.TestPassed = (err == nil) && checkResult(fileList[i], jsonResult, scanGoodFiles)

		tr.CombinedData = append(tr.CombinedData, sr)
		tr.Passed = tr.Passed && sr.TestPassed
	}

	tr.EndTime = time.Now()

	return tr
}

func scanFileListInParallel(fileList []string, scanGoodFiles bool, scanner *amaasclient.AmaasClient, tags []string) OverallTestResult {

	var tr OverallTestResult
	tr.Passed = true
	tr.StartTime = time.Now()

	c := make(chan ScanResult)

	for i := 0; i < len(fileList); i++ {
		filename := fileList[i]

		go func(f string) {
			log.Printf("Scanning file %s ...\n", f)

			var sr ScanResult
			sr.Id = hash(f)

			sr.StartTime = time.Now()

			jsonResult, err := scanner.ScanFile(f, tags)
			if err != nil {
				log.Print(err.Error())
			}

			sr.EndTime = time.Now()

			sr.Data = jsonResult
			sr.Test = fmt.Sprintf("%s: amaasclient.Scan(\"%s\")", strings.Join(os.Args, " "), f)
			sr.TestPassed = (err == nil) && checkResult(f, jsonResult, scanGoodFiles)

			c <- sr
		}(filename)
	}

	for i := 0; i < len(fileList); i++ {
		sr := <-c
		tr.CombinedData = append(tr.CombinedData, sr)
		tr.Passed = tr.Passed && sr.TestPassed
	}

	tr.EndTime = time.Now()

	return tr
}

/*
TBD: This will need to be updated in accordance with how the scan server evolves
over time. At some point, this should probably be moved into the AMaaS test suite module.
*/

func checkResult(filename string, input string, isGoodFile bool) bool {
	detectedVirus := false
	var rawResult amaasclient.ScanResult2Client

	err := json.Unmarshal([]byte(input), &rawResult)
	if err != nil {
		log.Printf("Invalid JSON returned from server for file %s\n", filename)
	}

	log.Printf("# detected viruses = %v", rawResult.ScanResult)

	if rawResult.ScanResult > 0 {
		detectedVirus = true
	}

	result := (detectedVirus != isGoodFile)

	log.Printf("checkResult: target file supposed to be good = %v, detected virus = %v, check result = %v\n",
		isGoodFile, detectedVirus, result)

	return result
}

func hash(s string) string {
	h := fnv.New32a()
	h.Write([]byte(s))
	return strconv.Itoa(int(h.Sum32()))
}
