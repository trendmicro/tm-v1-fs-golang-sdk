# Trend Vision One File Security Go SDK User Guide

The Trend Vision One File Security Go SDK empowers developers to craft applications seamlessly integrating with the cloud-based Trend Vision One anti-malware file scanning service. This ensures a thorough scan of data and artifacts within the applications, identifying potential malicious elements.

This guide outlines the steps to establish your development environment and configure your project, laying the foundation for utilizing the File Security Go SDK effectively.

## Environment

- Golang 1.19 or newer
- Trend Vision One account with a chosen region - for more information, see the [Trend Vision One documentation](https://docs.trendmicro.com/en-us/enterprise/trend-micro-xdr-help/Home).
- A Trend Vision One API key with proper role - for more information, see the [Trend Vision One API key documentation](https://docs.trendmicro.com/en-us/enterprise/trend-vision-one/administrative-setti/accountspartfoundati/api-keys.aspx).

## Installation

To integrate with our service using the Golang SDK, you need to import the SDK package into your project. Here are the installation steps:
1. Open your Go project or create a new one if you haven't already.
2. Import the SDK package into your project by adding the following import statement:

    ```go
    import (
        "github.com/trendmicro/tm-v1-fs-golang-sdk/client"
        // Other imports...
    )
    ```

3. Use `go get` to download the SDK package:

    ```sh
    go get github.com/trendmicro/tm-v1-fs-golang-sdk
    ```

4. You can now start using the SDK in your project.

## Obtain an API Key

The File Security SDK requires a valid API Key provided as parameter to the SDK client object. It can accept Trend Vision One API keys.

When obtaining the API Key, ensure that the API Key is associated with the region that you plan to use. It is important to note that Trend Vision One API Keys are associated with different regions, please refer to the region flag below to obtain a better understanding of the valid regions associated with the respective API Key.

If you plan on using a Trend Vision One region, be sure to pass in region parameter when running custom program with File Security SDK to specify the region of that API key and to ensure you have proper authorization. The list of supported Trend Vision One regions can be found at API Reference section below.

1. Login to the Trend Vision One.
2. Create a new Trend Vision One API key:

* Navigate to the Trend Vision One User Roles page.
* Verify that there is a role with the "Run file scan via SDK" permissions enabled. If not, create a role by clicking on "Add Role" and "Save" once finished.
* Directly configure a new key on the Trend Vision One API Keys page, using the role which contains the "Run file scan via SDK" permission. It is advised to set an expiry time for the API key and make a record of it for future reference.

## Initialization

Before using the SDK to interact with our service, you need to initialize it with your API key or token and specify the region you want to connect to. Here's how to initialize the SDK:

```go
apiKey := "YOUR_API_KEY_OR_TOKEN"
region := "YOUR_REGION"

client, err := client.NewClient(apiKey, region)
if err != nil {
    // Handle initialization error
    panic(err)
}
```
Replace "YOUR_API_KEY_OR_TOKEN" and "YOUR_REGION" with your actual API key or token and the desired region.

**_Parameters_**

| Parameter | Description                                                                                                                                                                                             |
|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| region    | The region you obtained your api key.  Value provided must be one of the Vision One regions, e.g. `us-east-1`, `eu-central-1`, `ap-northeast-1`, `ap-southeast-2`, `ap-southeast-1`, `ap-south-1`, etc. |
| apikey    | Your own Vision One API Key.                                                                                                                                                                            |

## Basic Usage

Once you have initialized the SDK, you can start using it to interact with our service. Here are some basic examples of how to use the SDK:

### Scanning a File

```go
filePath := "path/to/your/file.txt"
tags := []string{"tag1", "tag2"}

response, err := client.ScanFile(filePath, tags)
if err != nil {
    // Handle scanning error
    panic(err)
}

// Use the 'response' as needed
```

### Scanning a Buffer

```go
data := []byte("Your data to be scanned")
identifier := "UniqueIdentifier"
tags := []string{"tag1", "tag2"}

response, err := client.ScanBuffer(data, identifier, tags)
if err != nil {
    // Handle scanning error
    panic(err)
}

// Use the 'response' as needed
```

**_Note_**
- Max number of tags is 8. And the length of each tag can't exceed 63.

## Additional Functions

The SDK provides additional functions for advanced usage, such as dumping the configuration and cleaning up resources:

### Dumping Configuration

You can dump the current SDK configuration for debugging purposes:

```go
configDump := client.DumpConfig()
fmt.Println("SDK Configuration:\n", configDump)
```

### Cleaning Up

Remember to destroy the SDK client when you are done using it to release any allocated resources:

```go
client.Destroy()
```

### Enable PML (Predictive Machine Learning) Detection

You can enable PML detection by calling the `SetPMLEnable` function:

```go
client.SetPMLEnable()
```

### Enable SPN feedback

You can enable SPN feedback by calling the `SetFeedbackEnable` function:

```go
client.SetFeedbackEnable()
```

## Usage Examples
As examples, you can find two important files in the `tools/` directory of the SDK package:

`client.go`: This file contains the main client initialization logic and functions for scanning a single file.

`scanfiles.go`: This file provides examples of how to scan multiple files using the SDK.

You can refer to these files for a deeper understanding of how to integrate and use the SDK with our service.

## Usage Instructions for File Security SDK Programs

### Prerequisites
Build the client tools requires the following:
Execute `make build` in the root directory to build the client tools.

The build process will produce the following inside the `tools/` directory:

* client
* scanfiles

### client

This program is located in the `tools/` folder. It supports the gRPC-based server.

`client [command-line flags]`

The following flags are supported:

`-tls`
Specify to enable server authentication by client for gRPC

`-region <string>`
Specify the region to connect to for gRPC

`-addr <string>`
the address to connect to for gRPC (default "localhost:50051")

`-filename <string>`
Path of file to scan

`-apikey <string>`
API key for service authentication if authentication is enabled

`-pml`
Specify to enable PML (Predictive Machine Learning) detection

`-feedback`
Specify to enable SPN feedback

`-tag <string>`
Specify the tags to be used for scanning, separated by commas

### scanfiles

This is another program that uses the gRPC client library to communicate with our server. Depending on whether or not the `-good` flag is specified, and the scan result returned from the scan, the program will output result that shows the testing was successful or not.

If `-good` flag is specified, it indicates the files to be scanned are non-malicious. So if our server scan indicates a file is malicious, then the program will output result indicating the testing failed, for example.

The following flags are supported by the program:

`-path <string>`
Directory or file to scan. This flag must be specified in all scenarios.

`-good`
Specify if scanning good/non-malicious files.

`-parallel`
Specify if scanning of multiple files should be carried out simultaneously instead of sequentially.

`-tls`
Specify to enable server authentication by client for gRPC

`-region <string>`
Specify the region to connect to for gRPC

`-addr <string>`
The address to connect to for gRPC (default "localhost:50051")

`-apikey <string>`
API key for service authentication if authentication is enabled

`-pml`
Specify to enable PML (Predictive Machine Learning) detection

`-feedback`
Specify to enable SPN feedback

`-tag <string>`
Specify the tags to be used for scanning, separated by commas


## Proxy Configuration

The cli tool loads the proxy configuration from the following set of optional environment variables

| Environment Variable | Required/Optional | Description                                                                                                                                                     |
|----------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `NO_PROXY`           | Optional          | Add the endpoints to the comma-separated list of host names if you want to skip proxy settings. Note: only an asterisk, '\*' matches all hosts                  |
| `HTTP_PROXY `        | Optional          | `http://proxy.example.com`                                                                                                                                      |
| `HTTPS_PROXY`        | Optional          | `https://proxy.example.com`<br><br>If the proxy server is a SOCKS5 proxy, you must specify the SOCKS5 protocol in the URL as `socks5://socks_proxy.example.com` |
| `PROXY_USER`         | Optional          | Optional username for authentication header used in `Proxy-Authorization`                                                                                       |
| `PROXY_PASS`         | Optional          | Optional password for authentication header used in `Proxy-Authorization`, used only when `PROXY_USER` is configured                                            |
