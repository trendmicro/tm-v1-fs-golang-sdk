# AMaaS Golang Client SDK User Guide


The AMaaS Golang Client SDK  allows developers to build applications that interface with cloud-based Cloud One Antimalware Service (AMaaS), so data and artifacts handled by the applications can be scanned to determine whether they are malicious or not.

This guide shows how to set up your dev environment and project before using the AMaaS Golang Client SDK.

## Environment

- Have a [Trend Cloud One Account](https://cloudone.trendmicro.com). [Sign up for free trial now](https://cloudone.trendmicro.com/trial) if it's not already the case!
- A [Trend Cloud One API Key](https://cloudone.trendmicro.com/docs/identity-and-account-management/c1-api-key/#new-api-key)
- A [Trend Cloud One Region](https://cloudone.trendmicro.com/docs/identity-and-account-management/c1-regions/) of choice
- Golang 1.18 or newer
- A file or object to be scanned

## Installation

To integrate with our service using the Golang SDK, you need to import the SDK package into your project. Here are the installation steps:
1. Open your Go project or create a new one if you haven't already.
2. Import the SDK package into your project by adding the following import statement:

    ```go
    import (
        "github.com/trendmicro/cloudone-antimalware-golang-sdk/client"
        // Other imports...
    )
    ```

3. Use `go get` to download the SDK package:

    ```sh
    go get github.com/trendmicro/cloudone-antimalware-golang-sdk
    ```

4. You can now start using the SDK in your project.

---

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

| Parameter     | Description                                                                              |
| ------------- | ---------------------------------------------------------------------------------------- |
| region        | The region you obtained your api key.  Value provided must be one of the Cloud One regions, e.g. `us-1`, `in-1`, `de-1`, `sg-1`, `au-1`, `jp-1`, `gb-1`, `ca-1`, etc. |
| apikey        | Your own Cloud One API Key.                                                              |

## Basic Usage

Once you have initialized the SDK, you can start using it to interact with our service. Here are some basic examples of how to use the SDK:

### Scanning a File

```go
filePath := "path/to/your/file.txt"

response, err := client.ScanFile(filePath)
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

response, err := client.ScanBuffer(data, identifier)
if err != nil {
    // Handle scanning error
    panic(err)
}

// Use the 'response' as needed
```

## Advanced Configuration

The SDK provides additional configuration options and functions that you can use to customize its behavior. Here are some advanced configuration options:

### Getting Timeout Setting

You can retrieve the current timeout setting:

```go
timeout := client.GetTimeoutSetting()
fmt.Printf("Current Timeout Setting: %d seconds\n", timeout)
```

### Getting Connection and Authentication Context

You can access the underlying gRPC connection and authentication context:

```go
conn := client.GetConnection() // Get the gRPC connection
ctx := client.ConfigAuth(context.Background()) // Get the authentication context
```
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

## Usage Examples
As examples, you can find two important files in the `tools/` directory of the SDK package:

`client.go`: This file contains the main client initialization logic and functions for scanning a single file.

`scanfiles.go`: This file provides examples of how to scan multiple files using the SDK.

You can refer to these files for a deeper understanding of how to integrate and use the SDK with our service.

## Usage Instructions for Cloud One VSAPI Client Programs

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
