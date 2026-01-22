# Trend Vision One™ File Security Go SDK User Guide

Trend Vision One™ - File Security is a scanner app for files and cloud storage. This scanner can detect all types of malicious software (malware) including trojans, ransomware, spyware, and more. Based on fragments of previously seen malware, File Security detects obfuscated or polymorphic variants of malware.
File Security can assess any file type or size for malware and display real-time results. With the latest file reputation and variant protection technologies backed by leading threat research, File Security automates malware scanning.
File Security can also scan objects across your environment in any application, whether on-premises or in the cloud.

The Go software development kit (SDK) for Trend Vision One™ File Security empowers you to craft applications which seamlessly integrate with File Security. With this SDK you can perform a thorough scan of data and artifacts within your applications to identify potential malicious elements.
Follow the steps below to set up your development environment and configure your project, laying the foundation to effectively use File Security.

## Environment

- Golang 1.19 or newer
- Trend Vision One account with a chosen region - for more information, see the [Trend Vision One documentation](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-trend-micro-xdr-abou_001).
- A Trend Vision One API key with proper role - for more information, see the [Trend Vision One API key documentation](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-api-keys).

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

- Navigate to the Trend Vision One User Roles page.
- Verify that there is a role with the "Run file scan via SDK" permissions enabled. If not, create a role by clicking on "Add Role" and "Save" once finished.
- Directly configure a new key on the Trend Vision One API Keys page, using the role which contains the "Run file scan via SDK" permission. It is advised to set an expiry time for the API key and make a record of it for future reference.

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

### Scanning with AmaasClientReader

```go
type CustomReader struct {
    ...
}

func newCustomReader() *CustomReader {
    ...
}

func (r *CustomReader) Identifier() string {
    // It returns the name of the file.
}

func (r *CustomReader) DataSize() (int64, error) {
    // It should return the true size of the file in Reader.
}

func (r *CustomReader) ReadBytes(offset int64, length int32) (data []byte, err error) {
    // It should return required number of data bytes starting from certain offset.
}

reader := newCustomReader()

// It is recommended to disable digest when using AmaasReader.
// Because it will trigger ReadBytes to read whole file,
// network traffic will increase if it reads from the Internet.
client.SetDigestDisable()

response, err := client.ScanReader(reader, tags)
if err != nil {
    // Handle scanning error
    panic(err)
}

// Use the 'response' as needed
```

**_Note_**

- Max number of tags is 8. And the length of each tag can't exceed 63.
- If user wants to take a look how to scan a S3 file without downloading the whole to the ground,
  please refer to the [example code](examples/scan-s3obj/scan-s3obj.go) for further detail.

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

### Enable Verbose Scan Result

You can enable verbose scan result by calling the `SetVerboseEnable` function:

```go
client.SetVerboseEnable()
```

### Enable Active Content Detection

Enables active content detection for scanning operations. This feature allows the scanner to detect potentially malicious active content within files, specifically:

- **PDF scripts**: Detects embedded JavaScript and other scripting content in PDF files
- **Office macros**: Detects VBA macros and other executable content in Microsoft Office documents

When active content is detected, the scan result will include a type field with values of either `macro` or `script` to indicate the type of active content found.

```go
client.SetActiveContentEnable()
```


### Disable Digest Calculation

You can disable digest calculation by calling the `SetDigestDisable` function:

```go
client.SetDigestDisable()
```

### Set Cloud Account ID

You can set a cloud account ID that will be automatically appended to all scan tags in the format `cloudAccountId=value`:

```go
err := client.SetCloudAccountID("633537927402")
if err != nil {
    // Handle error - cloudAccountID too long
}
```

**Note**:
- The total tag length (including `cloudAccountId=` prefix) cannot exceed 63 characters
- Using cloud account ID occupies one tag slot, reducing max customer tags from 8 to 7

### Quarantine Malicious Files with Encode/Decode

The SDK provides Encode and Decode methods for quarantining malicious files detected during scanning. The recommended workflow is: **scan a file first, and if malware is detected, encode the file to neutralize it and then delete the original file** to prevent infection.

**Recommended Workflow:**
1. **Scan the file** using `ScanFile()` or `ScanBuffer()`
2. **Check scan result** - if `scanResult` is non-zero, malware was detected
3. **Encode the malicious file** to transform it into a safe, non-executable format
4. **Delete the original file** to eliminate the threat from your system
5. **Store the encoded file** in a quarantine location for later analysis if needed

**Use Cases:**
- **Malware Quarantine**: Neutralize detected threats by encoding them into a safe format
- **Threat Isolation**: Prevent malicious files from executing while preserving them for analysis
- **Security Research**: Safely archive malware samples for later investigation in isolated environments

#### Quarantining a Detected Malicious File

The following example demonstrates the complete workflow: scan, detect, encode, and delete:

```go
import (
    "context"
    "encoding/json"
    "os"
)

filePath := "/path/to/suspicious/file.exe"
quarantinePath := "/path/to/quarantine/file.exe.enc"
tags := []string{"scan-source:upload"}

// Step 1: Scan the file
response, err := client.ScanFile(filePath, tags)
if err != nil {
    // Handle scanning error
    panic(err)
}

// Step 2: Parse the scan result
var scanResult struct {
    ScanResult int `json:"scanResult"`
}
if err := json.Unmarshal([]byte(response), &scanResult); err != nil {
    panic(err)
}

// Step 3: If malware detected (scanResult != 0), encode and delete original
if scanResult.ScanResult != 0 {
    ctx := context.Background()

    // Encode the malicious file to quarantine location
    err := client.EncodeFile(ctx, filePath, quarantinePath)
    if err != nil {
        // Handle encoding error
        panic(err)
    }

    // Delete the original malicious file to prevent infection
    err = os.Remove(filePath)
    if err != nil {
        // Handle deletion error
        panic(err)
    }

    // File is now safely quarantined
}
```

#### Decoding a Quarantined File for Analysis

Restore a quarantined file back to its original form **only in a secure, isolated environment** (e.g., sandbox, VM) for malware analysis:

```go
ctx := context.Background()

// Decode the quarantined file for analysis in a secure environment
err := client.DecodeFile(ctx, "/path/to/quarantine/file.exe.enc", "/secure/sandbox/file.exe")
if err != nil {
    // Handle decoding error
    panic(err)
}

// WARNING: The decoded file is now a live malware sample
// Only perform this operation in an isolated analysis environment
```

#### Using Encode/Decode with Custom Readers

For advanced use cases (e.g., quarantining files from cloud storage), you can use the reader-based methods with custom implementations of `AmaasClientReader`:

```go
import (
    "context"
    "io"
)

ctx := context.Background()

// Encode using a custom reader (writer must implement io.WriterAt)
err := client.EncodeReader(ctx, customReader, customWriterAt)
if err != nil {
    // Handle encoding error
    panic(err)
}

// Decode using a custom reader (writer must implement io.Writer)
err = client.DecodeReader(ctx, customReader, customWriter)
if err != nil {
    // Handle decoding error
    panic(err)
}
```

**_Important Security Notes_**

- **Always scan before encoding** - Encode is designed for quarantining detected malware, not for general file encoding
- **Delete original files after encoding** - The original malicious file must be removed to prevent infection
- **Decode only in isolated environments** - Restored files are live malware; only decode in sandboxes or VMs designed for malware analysis
- **Implement access controls** - Restrict access to quarantine locations to prevent unauthorized decoding

## Golang Client SDK API Reference

### ```func NewClient(key string, region string) (c *AmaasClient, e error)```

Creates a new instance of the client object, and provisions essential settings, including authentication/authorization credentials (API key), preferred service region, etc.

**_Parameters_**

| Parameter       | Description                                                                                                                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| key (string)    | A valid API key must be provided if the environment variable `TM_AM_AUTH_KEY` is not set.                                                                                                    |
| region (string) | The region you obtained your api key.  Value provided must be one of the Vision One regions: `us-east-1`, `eu-central-1`, `eu-west-2`, `ca-central-1`, `ap-southeast-1`, `ap-southeast-2`, `ap-northeast-1`, `ap-south-1`, `me-central-1` |

**_Return values_**

| Parameter        | Description                                           |
| ---------------- | ----------------------------------------------------- |
| c (*AmaasClient) | Pointer to an client object. Nil if error encountered |
| e (error)        | Nil if no error encountered; non-nil otherwise.       |

**_Errors Conditions_**

- Invalid authentication
- Invalid region

---

### ```func (ac *AmaasClient) ScanFile(filePath string, tags []string) (resp string, e error)```

### ```func (ac *AmaasClient) ScanBuffer(buffer []byte, identifier string, tags []string) (resp string, e error)```

Submit content of a file or buffer to be scanned.

**_Parameters_**

| Parameter           | Description                                                                                                                             |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| filePath (string)   | Path of the file to scan                                                                                                                |
| buffer ([]byte)     | Buffer containing the data to scan                                                                                                      |
| identifier (string) | A caller-chosen string to associate with the scan that will be returned in JSON response as part of `fileName` name/value; can be empty |
| tags ([]string)     | Tags to be used for scanning                                                                                                            |

**_Return values_**

| Parameter     | Description                                        |
| ------------- | -------------------------------------------------- |
| resp (string) | JSON-formatted response describing the scan result |
| e (error)     | Nil if no error encountered; non-nil otherwise.    |

**_Sample JSON response_**

***_Concise Format_***

```json
{
  "scannerVersion":"1.0.0-27",
  "schemaVersion":"1.0.0",
  "scanResult": 1,
  "scanId": "25072030425f4f4d68953177d0628d0b",
  "scanTimestamp": "2022-11-02T00:55:31Z",
  "fileName": "EICAR_TEST_FILE-1.exe",
  "filePath": "AmspBvtTestSamples/BVT_RightClickScan_DS/unclean/EICAR_TEST_FILE-1.exe",
  "foundMalwares": [
    {
      "fileName": "Eicar.exe",
      "malwareName": "Eicar_test_file"
    }
  ],
  "fileSHA1":"fc7042d1d8bbe655ab950355f86a81ded9ee4903",
  "fileSHA256":"1b9f8773919a1770fec35e2988650fde3adaae81a3ac2ad77b67cafd013afcdc"
}
```

***_Verbose Format_***

```json
{
  "scanType": "sdk",
  "objectType": "file",
  "timestamp": {
    "start": "2024-07-05T20:01:21.064Z",
    "end": "2024-07-05T20:01:21.069Z"
  },
  "schemaVersion": "1.0.0",
  "scannerVersion": "1.0.0-59",
  "fileName": "eicar.com",
  "rsSize": 68,
  "scanId": "40d7a38e-a1d3-400b-a09c-7aa9cd62658f",
  "accountId": "",
  "result": {
    "atse": {
      "elapsedTime": 4693,
      "fileType": 5,
      "fileSubType": 0,
      "version": {
        "engine": "23.57.0-1002",
        "lptvpn": 385,
        "ssaptn": 731,
        "tmblack": 253,
        "tmwhite": 239,
        "macvpn": 914
      },
      "malwareCount": 1,
      "malware": [
        {
          "name": "Eicar_test_file",
          "fileName": "eicar.com",
          "type": "",
          "fileType": 5,
          "fileSubType": 0,
          "fileTypeName": "COM",
          "fileSubTypeName": "VSDT_COM_DOS"
        }
      ],
      "error": null,
      "fileTypeName": "COM",
      "fileSubTypeName": "VSDT_COM_DOS"
    }
  },
  "fileSHA1": "3395856ce81f2b7382dee72602f798b642f14140",
  "fileSHA256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "appName": "V1FS"
}
```

When malicious content is detected in the scanned object, `scanResult` will show a non-zero value. Otherwise, the value will be `0`. Moreover, when malware is detected, `foundMalwares` will be non-empty containing one or more name/value pairs of `fileName` and `malwareName`. `fileName` will be filename of malware detected while `malwareName` will be the name of the virus/malware found.

**_Errors Conditions_**

- Invalid authentication
- Invalid path specified
- Request timed out (deadline exceeded)
- Incompatible client used
- Service unreachable
- Client not ready for operation

---

### ```func (ac *AmaasClient) Destroy()```

Frees up internal resources used by client. It should only be invoked after one has finished scanning and no longer needs the client object.

---

### ```func (ac *AmaasClient) EncodeFile(ctx context.Context, src string, dst string) (e error)```

Transforms a file into a safe, encoded format. The encoded file cannot be accidentally executed and is safe for storage and transport. The encoding is performed server-side using the File Security service.

**_Parameters_**

| Parameter            | Description                                           |
| -------------------- | ----------------------------------------------------- |
| ctx (context.Context)| Context for the operation, can be used for cancellation and timeouts |
| src (string)         | Path to the source file to be encoded                 |
| dst (string)         | Path where the encoded file will be written           |

**_Return values_**

| Parameter | Description                                     |
| --------- | ----------------------------------------------- |
| e (error) | Nil if no error encountered; non-nil otherwise. |

**_Error Conditions_**

- Invalid authentication
- Invalid source path specified
- Unable to write to destination path
- Request timed out (deadline exceeded)
- Service unreachable
- Client not ready for operation

---

### ```func (ac *AmaasClient) EncodeReader(ctx context.Context, reader AmaasClientReader, writer io.WriterAt) (e error)```

Transforms data from a custom reader into a safe, encoded format and writes to the provided writer. This method is useful for encoding data from non-file sources such as cloud storage or memory buffers.

**_Parameters_**

| Parameter                  | Description                                           |
| -------------------------- | ----------------------------------------------------- |
| ctx (context.Context)      | Context for the operation, can be used for cancellation and timeouts |
| reader (AmaasClientReader) | Custom reader implementing the AmaasClientReader interface |
| writer (io.WriterAt)       | Writer where the encoded data will be written; must support random access writes |

**_Return values_**

| Parameter | Description                                     |
| --------- | ----------------------------------------------- |
| e (error) | Nil if no error encountered; non-nil otherwise. |

**_Error Conditions_**

- Invalid authentication
- Reader returns error during data access
- Writer returns error during write operation
- Request timed out (deadline exceeded)
- Service unreachable
- Client not ready for operation

---

### ```func (ac *AmaasClient) DecodeFile(ctx context.Context, src string, dst string) (e error)```

Restores an encoded file back to its original form. This operation should only be performed in a secure, isolated environment suitable for handling potentially malicious files.

**_Parameters_**

| Parameter            | Description                                           |
| -------------------- | ----------------------------------------------------- |
| ctx (context.Context)| Context for the operation, can be used for cancellation and timeouts |
| src (string)         | Path to the encoded file to be decoded                |
| dst (string)         | Path where the decoded (original) file will be written|

**_Return values_**

| Parameter | Description                                     |
| --------- | ----------------------------------------------- |
| e (error) | Nil if no error encountered; non-nil otherwise. |

**_Error Conditions_**

- Invalid authentication
- Invalid source path specified
- Source file is not a valid encoded file
- Unable to write to destination path
- Request timed out (deadline exceeded)
- Service unreachable
- Client not ready for operation

---

### ```func (ac *AmaasClient) DecodeReader(ctx context.Context, reader AmaasClientReader, writer io.Writer) (e error)```

Restores encoded data from a custom reader back to its original form and writes to the provided writer. This method is useful for decoding data from non-file sources such as cloud storage or memory buffers.

**_Parameters_**

| Parameter                  | Description                                           |
| -------------------------- | ----------------------------------------------------- |
| ctx (context.Context)      | Context for the operation, can be used for cancellation and timeouts |
| reader (AmaasClientReader) | Custom reader implementing the AmaasClientReader interface |
| writer (io.Writer)         | Writer where the decoded data will be written         |

**_Return values_**

| Parameter | Description                                     |
| --------- | ----------------------------------------------- |
| e (error) | Nil if no error encountered; non-nil otherwise. |

**_Error Conditions_**

- Invalid authentication
- Reader returns error during data access
- Input data is not valid encoded data
- Writer returns error during write operation
- Request timed out (deadline exceeded)
- Service unreachable
- Client not ready for operation

---

### ```func SetLoggingLevel(level LogLevel)```

For configuring the SDK's active logging level. The change is applied globally to all client instances. Default level is `LogLevelOff`, corresponding to all logging disabled. If logging is enabled, unless custom logging is configured using `ConfigLoggingCallback()` logs will be written to stdout.

**_Parameters_**

| Parameter        | Description                                                                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| level (LogLevel) | Valid values are LogLevelOff, LogLevelFatal, LogLevelError, LogLevelWarning, LogLevelInfo, and LogLevelDebug; default level is LogLevelOff |

---

### ```func ConfigLoggingCallback(f func(level LogLevel, levelStr string, format string, a ...interface{}))```

For setting up custom logging by provisioning the SDK with a custom callback function that is invoked whether the SDK wants to record a log.

**_Parameters_**

| Parameter    | Description                                                                                            |
| ------------ | ------------------------------------------------------------------------------------------------------ |
| f (function) | A function with the prototype `func(level LogLevel, levelStr string, format string, a ...interface{})` |

## Usage Examples

As examples, you can find two important files in the `examples/` directory of the SDK package:

`client.go`: This file contains the main client initialization logic and functions for scanning a single file.

`scanfiles.go`: This file provides examples of how to scan multiple files using the SDK.

You can refer to these files for a deeper understanding of how to integrate and use the SDK with our service.

## Usage Instructions for File Security SDK Programs

### Prerequisites

Build the client tools requires the following:
Execute `make build` in the root directory to build the client tools.

The build process will produce the following inside the `examples/` directory:

- client
- scanfiles

### client

This program is located in the `examples/` folder. It supports the gRPC-based server.

`client [command-line flags]`

The following flags are supported:

`-tls`
Specify to enable server authentication by client for gRPC. TLS should always be enabled when connecting to the File Security service. For more information, see the 'Ensuring Secure Communication with TLS' section.

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

`-verbose`
Specify to enable verbose scan result

`-active-content`
Specify to enable active content detection

`-tag <string>`
Specify the tags to be used for scanning, separated by commas

`-digest=false`
Specify to disable digest calculation

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
Specify to enable server authentication by client for gRPC. TLS should always be enabled when connecting to the File Security service. For more information, see the 'Ensuring Secure Communication with TLS' section.

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

`-verbose`
Specify to enable verbose scan result

`-active-content`
Specify to enable active content detection

`-tag <string>`
Specify the tags to be used for scanning, separated by commas

`-digest=false`
Specify to disable digest calculation

## Proxy Configuration

The cli tool loads the proxy configuration from the following set of optional environment variables

| Environment Variable | Required/Optional | Description                                                                                                                                                     |
| -------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NO_PROXY`           | Optional          | Add the endpoints to the comma-separated list of host names if you want to skip proxy settings. Note: only an asterisk, '\*' matches all hosts                  |
| `HTTP_PROXY`         | Optional          | `http://proxy.example.com`                                                                                                                                      |
| `HTTPS_PROXY`        | Optional          | `https://proxy.example.com`<br><br>If the proxy server is a SOCKS5 proxy, you must specify the SOCKS5 protocol in the URL as `socks5://socks_proxy.example.com` |
| `PROXY_USER`         | Optional          | Optional username for authentication header used in `Proxy-Authorization`                                                                                       |
| `PROXY_PASS`         | Optional          | Optional password for authentication header used in `Proxy-Authorization`, used only when `PROXY_USER` is configured                                            |

## Environment Variables

The following environment variables are supported by Golang Client SDK and can be used in lieu of values specified as function arguments.

For example, the API key can be specified using the `TM_AM_AUTH_KEY` environment variable instead of hardcoded into the application.

| Variable Name             | Description & Purpose                                                       | Valid Values               |
| ------------------------- | --------------------------------------------------------------------------- | -------------------------- |
| `TM_AM_SCAN_TIMEOUT_SECS` | Specify, in number of seconds, to override the default scan timeout period  | 0, 1, 2, ... ; default=300 |
| `TM_AM_AUTH_KEY`          | Can be used to specify the authorization key; overrides function call value | empty or string            |

## Thread Safety

- ScanFile() or ScanBuffer() are designed to be thread-safe. It should be able to invoke ScanFile() concurrently from multiple threads without protecting ScanFile() with mutex or other synchronization mechanisms.

- The Destroy() method is NOT thread-safe, so it should only be called upon completion of all the scan routines.

## Ensuring Secure Communication with TLS

The communication channel between the client program or SDK and the Trend Vision One™ File Security service is fortified with robust server-side TLS encryption. This ensures that all data transmitted between the client and Trend service remains thoroughly encrypted and safeguarded.
The certificate employed by server-side TLS is a publicly-signed certificate from Trend Micro Inc, issued by a trusted Certificate Authority (CA), further bolstering security measures.

The File Security SDK consistently adopts TLS as the default communication channel, prioritizing security at all times. It is strongly advised not to disable TLS in a production environment while utilizing the File Security SDK, as doing so could compromise the integrity and confidentiality of transmitted data.

## Disabling certificate verification

For customers who need to enable TLS channel encryption without verifying the provided CA certificate, the `TM_AM_DISABLE_CERT_VERIFY` environment variable can be set. However, this option is only recommended for use in testing environments.

When `TM_AM_DISABLE_CERT_VERIFY` is set to `1`, certificate verification is disabled. By default, the certificate will be verified.
