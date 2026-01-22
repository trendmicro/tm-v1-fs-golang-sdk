# CHANGELOG

## 1.7.0 - 2026-01-19

* Add `EncodeFile`, `EncodeReader`, `DecodeFile`, `DecodeReader` functions for quarantining malicious files
* Support new regions: eu-west-2 (UK), ca-central-1 (Canada)

## 1.6.1 - 2025-09-11

* Add customized cloud account id setting via `SetCloudAccountID` function

## 1.6.0 - 2025-06-30

* Add active content detection support via `SetActiveContentEnable` function

## 1.5.1 - 2025-03-03

* Support new region me-central-1
* Fix CVE-2023-45288

## 1.5.0 - 2024-12-16

* Add `ScanReader` for scanning a well-implemented `AmaasClientReader`
* Add example code `scan-s3obj` for scanning an S3 object which is an example of using `ScanReader`

## 1.4.2 - 2024-08-30

* Fixed the issue of the TLS parameter being overwritten

## 1.4.1 - 2024-08-27

* Support certificate verification bypass using environment variable

## 1.4.0 - 2024-08-21

* Support digest calculation bypass

## 1.3.0 - 2024-08-19

* Update README.md
* Support CA cert import

## 1.2.0 - 2024-07-05

* Support verbose scan result

## 1.1.2 - 2024-04-10

* Update README.md
* Extend default timeout to 300s

## 1.1.1 - 2024-04-04

* Fix bug in SPN smart feedback
* Add tag flag to example tools

## 1.1.0 - 2024-04-03

* Update protos
* Enable PML (Predictive Machine Learning) detection and smart feedback
* Enable bulk mode
* Enable India region
* Support for scanning large files (over 2GB)
* Support socks5 proxy

## 1.0.1 - 2023-11-21

* Fix sha1 issue

## 1.0.0 - 2023-11-17

* Update to latest version
