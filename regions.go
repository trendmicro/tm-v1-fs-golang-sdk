package client

const (
	AWS_JP_REGION   = "ap-northeast-1"
	AWS_SG_REGION   = "ap-southeast-1"
	AWS_AU_REGION   = "ap-southeast-2"
	AWS_IN_REGION   = "ap-south-1"
	AWS_US_REGION   = "us-east-1"
	AWS_DE_REGION   = "eu-central-1"
	AWS_CA_REGION   = "ca-central-1"
	AWS_GB_REGION   = "eu-west-2"
	AWS_AE_REGION   = "me-central-1"
	C1_JP_REGION    = "jp-1"
	C1_SG_REGION    = "sg-1"
	C1_AU_REGION    = "au-1"
	C1_IN_REGION    = "in-1"
	C1_US_REGION    = "us-1"
	C1_DE_REGION    = "de-1"
	C1_CA_REGION    = "ca-1"
	C1_GB_REGION    = "gb-1"
	C1_TREND_REGION = "trend-us-1"
	C1_AE_REGION    = "ae-1"
)

var C1Regions []string = []string{C1_AU_REGION, C1_CA_REGION, C1_DE_REGION, C1_GB_REGION, C1_IN_REGION, C1_JP_REGION, C1_SG_REGION, C1_US_REGION, C1_TREND_REGION, C1_AE_REGION}
var V1Regions []string = []string{AWS_AU_REGION, AWS_CA_REGION, AWS_DE_REGION, AWS_GB_REGION, AWS_IN_REGION, AWS_JP_REGION, AWS_SG_REGION, AWS_US_REGION, AWS_AE_REGION}
var SupportedV1Regions []string = []string{AWS_AU_REGION, AWS_DE_REGION, AWS_IN_REGION, AWS_JP_REGION, AWS_SG_REGION, AWS_US_REGION, AWS_AE_REGION}
var SupportedC1Regions []string = []string{C1_AU_REGION, C1_CA_REGION, C1_DE_REGION, C1_GB_REGION, C1_IN_REGION, C1_JP_REGION, C1_SG_REGION, C1_US_REGION}
var AllRegions []string = append(C1Regions, V1Regions...)
var AllValidRegions []string = append(SupportedC1Regions, SupportedV1Regions...)

var V1ToC1RegionMapping = map[string]string{
	AWS_AU_REGION: C1_AU_REGION,
	AWS_DE_REGION: C1_DE_REGION,
	AWS_IN_REGION: C1_IN_REGION,
	AWS_JP_REGION: C1_JP_REGION,
	AWS_SG_REGION: C1_SG_REGION,
	AWS_US_REGION: C1_US_REGION,
	AWS_AE_REGION: C1_AE_REGION,
}
