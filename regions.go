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
	AWS_ZA_REGION   = "af-south-1"
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
	C1_ZA_REGION    = "za-1"
)

var C1Regions = []string{C1_AU_REGION, C1_CA_REGION, C1_DE_REGION, C1_GB_REGION, C1_IN_REGION, C1_JP_REGION, C1_SG_REGION, C1_US_REGION, C1_TREND_REGION, C1_AE_REGION, C1_ZA_REGION}
var V1Regions = []string{AWS_AU_REGION, AWS_CA_REGION, AWS_DE_REGION, AWS_GB_REGION, AWS_IN_REGION, AWS_JP_REGION, AWS_SG_REGION, AWS_US_REGION, AWS_AE_REGION, AWS_ZA_REGION}
var SupportedV1Regions = []string{AWS_AU_REGION, AWS_CA_REGION, AWS_DE_REGION, AWS_GB_REGION, AWS_IN_REGION, AWS_JP_REGION, AWS_SG_REGION, AWS_US_REGION, AWS_AE_REGION, AWS_ZA_REGION}
var SupportedC1Regions = []string{C1_AU_REGION, C1_CA_REGION, C1_DE_REGION, C1_GB_REGION, C1_IN_REGION, C1_JP_REGION, C1_SG_REGION, C1_US_REGION, C1_ZA_REGION}
var AllRegions = append(C1Regions, V1Regions...)
var AllValidRegions = append(SupportedC1Regions, SupportedV1Regions...)

var V1ToC1RegionMapping = map[string]string{
	AWS_AU_REGION: C1_AU_REGION,
	AWS_CA_REGION: C1_CA_REGION,
	AWS_DE_REGION: C1_DE_REGION,
	AWS_GB_REGION: C1_GB_REGION,
	AWS_IN_REGION: C1_IN_REGION,
	AWS_JP_REGION: C1_JP_REGION,
	AWS_SG_REGION: C1_SG_REGION,
	AWS_US_REGION: C1_US_REGION,
	AWS_AE_REGION: C1_AE_REGION,
	AWS_ZA_REGION: C1_ZA_REGION,
}

var V1RegionFQDNMapping = map[string]string{
	AWS_AU_REGION: "antimalware-ase2.xdr.trendmicro.com",
	AWS_CA_REGION: "antimalware-cc1.xdr.trendmicro.com",
	AWS_DE_REGION: "antimalware-ec1.xdr.trendmicro.com",
	AWS_GB_REGION: "antimalware-ew2.xdr.trendmicro.com",
	AWS_IN_REGION: "antimalware-as1.xdr.trendmicro.com",
	AWS_JP_REGION: "antimalware-ane1.xdr.trendmicro.com",
	AWS_SG_REGION: "antimalware-ase1.xdr.trendmicro.com",
	AWS_US_REGION: "antimalware-ue1.xdr.trendmicro.com",
	AWS_AE_REGION: "antimalware-ae1.xdr.trendmicro.com",
	AWS_ZA_REGION: "antimalware-za1.xdr.trendmicro.com",
}

var C1RegionFQDNMapping = map[string]string{
	C1_US_REGION:    "antimalware.us-1.cloudone.trendmicro.com",
	C1_IN_REGION:    "antimalware.in-1.cloudone.trendmicro.com",
	C1_DE_REGION:    "antimalware.de-1.cloudone.trendmicro.com",
	C1_SG_REGION:    "antimalware.sg-1.cloudone.trendmicro.com",
	C1_AU_REGION:    "antimalware.au-1.cloudone.trendmicro.com",
	C1_JP_REGION:    "antimalware.jp-1.cloudone.trendmicro.com",
	C1_GB_REGION:    "antimalware.gb-1.cloudone.trendmicro.com",
	C1_CA_REGION:    "antimalware.ca-1.cloudone.trendmicro.com",
	C1_TREND_REGION: "antimalware.trend-us-1.cloudone.trendmicro.com",
	C1_AE_REGION:    "antimalware.ae-1.cloudone.trendmicro.com",
	C1_ZA_REGION:    "antimalware.za-1.cloudone.trendmicro.com",
}
