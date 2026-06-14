package arsenal

import (
	"encoding/json"
	"fmt"
	"os"
)

type ZapReport struct {
	Site []struct {
		Name   string     `json:"@name"`
		Host   string     `json:"@host"`
		Alerts []ZapAlert `json:"alerts"`
	} `json:"site"`
}

type ZapAlert struct {
	PluginID   string `json:"pluginid"`
	Alert      string `json:"alert"`
	Name       string `json:"name"`
	RiskCode   string `json:"riskcode"` // 3=High, 2=Medium, 1=Low, 0=Info
	Confidence string `json:"confidence"`
	RiskDesc   string `json:"riskdesc"`
	Desc       string `json:"desc"`
	Solution   string `json:"solution"`
	Instances  []struct {
		URI    string `json:"uri"`
		Method string `json:"method"`
		Param  string `json:"param"`
	} `json:"instances"`
}

// ParseZAP reads an OWASP ZAP generic JSON report.
// Command: zap-cli report -f json -o zap.json
func ParseZAP(path string) (*ZapReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var report ZapReport
	if err := json.Unmarshal(data, &report); err != nil {
		// Sometimes ZAP outputs a top-level object wrapper or straight fields depending on plugin
		return nil, fmt.Errorf("invalid zap json: %v", err)
	}

	return &report, nil
}
