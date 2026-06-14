package connectors

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
)

// XCCDFBenchmark is a simplified structure for parsing SCAP/XCCDF results.
// Compatible with OpenSCAP and SCC outputs.
type XCCDFBenchmark struct {
	XMLName     xml.Name     `xml:"Benchmark"`
	TestResults []TestResult `xml:"TestResult"`
}

type TestResult struct {
	Target      string       `xml:"target"`
	RuleResults []RuleResult `xml:"rule-result"`
	Score       float64      `xml:"score"`
}

type RuleResult struct {
	IDRef  string `xml:"idref,attr"`
	Result string `xml:"result"` // pass, fail, notapplicable
}

// ParseXCCDF parses an XML file and returns rule results.
func ParseXCCDF(path string) ([]RuleResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, _ := io.ReadAll(f)
	var bench XCCDFBenchmark

	// Try standard XCCDF 1.2
	if err := xml.Unmarshal(data, &bench); err != nil {
		return nil, fmt.Errorf("xccdf parse error: %v", err)
	}

	var results []RuleResult
	for _, tr := range bench.TestResults {
		for _, rr := range tr.RuleResults {
			if rr.Result == "fail" || rr.Result == "pass" {
				results = append(results, rr)
			}
		}
	}
	return results, nil
}
