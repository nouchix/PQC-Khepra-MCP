package stig

import (
	"runtime"
	"testing"
)

func TestLiveValidationAndCMMC(t *testing.T) {
	v := NewValidator(".")
	report, err := v.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	t.Logf("Detected OS: %s, Hostname: %s, Duration: %v", report.OSVersion, report.Hostname, report.ScanDuration)

	// Check if OS framework was detected and ran
	if runtime.GOOS == "windows" {
		foundWin := false
		for fwName, res := range report.Results {
			if fwName == FrameworkWindows10 || fwName == FrameworkWindows11 ||
				fwName == FrameworkWinServer2016 || fwName == FrameworkWinServer2019 ||
				fwName == FrameworkWinServer2022 {
				foundWin = true
				t.Logf("Ran Windows framework: %s with %d total findings (Passed: %d, Failed: %d, Manual: %d)",
					fwName, res.TotalControls, res.Passed, res.Failed, res.ManualReview)
				for i, f := range res.Findings {
					if i < 5 {
						t.Logf("Finding %d: ID=%s Status=%s Refs=%v", i, f.ID, f.Status, f.References)
					}
				}
				if res.TotalControls == 0 {
					t.Errorf("Expected Windows STIG checks to execute, got 0 findings")
				}
			}
		}
		if !foundWin {
			t.Errorf("Expected a Windows STIG framework to be auto-selected on Windows, but none found")
		}
	}

	// Verify CMMC results
	cmmcRes, ok := report.Results[FrameworkCMMC]
	if !ok {
		t.Fatalf("Expected %s in report results", FrameworkCMMC)
	}

	t.Logf("CMMC Results: %d total practices (Passed: %d, Failed: %d, NotAssessed: %d)",
		cmmcRes.TotalControls, cmmcRes.Passed, cmmcRes.Failed, cmmcRes.NotAssessed)

	for _, f := range cmmcRes.Findings {
		if f.Status == "Fail" {
			t.Logf("FAIL PRACTICE: %s | Title: %s | Reason: %s", f.ID, f.Title, f.Actual)
		}
	}

	if cmmcRes.TotalControls < 100 {
		t.Errorf("Expected at least 110 CMMC practices, got %d", cmmcRes.TotalControls)
	}
}
