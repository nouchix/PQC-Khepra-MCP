package stigs

import (
	"os"
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestLoadLibrary(t *testing.T) {
	// Create a mock Excel file
	f := excelize.NewFile()
	sheet := "Sheet1"

	// Headers
	headers := []string{"STIG_ID", "STIG_Title", "STIG_Severity", "CCI_ID", "File", "NIST_53", "Def", "NIST_171", "Family"}
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheet, cell, h)
	}

	// Data Row
	data := []string{"ID-1", "Test Title", "High", "CCI-123", "f.xml", "AC-1", "Def", "3.1.1", "Access Control"}
	for i, d := range data {
		cell, _ := excelize.CoordinatesToCellName(i+1, 2)
		f.SetCellValue(sheet, cell, d)
	}

	tmpfile, err := os.CreateTemp("", "test_stigs_*.xlsx")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	f.SaveAs(tmpfile.Name())
	f.Close()

	items, err := LoadLibrary(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadLibrary failed: %v", err)
	}

	if len(items) != 1 {
		t.Errorf("Expected 1 item, got %d", len(items))
	}
	if items[0].ID != "ID-1" {
		t.Errorf("Expected ID 'ID-1', got '%s'", items[0].ID)
	}
}
