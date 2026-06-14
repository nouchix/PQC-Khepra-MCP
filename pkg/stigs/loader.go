package stigs

import (
	"github.com/xuri/excelize/v2"
)

type STIGItem struct {
	ID          string `json:"stig_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	CCI         string `json:"cci"`
	NIST800_53  string `json:"nist_800_53"`
	NIST800_171 string `json:"nist_800_171"`
	Family      string `json:"control_family"`
}

// LoadLibrary reads the Ultimate STIG mapping excel file.
func LoadLibrary(path string) ([]STIGItem, error) {
	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Assume first sheet is the target
	sheet := f.GetSheetName(0)
	rows, err := f.GetRows(sheet)
	if err != nil {
		return nil, err
	}

	var items []STIGItem

	// Headers: [STIG_ID STIG_Title STIG_Severity CCI_ID STIG_File NIST_53_Ref Definition NIST_171_Ref Control_Family]
	// Mapping index based on observed output:
	// 0: STIG_ID
	// 1: STIG_Title
	// 2: STIG_Severity
	// 3: CCI_ID
	// 5: NIST_53_Ref
	// 7: NIST_171_Ref
	// 8: Control_Family

	for i, row := range rows {
		if i == 0 {
			continue
		} // Skip header
		if len(row) < 9 {
			continue
		} // Skip incomplete lines

		item := STIGItem{
			ID:          row[0],
			Title:       row[1],
			Severity:    row[2],
			CCI:         row[3],
			NIST800_53:  row[5],
			NIST800_171: row[7],
			Family:      row[8],
		}
		items = append(items, item)
	}

	return items, nil
}
