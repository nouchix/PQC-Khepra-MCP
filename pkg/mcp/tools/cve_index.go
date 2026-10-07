// Package tools — cve_index.go
//
// Offline CVE index for khepra_query_threat_intel. It loads, once per
// process, every *.json file under data/cve-database (searched recursively):
//
//   - CISA Known Exploited Vulnerabilities catalogs ({"vulnerabilities": [...]})
//   - MITRE CVE JSON 5.x records (one CVE per file, as in the CVE List repo)
//
// Results always state what was loaded (record count, publication years,
// KEV entries), so an empty result is never mistaken for "no known
// vulnerability" when the data simply does not cover it.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
package tools

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type cveIndex struct {
	dir     string
	records []VulnRecord
	kev     int
	minYear int
	maxYear int
}

var (
	cveIndexOnce sync.Once
	cveIdx       *cveIndex
)

// loadCVEIndex returns the process-wide index, building it on first use.
func loadCVEIndex() *cveIndex {
	cveIndexOnce.Do(func() { cveIdx = buildCVEIndex(cveDatabaseDirs()) })
	return cveIdx
}

func cveDatabaseDirs() []string {
	return []string{"data/cve-database", "../data/cve-database", filepath.Join(findProjectRoot(), "data", "cve-database")}
}

type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID          string `json:"cveID"`
		VendorProject  string `json:"vendorProject"`
		Product        string `json:"product"`
		DateAdded      string `json:"dateAdded"`
		ShortDesc      string `json:"shortDescription"`
		RequiredAction string `json:"requiredAction"`
	} `json:"vulnerabilities"`
}

type cve5Record struct {
	CveMetadata struct {
		CveID         string `json:"cveId"`
		State         string `json:"state"`
		DatePublished string `json:"datePublished"`
	} `json:"cveMetadata"`
	Containers struct {
		Cna struct {
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Affected []struct {
				Vendor  string `json:"vendor"`
				Product string `json:"product"`
			} `json:"affected"`
			Metrics []struct {
				V31 *cvssV3 `json:"cvssV3_1"`
				V30 *cvssV3 `json:"cvssV3_0"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cna"`
	} `json:"containers"`
}

type cvssV3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// buildCVEIndex indexes the first directory in dirs that yields records.
func buildCVEIndex(dirs []string) *cveIndex {
	idx := &cveIndex{}
	for _, dir := range dirs {
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		byID := map[string]*VulnRecord{}
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if p != dir && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), ".json") {
				return nil
			}
			if data, err := os.ReadFile(p); err == nil {
				idx.ingest(data, byID)
			}
			return nil
		})
		if len(byID) == 0 {
			continue
		}
		idx.dir = dir
		for _, r := range byID {
			idx.records = append(idx.records, *r)
		}
		sort.Slice(idx.records, func(i, j int) bool { return idx.records[i].CVEID < idx.records[j].CVEID })
		for _, r := range idx.records {
			if y := cveYear(r.CVEID); y > 0 {
				if idx.minYear == 0 || y < idx.minYear {
					idx.minYear = y
				}
				if y > idx.maxYear {
					idx.maxYear = y
				}
			}
		}
		break
	}
	return idx
}

func (idx *cveIndex) ingest(data []byte, byID map[string]*VulnRecord) {
	get := func(id string) *VulnRecord {
		id = strings.ToUpper(strings.TrimSpace(id))
		r := byID[id]
		if r == nil {
			r = &VulnRecord{CVEID: id}
			byID[id] = r
		}
		return r
	}
	var kev kevCatalog
	if json.Unmarshal(data, &kev) == nil && len(kev.Vulnerabilities) > 0 {
		for _, v := range kev.Vulnerabilities {
			if v.CVEID == "" {
				continue
			}
			r := get(v.CVEID)
			if !r.IsKEV {
				idx.kev++
			}
			r.IsKEV = true
			r.KEVDateAdded = v.DateAdded
			r.Remediation = v.RequiredAction
			if r.Description == "" {
				r.Description = v.ShortDesc
			}
			if r.AffectedVendor == "" {
				r.AffectedVendor, r.AffectedProduct = v.VendorProject, v.Product
			}
			r.References = appendUnique(r.References, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
		}
		return
	}
	var rec cve5Record
	if json.Unmarshal(data, &rec) != nil || rec.CveMetadata.CveID == "" || strings.EqualFold(rec.CveMetadata.State, "REJECTED") {
		return
	}
	r := get(rec.CveMetadata.CveID)
	cna := rec.Containers.Cna
	for _, d := range cna.Descriptions {
		if strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			r.Description = d.Value
			break
		}
	}
	if len(cna.Affected) > 0 {
		r.AffectedVendor, r.AffectedProduct = cna.Affected[0].Vendor, cna.Affected[0].Product
	}
	for _, m := range cna.Metrics {
		c := m.V31
		if c == nil {
			c = m.V30
		}
		if c != nil {
			r.CVSSScore, r.Severity = c.BaseScore, strings.ToUpper(c.BaseSeverity)
			break
		}
	}
	for i, ref := range cna.References {
		if i == 5 {
			break
		}
		r.References = appendUnique(r.References, ref.URL)
	}
}

// search returns up to limit records: an exact match for a CVE ID, otherwise
// a case-insensitive substring match on ID, description, vendor and product.
// Known exploited vulnerabilities come first, then newest CVE IDs.
func (idx *cveIndex) search(query string, limit int) []VulnRecord {
	q := strings.ToLower(strings.TrimSpace(query))
	exact := strings.HasPrefix(q, "cve-")
	var out []VulnRecord
	for _, r := range idx.records {
		if exact {
			if strings.EqualFold(r.CVEID, q) {
				out = append(out, r)
			}
			continue
		}
		if strings.Contains(strings.ToLower(r.CVEID), q) || strings.Contains(strings.ToLower(r.Description), q) ||
			strings.Contains(strings.ToLower(r.AffectedVendor), q) || strings.Contains(strings.ToLower(r.AffectedProduct), q) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsKEV != out[j].IsKEV {
			return out[i].IsKEV
		}
		return out[i].CVEID > out[j].CVEID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// describe states what the index holds.
func (idx *cveIndex) describe() string {
	if len(idx.records) == 0 {
		return "no offline CVE database installed"
	}
	kev := fmt.Sprintf("%d CISA KEV entries", idx.kev)
	if idx.kev == 0 {
		kev = "no CISA KEV catalog installed"
	}
	return fmt.Sprintf("offline CVE index: %d records, CVE years %d–%d, %s (%s)", len(idx.records), idx.minYear, idx.maxYear, kev, idx.dir)
}

func cveYear(id string) int {
	parts := strings.SplitN(id, "-", 3)
	if len(parts) < 3 {
		return 0
	}
	y, _ := strconv.Atoi(parts[1])
	return y
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
