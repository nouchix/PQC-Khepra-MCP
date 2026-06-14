package stig

// database_helpers.go — Additional query methods for ComplianceDatabase.
//
// These complement the base methods in database.go and are used by the
// sovereign MCP tools (khepra_query_stig, khepra_get_compliance_score, etc.)
//
// NOTE: ComplianceScore, ComplianceGrade, RiskLevel, EnableFramework are
// already declared in types.go / validator.go — do NOT redeclare them here.

import "strings"

// GetSTIGsForCCI returns all STIG IDs that map to a given CCI identifier.
// e.g. GetSTIGsForCCI("CCI-000001") → ["SV-257777r...", ...]
func (d *ComplianceDatabase) GetSTIGsForCCI(cciID string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.CCItoSTIG[cciID]
}

// GetCCIsForNIST53 returns all CCI identifiers that map to a NIST 800-53 control.
// e.g. GetCCIsForNIST53("AC-2") → ["CCI-000001", "CCI-000002", ...]
func (d *ComplianceDatabase) GetCCIsForNIST53(nist53Ref string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.NIST53toCCI[nist53Ref]
}

// AllSTIGs returns the full STIG→CCI mapping map for iteration.
// Callers must not modify the returned map.
func (d *ComplianceDatabase) AllSTIGs() map[string][]CCIMapping {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.STIGtoCCI
}

// SearchSTIGsByTitle returns STIG IDs whose title contains the given
// substring (case-insensitive). Results are capped at maxResults.
func (d *ComplianceDatabase) SearchSTIGsByTitle(query string, maxResults int) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	lowerQ := strings.ToLower(query)
	var results []string
	seen := make(map[string]bool)

	for stigID, mappings := range d.STIGtoCCI {
		if seen[stigID] {
			continue
		}
		for _, m := range mappings {
			if strings.Contains(strings.ToLower(m.STIGTitle), lowerQ) {
				results = append(results, stigID)
				seen[stigID] = true
				break
			}
		}
		if len(results) >= maxResults {
			break
		}
	}
	return results
}

// DisableAllFrameworks sets the enabled framework list to empty.
// Use before EnableFramework to run a targeted single-framework scan.
func (v *Validator) DisableAllFrameworks() {
	v.enabledFrameworks = []string{}
}
