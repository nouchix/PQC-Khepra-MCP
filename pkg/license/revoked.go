// Package license — revoked.go implements the compiled-in revocation denylist.
//
// WHY THIS EXISTS
//
// The IPFS CRL path (sovereign.go, Step 4) is network-dependent and fail-open:
// any party who can drop, delay, or poison a single HTTPS fetch defeats it.
// Worse, a license issued with an empty RevCRLHash is unrevokable through that
// path by construction, because checkRevocationList returns nil immediately.
//
// This file closes that hole. The denylist is compiled into the binary, so it
// requires no network, cannot be suppressed by an attacker with network
// control, and takes effect the moment a rebuilt binary is deployed. It is the
// mechanism of last resort for a credential that has been disclosed publicly.
//
// OPERATIONAL RULE: adding an ID here is a one-way door. A revoked license is
// never un-revoked; issue a new one instead.
package license

import (
	"fmt"
	"strings"
	"sync"
)

// RevokedLicense records a license that must never verify, regardless of its
// cryptographic validity. The signature on these licenses is genuine — that is
// precisely why a signature check alone cannot stop them.
type RevokedLicense struct {
	// LicenseID is the UUID from the license payload.
	LicenseID string
	// Reason is a short operator-facing explanation, surfaced in the error.
	Reason string
	// RevokedAt is the ISO-8601 date the revocation was published.
	RevokedAt string
}

// revokedLicenses is the compiled-in denylist.
//
// SECURITY INCIDENT 2026-09-06: license ce74939c was committed to the public
// repository nouchix/PQC-Khepra-MCP at deploy/.env.license and is therefore
// disclosed to anyone who cloned, forked, or scraped that repository. It is
// tier=master carrying the license_issue and license_revoke capabilities, and
// it was issued with an empty RevCRLHash, making the IPFS CRL path incapable
// of revoking it. It does not expire until 2027-06-22. Because
// KHEPRA_SKIP_DEVICE_BIND=1 disables hardware binding, the disclosed token is
// usable on any machine. This denylist is the only control that stops it.
var revokedLicenses = []RevokedLicense{
	{
		LicenseID: "ce74939c-6af8-4a77-98b6-c9e179255771",
		Reason:    "publicly disclosed in git history (master tier, license_issue/license_revoke)",
		RevokedAt: "2026-09-06",
	},
}

var (
	revokedOnce  sync.Once
	revokedIndex map[string]RevokedLicense
)

func buildRevokedIndex() {
	revokedIndex = make(map[string]RevokedLicense, len(revokedLicenses))
	for _, r := range revokedLicenses {
		revokedIndex[strings.ToLower(strings.TrimSpace(r.LicenseID))] = r
	}
}

// IsRevoked reports whether licenseID appears in the compiled-in denylist.
// Comparison is case-insensitive and whitespace-tolerant because license IDs
// travel through env vars, shell scripts, and JSON, any of which may alter
// surrounding whitespace or UUID casing.
//
// This performs no network I/O and cannot fail. That is the point: it is the
// control that still works when every network-dependent control has been
// suppressed.
func IsRevoked(licenseID string) (RevokedLicense, bool) {
	revokedOnce.Do(buildRevokedIndex)
	r, ok := revokedIndex[strings.ToLower(strings.TrimSpace(licenseID))]
	return r, ok
}

// CheckRevocationDenylist returns a non-nil error if the license is revoked.
// Callers must treat any error from this function as fatal and refuse to
// operate. It is deliberately impossible to downgrade this to a warning
// through configuration or environment.
func CheckRevocationDenylist(licenseID string) error {
	r, ok := IsRevoked(licenseID)
	if !ok {
		return nil
	}
	return fmt.Errorf(
		"license %s was REVOKED on %s (%s) — this credential is permanently invalid; obtain a newly issued license",
		r.LicenseID, r.RevokedAt, r.Reason,
	)
}
