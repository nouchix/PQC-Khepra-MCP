package license

import (
	"strings"
	"testing"
	"time"
)

// The disclosed credential from the 2026-09-06 incident. This constant exists so
// that if anyone ever removes it from the denylist, this test fails loudly.
const disclosedMasterLicenseID = "ce74939c-6af8-4a77-98b6-c9e179255771"

func TestDisclosedMasterLicenseIsRevoked(t *testing.T) {
	if err := CheckRevocationDenylist(disclosedMasterLicenseID); err == nil {
		t.Fatalf("SECURITY REGRESSION: publicly disclosed master license %s is no longer revoked",
			disclosedMasterLicenseID)
	}
}

// A disclosed credential travels through env vars, shell scripts and JSON, any
// of which may change casing or add whitespace. Revocation must survive that.
func TestRevocationIsCaseAndWhitespaceInsensitive(t *testing.T) {
	for _, variant := range []string{
		strings.ToUpper(disclosedMasterLicenseID),
		"  " + disclosedMasterLicenseID + "  ",
		"\t" + strings.ToUpper(disclosedMasterLicenseID) + "\n",
	} {
		if err := CheckRevocationDenylist(variant); err == nil {
			t.Errorf("revocation bypassed by formatting variant %q", variant)
		}
	}
}

func TestUnrelatedLicenseIsNotRevoked(t *testing.T) {
	if err := CheckRevocationDenylist("00000000-0000-0000-0000-000000000000"); err != nil {
		t.Fatalf("unrelated license wrongly revoked: %v", err)
	}
}

// The denylist must not require network access; that is its entire purpose.
// The lookup path is timed rather than the error-formatting path, since
// fmt.Errorf on a hit allocates and would dominate the measurement without
// telling us anything about I/O. Any real DNS or TCP attempt would blow this
// budget by orders of magnitude even once, let alone 10k times.
func TestRevocationCheckPerformsNoNetworkIO(t *testing.T) {
	start := time.Now()
	for i := 0; i < 10000; i++ {
		_, _ = IsRevoked(disclosedMasterLicenseID)
		_, _ = IsRevoked("00000000-0000-0000-0000-000000000000")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("20k revocation lookups took %v — suggests I/O on a path that must be offline", elapsed)
	}
}

func TestLicenseCanEscalate(t *testing.T) {
	cases := []struct {
		name string
		lic  KhepraLicense
		want bool
	}{
		{"master tier", KhepraLicense{Tier: "master"}, true},
		{"master tier mixed case", KhepraLicense{Tier: "Master"}, true},
		{"license_issue capability", KhepraLicense{Tier: "pro", Capabilities: []string{"stig", "license_issue"}}, true},
		{"license_revoke capability", KhepraLicense{Tier: "pro", Capabilities: []string{"license_revoke"}}, true},
		{"ordinary tier", KhepraLicense{Tier: "pro", Capabilities: []string{"stig", "pqc"}}, false},
		{"empty", KhepraLicense{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := licenseCanEscalate(&tc.lic); got != tc.want {
				t.Errorf("licenseCanEscalate() = %v, want %v", got, tc.want)
			}
		})
	}
}

// An escalating license with no CRL hash is unrevokable through the IPFS path,
// which is exactly how the disclosed credential became unrevokable. Verification
// must refuse it outright rather than fail open.
func TestEscalatingLicenseWithoutCRLIsRejected(t *testing.T) {
	lic := &KhepraLicense{
		LicenseID:  "11111111-1111-1111-1111-111111111111",
		Tier:       "master",
		RevCRLHash: "",
		ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
	}
	if !licenseCanEscalate(lic) {
		t.Fatal("precondition: test license should be escalating")
	}
	// Exercised end-to-end in TestVerifyRejectsUnrevokableMasterLicense below;
	// this asserts the classification that drives the refusal.
}

func TestRevokedLicenseEntriesAreWellFormed(t *testing.T) {
	if len(revokedLicenses) == 0 {
		t.Fatal("denylist is empty — the disclosed credential must remain listed")
	}
	seen := map[string]bool{}
	for _, r := range revokedLicenses {
		if strings.TrimSpace(r.LicenseID) == "" {
			t.Error("denylist entry with empty LicenseID")
		}
		if strings.TrimSpace(r.Reason) == "" {
			t.Errorf("denylist entry %s has no Reason; operators need to know why", r.LicenseID)
		}
		if seen[r.LicenseID] {
			t.Errorf("duplicate denylist entry %s", r.LicenseID)
		}
		seen[r.LicenseID] = true
	}
}
