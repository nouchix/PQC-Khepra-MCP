package compliance

// CheckStatus represents the result of a compliance check
type CheckStatus string

const (
	StatusPass  CheckStatus = "PASS"
	StatusFail  CheckStatus = "FAIL"
	StatusError CheckStatus = "ERROR"
)

// NativeCheck defines a hardcoded compliance check (STIG/CIS)
type NativeCheck struct {
	ID          string
	STIGID      string
	Title       string
	Description string
	OS          string
	Run         func() (CheckStatus, string, error)
}
