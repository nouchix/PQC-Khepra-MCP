package maat

// Isfet represents chaos/disorder that disrupts Maat
// Isfet (Egyptian): Chaos, disorder, injustice
type Isfet struct {
	ID        string
	Severity  Severity
	Source    string
	Omens     []Omen
	Certainty float64 // 0.0 = uncertain, 1.0 = certain
}

type Severity string

const (
	SeverityMinor        Severity = "MINOR"
	SeverityModerate     Severity = "MODERATE"
	SeveritySevere       Severity = "SEVERE"
	SeverityCatastrophic Severity = "CATASTROPHIC"
)

type Omen struct {
	Name        string
	Value       string
	Malevolence float64 // 0.0 = benign, 1.0 = malicious
}
