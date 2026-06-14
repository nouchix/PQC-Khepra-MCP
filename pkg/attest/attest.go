package attest

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

type Semantics struct {
	Boundary       string `json:"boundary"`
	Purpose        string `json:"purpose"`
	LeastPrivilege bool   `json:"least_privilege"`
}

type Lifecycle struct {
	Journey         string    `json:"journey"`
	CreatedAt       time.Time `json:"created_at"`
	RotationAfterND int       `json:"rotation_after_days"`
}

type Binding struct {
	OpenSSHPubSHA256 string `json:"openssh_pub_sha256"`
	Comment          string `json:"comment"`
}

type Assertion struct {
	Schema    string    `json:"schema"`
	Symbol    string    `json:"symbol"`
	Semantics Semantics `json:"semantics"`
	Lifecycle Lifecycle `json:"lifecycle"`
	Binding   Binding   `json:"binding"`
}

type RiskAttestation struct {
	Target       string        `json:"target"`
	SnapshotID   string        `json:"snapshot_id"`
	Timestamp    time.Time     `json:"timestamp"`
	Score        int           `json:"risk_score"` // 0-100
	Findings     []RiskFinding `json:"findings"`
	Narrative    string        `json:"narrative"` // LLM generated summary
	Signature    string        `json:"signature,omitempty"`
	PQCAlgorithm string        `json:"pqc_algorithm,omitempty"`
	PublicKey    string        `json:"public_key,omitempty"`
}

type RiskFinding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Evidence    []string `json:"evidence"` // Causality Chain
	Remediation string   `json:"remediation"`
}

func (a *RiskAttestation) SealWithPQC(privKey, pubKey []byte) error {
	a.PQCAlgorithm = "Dilithium3"
	a.Signature = ""
	a.PublicKey = hex.EncodeToString(pubKey)

	data, err := json.Marshal(a)
	if err != nil {
		return err
	}

	sig, err := adinkra.Sign(privKey, data)
	if err != nil {
		return err
	}

	a.Signature = hex.EncodeToString(sig)
	return nil
}
