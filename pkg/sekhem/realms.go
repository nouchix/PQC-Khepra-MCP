package sekhem

import "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"

// Realm defines the interface for each tier
type Realm interface {
	// Awaken initializes the realm
	Awaken() error

	// Perceive gathers awareness from Wedjat Eyes
	Perceive() []maat.Isfet

	// Deliberate invokes Anubis Weighing
	Deliberate(isfet []maat.Isfet) []maat.Heka

	// Manifest executes Heka through Khopesh Blades
	Manifest(heka []maat.Heka) error

	// Transcribe records to Seshat Chronicle
	Transcribe(actions []maat.Heka) error

	// GetName returns the realm name
	GetName() string
}
