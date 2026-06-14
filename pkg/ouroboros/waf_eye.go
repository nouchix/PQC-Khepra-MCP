package ouroboros

// waf_eye.go — WAFEye bridges the SEKHEM WAFShield and Suricata IDS into the
// Ouroboros Perceive-Deliberate-Manifest-Transcribe cycle.
//
// Two telemetry sources:
//  1. WAFShield.threatChan — buffered channel of L7 threat events (SQLi, XSS, …)
//     drained non-blocking each Gaze() call.
//  2. Suricata EVE JSON — tailed from /var/log/suricata/eve.json.
//     WAFEye gracefully handles a missing file (Suricata not yet running).
//
// Cycle integration: The Ouroboros ticker runs every 10 seconds. WAFEye.Gaze()
// is called once per tick. It drains all buffered WAF events (channel, not poll)
// and reads any new Suricata alert lines written since the last Gaze().

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
)

const (
	// suricataEVEPath is the standard Suricata EVE JSON log path on Ubuntu/Debian.
	suricataEVEPath = "/var/log/suricata/eve.json"

	// maxEVELinesPerCycle caps how many EVE lines WAFEye reads per Gaze() call.
	// Prevents a burst of Suricata alerts from blocking the Ouroboros ticker.
	maxEVELinesPerCycle = 500
)

// suricataAlert is the minimal subset of an EVE JSON event we care about.
// Full EVE schema: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
type suricataAlert struct {
	Timestamp  string `json:"timestamp"`
	EventType  string `json:"event_type"`
	SrcIP      string `json:"src_ip"`
	DestIP     string `json:"dest_ip"`
	DestPort   int    `json:"dest_port"`
	Proto      string `json:"proto"`
	Alert      struct {
		Action      string `json:"action"`
		GID         int    `json:"gid"`
		SignatureID  int    `json:"signature_id"`
		Rev         int    `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
	} `json:"alert"`
}

// WAFEye implements ouroboros.WedjatEye by consuming:
//   - SEKHEM WAFShield threat channel (L7 events)
//   - Suricata EVE JSON file (L3/L4 events)
//
// It is registered into DuatRealm.Eyes during Awaken() so the Ouroboros
// cycle automatically calls Gaze() every tick.
type WAFEye struct {
	name      string
	wafEvents <-chan maat.Isfet // read-only end of WAFShield.threatChan

	// Suricata EVE file tailing state.
	// eveFile is nil when Suricata is not running; WAFEye retries each Gaze().
	eveFile   *os.File
	eveReader *bufio.Reader
	evePath   string
}

// NewWAFEye constructs a WAFEye.
// wafEvents is the read-only channel from WAFShield.ThreatChan().
// evePath is the Suricata EVE JSON log path; pass "" to use the default.
func NewWAFEye(wafEvents <-chan maat.Isfet, evePath string) *WAFEye {
	if evePath == "" {
		evePath = suricataEVEPath
	}
	eye := &WAFEye{
		name:      "waf-eye",
		wafEvents: wafEvents,
		evePath:   evePath,
	}
	// Attempt to open the EVE file and seek to end on startup.
	// If Suricata is not yet running this is a no-op; retried on each Gaze().
	eye.tryOpenEVE()
	return eye
}

// tryOpenEVE opens the Suricata EVE file and seeks to the current end.
// New lines appended after this point will be read by Gaze().
// Safe to call repeatedly — it's a no-op if the file is already open.
func (we *WAFEye) tryOpenEVE() {
	if we.eveFile != nil {
		return // already open
	}
	f, err := os.Open(we.evePath)
	if err != nil {
		// File missing (Suricata not running) — not an error, will retry later.
		return
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return
	}
	we.eveFile = f
	we.eveReader = bufio.NewReaderSize(f, 64*1024)
	log.Printf("[%s] Suricata EVE JSON: tailing %s", we.name, we.evePath)
}

// Gaze implements WedjatEye. It is called by the Ouroboros cycle every 10 s.
// It drains WAF channel events and reads new Suricata EVE alert lines.
func (we *WAFEye) Gaze() []maat.Isfet {
	var threats []maat.Isfet

	// ── 1. Drain WAF L7 events (non-blocking) ────────────────────────────────
	for {
		select {
		case t := <-we.wafEvents:
			threats = append(threats, t)
		default:
			goto suricata
		}
	}

suricata:
	// ── 2. Read new Suricata EVE alerts since last Gaze() ────────────────────
	// Retry opening if Suricata came up between cycles.
	we.tryOpenEVE()

	if we.eveFile != nil {
		count := 0
		for count < maxEVELinesPerCycle {
			line, err := we.eveReader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					// No more new lines this cycle — normal; file was truncated (logrotate)?
					if len(line) == 0 {
						// Check if file was rotated (inode changed)
						we.handleRotation()
					}
				} else {
					log.Printf("[%s] EVE read error: %v — closing file", we.name, err)
					we.eveFile.Close()
					we.eveFile = nil
					we.eveReader = nil
				}
				if len(line) == 0 {
					break
				}
			}

			line = strings.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			isfet := parseEVELine(line, we.name)
			if isfet != nil {
				threats = append(threats, *isfet)
			}
			count++
		}
	}

	return threats
}

// handleRotation detects if the EVE file was rotated (log rotation) by comparing
// the current file's inode to the path's inode. If different, reopen.
func (we *WAFEye) handleRotation() {
	pathInfo, err := os.Stat(we.evePath)
	if err != nil {
		return // file gone; will retry open next Gaze
	}
	fileInfo, err := we.eveFile.Stat()
	if err != nil {
		return
	}
	if !os.SameFile(pathInfo, fileInfo) {
		log.Printf("[%s] Suricata EVE log rotated — reopening", we.name)
		we.eveFile.Close()
		we.eveFile = nil
		we.eveReader = nil
		we.tryOpenEVE() // seek to beginning of new file
		// After rotation we seek to start so we catch any alerts written
		// at the top of the fresh file before we noticed.
		if we.eveFile != nil {
			we.eveFile.Seek(0, io.SeekStart)
			we.eveReader = bufio.NewReaderSize(we.eveFile, 64*1024)
		}
	}
}

// parseEVELine decodes one EVE JSON line and converts it to an maat.Isfet.
// Returns nil for non-alert event types (flow, dns, http, etc.).
func parseEVELine(line, eyeName string) *maat.Isfet {
	var evt suricataAlert
	if err := json.Unmarshal([]byte(line), &evt); err != nil {
		// Not valid JSON or unknown format — skip silently.
		return nil
	}
	if evt.EventType != "alert" {
		return nil
	}

	severity := suricataSeverityToMaat(evt.Alert.Severity)

	return &maat.Isfet{
		ID:       suricataCorrelationID(evt),
		Severity: severity,
		Source:   evt.SrcIP,
		Omens: []maat.Omen{
			{Name: "ip", Value: evt.SrcIP, Malevolence: severityToMalevolenceL4(severity)},
			{Name: "dest_ip", Value: evt.DestIP, Malevolence: 0},
			{Name: "signature", Value: evt.Alert.Signature, Malevolence: 0.6},
			{Name: "category", Value: evt.Alert.Category, Malevolence: 0.5},
			{Name: "sid", Value: itoa(evt.Alert.SignatureID), Malevolence: 0},
			{Name: "proto", Value: evt.Proto, Malevolence: 0},
			{Name: "source", Value: "suricata-eve", Malevolence: 0},
		},
		Certainty: suricataCertainty(evt.Alert.Severity),
	}
}

// suricataSeverityToMaat maps Suricata alert severity (1=high, 2=medium, 3=low)
// to maat.Severity. Suricata uses inverted scale (1 is most severe).
func suricataSeverityToMaat(s int) maat.Severity {
	switch s {
	case 1:
		return maat.SeverityCatastrophic
	case 2:
		return maat.SeveritySevere
	case 3:
		return maat.SeverityModerate
	default:
		return maat.SeverityMinor
	}
}

func suricataCertainty(severity int) float64 {
	switch severity {
	case 1:
		return 0.95
	case 2:
		return 0.85
	case 3:
		return 0.70
	default:
		return 0.50
	}
}

func severityToMalevolenceL4(s maat.Severity) float64 {
	switch s {
	case maat.SeverityMinor:
		return 0.3
	case maat.SeverityModerate:
		return 0.55
	case maat.SeveritySevere:
		return 0.8
	case maat.SeverityCatastrophic:
		return 1.0
	default:
		return 0.5
	}
}

// suricataCorrelationID builds a deterministic ID from EVE event fields.
func suricataCorrelationID(evt suricataAlert) string {
	return "suricata-" + evt.SrcIP + "-" + itoa(evt.Alert.SignatureID) + "-" + evt.Timestamp
}

// itoa is a minimal int→string helper that avoids importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// Name implements WedjatEye.
func (we *WAFEye) Name() string {
	return we.name
}

// Close releases the Suricata EVE file handle. Call when the DuatRealm stops.
func (we *WAFEye) Close() {
	if we.eveFile != nil {
		we.eveFile.Close()
		we.eveFile = nil
		we.eveReader = nil
	}
}

// Ensure WAFEye satisfies the WedjatEye interface at compile time.
// WedjatEye requires Gaze() []maat.Isfet and Name() string.
var _ WedjatEye = (*WAFEye)(nil)

// WAFEyeWithTimeout wraps WAFEye.Gaze() with a deadline so a slow EVE read
// cannot stall the Ouroboros ticker. Used by DuatRealm if needed.
func WAFEyeWithTimeout(eye *WAFEye, timeout time.Duration) []maat.Isfet {
	type result struct{ threats []maat.Isfet }
	ch := make(chan result, 1)
	go func() {
		ch <- result{threats: eye.Gaze()}
	}()
	select {
	case r := <-ch:
		return r.threats
	case <-time.After(timeout):
		log.Printf("[%s] Gaze() timeout after %v — returning partial results", eye.name, timeout)
		return nil
	}
}
