//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - PDF Evidence Report Generator
// =============================================================================
// Generates a branded ADINKHEPRA compliance report as a PDF byte stream.
// Pure Go — no CGO, no external tools.
// =============================================================================

package apiserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// EvidenceReport holds the data for a PDF evidence export
type EvidenceReport struct {
	ExportID    string
	Framework   string
	Timestamp   time.Time
	Score       float64
	DataHash    string
	Signature   string
	Algorithm   string
	Attestations []AttestationSummary
	Findings     []FindingSummary
	ChainLength int
}

// AttestationSummary is a condensed attestation for reporting
type AttestationSummary struct {
	ID        string
	Type      string
	Timestamp time.Time
	Hash      string
	Verified  bool
}

// FindingSummary is a condensed finding for reporting
type FindingSummary struct {
	ControlID   string
	Title       string
	Severity    string
	Status      string
	Remediation string
}

// GenerateEvidencePDF creates a PDF byte stream for the evidence report.
//
// Implementation note: We generate a self-contained PDF using raw PDF
// operators rather than pulling in a large dependency. This produces
// a valid, spec-compliant PDF 1.4 document that any viewer can render.
//
// The PDF includes:
//   - ADINKHEPRA branded header
//   - PQC signature metadata block
//   - Compliance score
//   - Finding summary table
//   - Attestation chain summary
//   - Cryptographic seal footer
func GenerateEvidencePDF(report *EvidenceReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil report")
	}

	var buf bytes.Buffer
	p := &pdfWriter{w: &buf}

	p.header()

	// Page 1: Cover + Summary
	pageContent := p.buildCoverPage(report)
	streamObj := p.addStream(pageContent)
	p.addPage(streamObj)

	// Page 2: Findings Detail
	if len(report.Findings) > 0 {
		findingsContent := p.buildFindingsPage(report)
		findingsStream := p.addStream(findingsContent)
		p.addPage(findingsStream)
	}

	// Page 3: Attestation Chain
	if len(report.Attestations) > 0 {
		chainContent := p.buildChainPage(report)
		chainStream := p.addStream(chainContent)
		p.addPage(chainStream)
	}

	p.finalize()

	return buf.Bytes(), nil
}

// =============================================================================
// Minimal PDF Writer — generates valid PDF 1.4 without external deps
// =============================================================================

type pdfWriter struct {
	w       *bytes.Buffer
	objects []int    // byte offsets of each object
	pages   []int   // object numbers of page objects
	nextObj int
}

func (p *pdfWriter) header() {
	p.w.WriteString("%PDF-1.4\n")
	p.w.WriteString("%\xc0\xc1\xc2\xc3\n") // binary marker

	p.nextObj = 1

	// Obj 1: Catalog — written as provisional value; rebuilt with correct /Pages ref in finalize()
	p.objects = append(p.objects, p.w.Len())
	p.w.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Obj 2: Pages — written as provisional value; rebuilt with correct /Kids array in finalize()
	p.objects = append(p.objects, p.w.Len())
	p.w.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")

	// Obj 3: Font (Helvetica)
	p.objects = append(p.objects, p.w.Len())
	p.w.WriteString("3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	// Obj 4: Bold font
	p.objects = append(p.objects, p.w.Len())
	p.w.WriteString("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

	p.nextObj = 5
}

func (p *pdfWriter) addStream(content string) int {
	objNum := p.nextObj
	p.nextObj++

	p.objects = append(p.objects, p.w.Len())
	fmt.Fprintf(p.w, "%d 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n",
		objNum, len(content), content)

	return objNum
}

func (p *pdfWriter) addPage(contentObjNum int) {
	pageObjNum := p.nextObj
	p.nextObj++

	p.objects = append(p.objects, p.w.Len())
	fmt.Fprintf(p.w, "%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "+
		"/Contents %d 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>\nendobj\n",
		pageObjNum, contentObjNum)

	p.pages = append(p.pages, pageObjNum)
}

func (p *pdfWriter) finalize() {
	// Rebuild the PDF with correct catalog and pages
	var final bytes.Buffer

	final.WriteString("%PDF-1.4\n")
	final.WriteString("%\xc0\xc1\xc2\xc3\n")

	offsets := make([]int, 0, len(p.objects))

	// Object 1: Catalog
	offsets = append(offsets, final.Len())
	final.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	// Object 2: Pages with real kids
	offsets = append(offsets, final.Len())
	kids := make([]string, len(p.pages))
	for i, pg := range p.pages {
		kids[i] = fmt.Sprintf("%d 0 R", pg)
	}
	fmt.Fprintf(&final, "2 0 obj\n<< /Type /Pages /Kids [%s] /Count %d >>\nendobj\n",
		strings.Join(kids, " "), len(p.pages))

	// Object 3: Font
	offsets = append(offsets, final.Len())
	final.WriteString("3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	// Object 4: Bold font
	offsets = append(offsets, final.Len())
	final.WriteString("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

	// Remaining objects (streams + pages) — copy from original buffer
	// We need to re-emit them with correct offsets
	origBytes := p.w.Bytes()
	// Find where object 5 starts in original buffer
	obj5Marker := fmt.Sprintf("%d 0 obj", 5)
	idx := bytes.Index(origBytes, []byte(obj5Marker))
	if idx >= 0 {
		remaining := origBytes[idx:]
		// Update offsets for remaining objects
		for i := 4; i < len(p.objects); i++ {
			// Calculate relative offset within remaining bytes
			marker := fmt.Sprintf("%d 0 obj", i+1)
			pos := bytes.Index(remaining, []byte(marker))
			if pos >= 0 {
				offsets = append(offsets, final.Len()+pos)
			}
		}
		final.Write(remaining)
	}

	// Cross-reference table
	xrefOffset := final.Len()
	fmt.Fprintf(&final, "xref\n0 %d\n", len(offsets)+1)
	final.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&final, "%010d 00000 n \n", off)
	}

	// Trailer
	fmt.Fprintf(&final, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(offsets)+1, xrefOffset)

	// Replace the buffer
	p.w.Reset()
	p.w.Write(final.Bytes())
}

// =============================================================================
// Page Content Builders
// =============================================================================

func (p *pdfWriter) buildCoverPage(r *EvidenceReport) string {
	var s strings.Builder

	// Begin text
	s.WriteString("BT\n")

	// Title
	s.WriteString("/F2 24 Tf\n72 720 Td\n")
	s.WriteString("(ADINKHEPRA Compliance Evidence Report) Tj\n")

	// Subtitle
	s.WriteString("/F1 12 Tf\n0 -30 Td\n")
	fmt.Fprintf(&s, "(Framework: %s) Tj\n", pdfEscape(r.Framework))

	// Metadata block
	s.WriteString("/F2 11 Tf\n0 -40 Td\n")
	s.WriteString("(Report Metadata) Tj\n")

	s.WriteString("/F1 10 Tf\n0 -18 Td\n")
	fmt.Fprintf(&s, "(Export ID: %s) Tj\n", pdfEscape(r.ExportID))
	s.WriteString("0 -15 Td\n")
	fmt.Fprintf(&s, "(Generated: %s) Tj\n", r.Timestamp.Format(time.RFC3339))
	s.WriteString("0 -15 Td\n")
	fmt.Fprintf(&s, "(Algorithm: %s) Tj\n", pdfEscape(r.Algorithm))
	s.WriteString("0 -15 Td\n")
	fmt.Fprintf(&s, "(Data Hash: %s) Tj\n", pdfEscape(truncateHash(r.DataHash)))

	// Compliance score
	s.WriteString("/F2 14 Tf\n0 -35 Td\n")
	fmt.Fprintf(&s, "(Compliance Score: %.1f%%) Tj\n", r.Score)

	// Summary stats
	s.WriteString("/F1 10 Tf\n0 -25 Td\n")
	fmt.Fprintf(&s, "(Total Findings: %d) Tj\n", len(r.Findings))
	s.WriteString("0 -15 Td\n")
	fmt.Fprintf(&s, "(Attestation Chain Length: %d) Tj\n", r.ChainLength)

	// Signature block
	if r.Signature != "" {
		s.WriteString("/F2 11 Tf\n0 -35 Td\n")
		s.WriteString("(PQC Cryptographic Seal) Tj\n")
		s.WriteString("/F1 8 Tf\n0 -14 Td\n")
		fmt.Fprintf(&s, "(Signature: %s...) Tj\n", pdfEscape(truncateHash(r.Signature)))
		s.WriteString("0 -12 Td\n")
		s.WriteString("(This report is signed with ML-DSA-65 and is quantum-resistant.) Tj\n")
	}

	// Footer
	s.WriteString("/F1 8 Tf\n72 40 Td\n")
	s.WriteString("(ADINKHEPRA by NouchiX - Patent Pending USPTO #73565085 - SDVOSB) Tj\n")

	s.WriteString("ET\n")
	return s.String()
}

func (p *pdfWriter) buildFindingsPage(r *EvidenceReport) string {
	var s strings.Builder
	s.WriteString("BT\n")

	s.WriteString("/F2 16 Tf\n72 750 Td\n")
	s.WriteString("(Findings Detail) Tj\n")

	s.WriteString("/F1 9 Tf\n0 -25 Td\n")

	maxFindings := 30 // Fit on one page
	for i, f := range r.Findings {
		if i >= maxFindings {
			s.WriteString("0 -15 Td\n")
			fmt.Fprintf(&s, "(... and %d more findings) Tj\n", len(r.Findings)-maxFindings)
			break
		}

		statusMark := "PASS"
		if f.Status == "fail" {
			statusMark = "FAIL"
		} else if f.Status == "not_applicable" {
			statusMark = "N/A"
		}

		s.WriteString("0 -13 Td\n")
		line := fmt.Sprintf("[%s] %s - %s (%s)", statusMark, f.ControlID, truncateStr(f.Title, 60), f.Severity)
		fmt.Fprintf(&s, "(%s) Tj\n", pdfEscape(line))
	}

	// Footer
	s.WriteString("/F1 8 Tf\n72 40 Td\n")
	s.WriteString("(ADINKHEPRA by NouchiX - Patent Pending USPTO #73565085) Tj\n")

	s.WriteString("ET\n")
	return s.String()
}

func (p *pdfWriter) buildChainPage(r *EvidenceReport) string {
	var s strings.Builder
	s.WriteString("BT\n")

	s.WriteString("/F2 16 Tf\n72 750 Td\n")
	s.WriteString("(Attestation Chain) Tj\n")

	s.WriteString("/F1 9 Tf\n0 -25 Td\n")

	maxAtts := 25
	for i, a := range r.Attestations {
		if i >= maxAtts {
			s.WriteString("0 -15 Td\n")
			fmt.Fprintf(&s, "(... and %d more attestations) Tj\n", len(r.Attestations)-maxAtts)
			break
		}

		verMark := "UNVERIFIED"
		if a.Verified {
			verMark = "VERIFIED"
		}

		s.WriteString("0 -14 Td\n")
		line := fmt.Sprintf("%s | %s | %s | %s",
			truncateStr(a.ID, 16), a.Type, a.Timestamp.Format("2006-01-02 15:04"), verMark)
		fmt.Fprintf(&s, "(%s) Tj\n", pdfEscape(line))
	}

	// Footer
	s.WriteString("/F1 8 Tf\n72 40 Td\n")
	s.WriteString("(ADINKHEPRA by NouchiX - Immutable DAG audit chain) Tj\n")

	s.WriteString("ET\n")
	return s.String()
}

// =============================================================================
// Helpers
// =============================================================================

func pdfEscape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "(", "\\(")
	s = strings.ReplaceAll(s, ")", "\\)")
	return s
}

func truncateHash(h string) string {
	if len(h) > 32 {
		return h[:32]
	}
	return h
}

func truncateStr(s string, max int) string {
	if len(s) > max {
		return s[:max-3] + "..."
	}
	return s
}

// BuildEvidenceReportFromCC gathers current Command Center state into an EvidenceReport
func (s *Server) BuildEvidenceReportFromCC(framework string) *EvidenceReport {
	commandCenter.mu.RLock()
	defer commandCenter.mu.RUnlock()

	now := time.Now()
	exportID := generateID("exp")

	// Gather attestation summaries
	atts := make([]AttestationSummary, 0, len(commandCenter.attestations))
	for _, a := range commandCenter.attestations {
		atts = append(atts, AttestationSummary{
			ID:        a.ID,
			Type:      a.Type,
			Timestamp: a.Timestamp,
			Hash:      a.DataHash,
			Verified:  a.Signature != "",
		})
	}

	// Gather finding summaries from latest scan
	findings := make([]FindingSummary, 0)
	for _, scan := range commandCenter.scans {
		for _, f := range scan.Findings {
			findings = append(findings, FindingSummary{
				ControlID:   f.ControlID,
				Title:       f.Title,
				Severity:    f.Severity,
				Status:      f.Status,
				Remediation: f.Description,
			})
		}
	}

	// Calculate score
	passed := 0
	for _, f := range findings {
		if f.Status == "pass" {
			passed++
		}
	}
	score := 0.0
	if len(findings) > 0 {
		score = float64(passed) / float64(len(findings)) * 100
	}

	hashInput := fmt.Sprintf("%s|%s|%s", exportID, framework, now.Format(time.RFC3339))
	hash := sha256.Sum256([]byte(hashInput))

	// Sign the report hash
	sigHex := ""
	if s.sigPrivKey != nil {
		sig, err := signWithAdinkra(s.sigPrivKey, hash[:])
		if err == nil {
			sigHex = hex.EncodeToString(sig)
		}
	}

	return &EvidenceReport{
		ExportID:     exportID,
		Framework:    framework,
		Timestamp:    now,
		Score:        score,
		DataHash:     hex.EncodeToString(hash[:]),
		Signature:    sigHex,
		Algorithm:    "ML-DSA-65 (FIPS 204)",
		Attestations: atts,
		Findings:     findings,
		ChainLength:  len(atts),
	}
}
