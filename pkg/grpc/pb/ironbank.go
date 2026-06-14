// Package pb contains the Iron Bank scanner interface and types.
//
// The IronBankScannerClient interface maps conceptually to Harbor v2 REST
// operations on registry1.dso.mil. Implementations backed by the real
// Harbor REST client live in pkg/ironbank. This file provides the interface
// contract and type definitions shared across the codebase.
//
// NOTE: Iron Bank does NOT expose a gRPC API. The interface here is an
// adapter layer — the concrete implementation in pkg/ironbank uses Harbor
// v2 REST with PQC-signed requests routed through the AdinKhepra Firewall.
package pb

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ironbank"
)

// IronBankScannerClient is the client interface for Iron Bank scanning operations.
type IronBankScannerClient interface {
	// ScanImage triggers a vulnerability scan (legacy alias for Scan).
	ScanImage(ctx context.Context, in *ScanRequest, opts ...grpc.CallOption) (*ScanResponse, error)
	// Scan initiates a new scan.
	Scan(ctx context.Context, in *ScanRequest, opts ...grpc.CallOption) (*ScanResponse, error)
	// GetScanStatus checks scan progress.
	GetScanStatus(ctx context.Context, in *ScanStatusRequest, opts ...grpc.CallOption) (*ScanStatusResponse, error)
	// GetScanResult retrieves completed scan results.
	GetScanResult(ctx context.Context, in *ScanResultRequest, opts ...grpc.CallOption) (*ScanResponse, error)
	// ListVulnerabilities lists discovered vulnerabilities.
	ListVulnerabilities(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*VulnerabilityList, error)
	// ValidateCompliance checks against compliance frameworks.
	ValidateCompliance(ctx context.Context, in *ComplianceRequest, opts ...grpc.CallOption) (*ComplianceResult, error)
	// GetSBOM retrieves software bill of materials.
	GetSBOM(ctx context.Context, in *SBOMRequest, opts ...grpc.CallOption) (*SBOM, error)
	// BatchScan processes multiple artifacts in a stream.
	BatchScan(ctx context.Context, in *BatchScanRequest, opts ...grpc.CallOption) (IronBankScanner_BatchScanClient, error)
}

// IronBankScanner_BatchScanClient is the streaming client for batch scans.
type IronBankScanner_BatchScanClient interface {
	Recv() (*BatchScanResponse, error)
	grpc.ClientStream
}

// ScanRequest contains image scan parameters.
type ScanRequest struct {
	ImageDigest   string
	ImageTag      string
	Registry      string
	ScanType      string
	FIPSMode      bool
	PolicyProfile string
	TargetUri     string   // Target URI for scanning
	Frameworks    []string // Compliance frameworks to check
}

// ScanResponse contains scan results.
type ScanResponse struct {
	ScanId          string
	Status          string
	Vulnerabilities []*Vulnerability
	ComplianceScore float64
	Timestamp       int64
}

// ScanStatusRequest queries scan status.
type ScanStatusRequest struct {
	ScanId string
}

// ScanStatusResponse returns current scan status.
type ScanStatusResponse struct {
	ScanId   string
	Status   string
	Progress int32
	Message  string
}

// ScanResultRequest retrieves completed scan results.
type ScanResultRequest struct {
	ScanId     string
	IncludeRaw bool
}

// ListRequest queries vulnerabilities.
type ListRequest struct {
	ScanID       string
	MinSeverity  string
	IncludeFixes bool
}

// VulnerabilityList contains discovered vulnerabilities.
type VulnerabilityList struct {
	Vulnerabilities []*Vulnerability
	TotalCount      int32
}

// Vulnerability represents a single security issue.
type Vulnerability struct {
	ID          string
	Package     string
	Version     string
	Severity    string
	CVSS        float64
	Description string
	FixVersion  string
	References  []string
}

// ComplianceRequest checks against compliance frameworks.
type ComplianceRequest struct {
	TargetUri  string
	Frameworks []string
}

// ComplianceResult contains compliance validation results.
type ComplianceResult struct {
	TargetUri  string
	Passed     bool
	Score      float64
	Frameworks []*FrameworkResult
	Timestamp  int64
}

// FrameworkResult contains results for a single framework.
type FrameworkResult struct {
	Name     string
	Version  string
	Passed   bool
	Score    float64
	Controls []*ControlResult
}

// ControlResult contains a single control check result.
type ControlResult struct {
	ID       string
	Title    string
	Passed   bool
	Severity string
	Message  string
}

// SBOMRequest retrieves software bill of materials.
type SBOMRequest struct {
	TargetUri string
	Format    string // cyclonedx-json, spdx-json, etc.
}

// SBOM contains software bill of materials.
type SBOM struct {
	TargetUri  string
	Format     string
	Content    []byte
	Components []*SBOMComponent
	Timestamp  int64
}

// SBOMComponent represents a software component in the SBOM.
type SBOMComponent struct {
	Name     string
	Version  string
	Type     string
	Purl     string
	Licenses []string
	Hashes   map[string]string
}

// BatchScanRequest processes multiple artifacts.
type BatchScanRequest struct {
	Requests []*ScanRequest
}

// BatchScanResponse contains streaming batch results.
type BatchScanResponse struct {
	Result *ScanResponse
	Error  string
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────────────

// NewIronBankScannerClient creates a new Iron Bank scanner client backed by
// the Harbor v2 REST API with PQC-signed requests (AdinKhepra Firewall).
// Reads IRONBANK_USERNAME and IRONBANK_CLI_SECRET from environment.
//
// The cc parameter is retained for interface compatibility but is not used —
// Iron Bank does not expose a gRPC API.
func NewIronBankScannerClient(_ grpc.ClientConnInterface) IronBankScannerClient {
	c, err := ironbank.NewClient()
	if err != nil {
		// Fail loud — no silent fallback. Caller must set env vars.
		panic(fmt.Sprintf("ironbank: cannot create client — %v\n"+
			"Set IRONBANK_USERNAME and IRONBANK_CLI_SECRET environment variables.", err))
	}
	return &harborClient{c: c}
}

// NewIronBankScannerClientFromHarbor creates a client with explicit credentials.
// Use this in tests or when credentials come from a secret store.
func NewIronBankScannerClientFromHarbor(username, cliSecret string) (IronBankScannerClient, error) {
	c, err := ironbank.NewClientWithCredentials(username, cliSecret)
	if err != nil {
		return nil, err
	}
	return &harborClient{c: c}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Harbor-backed implementation
// ─────────────────────────────────────────────────────────────────────────────

type harborClient struct {
	c *ironbank.Client
}

func (h *harborClient) ScanImage(ctx context.Context, in *ScanRequest, _ ...grpc.CallOption) (*ScanResponse, error) {
	return h.Scan(ctx, in)
}

func (h *harborClient) Scan(ctx context.Context, in *ScanRequest, _ ...grpc.CallOption) (*ScanResponse, error) {
	target := in.TargetUri
	if target == "" {
		target = fmt.Sprintf("%s/%s:%s", in.Registry, in.ImageDigest, in.ImageTag)
	}

	scanID, err := h.c.TriggerScan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("ironbank Scan: %w", err)
	}

	return &ScanResponse{
		ScanId:    scanID,
		Status:    "scanning",
		Timestamp: time.Now().Unix(),
	}, nil
}

func (h *harborClient) GetScanStatus(ctx context.Context, in *ScanStatusRequest, _ ...grpc.CallOption) (*ScanStatusResponse, error) {
	overview, err := h.c.GetScanOverview(ctx, in.ScanId)
	if err != nil {
		return nil, fmt.Errorf("ironbank GetScanStatus: %w", err)
	}

	progress := int32(0)
	switch overview.ScanStatus {
	case "Success":
		progress = 100
	case "Running":
		progress = 50
	case "Pending":
		progress = 10
	}

	return &ScanStatusResponse{
		ScanId:   in.ScanId,
		Status:   overview.ScanStatus,
		Progress: progress,
		Message: fmt.Sprintf("severity=%s total=%d critical=%d high=%d",
			overview.Severity, overview.Total, overview.Critical, overview.High),
	}, nil
}

func (h *harborClient) GetScanResult(ctx context.Context, in *ScanResultRequest, _ ...grpc.CallOption) (*ScanResponse, error) {
	overview, err := h.c.GetScanOverview(ctx, in.ScanId)
	if err != nil {
		return nil, fmt.Errorf("ironbank GetScanResult: %w", err)
	}

	vulns, err := h.c.ListVulnerabilities(ctx, in.ScanId)
	if err != nil {
		return nil, fmt.Errorf("ironbank GetScanResult vulns: %w", err)
	}

	pbVulns := harborVulnsToPB(vulns)
	score := 100.0 - float64(overview.Critical)*20.0 - float64(overview.High)*5.0
	if score < 0 {
		score = 0
	}

	return &ScanResponse{
		ScanId:          in.ScanId,
		Status:          overview.ScanStatus,
		Vulnerabilities: pbVulns,
		ComplianceScore: score,
		Timestamp:       time.Now().Unix(),
	}, nil
}

func (h *harborClient) ListVulnerabilities(ctx context.Context, in *ListRequest, _ ...grpc.CallOption) (*VulnerabilityList, error) {
	harborVulns, err := h.c.ListVulnerabilities(ctx, in.ScanID)
	if err != nil {
		return nil, fmt.Errorf("ironbank ListVulnerabilities: %w", err)
	}

	pbVulns := harborVulnsToPB(harborVulns)
	if in.MinSeverity != "" {
		pbVulns = filterBySeverity(pbVulns, in.MinSeverity)
	}

	return &VulnerabilityList{
		Vulnerabilities: pbVulns,
		TotalCount:      int32(len(pbVulns)),
	}, nil
}

func (h *harborClient) ValidateCompliance(ctx context.Context, in *ComplianceRequest, _ ...grpc.CallOption) (*ComplianceResult, error) {
	overview, err := h.c.GetScanOverview(ctx, in.TargetUri)
	if err != nil {
		return nil, fmt.Errorf("ironbank ValidateCompliance: %w", err)
	}

	// Iron Bank ABC: max 1 Critical (5-day justify), max 4 High (10-day justify).
	passed := overview.Critical <= 1 && overview.High <= 4
	score := 100.0 - float64(overview.Critical)*20.0 - float64(overview.High)*5.0
	if score < 0 {
		score = 0
	}

	return &ComplianceResult{
		TargetUri: in.TargetUri,
		Passed:    passed,
		Score:     score,
		Frameworks: []*FrameworkResult{
			{
				Name:   "IronBank-ABC",
				Passed: passed,
				Score:  score,
				Controls: []*ControlResult{
					{
						ID:       "IB-CVE-CRITICAL",
						Title:    "Critical CVE Tolerance (max 1 justified in 5 days)",
						Passed:   overview.Critical <= 1,
						Severity: "critical",
						Message:  fmt.Sprintf("%d critical CVEs found", overview.Critical),
					},
					{
						ID:       "IB-CVE-HIGH",
						Title:    "High CVE Tolerance (max 4 justified in 10 days)",
						Passed:   overview.High <= 4,
						Severity: "high",
						Message:  fmt.Sprintf("%d high CVEs found", overview.High),
					},
				},
			},
		},
		Timestamp: time.Now().Unix(),
	}, nil
}

func (h *harborClient) GetSBOM(ctx context.Context, in *SBOMRequest, _ ...grpc.CallOption) (*SBOM, error) {
	content, err := h.c.GetSBOM(ctx, in.TargetUri, in.Format)
	if err != nil {
		return nil, fmt.Errorf("ironbank GetSBOM: %w", err)
	}

	return &SBOM{
		TargetUri: in.TargetUri,
		Format:    in.Format,
		Content:   content,
		Timestamp: time.Now().Unix(),
	}, nil
}

func (h *harborClient) BatchScan(ctx context.Context, in *BatchScanRequest, _ ...grpc.CallOption) (IronBankScanner_BatchScanClient, error) {
	results := make([]*BatchScanResponse, 0, len(in.Requests))
	for _, req := range in.Requests {
		resp, err := h.Scan(ctx, req)
		entry := &BatchScanResponse{Result: resp}
		if err != nil {
			entry.Error = err.Error()
		}
		results = append(results, entry)
	}
	return &batchScanStream{results: results}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch streaming client
// ─────────────────────────────────────────────────────────────────────────────

type batchScanStream struct {
	grpc.ClientStream
	results []*BatchScanResponse
	pos     int
}

func (b *batchScanStream) Recv() (*BatchScanResponse, error) {
	if b.pos >= len(b.results) {
		return nil, io.EOF
	}
	r := b.results[b.pos]
	b.pos++
	return r, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func harborVulnsToPB(harborVulns []*ironbank.HarborVulnerability) []*Vulnerability {
	out := make([]*Vulnerability, 0, len(harborVulns))
	for _, v := range harborVulns {
		out = append(out, &Vulnerability{
			ID:          v.ID,
			Package:     v.Package,
			Version:     v.Version,
			Severity:    v.Severity,
			CVSS:        v.CVSS3Score,
			Description: v.Description,
			FixVersion:  v.FixVersion,
			References:  v.Links,
		})
	}
	return out
}

var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"none":     0,
	"unknown":  0,
}

func filterBySeverity(vulns []*Vulnerability, minSeverity string) []*Vulnerability {
	minRank := severityRank[strings.ToLower(minSeverity)]
	out := make([]*Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if severityRank[strings.ToLower(v.Severity)] >= minRank {
			out = append(out, v)
		}
	}
	return out
}
