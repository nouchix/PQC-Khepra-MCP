// Layer 3: Anomaly Detection - ML-Powered Threat Analysis
// "The Mind of Thoth Perceives the Hidden"
//
// This layer integrates with PyTorch-based ML service for behavioral analysis
// and anomaly detection. It learns and evolves with each request processed.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sync"
	"time"
)

// AnomalyLayer implements Layer 3 ML-powered anomaly detection
type AnomalyLayer struct {
	config *AnomalyConfig

	// ML Service client
	mlClient *http.Client

	// Local baseline (for fallback when ML service unavailable)
	baseline     *RequestBaseline
	baselineMu   sync.RWMutex
	learningData []RequestFeatures

	// Behavioral tracking per identity
	behaviorProfiles   map[string]*BehaviorProfile
	behaviorProfilesMu sync.RWMutex

	// Geo-velocity tracking
	geoHistory   map[string][]GeoEvent
	geoHistoryMu sync.RWMutex
}

// RequestFeatures extracted from each request for ML analysis
type RequestFeatures struct {
	// Timing features
	Timestamp     time.Time `json:"timestamp"`
	HourOfDay     int       `json:"hour_of_day"`
	DayOfWeek     int       `json:"day_of_week"`
	RequestRateHz float64   `json:"request_rate_hz"`

	// Request characteristics
	Method          string `json:"method"`
	PathDepth       int    `json:"path_depth"`
	QueryParamCount int    `json:"query_param_count"`
	BodySizeBytes   int64  `json:"body_size_bytes"`
	HeaderCount     int    `json:"header_count"`
	ContentType     string `json:"content_type"`
	UserAgentHash   string `json:"user_agent_hash"`

	// Identity features
	IdentityID   string  `json:"identity_id"`
	IdentityType string  `json:"identity_type"`
	TrustScore   float64 `json:"trust_score"`
	Organization string  `json:"organization"`

	// Network features
	ClientIP     string `json:"client_ip"`
	GeoCountry   string `json:"geo_country"`
	GeoCity      string `json:"geo_city"`
	ASN          int    `json:"asn"`
	IsProxy      bool   `json:"is_proxy"`
	IsTor        bool   `json:"is_tor"`
	IsDatacenter bool   `json:"is_datacenter"`

	// Behavioral features
	SessionDuration     float64 `json:"session_duration_sec"`
	RequestsInSession   int     `json:"requests_in_session"`
	UniquePathsAccessed int     `json:"unique_paths_accessed"`
	ErrorRate           float64 `json:"error_rate"`

	// Payload analysis
	PayloadEntropy     float64 `json:"payload_entropy"`
	HasSuspiciousChars bool    `json:"has_suspicious_chars"`
	JSONDepth          int     `json:"json_depth"`
}

// RequestBaseline represents learned normal behavior
type RequestBaseline struct {
	// Statistical baselines
	AvgRequestsPerMinute float64
	StdRequestsPerMinute float64
	AvgBodySize          float64
	StdBodySize          float64
	AvgPathDepth         float64

	// Time patterns
	HourlyDistribution [24]float64
	DailyDistribution  [7]float64

	// Common patterns
	CommonMethods      map[string]float64
	CommonPaths        map[string]float64
	CommonUserAgents   map[string]float64
	CommonContentTypes map[string]float64

	// Last updated
	LastUpdated time.Time
	SampleCount int64
}

// BehaviorProfile tracks per-identity behavioral patterns
type BehaviorProfile struct {
	IdentityID      string
	FirstSeen       time.Time
	LastSeen        time.Time
	TotalRequests   int64
	AvgRequestRate  float64
	CommonPaths     map[string]int
	CommonHours     [24]int
	LastGeoLocation string
	RiskScore       float64
	Anomalies       []AnomalyEvent
}

// GeoEvent tracks geographic access for velocity checks
type GeoEvent struct {
	Timestamp time.Time
	Country   string
	City      string
	Latitude  float64
	Longitude float64
}

// AnomalyEvent records detected anomalies
type AnomalyEvent struct {
	Timestamp   time.Time
	Score       float64
	Type        string
	Description string
	Features    map[string]interface{}
}

// MLAnalysisRequest sent to PyTorch service
type MLAnalysisRequest struct {
	Features     RequestFeatures `json:"features"`
	ModelVersion string          `json:"model_version"`
	RequestID    string          `json:"request_id"`
}

// MLAnalysisResponse from PyTorch service
type MLAnalysisResponse struct {
	AnomalyScore    float64            `json:"anomaly_score"`
	Confidence      float64            `json:"confidence"`
	TopContributors []string           `json:"top_contributors"`
	Recommendations []string           `json:"recommendations"`
	ModelVersion    string             `json:"model_version"`
	LatencyMs       int                `json:"latency_ms"`
	FeatureScores   map[string]float64 `json:"feature_scores"`
}

// NewAnomalyLayer creates a new anomaly detection layer
func NewAnomalyLayer(cfg *AnomalyConfig) (*AnomalyLayer, error) {
	layer := &AnomalyLayer{
		config: cfg,
		mlClient: &http.Client{
			Timeout: cfg.MLServiceTimeout,
		},
		baseline: &RequestBaseline{
			CommonMethods:      make(map[string]float64),
			CommonPaths:        make(map[string]float64),
			CommonUserAgents:   make(map[string]float64),
			CommonContentTypes: make(map[string]float64),
		},
		behaviorProfiles: make(map[string]*BehaviorProfile),
		geoHistory:       make(map[string][]GeoEvent),
		learningData:     make([]RequestFeatures, 0, 10000),
	}

	log.Printf("[ANOMALY] Layer 3 initialized - ML[%s] Learning[%v] Behavioral[%v] GeoVelocity[%v]",
		cfg.MLServiceEndpoint, cfg.LearningMode,
		cfg.EnableBehavioralAnalysis, cfg.EnableGeoVelocity)

	// Start baseline update goroutine
	if cfg.BaselineUpdateInterval > 0 {
		go layer.baselineUpdateLoop()
	}

	return layer, nil
}

// Analyze performs ML-powered anomaly analysis on a request
func (a *AnomalyLayer) Analyze(r *http.Request, identity *Identity) (float64, error) {
	features := a.extractFeatures(r, identity)
	a.handleLearning(features)

	if a.config.MLServiceEndpoint != "" {
		if score, err := a.analyzeWithMLService(features); err == nil {
			a.updateBehaviorProfile(identity.ID, features, score)
			return score, nil
		}
		log.Printf("[ANOMALY] ML service error, falling back to local")
	}

	score := a.runLocalChecks(features, identity.ID)
	a.updateBehaviorProfile(identity.ID, features, score)
	return score, nil
}

func (a *AnomalyLayer) handleLearning(f RequestFeatures) {
	if !a.config.LearningMode {
		return
	}
	a.baselineMu.Lock()
	defer a.baselineMu.Unlock()
	if len(a.learningData) < 10000 {
		a.learningData = append(a.learningData, f)
	}
}

func (a *AnomalyLayer) runLocalChecks(f RequestFeatures, identityID string) float64 {
	score := a.localAnomalyAnalysis(f)

	if a.config.EnableGeoVelocity {
		score = math.Max(score, a.checkGeoVelocity(identityID, f))
	}

	if a.config.EnableBehavioralAnalysis {
		score = (score + a.analyzeBehavior(identityID, f)) / 2
	}

	return score
}

// extractFeatures extracts ML features from the request
func (a *AnomalyLayer) extractFeatures(r *http.Request, identity *Identity) RequestFeatures {
	now := time.Now()

	features := RequestFeatures{
		Timestamp:       now,
		HourOfDay:       now.Hour(),
		DayOfWeek:       int(now.Weekday()),
		Method:          r.Method,
		PathDepth:       countPathDepth(r.URL.Path),
		QueryParamCount: len(r.URL.Query()),
		BodySizeBytes:   r.ContentLength,
		HeaderCount:     len(r.Header),
		ContentType:     r.Header.Get("Content-Type"),
		UserAgentHash:   hashString(r.UserAgent())[:16],
		ClientIP:        getClientIP(r),
	}

	if identity != nil {
		features.IdentityID = identity.ID
		features.IdentityType = identity.Type
		features.TrustScore = identity.TrustScore
		features.Organization = identity.Organization
	}

	// Payload entropy calculation requires buffering the request body before it is
	// consumed by the handler. Use httputil.DumpRequest or middleware body-buffering
	// to capture the bytes, then compute Shannon entropy here.
	if r.Body != nil && r.ContentLength > 0 {
		features.PayloadEntropy = 0
	}

	return features
}

// analyzeWithMLService sends features to PyTorch ML service
func (a *AnomalyLayer) analyzeWithMLService(features RequestFeatures) (float64, error) {
	req := MLAnalysisRequest{
		Features:     features,
		ModelVersion: a.config.ModelVersion,
		RequestID:    fmt.Sprintf("khp-%d", time.Now().UnixNano()),
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.config.MLServiceTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		a.config.MLServiceEndpoint+"/analyze", bytes.NewBuffer(payload))
	if err != nil {
		return 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.mlClient.Do(httpReq)
	if err != nil {
		return 0, fmt.Errorf("ML service request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("ML service returned status: %d", resp.StatusCode)
	}

	var result MLAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, err
	}

	return result.AnomalyScore, nil
}

// localAnomalyAnalysis performs local statistical anomaly detection
func (a *AnomalyLayer) localAnomalyAnalysis(f RequestFeatures) float64 {
	a.baselineMu.RLock()
	defer a.baselineMu.RUnlock()

	if a.baseline.SampleCount < 100 {
		return 0.1
	}

	var indicators []float64
	indicators = append(indicators, a.checkRateAnomaly(f))
	indicators = append(indicators, a.checkSizeAnomaly(f))
	indicators = append(indicators, a.checkTimeAnomaly(f))
	indicators = append(indicators, a.checkMethodAnomaly(f))

	sum := 0.0
	for _, s := range indicators {
		sum += s
	}
	return sum / float64(len(indicators))
}

func (a *AnomalyLayer) checkRateAnomaly(f RequestFeatures) float64 {
	if a.baseline.StdRequestsPerMinute <= 0 {
		return 0
	}
	z := math.Abs(f.RequestRateHz*60-a.baseline.AvgRequestsPerMinute) / a.baseline.StdRequestsPerMinute
	return sigmoid(z - 2)
}

func (a *AnomalyLayer) checkSizeAnomaly(f RequestFeatures) float64 {
	if a.baseline.StdBodySize <= 0 || f.BodySizeBytes <= 0 {
		return 0
	}
	z := math.Abs(float64(f.BodySizeBytes)-a.baseline.AvgBodySize) / a.baseline.StdBodySize
	return sigmoid(z - 3)
}

func (a *AnomalyLayer) checkTimeAnomaly(f RequestFeatures) float64 {
	if a.baseline.HourlyDistribution[f.HourOfDay] < 0.01 {
		return 0.7
	}
	return 0
}

func (a *AnomalyLayer) checkMethodAnomaly(f RequestFeatures) float64 {
	if freq, ok := a.baseline.CommonMethods[f.Method]; ok {
		if freq < 0.01 {
			return 0.5
		}
		return 0
	}
	return 0.6
}

// checkGeoVelocity detects impossible travel patterns
func (a *AnomalyLayer) checkGeoVelocity(identityID string, features RequestFeatures) float64 {
	a.geoHistoryMu.Lock()
	defer a.geoHistoryMu.Unlock()

	history := a.geoHistory[identityID]
	newEvent := GeoEvent{
		Timestamp: features.Timestamp,
		Country:   features.GeoCountry,
		City:      features.GeoCity,
		// Latitude/Longitude would come from GeoIP lookup
	}

	// Add new event
	history = append(history, newEvent)

	// Keep only last 24 hours
	cutoff := time.Now().Add(-24 * time.Hour)
	filtered := make([]GeoEvent, 0)
	for _, e := range history {
		if e.Timestamp.After(cutoff) {
			filtered = append(filtered, e)
		}
	}
	a.geoHistory[identityID] = filtered

	if len(filtered) < 2 {
		return 0.0
	}

	// Check for impossible travel
	prev := filtered[len(filtered)-2]
	curr := filtered[len(filtered)-1]

	// If country changed in less than 1 hour, flag as suspicious
	if prev.Country != curr.Country && prev.Country != "" && curr.Country != "" {
		timeDiff := curr.Timestamp.Sub(prev.Timestamp)
		if timeDiff < time.Hour {
			log.Printf("[ANOMALY] Geo-velocity alert: %s -> %s in %v",
				prev.Country, curr.Country, timeDiff)
			return 0.95 // High anomaly score
		}
		if timeDiff < 4*time.Hour {
			return 0.7 // Moderate anomaly
		}
	}

	return 0.0
}

// analyzeBehavior performs behavioral analysis against profile
func (a *AnomalyLayer) analyzeBehavior(identityID string, features RequestFeatures) float64 {
	a.behaviorProfilesMu.RLock()
	profile, exists := a.behaviorProfiles[identityID]
	a.behaviorProfilesMu.RUnlock()

	if !exists || profile.TotalRequests < 10 {
		// New identity, can't do behavioral analysis
		return 0.2
	}

	var anomalyScore float64

	// Check if accessing unusual paths
	if profile.CommonPaths != nil {
		pathKey := features.Method + ":" + features.ContentType
		if _, common := profile.CommonPaths[pathKey]; !common {
			anomalyScore += 0.3
		}
	}

	// Check unusual access time
	hourCount := profile.CommonHours[features.HourOfDay]
	totalHourCount := 0
	for _, c := range profile.CommonHours {
		totalHourCount += c
	}
	if totalHourCount > 0 {
		hourRatio := float64(hourCount) / float64(totalHourCount)
		if hourRatio < 0.01 {
			anomalyScore += 0.2
		}
	}

	// Check request rate spike
	expectedRate := profile.AvgRequestRate
	if features.RequestRateHz > expectedRate*5 {
		anomalyScore += 0.4
	}

	return math.Min(anomalyScore, 1.0)
}

// updateBehaviorProfile updates the behavioral profile for an identity
func (a *AnomalyLayer) updateBehaviorProfile(identityID string, features RequestFeatures, anomalyScore float64) {
	a.behaviorProfilesMu.Lock()
	defer a.behaviorProfilesMu.Unlock()

	profile, exists := a.behaviorProfiles[identityID]
	if !exists {
		profile = &BehaviorProfile{
			IdentityID:  identityID,
			FirstSeen:   time.Now(),
			CommonPaths: make(map[string]int),
		}
		a.behaviorProfiles[identityID] = profile
	}

	profile.LastSeen = time.Now()
	profile.TotalRequests++
	profile.CommonHours[features.HourOfDay]++

	pathKey := features.Method + ":" + features.ContentType
	profile.CommonPaths[pathKey]++

	// Update risk score (exponential moving average)
	alpha := 0.1
	profile.RiskScore = alpha*anomalyScore + (1-alpha)*profile.RiskScore

	// Record anomaly if above alert threshold
	if anomalyScore >= a.config.AlertThreshold {
		profile.Anomalies = append(profile.Anomalies, AnomalyEvent{
			Timestamp:   time.Now(),
			Score:       anomalyScore,
			Type:        "behavioral",
			Description: fmt.Sprintf("Anomaly detected: score=%.2f", anomalyScore),
		})
	}
}

// baselineUpdateLoop periodically updates the baseline
func (a *AnomalyLayer) baselineUpdateLoop() {
	ticker := time.NewTicker(a.config.BaselineUpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		a.updateBaseline()
	}
}

// updateBaseline recalculates the statistical baseline
func (a *AnomalyLayer) updateBaseline() {
	a.baselineMu.Lock()
	defer a.baselineMu.Unlock()

	if len(a.learningData) < 100 {
		return
	}

	// Calculate statistics
	var bodySum, bodySquaredSum float64
	methodCounts := make(map[string]int)
	hourCounts := [24]int{}

	for _, f := range a.learningData {
		bodySum += float64(f.BodySizeBytes)
		bodySquaredSum += float64(f.BodySizeBytes * f.BodySizeBytes)
		methodCounts[f.Method]++
		hourCounts[f.HourOfDay]++
	}

	n := float64(len(a.learningData))
	a.baseline.AvgBodySize = bodySum / n
	a.baseline.StdBodySize = math.Sqrt(bodySquaredSum/n - a.baseline.AvgBodySize*a.baseline.AvgBodySize)

	// Normalize method frequencies
	for method, count := range methodCounts {
		a.baseline.CommonMethods[method] = float64(count) / n
	}

	// Normalize hour distribution
	for i, count := range hourCounts {
		a.baseline.HourlyDistribution[i] = float64(count) / n
	}

	a.baseline.SampleCount = int64(len(a.learningData))
	a.baseline.LastUpdated = time.Now()

	log.Printf("[ANOMALY] Baseline updated: %d samples, avg_body=%.0f, std_body=%.0f",
		a.baseline.SampleCount, a.baseline.AvgBodySize, a.baseline.StdBodySize)
}

// GetBehaviorProfile returns a copy of an identity's behavior profile
func (a *AnomalyLayer) GetBehaviorProfile(identityID string) *BehaviorProfile {
	a.behaviorProfilesMu.RLock()
	defer a.behaviorProfilesMu.RUnlock()

	if profile, exists := a.behaviorProfiles[identityID]; exists {
		// Return a copy
		copy := *profile
		return &copy
	}
	return nil
}

// GetBaseline returns the current baseline statistics
func (a *AnomalyLayer) GetBaseline() RequestBaseline {
	a.baselineMu.RLock()
	defer a.baselineMu.RUnlock()
	return *a.baseline
}

// Helper functions

func countPathDepth(path string) int {
	depth := 0
	for _, c := range path {
		if c == '/' {
			depth++
		}
	}
	return depth
}

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func hashString(s string) string {
	// Simple hash for feature extraction
	h := uint64(0)
	for _, c := range s {
		h = h*31 + uint64(c)
	}
	return fmt.Sprintf("%016x", h)
}
