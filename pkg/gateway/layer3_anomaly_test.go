package gateway

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnomalyLayer_FeatureExtraction(t *testing.T) {
	cfg := &AnomalyConfig{
		Enabled:                  true,
		LearningMode:             false,
		BlockThreshold:           0.9,
		AlertThreshold:           0.7,
		ChallengeThreshold:       0.5,
		EnableBehavioralAnalysis: true,
		EnableGeoVelocity:        true,
		BaselineUpdateInterval:   time.Hour,
	}

	anomaly, err := NewAnomalyLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create anomaly layer: %v", err)
	}

	identity := &Identity{
		ID:           "test-user",
		Type:         "api_key",
		Organization: "test-org",
		TrustScore:   0.8,
	}

	req := httptest.NewRequest("POST", "/api/users?page=1&limit=10", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "TestClient/1.0")
	req.ContentLength = 256
	req.RemoteAddr = "192.168.1.100:12345"

	features := anomaly.extractFeatures(req, identity)

	// Verify features
	if features.Method != "POST" {
		t.Errorf("Expected method POST, got %s", features.Method)
	}
	if features.PathDepth != 2 { // /api/users = 2 slashes
		t.Errorf("Expected path depth 2, got %d", features.PathDepth)
	}
	if features.QueryParamCount != 2 {
		t.Errorf("Expected 2 query params, got %d", features.QueryParamCount)
	}
	if features.BodySizeBytes != 256 {
		t.Errorf("Expected body size 256, got %d", features.BodySizeBytes)
	}
	if features.IdentityID != "test-user" {
		t.Errorf("Expected identity test-user, got %s", features.IdentityID)
	}
	if features.TrustScore != 0.8 {
		t.Errorf("Expected trust score 0.8, got %f", features.TrustScore)
	}
	if features.ContentType != "application/json" {
		t.Errorf("Expected content type application/json, got %s", features.ContentType)
	}
}

func TestAnomalyLayer_GeoVelocityDetection(t *testing.T) {
	cfg := &AnomalyConfig{
		Enabled:           true,
		EnableGeoVelocity: true,
	}

	anomaly, err := NewAnomalyLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create anomaly layer: %v", err)
	}

	identityID := "velocity-test-user"

	// First request from USA
	features1 := RequestFeatures{
		Timestamp:  time.Now(),
		IdentityID: identityID,
		GeoCountry: "US",
		GeoCity:    "New York",
	}

	score1 := anomaly.checkGeoVelocity(identityID, features1)
	if score1 != 0.0 {
		t.Errorf("First request should have 0 geo-velocity score, got %f", score1)
	}

	// Second request from US (same country) shortly after - should be fine
	features2 := RequestFeatures{
		Timestamp:  time.Now().Add(10 * time.Minute),
		IdentityID: identityID,
		GeoCountry: "US",
		GeoCity:    "Los Angeles",
	}

	score2 := anomaly.checkGeoVelocity(identityID, features2)
	if score2 != 0.0 {
		t.Errorf("Same country request should have 0 score, got %f", score2)
	}

	// Third request from Russia 30 minutes later - impossible travel!
	features3 := RequestFeatures{
		Timestamp:  time.Now().Add(30 * time.Minute),
		IdentityID: identityID,
		GeoCountry: "RU",
		GeoCity:    "Moscow",
	}

	score3 := anomaly.checkGeoVelocity(identityID, features3)
	if score3 < 0.7 {
		t.Errorf("Impossible travel should have high score, got %f", score3)
	}
}

func TestAnomalyLayer_BehaviorProfiling(t *testing.T) {
	cfg := &AnomalyConfig{
		Enabled:                  true,
		EnableBehavioralAnalysis: true,
	}

	anomaly, err := NewAnomalyLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create anomaly layer: %v", err)
	}

	identityID := "behavior-test-user"

	// Build up a behavior profile with consistent patterns
	for i := 0; i < 20; i++ {
		features := RequestFeatures{
			Timestamp:   time.Now(),
			HourOfDay:   10, // Consistent access hour
			Method:      "GET",
			ContentType: "application/json",
			IdentityID:  identityID,
		}
		anomaly.updateBehaviorProfile(identityID, features, 0.1)
	}

	// Get the profile
	profile := anomaly.GetBehaviorProfile(identityID)
	if profile == nil {
		t.Fatal("Expected behavior profile to exist")
	}

	if profile.TotalRequests != 20 {
		t.Errorf("Expected 20 requests, got %d", profile.TotalRequests)
	}

	// The common hour should be 10
	if profile.CommonHours[10] != 20 {
		t.Errorf("Expected hour 10 to have 20 requests, got %d", profile.CommonHours[10])
	}
}

func TestAnomalyLayer_LearningMode(t *testing.T) {
	cfg := &AnomalyConfig{
		Enabled:          true,
		LearningMode:     true,
		LearningDuration: 24 * time.Hour,
	}

	anomaly, err := NewAnomalyLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create anomaly layer: %v", err)
	}

	identity := &Identity{
		ID:   "learning-test",
		Type: "api_key",
	}

	// In learning mode, requests should be allowed (low score)
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "10.0.0.1:1234"

	score, err := anomaly.Analyze(req, identity)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// Learning mode should return validation result with valid=true
	if score > 0.5 {
		t.Errorf("Learning mode should have low anomaly score, got %f", score)
	}
}

func TestAnomalyLayer_LocalAnalysis(t *testing.T) {
	cfg := &AnomalyConfig{
		Enabled:           true,
		LearningMode:      false,
		BlockThreshold:    0.9,
		AlertThreshold:    0.7,
		MLServiceEndpoint: "", // No ML service - use local analysis
	}

	anomaly, err := NewAnomalyLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create anomaly layer: %v", err)
	}

	// With no baseline data (< 100 samples), should return permissive score
	features := RequestFeatures{
		Timestamp:     time.Now(),
		Method:        "GET",
		PathDepth:     2,
		BodySizeBytes: 100,
	}

	score := anomaly.localAnomalyAnalysis(features)
	if score > 0.5 {
		t.Errorf("With no baseline, score should be permissive, got %f", score)
	}
}

func TestAnomalyLayer_BaselineStatistics(t *testing.T) {
	cfg := &AnomalyConfig{
		Enabled:                true,
		LearningMode:           true,
		LearningDuration:       time.Hour,
		BaselineUpdateInterval: time.Minute,
	}

	anomaly, err := NewAnomalyLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create anomaly layer: %v", err)
	}

	// Add learning data manually
	for i := 0; i < 150; i++ {
		features := RequestFeatures{
			Timestamp:     time.Now(),
			HourOfDay:     i % 24,
			DayOfWeek:     i % 7,
			Method:        "GET",
			BodySizeBytes: int64(100 + i%50),
		}
		anomaly.baselineMu.Lock()
		anomaly.learningData = append(anomaly.learningData, features)
		anomaly.baselineMu.Unlock()
	}

	// Trigger baseline update
	anomaly.updateBaseline()

	baseline := anomaly.GetBaseline()
	if baseline.SampleCount != 150 {
		t.Errorf("Expected 150 samples, got %d", baseline.SampleCount)
	}

	if baseline.AvgBodySize == 0 {
		t.Error("Expected non-zero average body size")
	}

	if _, ok := baseline.CommonMethods["GET"]; !ok {
		t.Error("Expected GET in common methods")
	}
}

func TestAnomalyLayer_PathDepthCalculation(t *testing.T) {
	tests := []struct {
		path     string
		expected int
	}{
		{"/", 1},
		{"/api", 1},
		{"/api/users", 2},
		{"/api/users/123", 3},
		{"/api/v1/users/123/posts", 5},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			depth := countPathDepth(tt.path)
			if depth != tt.expected {
				t.Errorf("Path %s: expected depth %d, got %d", tt.path, tt.expected, depth)
			}
		})
	}
}

func TestAnomalyLayer_Sigmoid(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
		delta    float64
	}{
		{0, 0.5, 0.01},
		{-10, 0, 0.01},
		{10, 1, 0.01},
		{2, 0.88, 0.05},
	}

	for _, tt := range tests {
		result := sigmoid(tt.input)
		if result < tt.expected-tt.delta || result > tt.expected+tt.delta {
			t.Errorf("sigmoid(%f) = %f, expected ~%f", tt.input, result, tt.expected)
		}
	}
}

func TestAnomalyLayer_GetStats(t *testing.T) {
	cfg := &AnomalyConfig{
		Enabled:          true,
		LearningMode:     true,
		LearningDuration: time.Hour,
	}

	anomaly, err := NewAnomalyLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create anomaly layer: %v", err)
	}

	// Populate some data
	for i := 0; i < 10; i++ {
		anomaly.updateBehaviorProfile("user-"+string(rune('a'+i)), RequestFeatures{}, 0.1)
	}

	// Get stats (would come from GetBaseline and behavior profiles)
	baseline := anomaly.GetBaseline()
	if baseline.SampleCount < 0 {
		t.Error("Sample count should not be negative")
	}

	profile := anomaly.GetBehaviorProfile("user-a")
	if profile == nil {
		t.Error("Expected profile to exist")
	}
}

func BenchmarkAnomalyAnalysis(b *testing.B) {
	cfg := &AnomalyConfig{
		Enabled:                  true,
		LearningMode:             false,
		EnableBehavioralAnalysis: true,
		EnableGeoVelocity:        true,
		BlockThreshold:           0.9,
	}

	anomaly, _ := NewAnomalyLayer(cfg)

	identity := &Identity{
		ID:         "bench-user",
		Type:       "api_key",
		TrustScore: 0.8,
	}

	req := httptest.NewRequest("GET", "/api/users?page=1", nil)
	req.Header.Set("User-Agent", "BenchClient/1.0")
	req.RemoteAddr = "10.0.0.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		anomaly.Analyze(req, identity)
	}
}

func BenchmarkGeoVelocityCheck(b *testing.B) {
	cfg := &AnomalyConfig{
		Enabled:           true,
		EnableGeoVelocity: true,
	}

	anomaly, _ := NewAnomalyLayer(cfg)

	features := RequestFeatures{
		Timestamp:  time.Now(),
		IdentityID: "bench-user",
		GeoCountry: "US",
		GeoCity:    "New York",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		anomaly.checkGeoVelocity("bench-user", features)
	}
}
