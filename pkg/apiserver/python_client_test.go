package apiserver

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestPythonPing attempts to talk to the local python service
// Skips if the Python service isn't running (integration test)
func TestPythonPing(t *testing.T) {
	// Skip if PYTHON_SERVICE_URL not set or service not available
	serviceURL := os.Getenv("PYTHON_SERVICE_URL")
	if serviceURL == "" {
		serviceURL = "http://localhost:8000"
	}

	// Quick connectivity check - skip if service not available
	conn, err := net.DialTimeout("tcp", "localhost:8000", 2*time.Second)
	if err != nil {
		t.Skipf("Skipping Python service test - service not available: %v", err)
	}
	conn.Close()

	client := NewPythonServiceClient(serviceURL)

	// 1. Check Soul
	soul, err := client.GetSoulStatus()
	if err != nil {
		t.Fatalf("Failed to get soul status: %v", err)
	}
	fmt.Printf("Soul Status: %v\n", soul)

	// 2. Get Intuition (Mock Features)
	features := make([]float64, 32) // 32 dim zero vector
	prediction, err := client.GetIntuition(features, nil)
	if err != nil {
		t.Fatalf("Failed to get intuition: %v", err)
	}
	fmt.Printf("Intuition: Score=%.4f, Anomaly=%v, Trait=%v\n",
		prediction.AnomalyScore,
		prediction.IsAnomaly,
		prediction.ArchetypeInfluence)
}
