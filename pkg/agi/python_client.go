package agi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MotherboardClient handles communication with the SouHimBou ML (Python) service.
// This is a local copy of apiserver.PythonServiceClient — duplicated to break the
// circular import:  pkg/agi → pkg/apiserver → pkg/sekhem → pkg/agi.
//
// The concrete apiserver.PythonServiceClient satisfies the pythonCaller interface
// via an adapter (see pkg/apiserver/integration.go or the main binary wiring):
//
//	engine.SetPythonCaller(agi.NewMotherboardClient("http://localhost:8000"))
type MotherboardClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewMotherboardClient creates a new ML service client.
func NewMotherboardClient(baseURL string) *MotherboardClient {
	return &MotherboardClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// predictRequest is the payload sent to the ML service.
type predictRequest struct {
	Features []float64         `json:"features"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// GetIntuition queries the ML service for an anomaly prediction.
// It satisfies the pythonCaller interface.
func (c *MotherboardClient) GetIntuition(features []float64, metadata map[string]string) (*PredictResponse, error) {
	reqBody := predictRequest{
		Features: features,
		Metadata: metadata,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("agi: motherboard marshal: %w", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/predict", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("agi: motherboard unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agi: motherboard returned %s", resp.Status)
	}

	var result PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("agi: motherboard decode: %w", err)
	}

	return &result, nil
}
