package apiserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PythonServiceClient handles communication with the SouHimBou ML Service
type PythonServiceClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewPythonServiceClient creates a new client
func NewPythonServiceClient(baseURL string) *PythonServiceClient {
	return &PythonServiceClient{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// PredictRequest represents the payload sent to the ML service
type PredictRequest struct {
	Features []float64         `json:"features"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PredictResponse represents the intuition returned by the ML service
type PredictResponse struct {
	AnomalyScore       float64            `json:"anomaly_score"`
	IsAnomaly          bool               `json:"is_anomaly"`
	Confidence         float64            `json:"confidence"`
	ArchetypeInfluence map[string]float64 `json:"archetype_influence"`
}

// GetIntuition queries the ML service for an anomaly prediction
func (c *PythonServiceClient) GetIntuition(features []float64, metadata map[string]string) (*PredictResponse, error) {
	reqBody := PredictRequest{
		Features: features,
		Metadata: metadata,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/predict", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to contact python service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("python service returned error: %s", resp.Status)
	}

	var result PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// GetSoulStatus returns the current soul embedding from the service
func (c *PythonServiceClient) GetSoulStatus() (map[string]interface{}, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/soul")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
