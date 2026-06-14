package arsenal

import (
	"encoding/json"
	"fmt"
	"os"
)

// DetectSecretsOutput represents the report from Yelp/detect-secrets
// Structure is a map of filename -> slice of findings.
//
//	{
//	   "files/config.py": [
//	       { "type": "Secret Keyword", "hashed_secret": "...", "line_number": 12 }
//	   ]
//	}
type DetectSecretsResult struct {
	Type         string `json:"type"`
	HashedSecret string `json:"hashed_secret"`
	LineNumber   int    `json:"line_number"`
}

func ParseDetectSecrets(path string) (map[string][]DetectSecretsResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid detect-secrets json: %v", err)
	}

	// The "results" key is often where findings are, or sometimes top level depending on version.
	// Standard output: { "results": { "file.py": [...] }, "version": "..." }

	findings := make(map[string][]DetectSecretsResult)

	resultsData, ok := raw["results"]
	if !ok {
		// Fallback: maybe the root itself is the map if older version?
		// But usually it has a schema. Let's assume standard "results" key.
		return nil, fmt.Errorf("detect-secrets report missing 'results' key")
	}

	// Re-marshal results block to handle the map[string][]struct structure cleanly
	// manual traversal is painful.
	resultsJSON, _ := json.Marshal(resultsData)
	if err := json.Unmarshal(resultsJSON, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse findings block: %v", err)
	}

	return findings, nil
}
