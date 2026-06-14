package config

import (
	"os"
	"strconv"
)

type Config struct {
	ExternalIP      string
	SSHExternalPort int
	AgentListenPort int
	Username        string
	Tenant          string
	Comment         string
	RotateDays      int
	RepoSSH         string
	RepoName        string
	GitEmail        string
	// Storage (ECR-01: Kubernetes Persistent Volume Support)
	StoragePath string
	// LLM
	LLMProvider      string
	LLMModel         string
	LLMUrl           string
	LLMApiKey        string
	TailscaleAuthKey string
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func getenvInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func Load() Config {
	return Config{
		ExternalIP:      getenv("ADINKHEPRA_EXTERNAL_IP", "127.0.0.1"),
		SSHExternalPort: getenvInt("ADINKHEPRA_SSH_PORT", 22),
		AgentListenPort: getenvInt("ADINKHEPRA_AGENT_PORT", 45444),
		Username:        getenv("ADINKHEPRA_USER", "adinkhepra"),
		Tenant:          getenv("ADINKHEPRA_TENANT", "adinkhepra://edge-node-1"),
		Comment:         getenv("ADINKHEPRA_COMMENT", "skone@alumni.albany.edu eban:prod nkyinkyim:v1"),
		RotateDays:      getenvInt("ADINKHEPRA_ROTATE_DAYS", 90),
		RepoSSH:         getenv("ADINKHEPRA_REPO_SSH", "git@github.com:EtherVerseCodeMate/giza-cyber-shield.git"),
		RepoName:        getenv("ADINKHEPRA_REPO_NAME", "EtherVerseCodeMate/giza-cyber-shield"),
		GitEmail:        getenv("ADINKHEPRA_GIT_EMAIL", "skone@alumni.albany.edu"),
		// Storage Configuration (ECR-01: DoD Persistent Volume Compliance)
		// In Kubernetes StatefulSet deployments, set ADINKHEPRA_STORAGE_PATH=/var/lib/adinkhepra/data
		// For development/binary deployments, defaults to ./data
		StoragePath: getenv("ADINKHEPRA_STORAGE_PATH", "./data"),
		// LLM Configuration
		LLMProvider: getenv("ADINKHEPRA_LLM_PROVIDER", "ollama"),
		LLMModel:    getenv("ADINKHEPRA_LLM_MODEL", "phi4"),
		LLMUrl:      getenv("ADINKHEPRA_LLM_URL", "http://localhost:11434"),
		LLMApiKey:   getenv("ADINKHEPRA_LLM_API_KEY", ""),
		// Tailscale Configuration
		TailscaleAuthKey: getenv("TAILSCALE_AUTH_KEY", ""),
	}
}
