package arsenal

import (
	"fmt"
	"os/exec"
)

// Tool represents an external security capability
type Tool struct {
	Name        string
	Binary      string
	Description string
	Category    string // Recon, Exploitation, Web
	Present     bool
	Path        string
}

// Inventory is the collection of known tools
type Inventory struct {
	Tools map[string]*Tool
}

// NewInventory initializes the arsenal
func NewInventory() *Inventory {
	inv := &Inventory{
		Tools: make(map[string]*Tool),
	}

	// Define Standard Arsenal
	inv.Add("Nmap", "nmap", "Network Mapper", "Recon")
	inv.Add("Metasploit", "msfconsole", "Exploitation Framework", "Exploitation")
	inv.Add("SQLMap", "sqlmap", "Automated SQL Injection", "Web")
	inv.Add("Docker", "docker", "Container Runtime (for heavy tools)", "Infrastructure")

	// Check presence
	inv.ScanEnvironment()
	return inv
}

func (inv *Inventory) Add(name, binary, desc, cat string) {
	inv.Tools[name] = &Tool{
		Name: name, Binary: binary, Description: desc, Category: cat,
	}
}

// ScanEnvironment checks PATH for tool binaries
func (inv *Inventory) ScanEnvironment() {
	for _, t := range inv.Tools {
		path, err := exec.LookPath(t.Binary)
		if err == nil {
			t.Present = true
			t.Path = path
		} else {
			t.Present = false
		}
	}
}

// ReportGaps returns a string summarizing missing tools
func (inv *Inventory) ReportGaps() string {
	var missing []string
	for _, t := range inv.Tools {
		if !t.Present {
			missing = append(missing, t.Name)
		}
	}

	if len(missing) == 0 {
		return "ARSENAL STATUS: FULLY OPERATIONAL. All standard tools detected."
	}
	return fmt.Sprintf("ARSENAL GAPS DETECTED: The following tools are missing from the SCIF/Environment:\n- %s\n\nRecommendation: Install these binaries or provide Docker access to 'Commando Mode'.", missing)
}
