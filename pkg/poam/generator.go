package poam

import (
	"fmt"
	"sort"
	"time"
)

// ─── Generator ────────────────────────────────────────────────────────────────

// FindingInput is a minimal interface for passing scan findings to the generator
// without importing pkg/stig (avoiding circular deps).
type FindingInput struct {
	ID          string
	Description string
	Severity    Severity
	Status      string   // "Fail" triggers a POAM item
	Remediation string
}

// GenerateFromFindings builds a dollar-weighted, priority-sorted POAM register
// from a slice of scan findings. Only findings with Status == "Fail" are included.
//
// systemName: used for the Register.System field
// severityTable: pass nil to use DefaultSeverityTable
func GenerateFromFindings(systemName string, findings []FindingInput, severityTable map[Severity]SeverityConfig) *Register {
	if severityTable == nil {
		severityTable = DefaultSeverityTable
	}

	reg := &Register{
		System:      systemName,
		GeneratedAt: time.Now(),
		Items:       []Item{},
	}

	counter := 1
	year := time.Now().Year()

	for _, f := range findings {
		if f.Status != "Fail" {
			continue
		}

		cfg, ok := severityTable[f.Severity]
		if !ok {
			cfg = DefaultSeverityConfig
		}

		priorityScore := 0.0
		if cfg.Days > 0 {
			priorityScore = (cfg.Cost / float64(cfg.Days)) * cfg.Weight
		}

		dueDate := time.Now().Add(time.Duration(cfg.Days) * 24 * time.Hour)

		reg.Items = append(reg.Items, Item{
			ID:                  fmt.Sprintf("POAM-%d-%03d", year, counter),
			ControlID:           f.ID,
			Weakness:            f.Description,
			Severity:            f.Severity,
			Status:              "Open",
			PointOfContact:      "ISSM",
			EstimatedCost:       cfg.Cost,
			ScheduledCompletion: dueDate,
			MilestoneActions:    []string{f.Remediation},
			DollarImpact:        cfg.Cost,
			SeverityWeight:      cfg.Weight,
			PriorityScore:       priorityScore,
			EstimatedDays:       cfg.Days,
		})
		counter++
	}

	// Sort: highest PriorityScore first
	sort.Slice(reg.Items, func(i, j int) bool {
		return reg.Items[i].PriorityScore > reg.Items[j].PriorityScore
	})

	// Compute total exposure
	for _, item := range reg.Items {
		reg.TotalExposure += item.DollarImpact
	}

	return reg
}

// UpdateItemStatus updates the status of a POAM item by ID.
// If status is "Completed", sets ClosedAt to now.
// Returns true if the item was found and updated.
func (r *Register) UpdateItemStatus(itemID, status string, evidenceRef string) bool {
	for i, item := range r.Items {
		if item.ID == itemID {
			r.Items[i].Status = status
			if status == "Completed" {
				now := time.Now()
				r.Items[i].ClosedAt = &now
			}
			if evidenceRef != "" {
				r.Items[i].EvidenceRefs = append(r.Items[i].EvidenceRefs, evidenceRef)
			}
			return true
		}
	}
	return false
}

// Summary returns a breakdown of POAM items by severity and status.
func (r *Register) Summary() RegisterSummary {
	s := RegisterSummary{
		TotalItems:    len(r.Items),
		TotalExposure: r.TotalExposure,
	}
	for _, item := range r.Items {
		switch item.Severity {
		case SeverityCAT1, SeverityCritical:
			s.CAT1Count++
		case SeverityCAT2, SeverityHigh:
			s.CAT2Count++
		default:
			s.CAT3Count++
		}
		switch item.Status {
		case "Open":
			s.Open++
		case "In Progress":
			s.InProgress++
		case "Completed":
			s.Completed++
		case "Risk Accepted":
			s.RiskAccepted++
		}
	}
	return s
}

// RegisterSummary is the aggregate view of a POAM register.
type RegisterSummary struct {
	TotalItems    int
	TotalExposure float64
	CAT1Count     int
	CAT2Count     int
	CAT3Count     int
	Open          int
	InProgress    int
	Completed     int
	RiskAccepted  int
}
