package sbom

// SBOMDiff represents the difference between two SBOMs
type SBOMDiff struct {
	Added   []Component        `json:"added"`
	Removed []Component        `json:"removed"`
	Updated []ComponentUpdate  `json:"updated"`
}

// ComponentUpdate represents a component version change
type ComponentUpdate struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

// ComputeDiff computes the difference between two SBOMs
func (sg *SBOMGenerator) ComputeDiff(old, new *SBOM) *SBOMDiff {
	diff := &SBOMDiff{
		Added:   make([]Component, 0),
		Removed: make([]Component, 0),
		Updated: make([]ComponentUpdate, 0),
	}

	// Build maps for easy lookup
	oldMap := make(map[string]Component)
	newMap := make(map[string]Component)

	for _, comp := range old.Components {
		key := comp.Name + "@" + comp.Version
		oldMap[key] = comp
	}

	for _, comp := range new.Components {
		key := comp.Name + "@" + comp.Version
		newMap[key] = comp
	}

	// Find added and updated
	newNames := make(map[string]Component)
	for _, comp := range new.Components {
		newNames[comp.Name] = comp
	}

	for name, newComp := range newNames {
		foundOld := false
		for _, oldComp := range old.Components {
			if oldComp.Name == name {
				foundOld = true
				if oldComp.Version != newComp.Version {
					diff.Updated = append(diff.Updated, ComponentUpdate{
						Name:       name,
						OldVersion: oldComp.Version,
						NewVersion: newComp.Version,
					})
				}
				break
			}
		}
		if !foundOld {
			diff.Added = append(diff.Added, newComp)
		}
	}

	// Find removed
	for _, oldComp := range old.Components {
		found := false
		for _, newComp := range new.Components {
			if oldComp.Name == newComp.Name {
				found = true
				break
			}
		}
		if !found {
			diff.Removed = append(diff.Removed, oldComp)
		}
	}

	return diff
}
