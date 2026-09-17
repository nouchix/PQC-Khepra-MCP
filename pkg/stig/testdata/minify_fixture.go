package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	inPath := filepath.Join("pkg", "stig", "testdata", "stigviewer_live_pull_2026-09-16.json")
	outPath := filepath.Join("pkg", "stig", "testdata", "stigviewer_live_pull_minified.json")

	inFile, err := os.Open(inPath)
	if err != nil {
		fmt.Println("Error opening input:", err)
		return
	}
	defer inFile.Close()

	var allDownloads []map[string]interface{}
	if err := json.NewDecoder(inFile).Decode(&allDownloads); err != nil {
		fmt.Println("Error decoding:", err)
		return
	}

	// We only need stigs -> rules -> rule_id
	var minified []map[string]interface{}
	for _, dl := range allDownloads {
		stigsIf, ok := dl["stigs"].([]interface{})
		if !ok {
			continue
		}
		
		var minStigs []map[string]interface{}
		for _, stigIf := range stigsIf {
			stig, ok := stigIf.(map[string]interface{})
			if !ok {
				continue
			}
			
			rulesIf, ok := stig["rules"].([]interface{})
			if !ok {
				continue
			}
			
			var minRules []map[string]interface{}
			for _, ruleIf := range rulesIf {
				rule, ok := ruleIf.(map[string]interface{})
				if !ok {
					continue
				}
				
				minRule := map[string]interface{}{
					"rule_id": rule["rule_id"],
				}
				minRules = append(minRules, minRule)
			}
			minStigs = append(minStigs, map[string]interface{}{"rules": minRules})
		}
		minified = append(minified, map[string]interface{}{"stigs": minStigs})
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Println("Error creating output:", err)
		return
	}
	defer outFile.Close()

	if err := json.NewEncoder(outFile).Encode(minified); err != nil {
		fmt.Println("Error encoding output:", err)
	}
	fmt.Println("Minified fixture created successfully.")
}
