//go:build ignore
// +build ignore

// check_desc.go — dev script that audits tool schemas for missing parameter
// descriptions. Excluded from the build like gen_manifest.go: it references
// tools.GetAvailableTools, which is not part of the current tools API.
// Run: go run check_desc.go

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/tools"
)

func main() {
	ts := tools.GetAvailableTools()
	for _, t := range ts {
		schema := t.ArgsSchema
		if schema == nil {
			continue
		}
		props, ok := schema["properties"].(map[string]any)
		if !ok {
			continue
		}
		for k, v := range props {
			vMap, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if _, hasDesc := vMap["description"]; !hasDesc {
				fmt.Printf("Tool %s missing description for parameter %s\n", t.Name, k)
			}
		}
	}
}
