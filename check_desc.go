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
