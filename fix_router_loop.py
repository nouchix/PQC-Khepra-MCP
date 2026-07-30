import sys

with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

start = s.find('for _, sf := range runOutputSecretScan')
if start == -1:
    print("Not found")
    sys.exit(1)

# The end is the closing brace of the for loop. Let's find the closing brace.
end = s.find('}', start)
end = s.find('}', end + 1)
end = s.find('}', end + 1)
end = s.find('}', end + 1)
# Wait, let's just use string slicing carefully by checking the block.
block_str = '''		for _, sf := range runOutputSecretScan(outputBytes, call.ToolName) {
			r.logger.Printf("[MCP:SECRET-SCAN] tool=%q pattern=%q severity=%s owasp=%s (non-fatal)",
				call.ToolName, sf.title, sf.severity, sf.owaspTag)
			warnings = append(warnings, fmt.Sprintf("secret-scan [%s]: %s", sf.owaspTag, sf.title))
			r.events.Emit(MCPEvent{
				Type:    EventPolicy,
				Success: false,
				Metadata: map[string]any{
					"step":      "secret_scan",
					"tool":      call.ToolName,
					"agent":     id.AgentID,
					"owasp_tag": sf.owaspTag,
					"asi_tag":   sf.asiTag,
					"severity":  sf.severity,
					"pattern":   sf.title,
				},
			})
		}'''

s = s.replace(block_str, "")

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
