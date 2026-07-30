import re

with open("pkg/mcp/tools/ai_discovery_tools.go", "r") as f:
    s = f.read()

s = s.replace('call.Arguments', 'call.Args')

with open("pkg/mcp/tools/ai_discovery_tools.go", "w") as f:
    f.write(s)
