
with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = s.replace('r.license.Check(call.ToolName)', 'r.license.Allow(call.ToolName)')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
