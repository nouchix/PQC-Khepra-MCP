
with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = re.sub(r'\blicpkg "github\.com/nouchix/PQC-Khepra-MCP/pkg/license"\n', '', s)
s = re.sub(r'"github\.com/nouchix/PQC-Khepra-MCP/pkg/flight"\n', '', s)
s = s.replace('*licpkg.KhepraLicense', 'kernelports.LicenseChecker')
s = s.replace('licpkg.CheckToolAccess(r.license, call.ToolName)', 'r.license.Check(call.ToolName)')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
