import re

# 1. Fix kernelports.LicenseChecker to use Check
with open("pkg/mcp/kernelports/kernelports.go", "r") as f:
    s = f.read()
s = s.replace('Allow(toolName string) error', 'Check(toolName string) error')
with open("pkg/mcp/kernelports/kernelports.go", "w") as f:
    f.write(s)

# 2. Fix router.go to use Check
with open("pkg/mcp/router.go", "r") as f:
    s = f.read()
s = s.replace('r.license.Allow(call.ToolName)', 'r.license.Check(call.ToolName)')
with open("pkg/mcp/router.go", "w") as f:
    f.write(s)

# 3. Fix asaf-hub main.go
with open("cmd/asaf-hub/main.go", "r") as f:
    s = f.read()

s = s.replace('"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"\n', '"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/legacy"\n')

s = s.replace('khepramcp.AdinkraDemarcGateway', 'legacy.AdinkraDemarcGateway')
s = s.replace('khepramcp.AdinkraPolymorphicEngine', 'legacy.AdinkraPolymorphicEngine')
s = s.replace('khepramcp.NewDAGAttestor', 'legacy.NewDAGAttestor')
s = s.replace('khepramcp.NewDAGBridge', 'legacy.NewDAGBridge')

s = s.replace('WAF:                 wafShield,', 'WAF:                 func(h http.Handler) http.Handler { return wafShield(h) },')
s = s.replace('Gateway:             gw,', 'Gateway:             func(h http.Handler) http.Handler { return gw(h) },')

# GenerateSignedManifest has signature with Signer.
s = re.sub(r'khepramcp\.GenerateSignedManifest\(([^,]+, [^,]+, [^,)]+)\)', r'khepramcp.GenerateSignedManifest(\1, legacy.AdinkraSigner{})', s)

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)

# 4. Fix sonar main.go
with open("cmd/sonar/main.go", "r") as f:
    s = f.read()

s = s.replace('"github.com/nouchix/PQC-Khepra-MCP/pkg/types"', '"github.com/nouchix/PQC-Khepra-MCP/pkg/types"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/attestenvelope"\n')

s = s.replace('snapshot.SealWithPQC(rawPQC, publicKey)', 'snapshot.SealWithPQC(rawPQC, publicKey, attestenvelope.AdinkraSigner{})')
s = s.replace('snapshot.GenerateTelemetryProof(rawPQC, publicKey, version, "sonar")', 'snapshot.GenerateTelemetryProof(rawPQC, publicKey, version, "sonar", attestenvelope.AdinkraSigner{})')

with open("cmd/sonar/main.go", "w") as f:
    f.write(s)

