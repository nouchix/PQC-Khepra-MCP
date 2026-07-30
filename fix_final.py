import re

with open("pkg/mcp/legacy/compat.go", "r") as f:
    s = f.read()

s = s.replace('\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"\n', '')
s = s.replace('\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n', '')

with open("pkg/mcp/legacy/compat.go", "w") as f:
    f.write(s)

with open("cmd/sonar/main.go", "r") as f:
    s = f.read()

s = s.replace('snapshot.SealWithPQC(skBytes, pkBytes)', 'snapshot.SealWithPQC(skBytes, pkBytes, attestenvelope.AdinkraSigner{})')
s = s.replace('snapshot.GenerateTelemetryProof(skBytes, pkBytes, VERSION, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))', 'snapshot.GenerateTelemetryProof(skBytes, pkBytes, VERSION, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH), attestenvelope.AdinkraSigner{})')

with open("cmd/sonar/main.go", "w") as f:
    f.write(s)
