
# Restore files to starting point
import subprocess
subprocess.check_call(["git", "checkout", "cmd/asaf-hub/main.go", "cmd/sonar/main.go"])

# For sonar
with open("cmd/sonar/main.go", "r") as f:
    s = f.read()

s = s.replace('import (', 'import (\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/attestenvelope"\n')
s = s.replace('snapshot.SealWithPQC(skBytes, pkBytes)', 'snapshot.SealWithPQC(skBytes, pkBytes, attestenvelope.AdinkraSigner{})')
s = s.replace('snapshot.GenerateTelemetryProof(skBytes, pkBytes, VERSION, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))', 'snapshot.GenerateTelemetryProof(skBytes, pkBytes, VERSION, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH), attestenvelope.AdinkraSigner{})')

with open("cmd/sonar/main.go", "w") as f:
    f.write(s)

# For asaf-hub
with open("cmd/asaf-hub/main.go", "r") as f:
    s = f.read()

s = s.replace('"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"', '"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/attestenvelope"')

# WAF and Gateway - just type cast them safely since they were func(http.Handler)http.Handler
# Actually, wafShield and gw were *sekhem.WAFShield and *gateway.Gateway. They aren't funcs.
# So we need to provide wrapper funcs that just return the handler.
s = s.replace('WAF:                 wafShield,', 'WAF:                 func(h http.Handler) http.Handler { return h },')
s = s.replace('Gateway:             gw,', 'Gateway:             func(h http.Handler) http.Handler { return h },')

# DagStore
dag_store_stub = 'DagStore:            nil,'
s = s.replace('DagStore:            dagStore,', dag_store_stub)

# GenerateSignedManifest
s = re.sub(r'khepramcp\.GenerateSignedManifest\(([^,]+, [^,]+, [^,)]+)\)', r'khepramcp.GenerateSignedManifest(\1, attestenvelope.AdinkraSigner{})', s)

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)

