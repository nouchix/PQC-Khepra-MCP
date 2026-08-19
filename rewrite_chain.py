import re

with open("pkg/mcp/chain.go", "r") as f:
    s = f.read()

s = s.replace('import (\n\t"context"\n\t"crypto/sha256"\n\t"encoding/hex"\n\t"encoding/json"\n\t"fmt"\n\t"regexp"\n\t"strings"\n\t"time"\n\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"\n)',
              'import (\n\t"context"\n\t"crypto/sha256"\n\t"encoding/hex"\n\t"encoding/json"\n\t"fmt"\n\t"regexp"\n\t"strings"\n\t"time"\n\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n)')

s = s.replace("AdinkraDemarcGateway", "DefaultDemarcGateway")
s = s.replace("AdinkraPolymorphicEngine", "DefaultPolymorphicEngine")

s = s.replace('hex.EncodeToString(adinkra.GetSpectralFingerprint(p.Symbol)[:8])', 'hex.EncodeToString([]byte(p.Symbol))[:8]')

# Replace adinkra sign in PolymorphicEngine
s = s.replace('sig, err := adinkra.Sign(p.PrivateKey, h[:])', 'sig, err := p.Signer.Sign(p.PrivateKey, h[:])')
s = s.replace('type DefaultPolymorphicEngine struct {\n\t// Symbol is the Adinkra symbol', 'type DefaultPolymorphicEngine struct {\n\tSigner kernelports.Signer\n\t// Symbol is the Adinkra symbol')

# Remove DAGAttestor entirely (lines 249 to end)
s = re.sub(r"(?s)// ─── Attestor Implementation \(DAG \+ PQC\).*$", "", s)

with open("pkg/mcp/chain.go", "w") as f:
    f.write(s)
