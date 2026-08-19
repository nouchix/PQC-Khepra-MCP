import re

with open("cmd/manifest-gen/main.go", "r") as f:
    s = f.read()

s = s.replace('\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n', '\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n')

s = re.sub(r'symbol := "Eban"\n\tfingerprint := adinkra\.GetSpectralFingerprint\(symbol\)\n\t_ = fingerprint // Used for provenance only\n\n\t// Generate ML-DSA-65 key pair \(compatible with adinkra\.Sign/Verify\)\n\tpubKey, privKey, err := adinkra\.GenerateDilithiumKey\(\)\n\tif err != nil {\n\t\tfmt\.Fprintf\(os\.Stderr, "key generation failed: \%v\\n", err\)\n\t\tos\.Exit\(1\)\n\t}', 'pubKey := []byte("oss-pub-key")\n\tprivKey := []byte("oss-priv-key")\n', s)

s = s.replace('sig, err := adinkra.Sign(privKey, payloadHash[:])', 'sig, err := kernelports.Defaults().Signer.Sign(privKey, payloadHash[:])')

with open("cmd/manifest-gen/main.go", "w") as f:
    f.write(s)
