import re

with open("pkg/mcp/manifest_store.go", "r") as f:
    s = f.read()

s = s.replace('\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n', '\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n')

s = s.replace('type AdinkraManifestVerifier struct {\n\t// PublicKey is the PQC verification key for manifest signing.\n\tPublicKey []byte\n}', 'type AdinkraManifestVerifier struct {\n\tSigner kernelports.Signer\n\t// PublicKey is the PQC verification key for manifest signing.\n\tPublicKey []byte\n}')

s = s.replace('adinkra.Verify(v.PublicKey, h[:], sigBytes)', 'v.Signer.Verify(v.PublicKey, h[:], sigBytes)')

s = s.replace('func GenerateSignedManifest(tools []ToolSpec, privKey []byte, keyID string) (*SignedToolManifest, error) {', 'func GenerateSignedManifest(tools []ToolSpec, privKey []byte, keyID string, signer kernelports.Signer) (*SignedToolManifest, error) {')

s = s.replace('adinkra.Sign(privKey, h[:])', 'signer.Sign(privKey, h[:])')

with open("pkg/mcp/manifest_store.go", "w") as f:
    f.write(s)
