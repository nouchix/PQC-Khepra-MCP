import re

# Clean up the bad appends
for filepath in ["pkg/attestenvelope/attestenvelope.go", "pkg/mcp/legacy/compat.go"]:
    with open(filepath, "r") as f:
        s = f.read()
    s = re.sub(r'import "github\.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n\ntype AdinkraSigner struct\{\}\n\nfunc \(s AdinkraSigner\) Sign\(data \[\]byte, privateKey \[\]byte\) \(\[\]byte, error\) \{\n\treturn adinkra\.Sign\(privateKey, data\)\n\}\n\nfunc \(s AdinkraSigner\) Verify\(publicKey \[\]byte, data \[\]byte, signature \[\]byte\) \(bool, error\) \{\n\treturn adinkra\.Verify\(publicKey, data, signature\)\n\}\n', '', s)
    with open(filepath, "w") as f:
        f.write(s)

# Re-insert cleanly
for filepath in ["pkg/attestenvelope/attestenvelope.go", "pkg/mcp/legacy/compat.go"]:
    with open(filepath, "r") as f:
        s = f.read()
    s = s.replace('import (\n', 'import (\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n')
    
    code = """
type AdinkraSigner struct{}

func (s AdinkraSigner) Sign(data []byte, privateKey []byte) ([]byte, error) {
	return adinkra.Sign(privateKey, data)
}

func (s AdinkraSigner) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	return adinkra.Verify(publicKey, data, signature)
}
"""
    with open(filepath, "w") as f:
        f.write(s + code)

