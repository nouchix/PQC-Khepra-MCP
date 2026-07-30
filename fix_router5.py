import re

with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = s.replace('"golang.org/x/crypto/sha3"', '"golang.org/x/crypto/sha3"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
