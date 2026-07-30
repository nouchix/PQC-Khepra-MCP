import re

with open("pkg/mcp/legacy/compat.go", "r") as f:
    s = f.read()

s = s.replace('\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/legacy"\n', '')
s = re.sub(r'type \w+ = legacy\.\w+\n', '', s)
s = re.sub(r'var \w+ = legacy\.\w+\n', '', s)

# Ensure it imports mcp since it might reference mcp.Types
s = s.replace('import (\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n)', 'import (\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n)')

with open("pkg/mcp/legacy/compat.go", "w") as f:
    f.write(s)
