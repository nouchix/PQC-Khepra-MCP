import re

with open("scripts/extract_kernel.sh", "r") as f:
    s = f.read()

s = s.replace('"pkg/mcp/legacy"\n)', '"pkg/mcp/legacy"\n  "pkg/mcp/scanner_adapter.go"\n)')

with open("scripts/extract_kernel.sh", "w") as f:
    f.write(s)
