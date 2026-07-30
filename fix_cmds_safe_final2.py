import re

with open("cmd/asaf-hub/main.go", "r") as f:
    s = f.read()

s = s.replace('\t"github.com/nouchix/PQC-Khepra-MCP/pkg/gateway"\n', '')
s = re.sub(r'defer dagBridge\.Close\(\)', '', s)

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)

