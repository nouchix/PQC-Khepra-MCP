import re

with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = s.replace('\tkhlog "github.com/nouchix/PQC-Khepra-MCP/pkg/logging"\n', '')
s = s.replace('RiskClass:     spec.RiskClass', 'RiskClass:     string(spec.RiskClass)')
s = s.replace('return SecureEnvelope{}, err', 'return nil, err')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)

with open("pkg/license/validator.go", "r") as f:
    s = f.read()

# Remove the exact case strings
s = s.replace('\tcase TierCommunity, "community":', '\tcase TierCommunity:')
s = s.replace('\tcase TierSovereign, "sovereign":', '\tcase TierSovereign:')
s = s.replace('\tcase TierPharaoh, "pharaoh":', '\tcase TierPharaoh:')

with open("pkg/license/validator.go", "w") as f:
    f.write(s)
