import re

with open("cmd/asaf-hub/main.go", "r") as f:
    s = f.read()

# Replace types
s = s.replace('khepramcp.AdinkraDemarcGateway', 'khepramcp.DefaultDemarcGateway')
s = s.replace('khepramcp.AdinkraPolymorphicEngine', 'khepramcp.DefaultPolymorphicEngine')
s = re.sub(r'khepramcp\.NewDAGAttestor\([^)]+\)', 'kernelports.Defaults().Attestor', s)
s = re.sub(r'go dagBridge\(\)', '', s)
s = re.sub(r'dagBridge := khepramcp\.NewDAGBridge\([^)]+\)', '', s)

# Remove the lines creating wafShield and gw entirely
s = re.sub(r'var wafShield \*sekhem\.WAFShield\n(\s*if sekhemTriad != nil.*?\{\n\s*wafShield = sekhemTriad\.DuatRealm\.WAFShield\n\s*\})', '', s, flags=re.DOTALL)
s = re.sub(r'gw, gwErr := gateway\.New\(gateway\.DefaultConfig\(\)\)\n\s*if gwErr != nil \{\n.*?\} else \{\n.*?\}', '', s, flags=re.DOTALL)

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)

