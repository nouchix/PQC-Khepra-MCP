import re

with open("cmd/asaf-hub/main.go", "r") as f:
    s = f.read()

# Replace demarc and poly
s = s.replace('legacy.AdinkraDemarcGateway', 'khepramcp.DefaultDemarcGateway')
s = s.replace('legacy.AdinkraPolymorphicEngine', 'khepramcp.DefaultPolymorphicEngine')

# Replace NewDAGAttestor
s = re.sub(r'attestor := legacy.NewDAGAttestor\([^)]+\)', 'deps := kernelports.Defaults()\n\tattestor := deps.Attestor', s)
s = s.replace('legacy.NewDAGAttestor', 'kernelports.Defaults().Attestor')

# Remove dag bridge
s = re.sub(r'dagBridge := legacy\.NewDAGBridge\(dagStore\)', 'dagBridge := nil', s)

# Remove unused
s = s.replace('legacy.NewDAGBridge', 'nil')

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)
