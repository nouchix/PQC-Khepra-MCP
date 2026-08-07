
with open("cmd/asaf-hub/main.go", "r") as f:
    s = f.read()

s = re.sub(r'wafShield := sekhem\.NewWAFShield[^\n]+', '', s)
s = re.sub(r'gw := gateway\.NewGateway[^\n]+', '', s)
s = re.sub(r'go dagBridge\(\)', '', s)

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)
