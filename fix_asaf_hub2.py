
with open("cmd/asaf-hub/main.go", "r") as f:
    s = f.read()

s = re.sub(r'wafShield := sekhem\.NewWAFShield\(sekhem\.WAFConfig\{.*?\}\)', '', s, flags=re.DOTALL)
s = re.sub(r'gw := gateway\.NewGateway\(gateway\.Config\{.*?\}\)', '', s, flags=re.DOTALL)
s = s.replace('go dagBridge()', '')

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)

