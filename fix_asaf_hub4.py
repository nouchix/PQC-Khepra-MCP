
with open("cmd/asaf-hub/main.go", "r") as f:
    lines = f.readlines()

new_lines = []
skip = False
for i, line in enumerate(lines):
    if "var wafShield *sekhem.WAFShield" in line:
        continue
    if "wafShield =" in line and "sekhemTriad" in line:
        continue
    if "gw, gwErr :=" in line:
        new_lines.append("\t_, _ = gateway.New(gateway.DefaultConfig())\n")
        continue
    if "if gwErr != nil {" in line:
        skip = True
        continue
    if skip and "{" in line:
        pass
    if skip and "}" in line:
        skip = False
        continue
    if skip:
        continue
    if "nil()" in line:
        continue
    
    new_lines.append(line)

s = "".join(new_lines)
s = s.replace("go nil()", "")

with open("cmd/asaf-hub/main.go", "w") as f:
    f.write(s)

