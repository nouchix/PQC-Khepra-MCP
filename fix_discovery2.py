
with open("pkg/mcp/tools/ai_discovery_tools.go", "r") as f:
    s = f.read()

s = s.replace('\tif len(call.Args) > 0 {\n\t\t_ = json.Unmarshal(call.Args, &args)\n\t}', '\tif len(call.Args) > 0 {\n\t\tb, _ := json.Marshal(call.Args)\n\t\t_ = json.Unmarshal(b, &args)\n\t}')

with open("pkg/mcp/tools/ai_discovery_tools.go", "w") as f:
    f.write(s)
