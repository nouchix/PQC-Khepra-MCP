import re

# Fix mcp_gate.go
with open("pkg/license/mcp_gate.go", "r") as f:
    content = f.read()

content = re.sub(r'^\s*"community":\s*.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*"pilot":\s*.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*"enterprise":\s*.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*"master":\s*.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*"sovereign":\s*.*?\n', '', content, flags=re.MULTILINE)
content = re.sub(r'^\s*"pharaoh":\s*.*?\n', '', content, flags=re.MULTILINE)

with open("pkg/license/mcp_gate.go", "w") as f:
    f.write(content)

# Fix validator.go
with open("pkg/license/validator.go", "r") as f:
    content = f.read()

content = re.sub(r'\bcase "community":', 'case TierCommunity:', content)
content = re.sub(r'\bcase "sovereign":', 'case TierPilot:', content)
content = re.sub(r'\bcase "pharaoh":', 'case TierEnterprise:', content)
# But if case TierCommunity already exists, we will have two case TierCommunity.
# Let's replace 'case "community":\n\t\treturn "Community"' with nothing, etc.

content = re.sub(r'\s*case\s+"community":\s+return\s+"Community"', '', content)
content = re.sub(r'\s*case\s+"sovereign":\s+return\s+"Sovereign"', '', content)
content = re.sub(r'\s*case\s+"pharaoh":\s+return\s+"Pharaoh"', '', content)

with open("pkg/license/validator.go", "w") as f:
    f.write(content)
