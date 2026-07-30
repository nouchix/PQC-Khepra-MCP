import re

with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = re.sub(r'// Phase B: secret leakage scan.*?\}\n', '', s, flags=re.DOTALL)
# It might not match everything if there are blank lines in the loop.
# Let's just use string replacement for the exact block.

# Safer replacement:
s = re.sub(r'\s*// Phase B: secret leakage scan.*?EventPolicy,\n\s*\}\)\n\s*\}\n', '\n', s, flags=re.DOTALL)

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
