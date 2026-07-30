import re

with open("README.md", "r") as f:
    content = f.read()

content = content.replace("`pqc_stig` + 12 core tools", "`pqc_stig` + 24 core tools")
content = content.replace("All 34 tools", "All 72 tools")

with open("README.md", "w") as f:
    f.write(content)

