import re

with open("scripts/extract_kernel.sh", "r") as f:
    s = f.read()

s = s.replace("FORBIDDEN_IMPORT_RE='PQC-Khepra-MCP/pkg/(dag", "FORBIDDEN_IMPORT_RE='PQC-Khepra-MCP/pkg/(dag")
s = re.sub(r"FORBIDDEN_IMPORT_RE='(.*?)'\n", r"FORBIDDEN_IMPORT_RE='\1(?:/|\")'\n", s)

with open("scripts/extract_kernel.sh", "w") as f:
    f.write(s)
