import re

with open("cmd/khepra-mcp/main.go", "r") as f:
    s = f.read()

s = s.replace('func main() {', 'func main() {\n\tkeyID := "oss-key-id"\n\tpubKey := []byte("oss-pub-key")\n\tprivKey := []byte("oss-priv-key")\n')

s = re.sub(r'\n\tvar dagStore dag\.Store\n.*?\n\t}', '', s, flags=re.DOTALL)
s = re.sub(r'\tattest := khepramcp\.NewDAGAttestor\(dagStore, symbol, privKey\)', '\tattest := deps.Attestor', s)

s = re.sub(r'\n\trouter\.Events\(\)\.Subscribe\(khepramcp\.EventAudit, agi\.GlobalObserver\.HandleEvent\)\n', '\n', s)

with open("cmd/khepra-mcp/main.go", "w") as f:
    f.write(s)
