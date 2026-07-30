import re
import os

with open("cmd/khepra-mcp/main.go", "r") as f:
    s = f.read()

# Replace imports
s = s.replace('\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/agi"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/config"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/license"\n', '\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n')
s = s.replace('\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"\n', '\n')

# Adinkra PQC key setup
s = re.sub(r'// ── Adinkra PQC Key Setup.*?\n\s*keyID := hex.EncodeToString\(keyHash\[:8\]\)\n', '', s, flags=re.DOTALL)
s = s.replace('keyID := hex.EncodeToString(keyHash[:8])\n', 'keyID := "oss-key-id"\npubKey := []byte("oss-pub-key")\nprivKey := []byte("oss-priv-key")\n')

# Deployment mode config
s = re.sub(r'// ── Deployment Mode.*?runCfg := config\.LoadRuntime\(\)\n', '// Deployment Mode\n\ttype Config struct { Mode string; NetworkPolicy string; IsAirGapped bool; DAGPath string }\n\trunCfg := Config{Mode: "edge", NetworkPolicy: "open", IsAirGapped: false, DAGPath: ""}\n', s, flags=re.DOTALL)
s = s.replace('logger.Printf("  symbol=%s | key_id=%s", symbol, keyID)', 'logger.Printf("  symbol=Eban | key_id=%s", keyID)')

# License Validation
s = re.sub(r'// ── License Validation.*?logger\.Printf\("\[LICENSE\] %s tier \| tenant=%q \| id=%s \| expires=%s",.*?,\n\t\t\tlicenseClaim\.ExpiresAt\.Format\("2006-01-02"\),\n\t\t\)\n\t\}', '// License\n\tlogger.Printf("[LICENSE] OSS Community Tier")', s, flags=re.DOTALL)

# Build Security Chain
s = s.replace('demarc := &khepramcp.AdinkraDemarcGateway{', 'demarc := &khepramcp.DefaultDemarcGateway{')
s = s.replace('poly := &khepramcp.AdinkraPolymorphicEngine{', 'deps := kernelports.Defaults()\n\tpoly := &khepramcp.DefaultPolymorphicEngine{ Signer: deps.Signer,')
s = s.replace('symbol,', '"Eban",')

s = s.replace('attest := khepramcp.NewDAGAttestor(dagStore, symbol, privKey)', 'attest := deps.Attestor')

# Router config
s = s.replace('Attestor:          attest,', 'Attestor:          deps.Attestor,')
s = s.replace('License:           licenseClaim,', 'License:           deps.License,')
s = s.replace('FlightRecorder:    recorder,', 'FlightRecorder:    deps.Flight,')

s = s.replace('WAF:                 sekhem.NewWAFShield(),', 'WAF:                 nil,')
s = s.replace('DagStore:            dagStore,', 'DagStore:            nil,')

# Disable AGI hook and DagStore setup
s = re.sub(r'// 6\. Attestation Store.*?dagStore = dag\.NewMemoryStore\(\)\n\t\}', '// Attestation store OSS no-op', s, flags=re.DOTALL)
s = re.sub(r'// 7\. Flight Recorder.*?recorder, err = flight\.New\(flight\.RecorderConfig\{.*?\}\)', '// Flight recorder OSS no-op', s, flags=re.DOTALL)
s = re.sub(r'// ── AGI Hook \(SOW Agent Monitoring\).*?router\.Events\(\)\.Subscribe\(khepramcp\.EventAudit, agi\.GlobalObserver\.HandleEvent\)', '', s, flags=re.DOTALL)

with open("cmd/khepra-mcp/main.go", "w") as f:
    f.write(s)
