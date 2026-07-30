import re

with open("pkg/mcp/transport_http.go", "r") as f:
    s = f.read()

s = s.replace('\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/gateway"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"\n', '\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n')

s = s.replace('DagStore dag.Store', 'DagStore kernelports.NodeStore')
s = s.replace('WAF *sekhem.WAFShield', 'WAF func(http.Handler) http.Handler')
s = s.replace('Gateway *gateway.Gateway', 'Gateway func(http.Handler) http.Handler')

s = s.replace('dagStore    dag.Store', 'dagStore    kernelports.NodeStore')

s = s.replace('sekhem.HTTPMiddleware(t.config.WAF)(handler)', 't.config.WAF(handler)')
s = s.replace('gateway.Middleware(t.config.Gateway)(handler)', 't.config.Gateway(handler)')

s = re.sub(r't\.logger\.Printf\("\[MCP:HTTP\] ④ SEKHEM WAF bilateral: ACTIVE \(%d rules\)",\n\t\t\tlen\(t\.config\.WAF\.Rules\(\)\)\)', 't.logger.Printf("[MCP:HTTP] ④ SEKHEM WAF bilateral: ACTIVE")', s)

with open("pkg/mcp/transport_http.go", "w") as f:
    f.write(s)
