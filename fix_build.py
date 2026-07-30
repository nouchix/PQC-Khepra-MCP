import re

with open("pkg/mcp/kernelports/kernelports.go", "r") as f:
    s = f.read()

s = s.replace('type NodeSummary interface{}', 'type NodeSummary struct {\n\tID   string\n\tTime int64\n\tTool string\n}')
s = s.replace('All() []NodeSummary', 'All() []*NodeSummary')
s = s.replace('Add(node any, parents []string) error', 'Add(node *NodeSummary, parents []string) error')

with open("pkg/mcp/kernelports/kernelports.go", "w") as f:
    f.write(s)

with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = s.replace('_, recErr := r.recorder.Record(', 'recErr := r.recorder.Record(ctx, ')
s = s.replace('flight.OutcomeSuccess', '"success"')
s = s.replace('flight.OutcomeError', '"error"')

s = s.replace('signedEnv, err := r.config.Attestor.SignEnvelope(ctx, env)', 'signedEnvAny, err := r.config.Attestor.SignEnvelope(ctx, env)\n\t\tif err != nil { return SecureEnvelope{}, err }\n\t\tsignedEnv := signedEnvAny.(SecureEnvelope)')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)

with open("pkg/mcp/transport_http.go", "r") as f:
    s = f.read()

s = s.replace('Nodes []*dag.Node `json:"nodes"`', 'Nodes []*kernelports.NodeSummary `json:"nodes"`')

with open("pkg/mcp/transport_http.go", "w") as f:
    f.write(s)

