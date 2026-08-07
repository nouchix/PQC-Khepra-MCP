
with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = s.replace('signedEnv, err := r.attest.SignEnvelope(ctx, env)', 'signedEnvAny, err := r.attest.SignEnvelope(ctx, env)\n\t\tif err != nil { return SecureEnvelope{}, err }\n\t\tsignedEnv := signedEnvAny.(SecureEnvelope)')
s = s.replace('flight.RiskClass(spec.RiskClass)', 'spec.RiskClass')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
