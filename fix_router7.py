
with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = s.replace('signedEnvAny, err := r.attest.SignEnvelope(ctx, env)\n\t\tif err != nil { return nil, err }\n\t\tsignedEnv := signedEnvAny.(SecureEnvelope)', 'signedEnv, err := r.attest.SignEnvelope(ctx, env)')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
