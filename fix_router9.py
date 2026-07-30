import re

with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

# Remove the locally defined Attestor interface
s = re.sub(r'// Attestor records tool executions in the DAG audit chain with PQC signatures\.\n// Production impl: wrapper over pkg/dag\.Store \+ pkg/adinkra\.Sign\ntype Attestor interface \{\n\t// Append records a tool execution in the DAG and returns the attestation node ID\.\n\tAppend\(ctx context\.Context, toolName string, input \[\]byte, output \[\]byte\) \(string, error\)\n\t// SignEnvelope adds a PQC signature to the SecureEnvelope using the attestation key\.\n\tSignEnvelope\(ctx context\.Context, env SecureEnvelope\) \(SecureEnvelope, error\)\n\}\n', '', s)

# Also remove any fallback if the comment changed slightly
s = re.sub(r'type Attestor interface \{\n.*?SignEnvelope\(ctx context\.Context, env SecureEnvelope\) \(SecureEnvelope, error\)\n\}\n', '', s, flags=re.DOTALL)

# Change the Config and Router structs to use kernelports.Attestor
s = s.replace('attest   Attestor', 'attest   kernelports.Attestor')
s = s.replace('Attestor Attestor', 'Attestor kernelports.Attestor')

# We also need to restore the type cast since kernelports.Attestor returns (any, error)
# but wait! I just removed it in fix_router7.py! Let's put it back correctly.
s = s.replace('signedEnv, err := r.attest.SignEnvelope(ctx, env)', 'signedEnvAny, err := r.attest.SignEnvelope(ctx, env)\n\t\tif err != nil { return nil, err }\n\t\tsignedEnv := signedEnvAny.(SecureEnvelope)')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
