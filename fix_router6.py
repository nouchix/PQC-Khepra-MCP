
with open("pkg/mcp/router.go", "r") as f:
    s = f.read()

s = re.sub(r'khlog\.SanitizeForLog\(([^)]+)\)', r'\1', s)
s = s.replace('*licpkg.KhepraLicense', 'kernelports.LicenseChecker')
s = s.replace('flight.RecordInput', 'kernelports.RecordInput')
s = re.sub(r'flight\.BuildIntentSummary\([^)]+\)', '"intent_summary"', s)

# Let's see the SignEnvelope issue. Let's just restore the original call and if it fails, we will see.
s = s.replace('signedEnvAny, err := r.attest.SignEnvelope(ctx, env)\n\t\tif err != nil { return nil, err }\n\t\tsignedEnv := signedEnvAny.(SecureEnvelope)', 'signedEnvAny, err := r.attest.SignEnvelope(ctx, env)\n\t\tif err != nil { return nil, err }\n\t\tsignedEnv := signedEnvAny.(SecureEnvelope)')

with open("pkg/mcp/router.go", "w") as f:
    f.write(s)
