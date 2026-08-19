import re

with open("pkg/types/snapshot.go", "r") as f:
    s = f.read()

s = s.replace('\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n', '\t"github.com/nouchix/PQC-Khepra-MCP/pkg/attestenvelope"\n\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n')

s = s.replace('func (a *AuditSnapshot) SealWithPQC(privateKey, publicKey []byte) error {', 'func (a *AuditSnapshot) SealWithPQC(privateKey, publicKey []byte, signer kernelports.Signer) error {')
s = s.replace('signature, err := adinkra.Sign(privateKey, data)', 'signature, err := attestenvelope.Sign(data, privateKey, signer)')

s = s.replace('func (a *AuditSnapshot) VerifyPQC() (bool, error) {', 'func (a *AuditSnapshot) VerifyPQC(signer kernelports.Signer) (bool, error) {')
s = s.replace('return adinkra.Verify(publicKey, data, signature)', 'return attestenvelope.Verify(data, signature, publicKey, signer), nil')

s = s.replace('func (a *AuditSnapshot) GenerateTelemetryProof(privateKey, publicKey []byte, version, platform string) (*TelemetryProof, error) {', 'func (a *AuditSnapshot) GenerateTelemetryProof(privateKey, publicKey []byte, version, platform string, signer kernelports.Signer) (*TelemetryProof, error) {')

with open("pkg/types/snapshot.go", "w") as f:
    f.write(s)
