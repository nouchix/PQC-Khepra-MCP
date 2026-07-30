import re

with open("pkg/mcp/signed_audit_log.go", "r") as f:
    s = f.read()

s = s.replace('\t"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"\n', '\t"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"\n')

s = s.replace('writer  *bufio.Writer', 'writer  *bufio.Writer\n\tsigner  kernelports.Signer')

s = s.replace('PubKey []byte', 'PubKey []byte\n\n\t// Signer is the ML-DSA-65 signer (kernelports).\n\tSigner kernelports.Signer')

s = s.replace('writer:  bufio.NewWriterSize(f, 64*1024),\n\t\tprev:    "genesis",', 'writer:  bufio.NewWriterSize(f, 64*1024),\n\t\tprev:    "genesis",\n\t\tsigner:  cfg.Signer,')

s = s.replace('sal.seq.Store(0)\n\t}', 'sal.seq.Store(0)\n\t}\n\n\tif sal.signer == nil {\n\t\tsal.signer = &kernelports.NoopSigner{}\n\t}')

s = s.replace('adinkra.Sign(sal.privKey, digest)', 'sal.signer.Sign(sal.privKey, digest)')

s = s.replace('func VerifyChain(path string, pubKey []byte) (*VerifyChainResult, error) {', 'func VerifyChain(path string, pubKey []byte, signer kernelports.Signer) (*VerifyChainResult, error) {\n\tif signer == nil {\n\t\tsigner = &kernelports.NoopSigner{}\n\t}')

s = s.replace('adinkra.Verify(pubKey, digest, sig)', 'signer.Verify(pubKey, digest, sig)')

with open("pkg/mcp/signed_audit_log.go", "w") as f:
    f.write(s)
