
with open("scripts/extract_kernel.sh", "r") as f:
    s = f.read()

s = s.replace('"pkg/crypto"', '"pkg/crypto"\n  "pkg/attestenvelope"')

with open("scripts/extract_kernel.sh", "w") as f:
    f.write(s)

with open("docs/public-kernel/KERNEL_SCOPE.md", "r") as f:
    s = f.read()

s = s.replace('pkg/crypto/', 'pkg/crypto/\npkg/attestenvelope/')

with open("docs/public-kernel/KERNEL_SCOPE.md", "w") as f:
    f.write(s)
