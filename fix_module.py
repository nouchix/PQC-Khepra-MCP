import re
with open("scripts/extract_kernel.sh", "r") as f:
    s = f.read()

replacement = """  # Rewrite module path to public kernel
  ( cd "$DEST" && \
    find . -name "*.go" -exec sed -i '' 's|github.com/nouchix/PQC-Khepra-MCP|github.com/nouchix/khepra-kernel|g' {} + && \
    go mod edit -module github.com/nouchix/khepra-kernel && \
    rm -f go.sum && \
    export PATH=/Applications/Whitebox/PQC-Khepra-MCP/go/bin:$PATH && \
    go mod tidy \
  )

  ( cd "$DEST" && \\
    git init -q && \\
    git add . && \\
    git commit -qm "Initial import: KHEPRA MCP kernel (fresh history)" )
  echo "extracted to $DEST — now run: $0 --verify $DEST"
"""

s = s.replace('  ( cd "$DEST" && \\\n    git init -q && \\\n    git add . && \\\n    git commit -qm "Initial import: KHEPRA MCP kernel (fresh history)" )\n  echo "extracted to $DEST — now run: $0 --verify $DEST"\n  echo "NOTE: go.mod still names the private module path; rename module + trim"\n  echo "      go.sum as part of the condition-3 spike before publication."\n', replacement)

with open("scripts/extract_kernel.sh", "w") as f:
    f.write(s)
