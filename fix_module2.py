with open("scripts/extract_kernel.sh", "r") as f:
    s = f.read()

replacement = """  # Rewrite module path to public kernel
  ( cd "$DEST" && \\
    find . -name "*.go" -exec sed -i '' 's|github.com/nouchix/PQC-Khepra-MCP|github.com/nouchix/khepra-kernel|g' {} + && \\
    go mod edit -module github.com/nouchix/khepra-kernel && \\
    rm -f go.sum && \\
    go mod tidy \\
  )

  ( cd "$DEST" && \\
    git init -q && \\
    git add . && \\
    git commit -qm "Initial import: KHEPRA MCP kernel (fresh history)" )
  echo "extracted to $DEST — now run: $0 --verify $DEST"
}"""

s = re.sub(r'\s*\( cd "\$DEST" && \\\n\s*git init -q.*?\n\}', replacement, s, flags=re.DOTALL)

with open("scripts/extract_kernel.sh", "w") as f:
    f.write(s)
