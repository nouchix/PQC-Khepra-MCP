# KHEPRA MCP Server — Public Container
#
# This Dockerfile wraps the KHEPRA/ADINKHEPRA engine for public distribution
# via ghcr.io/nouchix/pqc-khepra-mcp.
#
# Build:
#   docker build -t ghcr.io/nouchix/pqc-khepra-mcp:1.0.0 .
#   docker push ghcr.io/nouchix/pqc-khepra-mcp:1.0.0
#
# The io.modelcontextprotocol.server.name label is REQUIRED for ownership
# verification by registry.modelcontextprotocol.io.

# Base image: pull the hardened Iron Bank build first:
#   docker login registry1.dso.mil
#   docker pull registry1.dso.mil/dsop/nouchix/adinkhepra:1.0.0
#   docker tag registry1.dso.mil/dsop/nouchix/adinkhepra:1.0.0 adinkhepra-base:1.0.0
FROM adinkhepra-base:1.0.0

# --- MCP Registry ownership verification label (required) ---
LABEL io.modelcontextprotocol.server.name="io.github.nouchix/pqc-khepra-mcp"

# --- OCI standard labels ---
LABEL org.opencontainers.image.title="KHEPRA MCP Server"
LABEL org.opencontainers.image.description="Sovereign compliance engine with 36,195 STIG/CCI/NIST/CMMC mappings. Air-gappable. Zero token costs."
LABEL org.opencontainers.image.source="https://github.com/nouchix/PQC-Khepra-MCP"
LABEL org.opencontainers.image.vendor="NouchiX SecRed Knowledge Inc."
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.licenses="Proprietary"
LABEL org.opencontainers.image.documentation="https://github.com/nouchix/PQC-Khepra-MCP"

# MCP server runs via stdio transport
# The entrypoint is set by the base image (khepra-mcp binary)
