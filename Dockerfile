# jcodemunch-mcp: Network-isolated Docker container
# Designed for local-only code indexing with ZERO outbound network access.

FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir .

# ── Runtime stage ──
FROM python:3.12-slim

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/jcodemunch-mcp /usr/local/bin/jcodemunch-mcp

# Create non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /home/mcp -s /bin/bash mcp \
    && mkdir -p /home/mcp/.code-index /workspace \
    && chown -R mcp:mcp /home/mcp /workspace

USER mcp
WORKDIR /workspace

# Hardened environment: telemetry off, no API keys, local-only
ENV JCODEMUNCH_SHARE_SAVINGS=0 \
    CODE_INDEX_PATH=/home/mcp/.code-index \
    PYTHONDONTWRITEBYTECODE=1

# MCP servers communicate over stdio
ENTRYPOINT ["jcodemunch-mcp"]
