# Secure Deployment Guide: jcodemunch-mcp with Restricted Network Access

This guide covers how to safely install, deploy, and use the jcodemunch-mcp MCP server with **zero outbound network access** — ensuring no code, credentials, or metadata ever leave your machine.

---

## Why Restrict Network Access?

jcodemunch-mcp is designed as a local-first tool, but out of the box it includes:

1. **GitHub API calls** — used by `index_repo` to fetch remote repositories
2. **AI API calls** — optional, used to generate symbol summaries via Anthropic, Google, or OpenAI-compatible endpoints
3. **Telemetry** — an anonymous community savings counter that POSTs `{"delta": <int>, "anon_id": "<uuid>"}` to `j.gravelle.us` (opt-out via env var)

If you only index **local folders** and don't need AI summaries, none of these are necessary. This guide shows how to guarantee that at multiple layers.

---

## Table of Contents

- [Option A: Bare Install (No Docker)](#option-a-bare-install-no-docker)
- [Option B: Docker with --network none](#option-b-docker-with---network-none)
- [Option C: Docker Compose with Internal Network](#option-c-docker-compose-with-internal-network)
- [Claude Code Configuration](#claude-code-configuration)
- [What Each Layer Blocks](#what-each-layer-blocks)
- [Verifying Network Isolation](#verifying-network-isolation)
- [Storage and Index Management](#storage-and-index-management)
- [Security Audit Summary](#security-audit-summary)

---

## Option A: Bare Install (No Docker)

The simplest approach. Relies on environment variables to disable all network features at the application level.

### 1. Install

```bash
pip install jcodemunch-mcp
```

### 2. Configure Claude Code

Add to your MCP settings (`~/.claude/claude_desktop_config.json` or project-level `.mcp.json`):

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "jcodemunch-mcp",
      "env": {
        "JCODEMUNCH_SHARE_SAVINGS": "0",
        "CODE_INDEX_PATH": "/home/you/.code-index"
      }
    }
  }
}
```

**Windows:**

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "jcodemunch-mcp",
      "env": {
        "JCODEMUNCH_SHARE_SAVINGS": "0",
        "CODE_INDEX_PATH": "C:\\Users\\YOU\\.code-index"
      }
    }
  }
}
```

### What this does

| Setting | Effect |
|---------|--------|
| `JCODEMUNCH_SHARE_SAVINGS=0` | Disables all telemetry to `j.gravelle.us` |
| No `GITHUB_TOKEN` | `index_repo` will fail (no GitHub access) — only `index_folder` works |
| No `ANTHROPIC_API_KEY` | No AI summary calls — falls back to docstring/signature extraction |
| No `GOOGLE_API_KEY` | Same — no Google API calls |
| No `OPENAI_API_BASE` | Same — no local LLM calls |

**Result:** The server makes **zero outbound HTTP requests** when using `index_folder`. Verified empirically — see the [Security Audit Summary](#security-audit-summary).

### Optional: Windows Firewall Rule

For defense-in-depth, block the Python process from making any connections:

```powershell
# Find your Python path
(Get-Command python).Source

# Block it outbound
New-NetFirewallRule -DisplayName "Block jcodemunch outbound" `
  -Direction Outbound `
  -Program "C:\Users\YOU\AppData\Local\Programs\Python\Python312\python.exe" `
  -Action Block
```

> **Note:** This blocks ALL Python outbound traffic, not just jcodemunch. Use Docker (Options B/C) for granular isolation.

---

## Option B: Docker with `--network none`

The strongest isolation. Removes the entire network stack from the container — no loopback, no DNS, no TCP. Any network call raises `ConnectError` immediately.

### 1. Build the Image

```bash
git clone https://github.com/jgravelle/jcodemunch-mcp.git
cd jcodemunch-mcp
docker build -t jcodemunch-mcp .
```

### 2. Configure Claude Code

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "none",
        "-v", "/path/to/your/project:/workspace:ro",
        "-v", "jcodemunch-index:/home/mcp/.code-index",
        "-e", "JCODEMUNCH_SHARE_SAVINGS=0",
        "-e", "CODE_INDEX_PATH=/home/mcp/.code-index",
        "jcodemunch-mcp"
      ]
    }
  }
}
```

**Windows (Docker Desktop):**

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "none",
        "-v", "C:\\Users\\YOU\\Projects\\myapp:/workspace:ro",
        "-v", "jcodemunch-index:/home/mcp/.code-index",
        "-e", "JCODEMUNCH_SHARE_SAVINGS=0",
        "-e", "CODE_INDEX_PATH=/home/mcp/.code-index",
        "jcodemunch-mcp"
      ]
    }
  }
}
```

### Key Flags

| Flag | Purpose |
|------|---------|
| `--network none` | Removes network namespace entirely — kernel-enforced |
| `-v ...:/workspace:ro` | Mounts source code **read-only** — container cannot modify your files |
| `-v jcodemunch-index:...` | Named volume persists the index across runs |
| `--rm` | Container is deleted after each session |
| `-i` | Keeps stdin open for MCP stdio communication |

### Multiple Projects

Mount additional projects as separate volumes:

```json
"args": [
  "run", "--rm", "-i",
  "--network", "none",
  "-v", "C:\\Users\\YOU\\Projects\\app-a:/projects/app-a:ro",
  "-v", "C:\\Users\\YOU\\Projects\\app-b:/projects/app-b:ro",
  "-v", "jcodemunch-index:/home/mcp/.code-index",
  "-e", "JCODEMUNCH_SHARE_SAVINGS=0",
  "-e", "CODE_INDEX_PATH=/home/mcp/.code-index",
  "jcodemunch-mcp"
]
```

Then index each with `index_folder`:

```
index_folder: { "path": "/projects/app-a" }
index_folder: { "path": "/projects/app-b" }
```

---

## Option C: Docker Compose with Internal Network

Use this if you want a persistent service or plan to add sidecars (monitoring, logging).

### 1. docker-compose.yml

```yaml
services:
  jcodemunch:
    build: .
    stdin_open: true
    networks:
      - no-internet
    volumes:
      - ${PROJECT_DIR:-.}:/workspace:ro
      - jcodemunch-index:/home/mcp/.code-index
    environment:
      - JCODEMUNCH_SHARE_SAVINGS=0
      - CODE_INDEX_PATH=/home/mcp/.code-index

networks:
  no-internet:
    driver: bridge
    internal: true   # No default gateway — no internet access

volumes:
  jcodemunch-index:
```

### 2. Run

```bash
# Set your project directory
export PROJECT_DIR=/path/to/your/project

# Build and run
docker compose build
docker compose run --rm jcodemunch
```

The `internal: true` network creates a bridge with no default gateway. Containers can communicate with each other on this network but cannot reach any external host.

---

## Claude Code Configuration

### Project-Level `.mcp.json` (Recommended)

Place this in your project root so the MCP server is automatically available when Claude Code opens the project:

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "none",
        "-v", ".:/workspace:ro",
        "-v", "jcodemunch-index:/home/mcp/.code-index",
        "-e", "JCODEMUNCH_SHARE_SAVINGS=0",
        "-e", "CODE_INDEX_PATH=/home/mcp/.code-index",
        "jcodemunch-mcp"
      ]
    }
  }
}
```

### Global Configuration

For system-wide availability, add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "jcodemunch-mcp",
      "env": {
        "JCODEMUNCH_SHARE_SAVINGS": "0",
        "CODE_INDEX_PATH": "/home/you/.code-index"
      }
    }
  }
}
```

### Logging

Add file-based logging to diagnose indexing issues without polluting MCP stdio:

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "jcodemunch-mcp",
      "args": ["--log-level", "DEBUG", "--log-file", "/tmp/jcodemunch.log"],
      "env": {
        "JCODEMUNCH_SHARE_SAVINGS": "0"
      }
    }
  }
}
```

---

## What Each Layer Blocks

| Threat | Option A (Bare) | Option B (Docker `--network none`) | Option C (Compose `internal`) |
|--------|:---:|:---:|:---:|
| Telemetry to `j.gravelle.us` | Env var | Kernel-blocked | Network-blocked |
| GitHub API calls | No token = no auth | Kernel-blocked | Network-blocked |
| AI API calls (Anthropic/Google) | No keys = no client | Kernel-blocked | Network-blocked |
| Arbitrary SSRF via `OPENAI_API_BASE` | No env var = disabled | Kernel-blocked | Network-blocked |
| DNS resolution | Available | Impossible | No external DNS |
| File modification | OS permissions | `:ro` mount | `:ro` mount |
| Process escape | Same user | Container sandbox | Container sandbox |

---

## Verifying Network Isolation

### Docker: Confirm No Network

```bash
# Start a shell in the container
docker run --rm -it --network none jcodemunch-mcp /bin/bash

# Try to reach anything
$ curl https://google.com
# curl: (6) Could not resolve host: google.com

$ python3 -c "import httpx; httpx.get('https://google.com')"
# httpx.ConnectError: ...
```

### Bare Install: Monitor with Wireshark/tcpdump

```bash
# Linux: capture traffic from the jcodemunch process
sudo tcpdump -i any -p "host j.gravelle.us or host api.github.com"

# Then run jcodemunch-mcp in another terminal and use index_folder
# Expected output: zero packets captured
```

### Check Index Files for Credentials

```bash
# Search all stored index files for sensitive strings
grep -r "GITHUB_TOKEN\|API_KEY\|Bearer\|ghp_\|sk-ant-" ~/.code-index/
# Expected: no matches
```

---

## Storage and Index Management

### Where the Index Lives

| Deployment | Index Location |
|------------|---------------|
| Bare install | `~/.code-index/` (or `CODE_INDEX_PATH`) |
| Docker | Named volume `jcodemunch-index` |

### What Gets Stored

```
~/.code-index/
├── local-myproject.json          # Symbol metadata (signatures, line numbers, byte offsets)
├── local-myproject/              # Raw source file copies (used for byte-offset retrieval)
│   └── src/
│       └── main.py
└── _savings.json                 # Token savings counter (local only when telemetry is off)
```

The index JSON contains **no credentials** — only symbol metadata (names, signatures, docstrings, line numbers). Raw source files are verbatim copies used for O(1) symbol retrieval.

### Preview the Index

```bash
# List indexed repos
python3 -c "
import json
from jcodemunch_mcp.storage import IndexStore
store = IndexStore()
for r in store.list_repos():
    print(f\"{r['repo']}: {r['file_count']} files, {r['symbol_count']} symbols\")
"

# Or just open the JSON directly
cat ~/.code-index/local-myproject.json | python3 -m json.tool | head -50
```

### Delete an Index

```bash
# Via MCP tool
invalidate_cache: { "repo": "local/myproject" }

# Or delete manually
rm ~/.code-index/local-myproject.json
rm -rf ~/.code-index/local-myproject/

# Docker: delete the named volume
docker volume rm jcodemunch-index
```

---

## Security Audit Summary

A comprehensive static + dynamic security audit was performed on jcodemunch-mcp v0.2.17. Key findings:

### All 11 tools tested with HTTP interception

| Tool | Network Calls (telemetry off) | Code Exfiltrated? |
|------|:---:|:---:|
| `index_folder` | 0 | No |
| `index_repo` | 1 (api.github.com) | No |
| `list_repos` | 0 | No |
| `get_file_tree` | 0 | No |
| `get_file_outline` | 0 | No |
| `get_symbol` | 0 | No |
| `get_symbols` | 0 | No |
| `search_symbols` | 0 | No |
| `search_text` | 0 | No |
| `get_repo_outline` | 0 | No |
| `invalidate_cache` | 0 | No |

### Telemetry Payload (when enabled)

Every telemetry POST contains **only** `{"delta": <integer>, "anon_id": "<uuid>"}`. No source code, file paths, repository names, or credentials are included. Setting `JCODEMUNCH_SHARE_SAVINGS=0` eliminates all telemetry.

### Credential Handling

- `GITHUB_TOKEN` — sent only in `Authorization` header to `api.github.com`
- `ANTHROPIC_API_KEY` — passed only to the Anthropic SDK constructor
- No credentials appear in index files, logs, error messages, or telemetry payloads

### Known CVEs (Dependency)

| Package | CVE | Fixed In |
|---------|-----|----------|
| `mcp` 1.9.4 | CVE-2025-53365 | mcp 1.10.0 |
| `mcp` 1.9.4 | CVE-2025-66416 | mcp 1.23.0 |

These are in the `mcp` SDK, not in jcodemunch-mcp itself. Monitor for a `pyproject.toml` update that raises the `mcp` floor version.

Full audit report: [SECURITY_AUDIT_REPORT.md](SECURITY_AUDIT_REPORT.md)

---

## Quick Reference

### Minimum Safe Config (Bare Install)

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "jcodemunch-mcp",
      "env": {
        "JCODEMUNCH_SHARE_SAVINGS": "0"
      }
    }
  }
}
```

### Maximum Isolation (Docker)

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "none",
        "-v", ".:/workspace:ro",
        "-v", "jcodemunch-index:/home/mcp/.code-index",
        "-e", "JCODEMUNCH_SHARE_SAVINGS=0",
        "-e", "CODE_INDEX_PATH=/home/mcp/.code-index",
        "jcodemunch-mcp"
      ]
    }
  }
}
```

### Only Tool You Need for Local Use

```
index_folder: { "path": "/workspace" }
```

All query tools (`get_file_tree`, `search_symbols`, `get_symbol`, etc.) work purely against the local index with zero network access.
