# Security & Privacy Audit Report: jcodemunch-mcp v0.2.17

**Audit Date:** 2026-03-06
**Auditor:** Automated Security Analysis (Claude)
**Scope:** Full static + dynamic analysis of data exfiltration, telemetry, and credential leakage
**Repository:** https://github.com/jgravelle/jcodemunch-mcp
**Commit:** v0.2.17

---

## Executive Summary

**Overall Rating: USE WITH CAUTION**

The jcodemunch-mcp server is well-engineered with strong security controls (path traversal prevention, secret file exclusion, symlink protection). No unauthorized data exfiltration or credential leakage was detected. However, the server does include **opt-out telemetry** that contacts a third-party domain, and there are known CVEs in the `mcp` dependency that should be addressed.

---

## Appendix: Comprehensive All-Tools Dynamic Test (Phase 2)

A second, more thorough dynamic test was conducted exercising **all 11 MCP tools** against a real indexed codebase (the repo itself, 35 files, 426 symbols). The test was run in three phases:

### Phase A: All Tools with Telemetry Disabled (`JCODEMUNCH_SHARE_SAVINGS=0`)

Every tool was invoked with telemetry disabled:

| # | Tool | Invocation | HTTP Requests | Result |
|---|------|------------|---------------|--------|
| 1 | `index_folder` | Indexed the repo itself (35 files, 426 symbols) | 0 | PASS |
| 2 | `index_repo` | Attempted GitHub API with fake token | 1 (api.github.com) | PASS — token only in auth header |
| 3 | `list_repos` | Listed indexed repos | 0 | PASS |
| 4 | `get_file_tree` | Full tree | 0 | PASS |
| 5 | `get_file_tree` | Filtered + summaries | 0 | PASS |
| 6 | `get_file_outline` | security.py (14 symbols) | 0 | PASS |
| 7 | `get_symbol` | validate_path with verify + context | 0 | PASS |
| 8 | `get_symbols` | Batch retrieval (3 symbols) | 0 | PASS |
| 9 | `search_symbols` | query="validate", kind=function | 0 | PASS |
| 10 | `search_text` | query="SECRET_PATTERNS" | 0 | PASS |
| 11 | `get_repo_outline` | Full repo outline | 0 | PASS |

**Result: ZERO telemetry requests. ZERO requests to unknown domains.** Only 1 expected request to `api.github.com` from `index_repo`. The `GITHUB_TOKEN` appeared only in the `Authorization` header to `api.github.com` — correct behavior.

### Phase B: Telemetry Enabled (`JCODEMUNCH_SHARE_SAVINGS=1`)

Re-exercised 8 tools that call `record_savings()` (get_file_tree, get_file_outline, search_symbols, search_text, get_repo_outline, get_symbol, get_symbols):

- **16 telemetry requests** to `https://j.gravelle.us/APIs/savings/post.php`
- **Every single payload** contained only `{"delta": <int>, "anon_id": "<uuid>"}`
- **Zero** payloads contained source code, file paths, repository names, or credentials
- **Zero** requests to any domain other than `j.gravelle.us`
- `anon_id` was consistent across all requests (same UUID) and in proper UUID4 format

### Phase C: Filesystem Audit + Cleanup

- **Scanned all index files** in `/tmp/audit_index_v2/` — zero credentials found in any stored JSON or raw content file
- `invalidate_cache` made **zero network requests**
- All stored data was local-only and contained no sensitive information

### Conclusion

**No code exfiltration detected across any of the 11 tools.** The only outbound data when telemetry is enabled is an anonymous integer counter. Setting `JCODEMUNCH_SHARE_SAVINGS=0` eliminates all outbound traffic except to `api.github.com` (for `index_repo` only).

---

## Phase 1: Static Application Security Testing

### 1.1 Dependency Review

| Package | Version | Verdict |
|---------|---------|---------|
| `mcp` | >=1.0.0,<1.10.0 | Official MCP SDK. **2 known CVEs** (CVE-2025-53365, CVE-2025-66416) |
| `httpx` | >=0.27.0 | Official HTTP client. Clean. |
| `tree-sitter-language-pack` | >=0.7.0,<1.0.0 | Official tree-sitter bindings. Clean. |
| `pathspec` | >=0.12.0 | Gitignore pattern matching. Clean. |
| `anthropic` (optional) | >=0.40.0 | Official Anthropic SDK. Clean. |
| `google-generativeai` (optional) | >=0.8.0 | Official Google AI SDK. Clean. |

**Finding:** No typo-squatted packages. No suspicious or unverified telemetry SDKs in dependencies. Two CVEs exist in the `mcp` SDK (fixed in 1.10.0 and 1.23.0 respectively).

### 1.2 Network Library & Domain Enumeration

**Network libraries used:** Only `httpx` (HTTP client) and `urllib.parse` (URL parsing only, no network calls).

**Complete list of external domains in source code:**

| Domain | File | Purpose | User Data Sent |
|--------|------|---------|----------------|
| `api.github.com` | `tools/index_repo.py:64,183` | Fetch repo tree and file contents | GITHUB_TOKEN in auth header |
| `j.gravelle.us` | `storage/token_tracker.py:24` | Anonymous telemetry (community savings meter) | `{"delta": int, "anon_id": "uuid"}` only |

**No other domains** are hardcoded anywhere in the source. The `ANTHROPIC_BASE_URL` and `OPENAI_API_BASE` environment variables allow user-configured endpoints for AI summarization.

### 1.3 Credential Data Flow Tracing

| Credential | Read From | Sent To | In Logs? | In Index Files? | In Error Messages? | Leak Risk |
|---|---|---|---|---|---|---|
| `GITHUB_TOKEN` | `os.environ.get("GITHUB_TOKEN")` | `Authorization: token {val}` header to `api.github.com` only | No | No | No (only "Set GITHUB_TOKEN" hint) | **Low** |
| `ANTHROPIC_API_KEY` | `os.environ.get("ANTHROPIC_API_KEY")` | `Anthropic(api_key=val)` constructor (SDK handles transport) | No | No | No | **Low** |
| `GOOGLE_API_KEY` | `os.environ.get("GOOGLE_API_KEY")` | `genai.configure(api_key=val)` (SDK handles transport) | No | No | No | **Low** |
| `OPENAI_API_KEY` | `os.environ.get("OPENAI_API_KEY", "local-llm")` | `Authorization: Bearer {val}` to user-configured `OPENAI_API_BASE` | No | No | No | **Medium** (SSRF) |

**Grep verification:** Zero matches for `print` or `logging` statements containing credential variable names.

### 1.4 Telemetry Analysis

**File:** `src/jcodemunch_mcp/storage/token_tracker.py:24-59`

The server sends anonymous usage telemetry to `https://j.gravelle.us/APIs/savings/post.php`:

```python
_TELEMETRY_URL = "https://j.gravelle.us/APIs/savings/post.php"

def _share_savings(delta: int, anon_id: str) -> None:
    threading.Thread(target=lambda: httpx.post(
        _TELEMETRY_URL,
        json={"delta": delta, "anon_id": anon_id},
        timeout=3.0,
    ), daemon=True).start()
```

**Telemetry characteristics:**
- Payload contains ONLY `{"delta": <tokens_saved>, "anon_id": "<uuid4>"}` — verified statically and dynamically
- `anon_id` is a random UUID4, not derived from hostname, username, IP, or any identifying information
- No code snippets, file paths, repository names, or credentials are included
- Fire-and-forget daemon thread — does not block operations
- **Opt-out:** Set `JCODEMUNCH_SHARE_SAVINGS=0` to disable entirely
- Enabled by default (opt-out, not opt-in)

---

## Phase 2: Virtual Environment Setup

A clean Python 3 virtual environment was created at `/tmp/audit-venv` with the package installed in editable mode. An HTTP interception layer was written to monkey-patch `httpx.Client.send`, `httpx.AsyncClient.send`, and `httpx.post` to log all outbound requests with credential redaction.

---

## Phase 3: Dynamic Behavioral Analysis

### 3.1 Test Results

| Test | Result | Details |
|------|--------|---------|
| Telemetry payload inspection | **PASS** | Payload contains only `delta` + `anon_id`. No credentials, paths, or code. |
| `index_repo` network behavior | **PASS** | Only contacted `api.github.com`. `GITHUB_TOKEN` sent only in `Authorization` header. |
| Read-only tools (`list_repos`) | **PASS** | Zero network requests for read-only operations. |
| `record_savings` telemetry | **PASS** | Telemetry POST to `j.gravelle.us` with minimal anonymous payload. |
| Filesystem credential audit | **PASS** | Index files (`_savings.json`) contain no credentials. |

### 3.2 Complete Network Traffic Log

During the full test run, exactly **5 HTTP requests** were captured:

1. `POST https://j.gravelle.us/APIs/savings/post.php` — telemetry (test 1, direct call)
2. `POST https://j.gravelle.us/APIs/savings/post.php` — same request at transport layer
3. `GET https://api.github.com/repos/testowner/testrepo/git/trees/HEAD?recursive=1` — repo tree fetch
4. `POST https://j.gravelle.us/APIs/savings/post.php` — telemetry (test 4, via record_savings)
5. `POST https://j.gravelle.us/APIs/savings/post.php` — same request at transport layer

**Domains contacted:** `api.github.com`, `j.gravelle.us` — **no other domains**.

### 3.3 Credential Leak Check

- `fake_gh_token_12345` — appeared ONLY in `Authorization` header to `api.github.com`. Never in request bodies, telemetry payloads, or filesystem.
- `fake_ant_key_67890` — did NOT appear in any network request (Anthropic SDK was not installed in test env, so summarizer fell back to signature mode). The API key is passed to the `Anthropic()` constructor which handles transport internally.

---

## Phase 4: Security Findings

### CRITICAL: None

### HIGH: None

### MEDIUM

#### M1: Opt-Out Telemetry to Third-Party Domain
- **Risk:** The server sends data to `j.gravelle.us` by default without explicit user consent.
- **Payload:** Anonymous and minimal (`delta` + `anon_id`), but the domain is owned by the package author, not a well-known analytics provider.
- **Mitigation:** Set `JCODEMUNCH_SHARE_SAVINGS=0` in your environment.
- **Recommendation:** Telemetry should be opt-in, not opt-out. Document prominently in installation instructions.

#### M2: Known CVEs in `mcp` Dependency
- **CVE-2025-53365** — Fixed in mcp 1.10.0 (current upper bound is <1.10.0, blocking the fix)
- **CVE-2025-66416** — Fixed in mcp 1.23.0
- **Recommendation:** Update `pyproject.toml` dependency range: `mcp>=1.10.0,<2.0.0`

#### M3: SSRF Risk via Configurable Base URLs
- **Risk:** `ANTHROPIC_BASE_URL` and `OPENAI_API_BASE` environment variables allow redirecting AI API calls to arbitrary endpoints. If an attacker controls these env vars, code symbol signatures (not full source) could be exfiltrated to an attacker-controlled endpoint.
- **Data at risk:** Symbol signatures (function names, parameter types) — NOT full source code.
- **Mitigation:** These env vars are set by the user, so this requires environment compromise first.
- **Recommendation:** Consider validating base URLs against an allowlist or at least logging a warning for non-standard endpoints.

### LOW

#### L1: No TLS Certificate Pinning on Telemetry
- The telemetry POST to `j.gravelle.us` relies on default SSL verification. A MITM attacker on the network could intercept or modify telemetry.
- **Impact:** Minimal — payload contains only token counts, no sensitive data.

#### L2: Logging to stderr by Default
- MCP uses stdio for communication. Logging to stderr (the default) could theoretically interfere with MCP stream parsing.
- **Recommendation:** Already documented; file-based logging is recommended.

#### L3: TOCTOU in File Operations
- Between path validation and file read, a race condition could theoretically allow symlink replacement.
- **Impact:** Low — requires local filesystem access and precise timing.

---

## Security Controls Assessment

| Control | Status | Implementation |
|---------|--------|---------------|
| Path traversal prevention | Implemented | `os.path.commonpath()` validation |
| Symlink escape protection | Implemented | Default disabled, fail-safe on errors |
| Secret file exclusion | Implemented | 27 patterns via fnmatch |
| Binary file detection | Implemented | Extension + null-byte content check |
| File size limits | Implemented | 500KB default, configurable |
| UTF-8 safe decode | Implemented | `errors="replace"` |
| CI secret scanning | Implemented | sdist checked for sensitive paths |
| Credential logging prevention | Verified | Zero print/log statements with credentials |
| Error message safety | Verified | No stack traces or credentials in MCP error responses |

---

## Final Rating

### USE WITH CAUTION

**Rationale:** The codebase demonstrates strong security practices and no evidence of malicious data exfiltration was found. All credentials are handled correctly. However, the opt-out telemetry to a third-party domain (`j.gravelle.us`) and known CVEs in the `mcp` dependency warrant the "Use with Caution" rating rather than "Safe".

### Remediation Steps (Priority Order)

1. **Set `JCODEMUNCH_SHARE_SAVINGS=0`** in your MCP server configuration to disable telemetry.
2. **Pin `mcp>=1.10.0`** to address CVE-2025-53365 (or wait for the upstream to update their version range).
3. **Audit your environment variables** — ensure `ANTHROPIC_BASE_URL` and `OPENAI_API_BASE` are not set to untrusted endpoints.
4. **Use file-based logging** (`--log-file /path/to/log`) instead of stderr.
5. **Restrict `GITHUB_TOKEN` scope** to read-only (`repo:read` or `public_repo`) to minimize blast radius.

### Safe Configuration Example

```json
{
  "mcpServers": {
    "jcodemunch": {
      "command": "jcodemunch-mcp",
      "args": ["--log-file", "/tmp/jcodemunch.log"],
      "env": {
        "GITHUB_TOKEN": "ghp_YOUR_READONLY_TOKEN",
        "CODE_INDEX_PATH": "/tmp/code-index",
        "JCODEMUNCH_SHARE_SAVINGS": "0",
        "JCODEMUNCH_MAX_INDEX_FILES": "500"
      }
    }
  }
}
```

---

---

## Appendix: Container Network Isolation Test (Phase 3)

**Date:** 2026-03-09
**Isolation Methods Tested:**
1. `unshare --net` — creates a network namespace with no interfaces (same kernel mechanism as Docker `--network none`)
2. `docker run --network none` — actual Docker container with network stack removed

Both use the `unshare(CLONE_NEWNET)` syscall. Both were tested and produced identical results: **all tools functional, all network requests blocked**.

This test proves jcodemunch-mcp is **fully functional with zero network access**, and that even with telemetry **intentionally enabled** (`JCODEMUNCH_SHARE_SAVINGS=1`), no data can leave the container.

### Network Isolation Proof (5/5 probes blocked)

| Probe | Target | Error | Pass |
|-------|--------|-------|:----:|
| TCP connect | 8.8.8.8:53 (Google DNS) | `[Errno 101] Network is unreachable` | YES |
| DNS resolve | j.gravelle.us (telemetry host) | `[Errno -3] Temporary failure in name resolution` | YES |
| DNS resolve | api.github.com | `[Errno -3] Temporary failure in name resolution` | YES |
| httpx GET | https://api.github.com | `ConnectError: [Errno 101] Network is unreachable` | YES |
| TCP connect | j.gravelle.us:443 | `[Errno -3] Temporary failure in name resolution` | YES |

**Conclusion:** No TCP connections, no DNS resolution, no HTTP requests can succeed. The kernel removes the entire network stack.

### All 11 MCP Tools: Functional Under Isolation (11/11 passed)

| # | Tool | Result | Detail |
|---|------|:------:|--------|
| 1 | `index_folder` | PASS | 36 files, 437 symbols indexed |
| 2 | `list_repos` | PASS | 1 repo found |
| 3 | `get_repo_outline` | PASS | 36 files, 437 symbols |
| 4 | `get_file_tree` | PASS | 36 files in tree |
| 5 | `get_file_tree` (filtered) | PASS | 20 files (src/ prefix) |
| 6 | `get_file_outline` | PASS | 14 symbols in security.py |
| 7 | `get_symbol` | PASS | validate_path, 754 bytes, verified |
| 8 | `get_symbols` | PASS | 3 symbols retrieved |
| 9 | `search_symbols` | PASS | 2 results for query="validate" |
| 10 | `search_text` | PASS | 5 matches for "SECRET_PATTERNS" |
| 11 | `index_repo` | PASS | Failed with "All connection attempts failed" (network error, NOT auth error) |

**Key insight for `index_repo`:** The error is `"All connection attempts failed"` (a `ConnectError`), NOT `"401 Unauthorized"`. This proves the block is at the **kernel level** (no TCP possible), not merely at the application level (missing credentials).

### HTTP Traffic Analysis

With telemetry **intentionally enabled** (`JCODEMUNCH_SHARE_SAVINGS=1`), the HTTP interception layer captured **17 attempted requests**:

| Destination | Method | Count | Payload | Reached Server? |
|-------------|--------|:-----:|---------|:---------------:|
| `j.gravelle.us/APIs/savings/post.php` | POST | 16 | `{"delta": int, "anon_id": "uuid"}` | **NO** — blocked by kernel |
| `api.github.com/repos/testowner/testrepo/...` | GET | 1 | Auth header only | **NO** — blocked by kernel |

**All 17 requests were blocked at the kernel level.** The application attempted to make them, but `unshare --net` / Docker `--network none` prevents any packet from leaving the process.

### Credential Leak Scan

- Scanned all 36 index files in the storage directory
- Searched for: `GITHUB_TOKEN`, `API_KEY`, `Bearer`, `ghp_`, `sk-ant-`, dummy test credentials
- **Result: ZERO credential strings found** in any stored index file
- The test script itself (containing dummy credential constants) was correctly excluded from the scan

### Conclusion

| Metric | Result |
|--------|--------|
| Network isolation confirmed | YES (5/5 probes blocked) |
| All tools functional | YES (11/11 passed) |
| Data leakage | NONE (17 requests attempted, 0 succeeded) |
| Credential leaks in stored data | NONE (36 files scanned) |
| Overall | **PASS** |

**jcodemunch-mcp is fully functional for local code indexing and querying with zero network access.** Docker `--network none` (or equivalent `unshare --net`) provides kernel-enforced isolation that blocks all outbound traffic, including telemetry, regardless of application-level settings. This is the recommended deployment mode for security-sensitive environments.

Full test script: [`tests/test_docker_isolation.py`](tests/test_docker_isolation.py)
Full JSON results: available in test output

---

*Audit methodology: Static grep-based analysis + monkey-patched HTTP interception + runtime behavioral testing with dummy credentials + kernel-level network isolation testing via both `unshare --net` and Docker `--network none`. No actual credentials were used or exposed during this audit.*
