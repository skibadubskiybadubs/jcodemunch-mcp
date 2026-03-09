"""Container network isolation test for jcodemunch-mcp.

Proves that jcodemunch-mcp is FULLY FUNCTIONAL with zero network access,
using the same kernel isolation mechanism as Docker --network none.

Run with:
    unshare --net /path/to/python tests/test_docker_isolation.py

This creates a network namespace with no interfaces — identical to
Docker's --network none flag (both use unshare(CLONE_NEWNET) syscall).
"""

import asyncio
import json
import os
import socket
import sys
import threading
import time

# ── Environment setup (before any jcodemunch imports) ──
os.environ["JCODEMUNCH_SHARE_SAVINGS"] = "1"  # Intentionally ON to prove it can't phone home
os.environ["GITHUB_TOKEN"] = "fake_gh_token_12345"
os.environ["ANTHROPIC_API_KEY"] = "fake_ant_key_67890"
os.environ["GOOGLE_API_KEY"] = ""
os.environ["OPENAI_API_BASE"] = ""
STORAGE = "/tmp/container_isolation_index"
os.environ["CODE_INDEX_PATH"] = STORAGE
REPO_PATH = "/home/user/jcodemunch-mcp"

# ── HTTP interception (inline, no external dependency) ──
_captured_requests = []
_lock = threading.Lock()


def _install_http_hooks():
    """Monkey-patch httpx to capture all outbound HTTP attempts."""
    import httpx

    _original_send = httpx.Client.send

    def patched_send(self, request, **kwargs):
        entry = {"method": request.method, "url": str(request.url), "timestamp": time.time()}
        with _lock:
            _captured_requests.append(entry)
        return _original_send(self, request, **kwargs)

    httpx.Client.send = patched_send

    _original_async_send = httpx.AsyncClient.send

    async def patched_async_send(self, request, **kwargs):
        entry = {"method": request.method, "url": str(request.url), "timestamp": time.time()}
        with _lock:
            _captured_requests.append(entry)
        return await _original_async_send(self, request, **kwargs)

    httpx.AsyncClient.send = patched_async_send

    _original_post = httpx.post

    def patched_post(url, **kwargs):
        entry = {"method": "POST", "url": str(url), "timestamp": time.time()}
        with _lock:
            _captured_requests.append(entry)
        return _original_post(url, **kwargs)

    httpx.post = patched_post


_install_http_hooks()

# ── Now import jcodemunch tools ──
from jcodemunch_mcp.tools.index_repo import index_repo
from jcodemunch_mcp.tools.index_folder import index_folder
from jcodemunch_mcp.tools.list_repos import list_repos
from jcodemunch_mcp.tools.get_file_tree import get_file_tree
from jcodemunch_mcp.tools.get_file_outline import get_file_outline
from jcodemunch_mcp.tools.get_symbol import get_symbol, get_symbols
from jcodemunch_mcp.tools.search_symbols import search_symbols
from jcodemunch_mcp.tools.search_text import search_text
from jcodemunch_mcp.tools.get_repo_outline import get_repo_outline
from jcodemunch_mcp.tools.invalidate_cache import invalidate_cache

# ══════════════════════════════════════════════════════════════
# RESULTS COLLECTOR
# ══════════════════════════════════════════════════════════════
results = {
    "test_name": "Container Network Isolation Test",
    "isolation_method": "unshare --net (identical to Docker --network none)",
    "kernel_mechanism": "unshare(CLONE_NEWNET) — new network namespace, no interfaces",
    "telemetry_setting": "JCODEMUNCH_SHARE_SAVINGS=1 (intentionally ON to prove it cannot reach the network)",
    "network_probes": [],
    "tool_tests": [],
    "http_capture": {},
    "credential_scan": {},
    "overall": "PENDING",
}


def log(msg):
    print(msg, flush=True)


# ══════════════════════════════════════════════════════════════
# PART A: PROVE NETWORK ISOLATION
# ══════════════════════════════════════════════════════════════
def test_network_isolation():
    log("\n" + "=" * 70)
    log("  PART A: NETWORK ISOLATION PROOF")
    log("=" * 70)

    probes = []

    # Probe 1: Raw TCP connection to 8.8.8.8:53
    log("\n[Probe 1] TCP connect to 8.8.8.8:53 (Google DNS)...")
    try:
        s = socket.create_connection(("8.8.8.8", 53), timeout=3)
        s.close()
        probes.append({"probe": "TCP 8.8.8.8:53", "result": "CONNECTED", "pass": False})
        log("  [FAIL] Connection succeeded — network is NOT isolated!")
    except OSError as e:
        probes.append({"probe": "TCP 8.8.8.8:53", "result": str(e), "pass": True})
        log(f"  [PASS] Blocked: {e}")

    # Probe 2: DNS resolution of j.gravelle.us (telemetry host)
    log("\n[Probe 2] DNS resolve j.gravelle.us (telemetry host)...")
    try:
        addrs = socket.getaddrinfo("j.gravelle.us", 443)
        probes.append({"probe": "DNS j.gravelle.us", "result": f"Resolved to {addrs[0][4]}", "pass": False})
        log(f"  [FAIL] DNS resolved — network is NOT isolated!")
    except (socket.gaierror, OSError) as e:
        probes.append({"probe": "DNS j.gravelle.us", "result": str(e), "pass": True})
        log(f"  [PASS] Blocked: {e}")

    # Probe 3: DNS resolution of api.github.com
    log("\n[Probe 3] DNS resolve api.github.com...")
    try:
        addrs = socket.getaddrinfo("api.github.com", 443)
        probes.append({"probe": "DNS api.github.com", "result": f"Resolved to {addrs[0][4]}", "pass": False})
        log(f"  [FAIL] DNS resolved — network is NOT isolated!")
    except (socket.gaierror, OSError) as e:
        probes.append({"probe": "DNS api.github.com", "result": str(e), "pass": True})
        log(f"  [PASS] Blocked: {e}")

    # Probe 4: HTTP GET via httpx
    log("\n[Probe 4] httpx.get('https://api.github.com')...")
    try:
        import httpx
        resp = httpx.get("https://api.github.com", timeout=3)
        probes.append({"probe": "httpx GET api.github.com", "result": f"Status {resp.status_code}", "pass": False})
        log(f"  [FAIL] HTTP request succeeded — network is NOT isolated!")
    except Exception as e:
        error_type = type(e).__name__
        probes.append({"probe": "httpx GET api.github.com", "result": f"{error_type}: {e}", "pass": True})
        log(f"  [PASS] Blocked: {error_type}: {e}")

    # Probe 5: TCP to j.gravelle.us telemetry port
    log("\n[Probe 5] TCP connect to j.gravelle.us:443 (telemetry endpoint)...")
    try:
        s = socket.create_connection(("j.gravelle.us", 443), timeout=3)
        s.close()
        probes.append({"probe": "TCP j.gravelle.us:443", "result": "CONNECTED", "pass": False})
        log("  [FAIL] Connection succeeded — network is NOT isolated!")
    except (socket.gaierror, OSError) as e:
        probes.append({"probe": "TCP j.gravelle.us:443", "result": str(e), "pass": True})
        log(f"  [PASS] Blocked: {e}")

    results["network_probes"] = probes
    all_blocked = all(p["pass"] for p in probes)
    log(f"\n  Network isolation: {'CONFIRMED' if all_blocked else 'FAILED'} ({sum(p['pass'] for p in probes)}/{len(probes)} probes blocked)")
    return all_blocked


# ══════════════════════════════════════════════════════════════
# PART B: EXERCISE ALL 11 MCP TOOLS
# ══════════════════════════════════════════════════════════════
async def test_all_tools():
    log("\n" + "=" * 70)
    log("  PART B: ALL 11 MCP TOOLS UNDER NETWORK ISOLATION")
    log("=" * 70)

    tool_results = []

    # Clear HTTP capture before tool tests
    with _lock:
        _captured_requests.clear()

    # ── 1. index_folder ──
    log("\n[1/11] index_folder — indexing the repo itself...")
    r = index_folder(path=REPO_PATH, use_ai_summaries=False, storage_path=STORAGE)
    ok = r.get("success", False)
    tool_results.append({
        "tool": "index_folder", "success": ok,
        "detail": f"{r.get('file_count')} files, {r.get('symbol_count')} symbols" if ok else r.get("error"),
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    REPO_ID = r.get("repo", "local/jcodemunch-mcp")

    # ── 2. list_repos ──
    log("\n[2/11] list_repos...")
    r = list_repos(storage_path=STORAGE)
    ok = r.get("count", 0) > 0
    tool_results.append({
        "tool": "list_repos", "success": ok,
        "detail": f"{r.get('count')} repos found",
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 3. get_repo_outline ──
    log("\n[3/11] get_repo_outline...")
    r = get_repo_outline(repo=REPO_ID, storage_path=STORAGE)
    ok = "error" not in r and r.get("file_count", 0) > 0
    tool_results.append({
        "tool": "get_repo_outline", "success": ok,
        "detail": f"{r.get('file_count')} files, {r.get('symbol_count')} symbols, dirs={r.get('directories')}",
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 4. get_file_tree ──
    log("\n[4/11] get_file_tree...")
    r = get_file_tree(repo=REPO_ID, storage_path=STORAGE)
    ok = "error" not in r and len(r.get("tree", [])) > 0
    tool_results.append({
        "tool": "get_file_tree", "success": ok,
        "detail": f"{r.get('_meta', {}).get('file_count', 0)} files in tree",
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 5. get_file_tree (filtered + summaries) ──
    log("\n[5/11] get_file_tree (path_prefix='src/', summaries=True)...")
    r = get_file_tree(repo=REPO_ID, path_prefix="src/", include_summaries=True, storage_path=STORAGE)
    ok = "error" not in r
    tool_results.append({
        "tool": "get_file_tree (filtered)", "success": ok,
        "detail": f"{r.get('_meta', {}).get('file_count', 0)} files",
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 6. get_file_outline ──
    log("\n[6/11] get_file_outline (security.py)...")
    r = get_file_outline(repo=REPO_ID, file_path="src/jcodemunch_mcp/security.py", storage_path=STORAGE)
    symbols = r.get("symbols", [])
    ok = len(symbols) > 0
    tool_results.append({
        "tool": "get_file_outline", "success": ok,
        "detail": f"{len(symbols)} symbols in security.py",
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # Collect symbol IDs for subsequent tests
    symbol_ids = [s["id"] for s in symbols] if symbols else []

    # ── 7. get_symbol ──
    log("\n[7/11] get_symbol (with verify + context)...")
    if symbol_ids:
        r = get_symbol(repo=REPO_ID, symbol_id=symbol_ids[0], verify=True, context_lines=3, storage_path=STORAGE)
        ok = "error" not in r and len(r.get("source", "")) > 0
        tool_results.append({
            "tool": "get_symbol", "success": ok,
            "detail": f"name={r.get('name')}, source_len={len(r.get('source', ''))}, verified={r.get('_meta', {}).get('content_verified')}",
        })
    else:
        ok = False
        tool_results.append({"tool": "get_symbol", "success": False, "detail": "no symbols available"})
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 8. get_symbols (batch) ──
    log("\n[8/11] get_symbols (batch of 3)...")
    if len(symbol_ids) >= 3:
        r = get_symbols(repo=REPO_ID, symbol_ids=symbol_ids[:3], storage_path=STORAGE)
        ok = len(r.get("symbols", [])) == 3
        tool_results.append({
            "tool": "get_symbols", "success": ok,
            "detail": f"retrieved {r.get('_meta', {}).get('symbol_count', 0)} symbols",
        })
    else:
        ok = False
        tool_results.append({"tool": "get_symbols", "success": False, "detail": "not enough symbols"})
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 9. search_symbols ──
    log("\n[9/11] search_symbols (query='validate', kind='function')...")
    r = search_symbols(repo=REPO_ID, query="validate", kind="function", max_results=5, storage_path=STORAGE)
    ok = r.get("result_count", 0) > 0
    tool_results.append({
        "tool": "search_symbols", "success": ok,
        "detail": f"{r.get('result_count')} results",
    })
    if ok:
        for match in r.get("results", [])[:3]:
            log(f"    {match.get('name')} — {match.get('file')}:{match.get('line')}")
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 10. search_text ──
    log("\n[10/11] search_text (query='SECRET_PATTERNS', pattern='*.py')...")
    r = search_text(repo=REPO_ID, query="SECRET_PATTERNS", file_pattern="*.py", max_results=10, storage_path=STORAGE)
    ok = r.get("result_count", 0) > 0
    tool_results.append({
        "tool": "search_text", "success": ok,
        "detail": f"{r.get('result_count')} matches",
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")

    # ── 11. index_repo (MUST fail with ConnectError, NOT 401) ──
    log("\n[11/11] index_repo (expected: network error, NOT auth error)...")
    r = await index_repo(url="testowner/testrepo", use_ai_summaries=False, storage_path=STORAGE)
    error_msg = r.get("error", "")
    # Key test: error must indicate network failure, not HTTP 401
    is_network_error = any(s in error_msg for s in ["Network is unreachable", "ConnectError", "connect", "network"])
    is_auth_error = "401" in error_msg or "Unauthorized" in error_msg
    ok = is_network_error and not is_auth_error
    tool_results.append({
        "tool": "index_repo", "success": ok,
        "detail": f"error={error_msg[:120]}",
        "is_network_error": is_network_error,
        "is_auth_error": is_auth_error,
        "note": "Network error proves kernel-level isolation (not just missing credentials)",
    })
    log(f"  {'[PASS]' if ok else '[FAIL]'} {tool_results[-1]['detail']}")
    if ok:
        log("  This confirms KERNEL-LEVEL network block (not just auth failure)")

    # Wait for any daemon threads (telemetry attempts)
    time.sleep(2)

    results["tool_tests"] = tool_results
    return all(t["success"] for t in tool_results)


# ══════════════════════════════════════════════════════════════
# PART C: VERIFY NO DATA LEAKAGE
# ══════════════════════════════════════════════════════════════
def test_no_leakage():
    log("\n" + "=" * 70)
    log("  PART C: DATA LEAKAGE VERIFICATION")
    log("=" * 70)

    # Check HTTP capture
    log(f"\n[HTTP Capture] Total attempted HTTP requests: {len(_captured_requests)}")
    for req in _captured_requests:
        log(f"  {req['method']} {req['url']}")

    results["http_capture"] = {
        "total_attempted_requests": len(_captured_requests),
        "requests": _captured_requests[:20],  # cap at 20 for readability
        "note": "These requests were ATTEMPTED but FAILED due to network isolation",
    }

    # Scan index files for credentials
    log(f"\n[Credential Scan] Scanning index files in {STORAGE}...")
    cred_leaks = []
    files_scanned = 0
    # Exclude the test script itself — it contains dummy creds as string constants
    self_basename = "test_docker_isolation.py"
    for root, dirs, files in os.walk(STORAGE):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname == self_basename:
                log(f"  [SKIP] {fpath} (this test script — contains dummy cred constants)")
                continue
            try:
                content = open(fpath, errors="replace").read()
                files_scanned += 1
                for cred_name, cred_val in [
                    ("GITHUB_TOKEN", "fake_gh_token_12345"),
                    ("ANTHROPIC_API_KEY", "fake_ant_key_67890"),
                ]:
                    if cred_val in content:
                        cred_leaks.append(f"{cred_name} in {fpath}")
                        log(f"  [ALERT] {cred_name} found in {fpath}")
            except Exception:
                pass

    if not cred_leaks:
        log(f"  [PASS] No credentials found in {files_scanned} index files")
    else:
        log(f"  [FAIL] {len(cred_leaks)} credential leaks!")

    results["credential_scan"] = {
        "files_scanned": files_scanned,
        "leaks_found": len(cred_leaks),
        "leaks": cred_leaks,
        "pass": len(cred_leaks) == 0,
    }

    # Cleanup: invalidate_cache
    log("\n[Cleanup] invalidate_cache...")
    r = invalidate_cache(repo="local/jcodemunch-mcp", storage_path=STORAGE)
    log(f"  {r}")

    return len(cred_leaks) == 0


# ══════════════════════════════════════════════════════════════
async def main():
    log("=" * 70)
    log("  jcodemunch-mcp CONTAINER NETWORK ISOLATION TEST")
    log("=" * 70)
    log(f"  Isolation: unshare --net (identical to Docker --network none)")
    log(f"  Telemetry: INTENTIONALLY ENABLED (SHARE_SAVINGS=1)")
    log(f"  Purpose:   Prove MCP is fully functional with zero network")
    log(f"  Storage:   {STORAGE}")
    log(f"  Source:    {REPO_PATH}")

    net_ok = test_network_isolation()
    tools_ok = await test_all_tools()
    leak_ok = test_no_leakage()

    all_ok = net_ok and tools_ok and leak_ok
    results["overall"] = "PASS" if all_ok else "FAIL"

    log("\n" + "=" * 70)
    log("  FINAL RESULTS")
    log("=" * 70)
    log(f"  Network isolation confirmed:  {'YES' if net_ok else 'NO'}")
    log(f"  All tools functional:         {'YES' if tools_ok else 'NO'}")
    log(f"  No data leakage:              {'YES' if leak_ok else 'NO'}")
    log(f"  Overall:                       {'PASS' if all_ok else 'FAIL'}")

    tool_pass = sum(1 for t in results["tool_tests"] if t["success"])
    tool_total = len(results["tool_tests"])
    log(f"\n  Tools passed: {tool_pass}/{tool_total}")

    http_attempted = len(_captured_requests)
    log(f"  HTTP requests attempted: {http_attempted} (all BLOCKED by kernel)")
    log(f"  Credential leaks: {results['credential_scan']['leaks_found']}")

    # Write structured JSON results
    results_path = "/tmp/container_isolation_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"\n  Full results: {results_path}")

    log("\n" + "=" * 70)

    return all_ok


if __name__ == "__main__":
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)
