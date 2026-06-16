#!/usr/bin/env python3
"""
PQC-Khepra-MCP Docker Smoke Test
Tests the published ghcr.io/nouchix/pqc-khepra-mcp:v1.0.0 image
via MCP JSON-RPC over stdin/stdout.

Run: python smoke_test_docker.py
"""

import subprocess, json, sys, time
from typing import Optional

IMAGE = "ghcr.io/nouchix/pqc-khepra-mcp:v1.0.0"
TOOLS_REQUIRED = [
    "discover_assets", "agent_record", "flight_export",
    "khepra_query_stig", "khepra_get_dag_chain",
    "nist_map", "dag_attestation", "acp_status",
    "nhi_inventory", "khepra_query_threat_intel",
    "owasp_agent_assess", "dark_crypto_contribute", "pqc_stig",
]

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
SKIP = "\033[93m⏭  SKIP\033[0m"
INFO = "\033[96mℹ️  INFO\033[0m"

results = {"pass": 0, "fail": 0, "skip": 0}


import os as _os
import pathlib as _pathlib

# Absolute path to the fixed UTF-8 manifest.json in this repo.
_MANIFEST_LOCAL = str(_pathlib.Path(__file__).parent / "manifest.json")


def start_container():
    """Start the MCP server container, return Popen.

    Mounts the locally-fixed manifest.json over /app/manifest.json so that
    ghcr.io/nouchix/pqc-khepra-mcp:v1.0.0 (which shipped a UTF-16 LE / garbage-
    appended manifest) boots correctly without needing a rebuild.
    """
    # Convert Windows path to Docker-friendly format (forward slashes)
    local_manifest = _MANIFEST_LOCAL.replace("\\", "/")
    cmd = ["docker", "run", "-i", "--rm",
           "-e", "KHEPRA_MODE=community",
           "-v", f"{local_manifest}:/app/manifest.json:ro",
           IMAGE]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, bufsize=0
    )
    time.sleep(1.5)  # allow container startup
    if proc.poll() is not None:
        stderr = proc.stderr.read().decode(errors="replace")
        raise RuntimeError(f"Container exited early:\n{stderr}")
    return proc


def send(proc, msg: dict) -> Optional[dict]:
    """Send JSON-RPC message, return parsed response (15s timeout)."""
    line = json.dumps(msg) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()

    if msg.get("method") in ("notifications/initialized",):
        return None  # Notifications have no response

    deadline = time.time() + 15
    buf = b""
    while time.time() < deadline:
        ch = proc.stdout.read(1)
        if not ch:
            break
        buf += ch
        if ch == b"\n":
            text = buf.decode(errors="replace").strip()
            buf = b""
            if not text:
                continue
            try:
                resp = json.loads(text)
                if resp.get("id") == msg.get("id"):
                    return resp
            except json.JSONDecodeError:
                pass
    return None


def tool_result(resp: Optional[dict]) -> tuple[Optional[dict], Optional[str]]:
    """Unwrap MCP content envelope + KHEPRA SecureEnvelope."""
    if resp is None:
        return None, "no response (timeout)"
    if "error" in resp:
        return None, f"RPC error {resp['error']['code']}: {resp['error']['message']}"
    result = resp.get("result", {})
    # MCP content envelope
    if isinstance(result, dict) and "content" in result:
        if result.get("isError"):
            for c in result["content"]:
                if c.get("type") == "text":
                    return None, f"tool error: {c['text']}"
        for c in result.get("content", []):
            if c.get("type") == "text" and c.get("text"):
                try:
                    inner = json.loads(c["text"])
                    if "envelope" in inner:
                        env = inner["envelope"]
                        if env.get("result"):
                            return env["result"], None
                        if env.get("error_message"):
                            return None, f"tool error: {env['error_message']}"
                    return inner, None
                except json.JSONDecodeError:
                    return {"text": c["text"]}, None
    # Bare result
    if isinstance(result, dict):
        if result.get("is_error"):
            return None, result.get("error_message", "unknown error")
        if "envelope" in result:
            env = result["envelope"]
            if env.get("result"):
                return env["result"], None
        return result, None
    return result, None


def check(label: str, condition: bool, detail: str = ""):
    if condition:
        print(f"  {PASS}  {label}" + (f" — {detail}" if detail else ""))
        results["pass"] += 1
    else:
        print(f"  {FAIL}  {label}" + (f" — {detail}" if detail else ""))
        results["fail"] += 1


def is_license_error(err: str) -> bool:
    if not err:
        return False
    return any(k in err.lower() for k in ("license", "enterprise tier", "upgrade at", "requires enterprise"))


def run_tests():
    print(f"\n{'='*60}")
    print(f"  PQC-Khepra-MCP Docker Smoke Test")
    print(f"  Image: {IMAGE}")
    print(f"{'='*60}\n")

    print(f"{INFO}  Starting container...")
    proc = start_container()
    print(f"{INFO}  Container started (PID {proc.pid})\n")

    msg_id = [0]
    def nxt():
        msg_id[0] += 1
        return msg_id[0]

    try:
        # ── 1. initialize ────────────────────────────────────────────────
        print("1. MCP Initialize")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "initialize",
                           "params": {"protocolVersion": "2024-11-05",
                                      "capabilities": {},
                                      "clientInfo": {"name": "smoke-test", "version": "1.0"}}})
        res, err = tool_result(resp)
        if err:
            # initialize returns bare result, not envelope
            res = resp.get("result", {}) if resp else {}
            err = None
        proto = res.get("protocolVersion") if res else None
        check("protocolVersion=2024-11-05", proto == "2024-11-05", f"got={proto}")

        # Initialized notification
        send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        # ── 2. tools/list ───────────────────────────────────────────────
        print("\n2. tools/list")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/list", "params": {}})
        tools_list = []
        if resp and "result" in resp:
            r = resp["result"]
            if isinstance(r, dict) and "tools" in r:
                tools_list = [t["name"] for t in r["tools"]]
        check(f"≥10 tools registered", len(tools_list) >= 10, f"got {len(tools_list)}")
        print(f"  {INFO}  Tools: {', '.join(tools_list[:8])}{'...' if len(tools_list)>8 else ''}")
        missing = [t for t in TOOLS_REQUIRED if t not in tools_list]
        check("All required tools present", len(missing) == 0,
              f"missing: {missing}" if missing else f"all {len(TOOLS_REQUIRED)} present")

        # ── 3. nist_map ─────────────────────────────────────────────────
        print("\n3. nist_map — post-quantum cryptography query")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "nist_map",
                                      "arguments": {"query": "post-quantum cryptography", "top_k": 3}}})
        res, err = tool_result(resp)
        if err:
            check("nist_map", False, err)
        else:
            check("nist_map returns results", res is not None, f"index_size={res.get('index_size')}")

        # ── 4. khepra_query_stig ─────────────────────────────────────────
        print("\n4. khepra_query_stig — CCI-000001")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "khepra_query_stig",
                                      "arguments": {"control_id": "CCI-000001"}}})
        res, err = tool_result(resp)
        if err:
            check("khepra_query_stig", False, err)
        else:
            check("khepra_query_stig returns data", res is not None, f"keys={list((res or {}).keys())[:5]}")

        # ── 5. agent_record ──────────────────────────────────────────────
        print("\n5. agent_record — tamper-evident log entry")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "agent_record",
                                      "arguments": {"action": "smoke_test_v1.0.0", "agent_id": "smoke-runner"}}})
        res, err = tool_result(resp)
        if err:
            check("agent_record", False, err)
        else:
            check("recorded=true", res.get("recorded") == True, f"record_id={res.get('record_id')}")

        # ── 6. dag_attestation ──────────────────────────────────────────
        print("\n6. dag_attestation — PQC-signed DAG state")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "dag_attestation", "arguments": {}}})
        res, err = tool_result(resp)
        if err:
            check("dag_attestation", False, err)
        else:
            check("dag_attestation returns node_count", "node_count" in (res or {}),
                  f"node_count={res.get('node_count')}")

        # ── 7. owasp_agent_assess ──────────────────────────────────────
        print("\n7. owasp_agent_assess — OWASP Agentic Top 10")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "owasp_agent_assess", "arguments": {"profile": "full"}}})
        res, err = tool_result(resp)
        if err:
            check("owasp_agent_assess", False, err)
        else:
            check("standard=OWASP Agentic Top 10",
                  res.get("standard") == "OWASP Agentic Top 10",
                  f"total_risks={res.get('total_risks')} score={res.get('composite_score')}")

        # ── 8. dark_crypto_contribute ──────────────────────────────────
        print("\n8. dark_crypto_contribute — PQC crypto inventory")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "dark_crypto_contribute", "arguments": {}}})
        res, err = tool_result(resp)
        if err:
            check("dark_crypto_contribute", False, err)
        else:
            check("contribution_id present", bool(res.get("contribution_id")),
                  f"algorithms={res.get('algorithms_catalogued')} risk={res.get('quantum_risk_level')}")

        # ── 9. pqc_stig ─────────────────────────────────────────────────
        print("\n9. pqc_stig — World's First DoD PQC STIG (PQC-01-STIG-V1R1)")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "pqc_stig",
                                      "arguments": {"scan_path": "/app", "profile": "quick"}}})
        res, err = tool_result(resp)
        if err:
            check("pqc_stig", False, err)
        else:
            check("standard=PQC-01-STIG-V1R1",
                  res.get("standard") == "PQC-01-STIG-V1R1",
                  f"score={res.get('compliance_score')} verdict={res.get('verdict')}")

        # ── 10. nhi_inventory / acp_status (Enterprise — skip-ok) ──────
        print("\n10. nhi_inventory (Enterprise feature — skip if community)")
        resp = send(proc, {"jsonrpc": "2.0", "id": nxt(), "method": "tools/call",
                           "params": {"name": "nhi_inventory", "arguments": {}}})
        res, err = tool_result(resp)
        if err and is_license_error(err):
            print(f"  {SKIP}  nhi_inventory — enterprise gate (expected for community tier)")
            results["skip"] += 1
        elif err:
            check("nhi_inventory", False, err)
        else:
            check("nhi_inventory", True, "enterprise access granted")

    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ── Summary ─────────────────────────────────────────────────────────
    total = results["pass"] + results["fail"] + results["skip"]
    print(f"\n{'='*60}")
    print(f"  Results: {results['pass']}/{total} passed  "
          f"|  {results['skip']} skipped  |  {results['fail']} failed")
    print(f"  Image: {IMAGE}")
    print(f"{'='*60}\n")
    if results["fail"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
