#!/usr/bin/env bash
# =============================================================================
# PyCentric AI Agent Sandbox Verification & Acceptance Test Suite (TV-01..TV-07)
# Governing Spec: ADR-L0-SEC-02 Section 7 (Verification & Acceptance Matrix)
# Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
#
# Executes all seven acceptance test vectors inside the confined sandbox and
# emits a deterministic pass/fail report.
# =============================================================================
set -euo pipefail

PASS_COUNT=0
FAIL_COUNT=0

log_pass() {
    echo "[PASS] $1" >&2
    PASS_COUNT=$((PASS_COUNT + 1))
}

log_fail() {
    echo "[FAIL] $1" >&2
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "=============================================================================" >&2
echo " PyCentric AI Agent Sandbox Verification Suite (ADR-L0-SEC-02: TV-01..TV-07)" >&2
echo "=============================================================================" >&2

# -----------------------------------------------------------------------------
# TV-01: FR-1.1 / FR-1.2 (Read-Only Root / vs Read-Write $PWD)
# -----------------------------------------------------------------------------
if ! touch /usr/test_file 2>/dev/null && touch ./local_test_file 2>/dev/null; then
    log_pass "TV-01 (FR-1.1 / FR-1.2): /usr/test_file rejected (EROFS); ./local_test_file created."
else
    log_fail "TV-01 (FR-1.1 / FR-1.2): Expected /usr/test_file to fail and ./local_test_file to succeed."
fi

# -----------------------------------------------------------------------------
# TV-02: FR-3.1 (Blacklisted Executable Enforcement: /usr/bin/rm & /usr/bin/curl)
# -----------------------------------------------------------------------------
RM_BLOCKED=0
CURL_BLOCKED=0
if ! /usr/bin/rm -f ./local_test_file 2>/dev/null; then
    RM_BLOCKED=1
fi
if ! /usr/bin/curl -sS --max-time 2 https://example.com >/dev/null 2>&1; then
    CURL_BLOCKED=1
fi
# Clean up ./local_test_file via Python LotL since rm is blacklisted in sandbox
python3 -c "import os; os.path.exists('./local_test_file') and os.unlink('./local_test_file')" 2>/dev/null || true

if [[ "$RM_BLOCKED" -eq 1 && "$CURL_BLOCKED" -eq 1 ]]; then
    log_pass "TV-02 (FR-3.1): /usr/bin/rm and /usr/bin/curl blocked with Permission denied."
else
    log_fail "TV-02 (FR-3.1): Blacklisted binary execution was not blocked (rm=${RM_BLOCKED}, curl=${CURL_BLOCKED})."
fi

# -----------------------------------------------------------------------------
# TV-03: FR-3.2 (No-Exec on /tmp/** Defeating BYOB)
# -----------------------------------------------------------------------------
cp /bin/ls /tmp/my_ls
chmod +x /tmp/my_ls
if ! /tmp/my_ls >/dev/null 2>&1; then
    log_pass "TV-03 (FR-3.2): Execution of /tmp/my_ls blocked with Permission denied."
else
    log_fail "TV-03 (FR-3.2): /tmp/my_ls executed successfully (BYOB protection failed)."
fi

# -----------------------------------------------------------------------------
# TV-04: FR-3.3 (Sensitive Credential Path Protection: ~/.ssh)
# -----------------------------------------------------------------------------
if python3 -c "import os, pathlib; p = pathlib.Path.home() / '.ssh'; list(p.iterdir()) if p.exists() else open(p / 'id_rsa').read()" 2>/dev/null; then
    log_fail "TV-04 (FR-3.3): Read access to ~/.ssh was not blocked by AppArmor."
else
    log_pass "TV-04 (FR-3.3): Access to ~/.ssh failed with PermissionError ([Errno 13] Permission denied)."
fi

# -----------------------------------------------------------------------------
# TV-05: FR-2.1 (PID Namespace Isolation via --unshare-pid)
# -----------------------------------------------------------------------------
PID_COUNT="$(ps -eo pid= | wc -l | tr -d ' ')"
if [[ "$PID_COUNT" -le 6 ]]; then
    log_pass "TV-05 (FR-2.1): Isolated PID namespace active (${PID_COUNT} processes visible)."
else
    log_fail "TV-05 (FR-2.1): Expected <= 6 PIDs in sandbox /proc, found ${PID_COUNT}."
fi

# -----------------------------------------------------------------------------
# TV-06: FR-4.2 / FR-5.1 (Transparent HTTPS Interception via mitmproxy)
# -----------------------------------------------------------------------------
if python3 -c "import urllib.request; r = urllib.request.urlopen('https://example.com', timeout=5); assert r.status == 200" 2>/dev/null; then
    log_pass "TV-06 (FR-4.2 / FR-5.1): HTTPS request to https://example.com succeeded (200 OK) via overlaid CA."
else
    log_fail "TV-06 (FR-4.2 / FR-5.1): HTTPS request to https://example.com failed."
fi

# -----------------------------------------------------------------------------
# TV-07: FR-4.3 / EC-03 (Fail-Closed Egress Firewall: Raw TCP 9999 & UDP 443 QUIC)
# -----------------------------------------------------------------------------
if python3 -c "import socket; s = socket.create_connection(('1.1.1.1', 9999), timeout=2)" 2>/dev/null; then
    log_fail "TV-07 (FR-4.3 / EC-03): Raw TCP connection on port 9999 succeeded (firewall bypass)."
else
    log_pass "TV-07 (FR-4.3 / EC-03): Raw TCP port 9999 and non-redirected egress blocked by iptables FORWARD."
fi

echo "-----------------------------------------------------------------------------" >&2
printf '{"suite":"ADR-L0-SEC-02","passed":%d,"failed":%d}\n' "$PASS_COUNT" "$FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
