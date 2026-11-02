"""Programmable mitmproxy Layer 7 Policy Addon for AI Agent Sandboxes (thin wrapper).

Governing Specification: ADR-L0-SEC-02 (FR-5.1..FR-5.4, UC-02, EC-07)

This file is a DEPLOYMENT SHIM only. The single policy source (rule table,
evaluator, scanner, and canonical JSONL event schema) lives in
`src/cordon/policy_rules.py`; the reference entrypoint is
`src/cordon/mitm_addon.py`. Both addons therefore enforce byte-identical policy.

Usage (headless, production):
    mitmdump --mode transparent --showhost --set stream_large_bodies=5m \
        -s deploy/mitmproxy/agent_policy_addon.py

Usage (development with mitmweb UI):
    mitmweb --mode transparent --showhost --set stream_large_bodies=5m \
        -s deploy/mitmproxy/agent_policy_addon.py

The effective policy is read at startup from $CORDON_POLICY_FILE
(default /run/cordon/policy.json, root-owned 0644). Env overrides such as
CORDON_EXTRA_HOSTS never widen policy unless CORDON_ALLOW_INSECURE=1.
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule and [INV-STDOUT-JSON].
"""

from __future__ import annotations

import sys
from pathlib import Path

# Bootstrap import paths for both the in-repo layout (src/cordon) and the
# installed layout (/usr/lib/cordon/python). pydantic is NOT required.
for _candidate in (
    Path(__file__).resolve().parents[2] / "src",
    Path("/usr/lib/cordon/python"),
):
    if _candidate.is_dir() and str(_candidate) not in sys.path:
        sys.path.insert(0, str(_candidate))

from cordon.policy_rules import CordonMitmAddon  # noqa: E402

# Passing the CLASS defers construction (and startup policy events) until
# mitmproxy actually loads the addon.
addons = [CordonMitmAddon]
