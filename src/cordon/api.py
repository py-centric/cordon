"""Cordon Control Plane HTTP Server & WCAG AA Responsive Web Dashboard.

Provides a zero-bloat, standard-library ThreadingHTTPServer + Pydantic v2
REST Control Plane and an interactive WCAG AA tri-theme (Dark / Light / High Contrast)
Web Dashboard for inspecting universal workload profiles, simulating L7 HTTP/HTTPS
policy evaluations, previewing 5-gate Bubblewrap + AppArmor + netns launch plans,
and viewing live audit telemetry.
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import BaseModel, ConfigDict, Field

from cordon.apparmor import render_apparmor_profile
from cordon.mitm_addon import CordonPolicyEvaluator
from cordon.models import WorkloadKind
from cordon.network import generate_network_setup_commands
from cordon.profiles import BUILTIN_PROFILES, get_profile
from cordon.sandbox import compile_launch_plan, run_doctor_checks


class PolicyEvaluateRequest(BaseModel):
    """Request payload for simulating an L7 outbound HTTP/HTTPS call."""

    model_config = ConfigDict(extra="forbid")

    profile: WorkloadKind = Field(default=WorkloadKind.AI_AGENT)
    host: str = Field(..., examples=["api.anthropic.com", "webhook.attacker.io"])
    method: str = Field(default="POST")
    url: str = Field(default="https://api.anthropic.com/v1/messages")
    path: str = Field(default="/v1/messages")
    body_text: str = Field(default="")


class LaunchPlanRequest(BaseModel):
    """Request payload for compiling a 5-gate sandbox launch plan."""

    model_config = ConfigDict(extra="forbid")

    profile: WorkloadKind = Field(default=WorkloadKind.AI_AGENT)
    command: list[str] = Field(default_factory=lambda: ["python3", "main.py"])
    workspace_dir: str = Field(default="/tmp/demo-project")


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cordon | Universal Linux Sandbox & Network Inspection Control Plane</title>
  <style>
    :root {
      --bg: #0b1120;
      --surface: #111827;
      --border: #1e293b;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #3b82f6;
      --ok: #10b981;
      --danger: #ef4444;
    }
    [data-theme="light"] {
      --bg: #f8fafc;
      --surface: #ffffff;
      --border: #cbd5e1;
      --text: #0f172a;
      --muted: #475569;
      --accent: #2563eb;
      --ok: #059669;
      --danger: #dc2626;
    }
    [data-theme="contrast"] {
      --bg: #000000;
      --surface: #0a0a0a;
      --border: #ffffff;
      --text: #ffffff;
      --muted: #fde047;
      --accent: #38bdf8;
      --ok: #4ade80;
      --danger: #f87171;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem 2rem;
      border-bottom: 1px solid var(--border);
      background: var(--surface);
    }
    main {
      max-width: 1200px;
      margin: 1.5rem auto;
      padding: 0 1.5rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 1.25rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1.25rem;
    }
    h1, h2, h3 { margin-top: 0; }
    button {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 0.375rem;
      padding: 0.45rem 0.9rem;
      cursor: pointer;
      font-weight: 600;
    }
    pre {
      background: rgba(0, 0, 0, 0.25);
      padding: 0.75rem;
      border-radius: 0.375rem;
      overflow-x: auto;
      font-size: 0.82rem;
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>Cordon Universal Sandbox &amp; Network Pipeline</h1>
      <small>AppArmor LSM + Bubblewrap + ip netns + iptables + mitmproxy + tshark (ADR-L0-SEC-02)</small>
    </div>
    <div>
      <button onclick="document.documentElement.dataset.theme='dark'">Dark</button>
      <button onclick="document.documentElement.dataset.theme='light'">Light</button>
      <button onclick="document.documentElement.dataset.theme='contrast'">High Contrast</button>
    </div>
  </header>
  <main>
    <section class="card" aria-labelledby="profiles-heading">
      <h2 id="profiles-heading">Universal Workload Profiles</h2>
      <ul>
        <li><strong>ai-agent</strong>: Local AI CLI agents (opencode, antigravity, pi) with RW workspace, RO .git, L7 LLM inspection.</li>
        <li><strong>untrusted-code</strong>: Arbitrary scripts &amp; third-party binaries with RO workspace &amp; tmpfs-masked $HOME.</li>
        <li><strong>package-build</strong>: Supply-chain safe npm/pip/cargo builds with local TMPDIR &amp; GET-only registry allowlist.</li>
        <li><strong>network-audit</strong>: Binary reverse-engineering &amp; telemetry mode with 100% PCAP + L7 flow logging.</li>
        <li><strong>gui-desktop</strong>: Contained Wayland/X11 desktop &amp; browser applications.</li>
        <li><strong>airgapped</strong>: Zero-network (--unshare-net) + ephemeral RAM workspace.</li>
      </ul>
    </section>
    <section class="card" aria-labelledby="cli-heading">
      <h2 id="cli-heading">Quick-Start CLI Commands</h2>
      <pre># Run any untrusted Python or binary in sandbox:
cordon run --profile untrusted-code -- python3 script.py

# Run AI CLI coding agent in current repo:
cordon run --profile ai-agent -- opencode

# Run airgapped binary with zero network or disk mutation:
cordon run --profile airgapped -- ./unknown_binary

# Run supply-chain safe package installation:
cordon run --profile package-build -- npm install</pre>
    </section>
  </main>
</body>
</html>
"""


class CordonControlPlane:
    """In-process REST router and state controller for Cordon."""

    def __init__(self) -> None:
        self.evaluator_cache: dict[WorkloadKind, CordonPolicyEvaluator] = {
            kind: CordonPolicyEvaluator(profile) for kind, profile in BUILTIN_PROFILES.items()
        }

    def handle_request(
        self,
        method: str,
        raw_url: str,
        body: bytes | str | dict[str, Any] | None = None,
    ) -> tuple[int, str, str]:
        """Routes a control-plane HTTP request and returns (status_code, content_type, body)."""
        parsed = urlparse(raw_url)
        path = parsed.path
        query = parse_qs(parsed.query)
        verb = method.upper()

        if verb == "GET" and path == "/":
            return 200, "text/html; charset=utf-8", DASHBOARD_HTML

        if verb == "GET" and path in {"/health", "/api/v1/health"}:
            return (
                200,
                "application/json",
                json.dumps(
                    {
                        "status": "ok",
                        "service": "cordon",
                        "version": "1.0.0",
                        "governing_adr": "ADR-L0-SEC-02",
                    }
                ),
            )

        if verb == "GET" and path == "/health/liveness":
            return 200, "application/json", json.dumps({"status": "alive"})

        if verb == "GET" and path == "/health/readiness":
            return (
                200,
                "application/json",
                json.dumps({"status": "ready", "profiles_loaded": len(BUILTIN_PROFILES)}),
            )

        if verb == "GET" and path == "/metrics":
            total_events = sum(len(ev.audit_buffer) for ev in self.evaluator_cache.values())
            prom_text = (
                "# HELP cordon_profiles_total Total registered sandbox profiles\n"
                "# TYPE cordon_profiles_total gauge\n"
                f"cordon_profiles_total {len(BUILTIN_PROFILES)}\n"
                "# HELP cordon_audit_events_buffered Total buffered audit events\n"
                "# TYPE cordon_audit_events_buffered gauge\n"
                f"cordon_audit_events_buffered {total_events}\n"
            )
            return 200, "text/plain; version=0.0.4", prom_text

        if verb == "GET" and path == "/api/v1/profiles":
            payload = [p.model_dump() for p in BUILTIN_PROFILES.values()]
            return 200, "application/json", json.dumps(payload)

        if verb == "GET" and path == "/api/v1/doctor":
            return 200, "application/json", run_doctor_checks().model_dump_json()

        if verb == "GET" and path == "/api/v1/network/commands":
            return (
                200,
                "application/json",
                json.dumps({"commands": list(generate_network_setup_commands())}),
            )

        if verb == "GET" and path.startswith("/api/v1/apparmor/"):
            prof_slug = path.removeprefix("/api/v1/apparmor/")
            prof = get_profile(prof_slug)
            return (
                200,
                "application/json",
                json.dumps(
                    {
                        "profile": str(prof.name),
                        "apparmor_policy": render_apparmor_profile(prof),
                    }
                ),
            )

        if verb == "GET" and path == "/api/v1/audit/events":
            prof_param = query.get("profile", [WorkloadKind.AI_AGENT.value])[0]
            kind = WorkloadKind(prof_param)
            events = [e.model_dump() for e in self.evaluator_cache[kind].audit_buffer]
            return 200, "application/json", json.dumps(events)

        if verb == "POST" and path == "/api/v1/command/preview":
            data = self._parse_json(body)
            req = LaunchPlanRequest.model_validate(data)
            prof = get_profile(req.profile)
            plan = compile_launch_plan(
                prof,
                req.command,
                workspace_dir=Path(req.workspace_dir),
                home_dir=Path("/home/sandbox-user"),
            )
            return 200, "application/json", plan.model_dump_json()

        if verb == "POST" and path == "/api/v1/policy/evaluate":
            data = self._parse_json(body)
            eval_req = PolicyEvaluateRequest.model_validate(data)
            evaluator = self.evaluator_cache[eval_req.profile]
            decision = evaluator.evaluate_request(
                host=eval_req.host,
                method=eval_req.method,
                url=eval_req.url,
                path=eval_req.path,
                body_text=eval_req.body_text,
            )
            return 200, "application/json", decision.model_dump_json()

        return 404, "application/json", json.dumps({"error": "NOT_FOUND", "path": path})

    @staticmethod
    def _parse_json(body: bytes | str | dict[str, Any] | None) -> dict[str, Any]:
        if isinstance(body, dict):
            return body
        if isinstance(body, bytes):
            return json.loads(body.decode("utf-8"))
        if isinstance(body, str) and body:
            return json.loads(body)
        return {}


def serve_control_plane(host: str = "127.0.0.1", port: int = 8095) -> None:
    """Starts the Cordon HTTP Control Plane and Web Dashboard server."""
    plane = CordonControlPlane()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            status, ctype, payload = plane.handle_request("GET", self.path)
            self._send(status, ctype, payload)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            status, ctype, payload = plane.handle_request("POST", self.path, raw)
            self._send(status, ctype, payload)

        def _send(self, status: int, ctype: str, payload: str) -> None:
            encoded = payload.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(encoded)))
            trace_id = self.headers.get("Trace-ID")
            if trace_id:
                self.send_header("Trace-ID", trace_id)
            idem_key = self.headers.get("Idempotency-Key")
            if idem_key:
                self.send_header("Idempotency-Key", idem_key)
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()
