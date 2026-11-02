"""Comprehensive Automated Test Suite for Cordon Universal Sandbox Engine.

Verifies all functional requirements (FR-1.1..FR-6.2), edge cases (EC-01..EC-07),
universal workload profiles (ai-agent, untrusted-code, package-build, network-audit,
gui-desktop, airgapped), FastAPI Control Plane endpoints, and CLI JSON stdout
invariants.
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cordon.api import CordonControlPlane
from cordon.apparmor import render_apparmor_profile
from cordon.cli import app as cli_app
from cordon.config import CordonEnvironmentConfig
from cordon.mitm_addon import CordonPolicyEvaluator
from cordon.models import FilesystemMode, NetworkMode, WorkloadKind
from cordon.network import build_mitmproxy_command, generate_network_setup_commands
from cordon.policy_rules import PolicyConfig, PolicyEngine, resolve_runtime_policy, write_policy_file
from cordon.profiles import BUILTIN_PROFILES, get_profile
from cordon.sandbox import compile_launch_plan, resolve_canonical_paths, run_doctor_checks

runner = CliRunner()


def test_builtin_universal_profiles_catalog() -> None:
    """Verifies all 6 universal workload profiles exist and enforce expected invariants."""
    assert len(BUILTIN_PROFILES) == 6
    for kind in WorkloadKind:
        prof = get_profile(kind.value)
        assert prof.name == kind
        assert "~/.ssh" in prof.protected_credential_paths
        assert "~/.aws" in prof.protected_credential_paths
        assert "~/.mitmproxy/mitmproxy-ca.pem" in prof.protected_credential_paths


def test_canonical_symlink_path_resolution_ec05(tmp_path: Path) -> None:
    """Verifies EC-05 symlink canonicalization via realpath."""
    real_repo = tmp_path / "physical_nvme" / "project_alpha"
    real_repo.mkdir(parents=True)
    symlink_repo = tmp_path / "symlink_work"
    symlink_repo.symlink_to(real_repo)

    resolved_pwd, _ = resolve_canonical_paths(symlink_repo, tmp_path)
    assert resolved_pwd == real_repo.resolve()


def test_compile_launch_plan_ai_agent_and_git_protection_ec01(tmp_path: Path) -> None:
    """Verifies FR-1.1..FR-2.2, FR-5.2, and EC-01 (.git read-only protection)."""
    repo_dir = tmp_path / "payment_service"
    (repo_dir / ".git").mkdir(parents=True)
    home_dir = tmp_path / "home_user"
    home_dir.mkdir(parents=True)

    prof = get_profile(WorkloadKind.AI_AGENT)
    plan = compile_launch_plan(
        prof,
        ["opencode"],
        workspace_dir=repo_dir,
        home_dir=home_dir,
    )

    assert plan.profile == WorkloadKind.AI_AGENT
    assert "--ro-bind" in plan.bwrap_argv
    assert "--unshare-pid" in plan.bwrap_argv
    assert "--die-with-parent" in plan.bwrap_argv
    assert str(repo_dir / ".git") in plan.bwrap_argv
    assert plan.env_exports["SSL_CERT_FILE"] == "/etc/ssl/certs/ca-certificates.crt"
    assert plan.env_exports["NODE_EXTRA_CA_CERTS"] == "/etc/ssl/certs/ca-certificates.crt"


def test_compile_launch_plan_refuses_root_or_home_rw(tmp_path: Path) -> None:
    """Verifies safety guard against mounting / or entire $HOME read-write."""
    prof = get_profile(WorkloadKind.AI_AGENT)
    with pytest.raises(ValueError, match="Refusing to mount root"):
        compile_launch_plan(prof, ["bash"], workspace_dir="/", home_dir=tmp_path)
    with pytest.raises(ValueError, match="Refusing to mount root"):
        compile_launch_plan(prof, ["bash"], workspace_dir=tmp_path, home_dir=tmp_path)


def test_compile_launch_plan_package_build_and_airgapped(tmp_path: Path) -> None:
    """Verifies EC-02 build scratch TMPDIR and airgapped --unshare-net."""
    repo_dir = tmp_path / "rust_service"
    repo_dir.mkdir()
    home_dir = tmp_path / "home"
    home_dir.mkdir()

    build_prof = get_profile(WorkloadKind.PACKAGE_BUILD)
    build_plan = compile_launch_plan(
        build_prof,
        ["cargo", "build"],
        workspace_dir=repo_dir,
        home_dir=home_dir,
    )
    assert build_plan.env_exports["TMPDIR"].endswith(".cordon-build-tmp")

    airgap_prof = get_profile(WorkloadKind.AIRGAPPED)
    airgap_plan = compile_launch_plan(
        airgap_prof,
        ["./untrusted_elf"],
        workspace_dir=repo_dir,
        home_dir=home_dir,
    )
    assert airgap_plan.network_mode == NetworkMode.AIRGAPPED
    assert airgap_plan.filesystem_mode == FilesystemMode.EPHEMERAL_TMPFS
    assert "--unshare-net" in airgap_plan.bwrap_argv


def test_compile_launch_plan_gui_desktop(tmp_path: Path) -> None:
    """Verifies GUI desktop profile passes Wayland/X11 sockets and workspace-ro."""
    repo_dir = tmp_path / "gui_project"
    repo_dir.mkdir()
    home_dir = tmp_path / "home"
    home_dir.mkdir()

    gui_prof = get_profile(WorkloadKind.GUI_DESKTOP)
    gui_plan = compile_launch_plan(
        gui_prof,
        ["firefox"],
        workspace_dir=repo_dir,
        home_dir=home_dir,
        filesystem_mode_override=FilesystemMode.WORKSPACE_RO,
    )
    assert "/tmp/.X11-unix" in gui_plan.bwrap_argv


def test_apparmor_profile_generation_fr3_and_ec06() -> None:
    """Verifies AppArmor 4.0+ profile contains userns, bwrap ix, no-exec /tmp, and credential denies."""
    prof = get_profile(WorkloadKind.AI_AGENT)
    policy = render_apparmor_profile(prof)

    assert "abi <abi/4.0>," in policy
    assert "userns," in policy
    assert "/usr/bin/bwrap ix," in policy
    assert "deny /{usr/,}bin/rm x," in policy
    assert "deny /{usr/,}bin/curl x," in policy
    assert "deny /tmp/** x," in policy
    assert "deny /var/tmp/** x," in policy
    assert "deny /dev/shm/** x," in policy
    assert "deny @{HOME}/.ssh/** rwlkmx," in policy
    assert "deny @{HOME}/.aws/** rwlkmx," in policy
    assert "deny @{HOME}/.mitmproxy/mitmproxy-ca.pem rwlkmx," in policy
    assert "deny capability net_admin," in policy
    assert "deny ptrace," in policy


def test_network_setup_and_mitmproxy_commands_fr4_ec03_ec07() -> None:
    """Verifies network namespace, RFC 9114 QUIC UDP 443 reject, DNS DNAT, and tshark ring buffer."""
    cmds = generate_network_setup_commands()
    joined = "\n".join(cmds)

    assert "ip netns add agent-net" in joined
    assert "--dports 80,443 -j REDIRECT --to-ports 8080" in joined
    assert "-p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable" in joined
    # Canonical EC-07: DNS is DNATed to the host-local resolver (dnsmasq-cordon.conf)
    assert "-p udp --dport 53 -j DNAT --to-destination 10.200.1.1:53" in joined
    assert "-p tcp --dport 53 -j DNAT --to-destination 10.200.1.1:53" in joined
    assert "tshark -i veth-host -b filesize:102400 -b files:10" in joined

    mitm_cmd = build_mitmproxy_command(
        pinned_passthrough_hosts=(r"^api\.vendor\.com:443$",),
        use_web_ui=True,
    )
    assert "--mode" in mitm_cmd
    assert "transparent" in mitm_cmd
    assert "stream_large_bodies=5m" in mitm_cmd
    assert "--ignore-hosts" in mitm_cmd


def test_mitm_policy_evaluator_uc02_and_ec07() -> None:
    """Verifies L7 allowlist, POST restriction, secret exfiltration block, and DoH block."""
    evaluator = CordonPolicyEvaluator(get_profile(WorkloadKind.AI_AGENT))

    # 1. Allowed LLM API POST without secrets
    ok_res = evaluator.evaluate_request(
        host="api.anthropic.com",
        method="POST",
        url="https://api.anthropic.com/v1/messages",
        path="/v1/messages",
        body_text='{"model": "claude-sonnet-4-20250514", "messages": []}',
    )
    assert ok_res.allowed is True
    assert ok_res.status_code == 200

    # 2. UC-02: Blocked unknown external webhook domain.
    # Field split: rule_id carries the stable machine ID (parity contract shared
    # with src/l7_policy.rs and tests/golden/l7_corpus.json); reason carries the
    # human-readable explanation.
    bad_domain = evaluator.evaluate_request(
        host="webhook.attacker-domain.io",
        method="POST",
        url="https://webhook.attacker-domain.io/collect",
        path="/collect",
        body_text="hello",
    )
    assert bad_domain.allowed is False
    assert bad_domain.status_code == 403
    assert bad_domain.rule_id == "ALLOWLIST_MISS"
    assert "allowed_domains" in bad_domain.reason

    # 3. FR-5.4: Blocked POST to a read-only registry host (e.g. pypi.org)
    bad_method = evaluator.evaluate_request(
        host="pypi.org",
        method="POST",
        url="https://pypi.org/legacy/",
        path="/legacy/",
        body_text="upload",
    )
    assert bad_method.allowed is False
    assert bad_method.rule_id == "UNAUTHORIZED_MUTATING_METHOD"
    assert "FR-5.4" in bad_method.reason

    # 4. UC-02: Blocked secret exfiltration even to an allowed LLM host
    secret_leak = evaluator.evaluate_request(
        host="api.anthropic.com",
        method="POST",
        url="https://api.anthropic.com/v1/messages",
        path="/v1/messages",
        body_text="-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=",
    )
    assert secret_leak.allowed is False
    assert secret_leak.rule_id == "SECRET_PRIVATE_KEY_PEM"
    assert secret_leak.matched_secret_pattern == "SECRET_PRIVATE_KEY_PEM"
    assert "credential exfiltration" in secret_leak.reason

    # 5. EC-07: Blocked covert DNS-over-HTTPS (DoH)
    doh_attempt = evaluator.evaluate_request(
        host="api.anthropic.com",
        method="GET",
        url="https://api.anthropic.com/dns-query?name=evil.com",
        path="/dns-query",
    )
    assert doh_attempt.allowed is False
    assert doh_attempt.rule_id == "DOH_RESOLVER_BLOCK"
    assert "DoH" in doh_attempt.reason


def test_control_plane_endpoints() -> None:
    """Verifies Cordon Control Plane and Web Dashboard routes."""
    plane = CordonControlPlane()

    status, ctype, dash_body = plane.handle_request("GET", "/")
    assert status == 200
    assert "text/html" in ctype
    assert "Cordon Universal Sandbox" in dash_body

    status, _, health_body = plane.handle_request("GET", "/api/v1/health")
    assert status == 200
    assert json.loads(health_body)["service"] == "cordon"

    status, _, profiles_body = plane.handle_request("GET", "/api/v1/profiles")
    assert status == 200
    assert len(json.loads(profiles_body)) == 6

    status, _, doc_body = plane.handle_request("GET", "/api/v1/doctor")
    assert status == 200
    assert "kernel_release" in json.loads(doc_body)

    status, _, preview_body = plane.handle_request(
        "POST",
        "/api/v1/command/preview",
        {
            "profile": "untrusted-code",
            "command": ["python3", "untrusted.py"],
            "workspace_dir": "/tmp/demo-project",
        },
    )
    assert status == 200
    assert json.loads(preview_body)["profile"] == "untrusted-code"

    status, _, eval_body = plane.handle_request(
        "POST",
        "/api/v1/policy/evaluate",
        {
            "profile": "ai-agent",
            "host": "webhook.attacker.io",
            "method": "POST",
            "url": "https://webhook.attacker.io/exfil",
            "path": "/exfil",
            "body_text": "DATABASE_URL=postgres://secret",
        },
    )
    assert status == 200
    assert json.loads(eval_body)["allowed"] is False

    status, _, events_body = plane.handle_request("GET", "/api/v1/audit/events?profile=ai-agent")
    assert status == 200
    assert len(json.loads(events_body)) >= 1

    status, _, aa_body = plane.handle_request("GET", "/api/v1/apparmor/ai-agent")
    assert status == 200
    assert "abi <abi/4.0>," in json.loads(aa_body)["apparmor_policy"]

    status, _, net_body = plane.handle_request("GET", "/api/v1/network/commands")
    assert status == 200
    assert len(json.loads(net_body)["commands"]) > 10

    status, _, not_found = plane.handle_request("GET", "/api/v1/unknown")
    assert status == 404
    assert json.loads(not_found)["error"] == "NOT_FOUND"


def test_cli_json_stdout_invariants(tmp_path: Path) -> None:
    """Verifies CLI commands emit deterministic JSON to stdout when --json is passed."""
    ver_res = runner.invoke(cli_app, ["version", "--json"])
    assert ver_res.exit_code == 0
    assert json.loads(ver_res.stdout)["service"] == "cordon"

    prof_res = runner.invoke(cli_app, ["profiles", "--json"])
    assert prof_res.exit_code == 0
    assert len(json.loads(prof_res.stdout)) == 6

    doc_res = runner.invoke(cli_app, ["doctor", "--json"])
    assert doc_res.exit_code == 0
    assert "checks" in json.loads(doc_res.stdout)

    ws = tmp_path / "subproject"
    ws.mkdir()
    run_res = runner.invoke(
        cli_app,
        ["run", "--profile", "untrusted-code", "--workspace", str(ws), "--json", "python3", "a.py"],
    )
    assert run_res.exit_code == 0
    assert json.loads(run_res.stdout)["profile"] == "untrusted-code"

    proxy_res = runner.invoke(
        cli_app,
        [
            "proxy",
            "--profile",
            "ai-agent",
            "--evaluate-url",
            "https://webhook.evil.io/steal",
            "--method",
            "POST",
            "--json",
        ],
    )
    assert proxy_res.exit_code == 0
    assert json.loads(proxy_res.stdout)["allowed"] is False


def test_doctor_checks_execution() -> None:
    """Verifies run_doctor_checks returns structured DoctorReport."""
    report = run_doctor_checks()
    assert len(report.checks) == 7


def test_sandbox_hardening_remediations(tmp_path: Path) -> None:
    """Verifies --new-session, .git/hooks + .husky RO mounts, system path refusal, IPv6 block, and OpenAI/JWT secret checks."""
    home_dir = tmp_path / "user_home"
    repo_dir = home_dir / "workspace_repo"
    (repo_dir / ".git" / "hooks").mkdir(parents=True)
    (repo_dir / ".husky").mkdir(parents=True)

    prof = get_profile(WorkloadKind.AI_AGENT)
    plan = compile_launch_plan(
        prof,
        ["opencode"],
        workspace_dir=repo_dir,
        home_dir=home_dir,
    )
    assert "--new-session" in plan.bwrap_argv
    assert str(repo_dir / ".git" / "hooks") in plan.bwrap_argv
    assert str(repo_dir / ".husky") in plan.bwrap_argv

    with pytest.raises(ValueError, match="Refusing to mount root"):
        compile_launch_plan(prof, ["bash"], workspace_dir="/etc", home_dir=home_dir)

    net_joined = "\n".join(generate_network_setup_commands())
    assert "net.ipv6.conf.all.disable_ipv6=1" in net_joined
    assert "ip6tables -A FORWARD -i veth-host -j DROP" in net_joined

    evaluator = CordonPolicyEvaluator(prof)
    openai_leak = evaluator.evaluate_request(
        host="api.anthropic.com",
        method="POST",
        url="https://api.anthropic.com/v1/messages",
        path="/v1/messages",
        body_text="padding " * 600 + "sk-1234567890abcdefghijklmnop",
    )
    assert openai_leak.allowed is False
    assert openai_leak.rule_id == "SECRET_OPENAI_KEY"
    assert openai_leak.matched_secret_pattern == "SECRET_OPENAI_KEY"


def test_block_events_carry_rule_id_and_fingerprint_never_payload() -> None:
    """Verifies audit events carry rule_id + secret_fingerprint and NEVER raw payload bytes."""
    evaluator = CordonPolicyEvaluator(get_profile(WorkloadKind.AI_AGENT))
    secret = "sk-1234567890abcdefghijklmnop"
    decision = evaluator.evaluate_request(
        host="api.anthropic.com",
        method="POST",
        url="https://api.anthropic.com/v1/messages",
        path="/v1/messages",
        body_text=f"leak {secret}",
    )
    assert decision.allowed is False
    event = evaluator.audit_buffer[-1]
    assert event.rule_id == "SECRET_OPENAI_KEY"
    assert event.secret_fingerprint is not None
    assert len(event.secret_fingerprint) == 16
    assert event.secret_fingerprint not in secret
    assert secret not in event.model_dump_json()


def test_l7_golden_corpus_python_parity() -> None:
    """Conformance: PolicyEngine must score the shared golden corpus exactly like Rust.

    src/l7_policy.rs evaluates the SAME tests/golden/l7_corpus.json via its
    inline include_str! test, so any Python/Rust engine divergence fails at
    least one suite (TECH_DEBT_VERIFICATION_POLICY same-commit rule).
    """
    corpus = json.loads(
        (Path(__file__).parent / "golden" / "l7_corpus.json").read_text(encoding="utf-8")
    )
    engine = PolicyEngine(PolicyConfig.from_mapping(corpus["profile"]))
    assert len(corpus["cases"]) >= 25
    for case in corpus["cases"]:
        result = engine.evaluate(
            method=case["method"],
            url=case["url"],
            headers=dict(case.get("headers") or {}),
            body_text=case.get("payload") or "",
            body_streamed=bool(case.get("body_streamed", False)),
        )
        verdict = "ALLOW" if result.allowed else "BLOCK"
        assert verdict == case["expected_verdict"], case["id"]
        assert result.rule_id == case["expected_rule_id"], case["id"]


def test_cordonfile_policy_wiring_reaches_running_addon(tmp_path: Path) -> None:
    """FR-5.3: ALLOW_DOMAIN / DENY_DOMAIN / POST_ALLOWED_HOST reach the addon via the policy JSON file."""
    cfg = CordonEnvironmentConfig.from_cordonfile_str(
        "FROM ai-agent\n"
        "ALLOW_DOMAIN api.vendor.com registry.example.com\n"
        "DENY_DOMAIN webhook.site\n"
        "POST_ALLOWED_HOST api.vendor.com\n"
    )
    policy = cfg.resolve_effective_policy()
    assert policy.strict_whitelist is True
    assert "api.vendor.com" in policy.allowed_domains
    assert "webhook.site" in policy.denied_domains
    assert "api.vendor.com" in policy.post_allowed_hosts

    policy_path = tmp_path / "policy.json"
    write_policy_file(policy, policy_path)

    # The running addon resolves its policy from the file at startup.
    resolved = resolve_runtime_policy({"CORDON_POLICY_FILE": str(policy_path)})
    assert resolved.events == ()
    assert resolved.config.strict_whitelist is True
    assert resolved.config.allowed_domains == policy.allowed_domains
    assert resolved.config.denied_domains == policy.denied_domains
    assert resolved.config.post_allowed_hosts == policy.post_allowed_hosts

    engine = PolicyEngine(resolved.config, session_id=resolved.session_id)
    denied = engine.evaluate(method="POST", url="https://webhook.site/collect", body_text="x")
    assert denied.rule_id == "DENY_DOMAIN:webhook.site"
    post_blocked = engine.evaluate(
        method="POST", url="https://registry.example.com/upload", body_text="x"
    )
    assert post_blocked.rule_id == "UNAUTHORIZED_MUTATING_METHOD"
    allow_get = engine.evaluate(method="GET", url="https://api.vendor.com/ok")
    assert allow_get.rule_id == "DEFAULT_ALLOW"


def test_env_overrides_cannot_widen_policy_without_insecure_flag() -> None:
    """CORDON_EXTRA_HOSTS never widens policy without CORDON_ALLOW_INSECURE=1 (logged as events)."""
    base_env = {
        "CORDON_POLICY_FILE": "/nonexistent/cordon-policy.json",
        "CORDON_EXTRA_HOSTS": "evil.example.com",
    }
    ignored = resolve_runtime_policy(base_env)
    assert "evil.example.com" not in ignored.config.allowed_domains
    assert any(e["rule_id"] == "POLICY_ENV_OVERRIDE_IGNORED" for e in ignored.events)

    widened = resolve_runtime_policy({**base_env, "CORDON_ALLOW_INSECURE": "1"})
    assert "evil.example.com" in widened.config.allowed_domains
    assert any(e["rule_id"] == "POLICY_ENV_WIDENED" for e in widened.events)


def test_cli_run_config_serializes_policy_for_addon(tmp_path: Path) -> None:
    """Verifies cordon run --config serializes Cordonfile policy for the L7 addon."""
    cfg_file = tmp_path / "Cordonfile"
    cfg_file.write_text(
        "FROM ai-agent\n"
        "ALLOW_DOMAIN api.vendor.com\n"
        "DENY_DOMAIN webhook.site\n"
        "POST_ALLOWED_HOST api.vendor.com\n",
        encoding="utf-8",
    )
    workspace = tmp_path / "work"
    workspace.mkdir()
    policy_path = tmp_path / "policy.json"

    res = runner.invoke(
        cli_app,
        [
            "run",
            "--config",
            str(cfg_file),
            "--workspace",
            str(workspace),
            "--dry-run",
            "--json",
            "python3",
            "a.py",
        ],
        env={"CORDON_POLICY_FILE": str(policy_path)},
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)
    assert payload["profile"] == "ai-agent"
    assert payload["policy_file"]["path"] == str(policy_path)
    joined = "\n".join(payload["policy_file"]["commands"])
    assert "api.vendor.com" in joined
    assert "webhook.site" in joined

