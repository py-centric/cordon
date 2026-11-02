"""Cordon CLI: Universal Sandbox & L3/L4/L7 Network Inspection Orchestrator.

Adheres to the PyCentric CLI taxonomy and [INV-STDOUT-JSON] constitutional
stream separation:
  - sys.stdout is strictly reserved for deterministic JSON (--json) or raw rendered configs.
  - sys.stderr receives all Rich tables, banners, and human-readable diagnostics.
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from cordon import __version__
from cordon.apparmor import render_apparmor_profile
from cordon.config import CordonEnvironmentConfig
from cordon.mitm_addon import CordonPolicyEvaluator
from cordon.models import FilesystemMode, NetworkMode, WorkloadKind
from cordon.network import (
    build_mitmproxy_command,
    build_policy_file_commands,
    generate_network_setup_commands,
)
from cordon.policy_rules import DEFAULT_POLICY_FILE, write_policy_file
from cordon.profiles import BUILTIN_PROFILES, get_profile
from cordon.sandbox import compile_launch_plan, run_doctor_checks

app = typer.Typer(
    name="cordon",
    help=(
        "Cordon: Universal Lightweight Host Sandbox & L3/L4/L7 Network Inspection Pipeline "
        "(AppArmor + Bubblewrap + ip netns + iptables + mitmproxy + tshark)."
    ),
    no_args_is_help=True,
)
err_console = Console(stderr=True)


def _emit_json(payload: object) -> None:
    """Writes deterministic machine-parseable JSON to stdout per [INV-STDOUT-JSON]."""
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    sys.stdout.flush()


@app.command("version")
def cmd_version(
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine JSON to stdout.")] = False,
) -> None:
    """Display Cordon version and governing ADR metadata."""
    data = {
        "service": "cordon",
        "package": "pycentric-cordon",
        "version": __version__,
        "governing_adr": "ADR-L0-SEC-02",
    }
    if as_json:
        _emit_json(data)
    else:
        err_console.print(f"[bold blue]cordon[/bold blue] v{__version__} (ADR-L0-SEC-02)")


@app.command("doctor")
def cmd_doctor(
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine JSON to stdout.")] = False,
) -> None:
    """Verify Linux kernel, AppArmor LSM, Bubblewrap, iproute2, iptables, mitmproxy, and tshark."""
    report = run_doctor_checks()
    if as_json:
        _emit_json(report.model_dump())
        return

    table = Table(title=f"Cordon System Readiness (Kernel {report.kernel_release})")
    table.add_column("Component", style="cyan")
    table.add_column("Requirement")
    table.add_column("Status")
    table.add_column("Detail", style="dim")

    for check in report.checks:
        status = "[bold green]PASS[/bold green]" if check.passed else "[bold red]MISSING[/bold red]"
        table.add_row(check.name, check.requirement, status, check.detail)

    err_console.print(table)


@app.command("profiles")
def cmd_profiles(
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine JSON to stdout.")] = False,
) -> None:
    """List all built-in universal workload isolation profiles."""
    profiles_list = [p.model_dump() for p in BUILTIN_PROFILES.values()]
    if as_json:
        _emit_json(profiles_list)
        return

    table = Table(title="Cordon Universal Workload Isolation Profiles")
    table.add_column("Profile", style="bold cyan")
    table.add_column("Filesystem Mode", style="green")
    table.add_column("Network Mode", style="yellow")
    table.add_column("Description")

    for prof in BUILTIN_PROFILES.values():
        table.add_row(
            str(prof.name),
            str(prof.filesystem_mode),
            str(prof.network_mode),
            prof.description,
        )
    err_console.print(table)


@app.command("run")
def cmd_run(
    command: Annotated[
        list[str] | None,
        typer.Argument(help="Target software, binary, script, or AI agent command to execute."),
    ] = None,
    profile: Annotated[
        WorkloadKind,
        typer.Option("--profile", "-p", help="Workload isolation profile."),
    ] = WorkloadKind.AI_AGENT,
    network: Annotated[
        NetworkMode | None,
        typer.Option(
            "--network", "-n", help="Override network mode (inspected/passthrough/airgapped)."
        ),
    ] = None,
    filesystem: Annotated[
        FilesystemMode | None,
        typer.Option("--filesystem", "-f", help="Override workspace VFS mount mode."),
    ] = None,
    workspace: Annotated[
        str | None,
        typer.Option("--workspace", "-w", help="Target directory (defaults to $PWD)."),
    ] = None,
    allow_git_write: Annotated[
        bool,
        typer.Option("--allow-git-write", help="Allow writes to $PWD/.git directory."),
    ] = False,
    mask_bin: Annotated[
        list[str] | None,
        typer.Option("--mask-bin", help="Additional binaries to mask with /dev/null (FR-1.5)."),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Compile and print the 5-gate execution plan without exec."),
    ] = False,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit compiled launch plan as JSON to stdout."),
    ] = False,
    config: Annotated[
        str | None,
        typer.Option(
            "--config",
            help=(
                "Path to a Cordonfile / Cordonfile.toml / cordon.json whose ALLOW_DOMAIN, "
                "DENY_DOMAIN, and POST_ALLOWED_HOST policy is serialized to the L7 policy "
                "file consumed by the running mitmproxy addon. The config's PROFILE/FROM "
                "directive selects the base profile (overrides --profile)."
            ),
        ),
    ] = None,
) -> None:
    """Execute any software, script, build, or AI agent inside the Cordon 5-gate sandbox."""
    prof = get_profile(profile)
    env_cfg: CordonEnvironmentConfig | None = None
    if config is not None:
        env_cfg = CordonEnvironmentConfig.from_file(config)
        prof = env_cfg.resolve_effective_profile()
    plan = compile_launch_plan(
        prof,
        command or ["/bin/bash", "--norc", "-i"],
        workspace_dir=workspace,
        extra_masked_bins=tuple(mask_bin or ()),
        allow_git_write_override=allow_git_write if allow_git_write else None,
        network_mode_override=network,
        filesystem_mode_override=filesystem,
    )
    policy_path = os.environ.get("CORDON_POLICY_FILE") or DEFAULT_POLICY_FILE
    policy_commands: tuple[str, ...] = ()
    if env_cfg is not None:
        policy_commands = build_policy_file_commands(
            env_cfg.resolve_effective_policy().to_mapping(),
            policy_path=policy_path,
        )

    if as_json:
        payload: dict[str, object] = dict(plan.model_dump())
        if env_cfg is not None:
            payload["policy_file"] = {"path": policy_path, "commands": list(policy_commands)}
        _emit_json(payload)
        return

    if dry_run:
        err_console.print(f"[bold green]Compiled Cordon Launch Plan ({plan.profile}):[/bold green]")
        for gate in plan.gates_applied:
            err_console.print(f"  - {gate}")
        err_console.print(f"\n[bold]Command:[/bold] {' '.join(plan.bwrap_argv)}")
        if env_cfg is not None:
            err_console.print(f"\n[bold]L7 policy file ({policy_path}):[/bold]")
            for cmd in policy_commands:
                err_console.print(f"  {cmd}")
        return

    # FR-5.3: Materialize the effective L7 policy before launch (fail closed).
    if env_cfg is not None:
        try:
            written = write_policy_file(env_cfg.resolve_effective_policy(), policy_path)
        except OSError as exc:
            err_console.print(
                f"[bold red]ERROR:[/bold red] Failed to write L7 policy file '{policy_path}': {exc}"
            )
            raise typer.Exit(code=1) from exc
        err_console.print(f"[bold green]L7 policy written:[/bold green] {written}")

    os.execvp(plan.bwrap_argv[0], list(plan.bwrap_argv))


@app.command("apparmor")
def cmd_apparmor(
    profile: Annotated[
        WorkloadKind,
        typer.Option("--profile", "-p", help="Workload profile to render AppArmor rules for."),
    ] = WorkloadKind.AI_AGENT,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON to stdout.")] = False,
) -> None:
    """Render the AppArmor 4.0+ kernel MAC profile for /etc/apparmor.d/."""
    prof = get_profile(profile)
    rendered = render_apparmor_profile(prof)
    if as_json:
        _emit_json({"profile": str(profile), "apparmor_policy": rendered})
    else:
        sys.stdout.write(rendered)
        sys.stdout.flush()


@app.command("net")
def cmd_net(
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON to stdout.")] = False,
) -> None:
    """Output the ip netns, veth, iptables (RFC 9114 QUIC reject + DNS DNAT), and tshark commands."""
    cmds = generate_network_setup_commands()
    if as_json:
        _emit_json({"commands": list(cmds)})
    else:
        for cmd in cmds:
            sys.stdout.write(cmd + "\n")
        sys.stdout.flush()


@app.command("proxy")
def cmd_proxy(
    profile: Annotated[
        WorkloadKind,
        typer.Option("--profile", "-p", help="Profile to evaluate against."),
    ] = WorkloadKind.AI_AGENT,
    evaluate_url: Annotated[
        str | None,
        typer.Option("--evaluate-url", help="Simulate L7 policy evaluation for a target URL."),
    ] = None,
    method: Annotated[
        str,
        typer.Option("--method", "-X", help="HTTP method for policy simulation."),
    ] = "GET",
    body: Annotated[
        str,
        typer.Option("--body", help="Optional HTTP request body to scan for secret leaks."),
    ] = "",
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON to stdout.")] = False,
) -> None:
    """Generate the transparent mitmproxy launch command or simulate an L7 policy decision."""
    prof = get_profile(profile)
    if evaluate_url:
        from urllib.parse import urlparse

        parsed = urlparse(evaluate_url)
        host = parsed.hostname or evaluate_url
        path = parsed.path or "/"
        evaluator = CordonPolicyEvaluator(prof)
        decision = evaluator.evaluate_request(
            host=host,
            method=method,
            url=evaluate_url,
            path=path,
            body_text=body,
        )
        if as_json:
            _emit_json(decision.model_dump())
        else:
            verdict = "ALLOWED" if decision.allowed else "BLOCKED (403)"
            err_console.print(
                f"[bold]{verdict}[/bold] | profile={decision.profile} | "
                f"reason={decision.reason} | url={decision.url}"
            )
        return

    cmd = build_mitmproxy_command(pinned_passthrough_hosts=prof.pinned_passthrough_hosts)
    if as_json:
        _emit_json({"profile": str(profile), "mitmproxy_argv": list(cmd)})
    else:
        sys.stdout.write(" ".join(cmd) + "\n")
        sys.stdout.flush()


@app.command("serve")
def cmd_serve(
    host: Annotated[str, typer.Option("--host", help="Bind address.")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port.")] = 8095,
) -> None:
    """Start the Cordon HTTP Control Plane & Web Dashboard."""
    from cordon.api import serve_control_plane

    err_console.print(
        f"[bold green]Starting Cordon Control Plane on http://{host}:{port}[/bold green]"
    )
    serve_control_plane(host=host, port=port)


if __name__ == "__main__":
    app()
