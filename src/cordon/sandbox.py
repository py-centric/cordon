"""5-Gate Bubblewrap & Namespace Execution Compiler and System Doctor for Cordon.

Implements FR-1.1..FR-2.2, FR-5.2, and EC-01..EC-05 across all universal
workload profiles (ai-agent, untrusted-code, package-build, network-audit,
gui-desktop, airgapped).
Strictly complies with the PyCentric Zero Unicode Em-Dash Rule.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

from cordon.models import (
    CordonProfile,
    DoctorCheck,
    DoctorReport,
    FilesystemMode,
    NetworkMode,
    SandboxLaunchPlan,
)

HOST_CA_CANDIDATES: tuple[str, ...] = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
)


def resolve_canonical_paths(
    workspace_dir: str | Path | None = None,
    home_dir: str | Path | None = None,
) -> tuple[Path, Path]:
    """Resolves canonical physical paths via realpath per FR-1.2 & EC-05."""
    raw_pwd = Path(workspace_dir or os.getcwd())
    raw_home = Path(home_dir or Path.home())
    real_pwd = raw_pwd.resolve()
    real_home = raw_home.resolve()
    return real_pwd, real_home


def compile_launch_plan(
    profile: CordonProfile,
    command: list[str] | tuple[str, ...] | None = None,
    *,
    workspace_dir: str | Path | None = None,
    home_dir: str | Path | None = None,
    netns_name: str = "agent-net",
    agent_shell_bin: str = "/usr/local/bin/agent-shell",
    extra_masked_bins: tuple[str, ...] = (),
    allow_git_write_override: bool | None = None,
    network_mode_override: NetworkMode | None = None,
    filesystem_mode_override: FilesystemMode | None = None,
) -> SandboxLaunchPlan:
    """Compiles the deterministic 5-gate Bubblewrap + AppArmor + netns execution plan."""
    real_pwd, real_home = resolve_canonical_paths(workspace_dir, home_dir)
    fs_mode = filesystem_mode_override or profile.filesystem_mode
    net_mode = network_mode_override or profile.network_mode
    protect_git = (
        not allow_git_write_override
        if allow_git_write_override is not None
        else profile.protect_git_dir
    )

    forbidden_rw_roots = {
        Path("/"),
        Path("/etc"),
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/boot"),
        Path("/root"),
        Path("/proc"),
        Path("/sys"),
        Path("/dev"),
        Path("/home"),
        real_home,
    }
    if fs_mode == FilesystemMode.WORKSPACE_RW and real_pwd in forbidden_rw_roots:
        raise ValueError(
            f"Refusing to mount root (/), critical system path, or entire $HOME ({real_home}) read-write. "
            "Select a project subdirectory or use --filesystem workspace-ro / ephemeral-tmpfs."
        )

    target_cmd = tuple(command) if command else ("/bin/bash", "--norc", "-i")
    combined_ca = str(real_home / ".mitmproxy" / "combined-ca-bundle.pem")
    primary_ca_target = "/etc/ssl/certs/ca-certificates.crt"

    bwrap_args: list[str] = [
        "/usr/bin/bwrap",
        # FR-1.1: Read-only base host pass-through
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        # FR-2.1: PID namespace isolation & fresh /proc mount
        "--unshare-pid",
        "--proc",
        "/proc",
        # FR-1.3: Ephemeral RAM-backed /tmp, /var/tmp, /dev/shm
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/var/tmp",
        "--tmpfs",
        "/dev/shm",
        # FR-2.2: Lifecycle coupling & setsid() terminal session isolation
        "--die-with-parent",
        "--new-session",
    ]

    # Airgapped mode unshares the network namespace directly inside bwrap
    if net_mode == NetworkMode.AIRGAPPED:
        bwrap_args.append("--unshare-net")

    # Optional $HOME tmpfs isolation for general untrusted software/scripts
    if profile.isolate_home_tmpfs:
        bwrap_args.extend(["--tmpfs", str(real_home)])

    # Filesystem workspace mounting strategy (FR-1.2)
    if fs_mode == FilesystemMode.WORKSPACE_RW:
        bwrap_args.extend(["--bind", str(real_pwd), str(real_pwd), "--chdir", str(real_pwd)])
        # EC-01: Read-only .git, .git/hooks, and .husky guards inside RW workspace
        git_dir = real_pwd / ".git"
        git_hooks_dir = real_pwd / ".git" / "hooks"
        husky_dir = real_pwd / ".husky"
        if protect_git:
            bwrap_args.extend(["--ro-bind-try", str(git_dir), str(git_dir)])
            bwrap_args.extend(["--ro-bind-try", str(git_hooks_dir), str(git_hooks_dir)])
            bwrap_args.extend(["--ro-bind-try", str(husky_dir), str(husky_dir)])
    elif fs_mode == FilesystemMode.WORKSPACE_RO:
        bwrap_args.extend(["--ro-bind", str(real_pwd), str(real_pwd), "--chdir", str(real_pwd)])
    elif fs_mode == FilesystemMode.EPHEMERAL_TMPFS:
        bwrap_args.extend(["--tmpfs", "/tmp/cordon-work", "--chdir", "/tmp/cordon-work"])

    # FR-1.4 & EC-04: Overlay combined CA bundle over distribution trust stores
    if net_mode == NetworkMode.INSPECTED:
        for ca_target in HOST_CA_CANDIDATES:
            bwrap_args.extend(["--ro-bind-try", combined_ca, ca_target])
        bwrap_args.extend(
            ["--ro-bind-try", f"/etc/netns/{netns_name}/resolv.conf", "/etc/resolv.conf"]
        )

    # FR-1.5: Supplementary binary masking via /dev/null bind mounts
    all_masked = dict.fromkeys((*profile.blacklisted_binaries, *extra_masked_bins))
    for bin_path in all_masked:
        bwrap_args.extend(["--ro-bind-try", "/dev/null", bin_path])

    # GUI / Desktop socket pass-through when requested
    if profile.pass_display_sockets:
        uid = os.getuid()
        wayland_sock = f"/run/user/{uid}/wayland-0"
        bwrap_args.extend(["--ro-bind-try", wayland_sock, wayland_sock])
        bwrap_args.extend(["--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix"])

    # FR-5.2 & EC-02: Environment variable exports
    env_exports: dict[str, str] = {
        "CORDON_SANDBOX_ACTIVE": "1",
        "CORDON_PROFILE": str(profile.name),
        "CORDON_NETWORK_MODE": str(net_mode),
        "CORDON_WORKSPACE": str(real_pwd),
        "PS1": f"[cordon:{profile.name}:\\W]\\$ ",
    }
    if net_mode == NetworkMode.INSPECTED:
        env_exports.update(
            {
                "SSL_CERT_FILE": primary_ca_target,
                "REQUESTS_CA_BUNDLE": primary_ca_target,
                "CURL_CA_BUNDLE": primary_ca_target,
                "NODE_EXTRA_CA_CERTS": primary_ca_target,
                "AWS_CA_BUNDLE": primary_ca_target,
                "GIT_SSL_CAINFO": primary_ca_target,
            }
        )
    if profile.enable_build_scratch and fs_mode == FilesystemMode.WORKSPACE_RW:
        scratch_dir = str(real_pwd / ".cordon-build-tmp")
        env_exports["TMPDIR"] = scratch_dir

    for key, val in env_exports.items():
        bwrap_args.extend(["--setenv", key, val])

    bwrap_args.append("--")
    bwrap_args.extend(target_cmd)

    # Full 5-gate command pipeline
    gates: list[str] = []
    if net_mode in (NetworkMode.INSPECTED, NetworkMode.PASSTHROUGH):
        gates.append(f"Gate 1: ip netns ({netns_name} 10.200.1.2/24)")
        full_argv: tuple[str, ...] = (
            "ip",
            "netns",
            "exec",
            netns_name,
            agent_shell_bin,
            *target_cmd,
        )
    else:
        gates.append("Gate 1: bwrap --unshare-net (Loopback Airgap)")
        full_argv = tuple(bwrap_args)

    gates.extend(
        [
            f"Gate 2: AppArmor LSM Profile ({agent_shell_bin})",
            f"Gate 3: Bubblewrap VFS ({fs_mode}) & PID Namespace (--unshare-pid)",
            "Gate 4: Sandboxed Workload Process",
        ]
    )
    if net_mode == NetworkMode.INSPECTED:
        gates.append("Gate 5: veth-host -> tshark Ring Buffer + iptables -> mitmproxy (:8080)")

    return SandboxLaunchPlan(
        profile=profile.name,
        network_mode=net_mode,
        filesystem_mode=fs_mode,
        real_pwd=str(real_pwd),
        real_home=str(real_home),
        netns_name=netns_name,
        bwrap_argv=tuple(bwrap_args),
        full_argv=full_argv,
        env_exports=env_exports,
        gates_applied=tuple(gates),
    )


def run_doctor_checks() -> DoctorReport:
    """Inspects host kernel and required binary dependencies per Section 2.2."""
    rel = platform.release()
    parts = rel.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1].split("-")[0])
        kernel_ok = (major, minor) >= (5, 15)
    except (ValueError, IndexError):
        kernel_ok = False

    checks: list[DoctorCheck] = [
        DoctorCheck(
            name="linux_kernel",
            requirement="Linux Kernel >= 5.15 (6.x recommended)",
            passed=kernel_ok,
            detail=f"Detected kernel {rel}",
        ),
    ]

    required_bins = (
        ("bubblewrap", "bwrap", "Bubblewrap >= 0.8.0 (unprivileged mount/PID namespaces)"),
        ("apparmor_parser", "apparmor_parser", "AppArmor LSM policy compiler"),
        ("iproute2", "ip", "Linux network namespace manager (ip netns)"),
        ("iptables", "iptables", "Netfilter NAT PREROUTING & fail-closed FORWARD firewall"),
        ("mitmproxy", "mitmdump", "Layer 7 transparent HTTPS inspection proxy"),
        ("tshark", "tshark", "Layer 3/4 ring-buffer packet & DNS capture"),
    )
    for check_name, bin_name, req_desc in required_bins:
        resolved = shutil.which(bin_name)
        checks.append(
            DoctorCheck(
                name=check_name,
                requirement=req_desc,
                passed=resolved is not None,
                detail=resolved or f"Binary '{bin_name}' not found on PATH",
            )
        )

    return DoctorReport(
        healthy=all(c.passed for c in checks),
        kernel_release=rel,
        checks=tuple(checks),
    )
