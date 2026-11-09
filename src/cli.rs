//! `clap` (derive) CLI and `stdout`/`stderr` stream-split orchestration for Cordon.

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use chrono::Utc;
use clap::builder::PossibleValuesParser;
use clap::{CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{Shell, generate};

use crate::api::{CordonControlPlane, serve_control_plane};
use crate::apparmor::{try_render_apparmor_microvm_profile, try_render_apparmor_profile};
use crate::config::{
    CordonEnvironmentConfig, RESERVED_ENV_KEYS, expand_tilde, get_config_template,
    list_config_templates, parse_env_assignment, parse_volume_spec,
};
use crate::domain::{
    IsolationBackend, RawMicroVmSpec, SandboxLaunchPlan, TapSlot, Verdict, VmDiskMode,
};
use crate::error::CordonError;
use crate::groups::{
    COMMAND_GROUP_CANDIDATES, list_command_group_infos, list_directory_group_infos,
};
use crate::l7_policy::CordonPolicyEvaluator;
use crate::network::{generate_microvm_tap_commands, generate_network_setup_commands};
use crate::plugins::{
    PLUGIN_CANDIDATES, list_available_plugins_with_workspace, resolve_plugin_with_policy,
};
use crate::profiles::{get_profile, list_profiles};
use crate::repl::{ReplNetMode, ReplSession, run_interactive_repl, write_groups_summary};
use crate::sandbox::{prepare_live_execution_argv, run_doctor_checks};
use crate::tui::{render_tui_snapshot, run_interactive_tui};

/// Built-in sandbox profile names advertised to shell completion engines (`bash`, `zsh`, `fish`).
pub const PROFILE_CANDIDATES: [&str; 6] = [
    "ai-agent",
    "untrusted-code",
    "package-build",
    "network-audit",
    "gui-desktop",
    "airgapped",
];

/// Built-in reproducible config template slugs advertised to shell completion engines.
pub const TEMPLATE_CANDIDATES: [&str; 4] =
    ["opencode", "antigravity", "python-sandbox", "package-build"];

/// Supported config serialization formats advertised to shell completion engines.
pub const CONFIG_FORMAT_CANDIDATES: [&str; 3] = ["cordonfile", "toml", "json"];

/// Common HTTP methods advertised to shell completion engines for `evaluate-url`.
pub const HTTP_METHOD_CANDIDATES: [&str; 6] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"];

/// Cordon: Universal Linux Sandbox & L3-L7 Network Inspection Pipeline.
#[derive(Debug, Parser)]
#[command(
    name = "cordon",
    version,
    about = "Lightweight Blacklist Sandbox & L3-L7 Network Inspection Pipeline (Engineered by PyCentric)"
)]
pub struct CordonCli {
    /// Emit machine-parseable JSON to stdout while routing diagnostics to stderr.
    #[arg(long, global = true)]
    pub json: bool,

    /// Permit reserved environment keys (SSL_CERT_FILE, HTTPS_PROXY, LD_PRELOAD, ...) to be set
    /// from configs or `--env`; overrides are recorded as audited warnings.
    #[arg(long = "allow-reserved-env", global = true)]
    pub allow_reserved_env: bool,

    /// Permit workspace-relative plugin manifests (`./plugins/*/plugin.toml`) to be loaded;
    /// denied by default so hostile workspaces cannot shadow or extend the plugin catalog.
    #[arg(long = "allow-workspace-plugins", global = true)]
    pub allow_workspace_plugins: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Subcommands for managing reproducible Cordon environment files (`Cordonfile` / `Cordonfile.toml` / `cordon.json`).
#[derive(Debug, Subcommand)]
pub enum ConfigSubcommand {
    /// List built-in reproducible environment templates (`opencode`, `antigravity`, `python-sandbox`, `package-build`).
    ListTemplates,

    /// Scaffold a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json` from a template.
    Init {
        /// Template slug (`opencode`, `antigravity`, `python-sandbox`, `package-build`).
        #[arg(
            short,
            long,
            default_value = "opencode",
            value_parser = PossibleValuesParser::new(TEMPLATE_CANDIDATES)
        )]
        template: String,
        /// Output format (`cordonfile`, `toml`, `json`).
        #[arg(
            short,
            long,
            default_value = "cordonfile",
            value_parser = PossibleValuesParser::new(CONFIG_FORMAT_CANDIDATES)
        )]
        format: String,
        /// Optional output file path (prints to stdout when omitted).
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },

    /// Validate a `Cordonfile`, `Cordonfile.toml`, or `cordon.json` and preview its 5-gate launch plan.
    Validate {
        /// Path to the configuration file to validate.
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        file: PathBuf,
    },
}

/// Subcommands for inspecting and managing the tmux-style Cordon plugin ecosystem (`cordon-fish`, `cordon-hud`).
#[derive(Debug, Subcommand)]
pub enum PluginSubcommand {
    /// List all available Cordon plugins (`cordon-fish`, `cordon-hud`, and custom `plugins/*/plugin.toml`).
    List,

    /// Inspect manifest details, features, groups, and aliases for a specific plugin.
    Info {
        /// Plugin name or repo identifier (`cordon-fish`, `cordon-hud`).
        #[arg(
            default_value = "cordon-hud",
            value_parser = PossibleValuesParser::new(PLUGIN_CANDIDATES)
        )]
        name: String,
    },
}

/// Supported CLI subcommands.
/// Gate 3.5 MicroVM flags shared by `run` and `inspect-cmd`. Any flag enables the MicroVM plane
/// and overrides the matching `[vm]` / `VM_*` setting of a loaded config.
#[derive(Debug, Clone, Default, clap::Args)]
pub struct VmCliArgs {
    /// MicroVM isolation backend (`qemu-microvm`, `firecracker`; `native-bwrap` disables it).
    #[arg(long = "vm-backend", value_enum)]
    pub vm_backend: Option<IsolationBackend>,
    /// Guest vCPUs (1-32).
    #[arg(long = "vm-vcpus")]
    pub vm_vcpus: Option<u8>,
    /// Guest memory in MiB (128-65536).
    #[arg(long = "vm-memory")]
    pub vm_memory: Option<u32>,
    /// Guest disk mode (`virtio-fs-live`, `ephemeral-tmpfs`, `btrfs-cow-overlay`, `snapshot-restore`).
    #[arg(long = "vm-disk-mode", value_enum)]
    pub vm_disk_mode: Option<VmDiskMode>,
    /// Guest kernel image (under `/boot`, `/var/lib/cordon/kernels`, or `~/.local/share/cordon/kernels`).
    #[arg(long = "vm-kernel", value_hint = ValueHint::FilePath)]
    pub vm_kernel: Option<String>,
    /// Guest root filesystem image (under `/var/lib/cordon/images` or `~/.local/share/cordon/images`).
    #[arg(long = "vm-rootfs", value_hint = ValueHint::FilePath)]
    pub vm_rootfs: Option<String>,
    /// Named Firecracker snapshot to restore (implies `--vm-disk-mode snapshot-restore`).
    #[arg(long = "vm-snapshot")]
    pub vm_snapshot: Option<String>,
}

impl VmCliArgs {
    /// Returns `true` when any MicroVM flag was passed.
    pub const fn is_set(&self) -> bool {
        self.vm_backend.is_some()
            || self.vm_vcpus.is_some()
            || self.vm_memory.is_some()
            || self.vm_disk_mode.is_some()
            || self.vm_kernel.is_some()
            || self.vm_rootfs.is_some()
            || self.vm_snapshot.is_some()
    }

    /// Overlays these flags onto the config's raw `[vm]` settings.
    pub fn apply_to(&self, cfg: &mut CordonEnvironmentConfig) {
        if !self.is_set() {
            return;
        }
        let vm = cfg.vm.get_or_insert_with(RawMicroVmSpec::default);
        if let Some(backend) = self.vm_backend {
            vm.backend = backend;
        }
        if let Some(vcpus) = self.vm_vcpus {
            vm.vcpus = Some(vcpus);
        }
        if let Some(memory) = self.vm_memory {
            vm.memory_mib = Some(memory);
        }
        if let Some(ref kernel) = self.vm_kernel {
            vm.kernel_image = Some(expand_tilde(kernel));
        }
        if let Some(ref rootfs) = self.vm_rootfs {
            vm.rootfs_image = Some(expand_tilde(rootfs));
        }
        if let Some(ref snapshot) = self.vm_snapshot {
            vm.snapshot = Some(snapshot.clone());
            vm.disk_mode = Some(VmDiskMode::SnapshotRestore);
        }
        if let Some(mode) = self.vm_disk_mode {
            vm.disk_mode = Some(mode);
        }
    }
}

/// Gate 3.5 MicroVM subcommands.
#[derive(Debug, Subcommand)]
pub enum VmSubcommand {
    /// Internal: Gate 3.5 supervisor executed inside the Bubblewrap tail of a MicroVM plan.
    #[command(hide = true)]
    Supervise {
        /// Validated MicroVM spec (JSON).
        #[arg(long = "spec-json")]
        spec_json: String,
        /// Run identifier.
        #[arg(long = "run-id")]
        run_id: String,
        /// Tap selection (`auto` or `none`).
        #[arg(long, default_value = "none")]
        tap: String,
        /// Comma-separated environment keys forwarded into the guest.
        #[arg(long = "forward-env", default_value = "")]
        forward_env: String,
        /// Guest command.
        #[arg(num_args = 0.., trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
}

/// Refuses live execution of MicroVM plans until the guest agent and supervisor ship
/// (`--dry-run`, `inspect-cmd`, and the API compile plans normally).
fn ensure_live_launch_supported(plan: &SandboxLaunchPlan) -> Result<(), CordonError> {
    if plan.microvm.is_some() {
        return Err(CordonError::MicroVmUnavailable(
            "live MicroVM launch is not available in this build yet; use --dry-run or inspect-cmd to review the Gate 3.5 plan".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Compile and execute (or dry-run) any command or `Cordonfile` inside the 5-gate Cordon sandbox.
    #[command(visible_alias = "exec")]
    Run {
        /// Workload profile (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`).
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`.
        #[arg(short = 'f', long = "config", value_hint = ValueHint::FilePath)]
        config: Option<PathBuf>,
        /// Workspace directory to bind inside Bubblewrap.
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        workspace: Option<PathBuf>,
        /// Docker/Podman-style volume mount (`<HOST_PATH>[:ro|:rw]`, defaults to `:ro`).
        #[arg(short = 'v', long = "volume", value_hint = ValueHint::AnyPath)]
        volumes: Vec<String>,
        /// Additional host paths to bind read-only (`--ro-bind`).
        #[arg(long = "bind-ro", value_hint = ValueHint::DirPath)]
        bind_ro: Vec<String>,
        /// Additional host paths to bind read-write (`--bind`).
        #[arg(long = "bind-rw", value_hint = ValueHint::DirPath)]
        bind_rw: Vec<String>,
        /// Additional host binary paths to mask with `/dev/null`.
        #[arg(long = "mask-bin", value_hint = ValueHint::FilePath)]
        mask_bins: Vec<String>,
        /// Expose/unmask specific host binaries inside the sandbox (`bat`, `rg`, `fd`, `jq`, etc.).
        #[arg(long = "allow-bin", value_hint = ValueHint::CommandName)]
        allow_bins: Vec<String>,
        /// Enable pre-populated command groups (`coreutils`, `shell-builtins`, `search-tools`, `vcs-git`, `rust-toolchain`, `python-uv`, `node-web`, `net-diag`).
        #[arg(
            long = "allow-group",
            value_parser = PossibleValuesParser::new(COMMAND_GROUP_CANDIDATES)
        )]
        allow_groups: Vec<String>,
        /// Mount pre-populated directory groups (`system-libs`, `ssl-certs`, `xdg-config`, `agent-state`, `toolchain-caches`, `temp-scratch`).
        #[arg(long = "mount-group")]
        mount_groups: Vec<String>,
        /// Additional environment variables (`KEY=VALUE`) injected into the sandbox.
        #[arg(short = 'e', long = "env")]
        envs: Vec<String>,
        /// Additional outbound domains permitted by L7 policy.
        #[arg(long = "allow-domain", value_hint = ValueHint::Hostname)]
        allow_domains: Vec<String>,
        /// Force complete loopback air-gap (`bwrap --unshare-net`) regardless of profile default.
        #[arg(long)]
        offline: bool,
        /// Force direct host network namespace inside Bubblewrap (bypassing `ip netns exec`).
        #[arg(long = "host-net")]
        host_net: bool,
        /// Gate 3.5 MicroVM options.
        #[command(flatten)]
        vm: VmCliArgs,
        /// Compile and print the 5-gate execution plan without spawning the child process.
        #[arg(long)]
        dry_run: bool,
        /// Target command and arguments to execute inside the sandbox (optional if `--config` defines `CMD`).
        #[arg(
            num_args = 0..,
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_hint = ValueHint::CommandWithArguments
        )]
        argv: Vec<String>,
    },

    /// Launch an interactive sandboxed `/bin/bash --norc` shell inside Bubblewrap.
    Shell {
        /// Workload profile (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`).
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`.
        #[arg(short = 'f', long = "config", value_hint = ValueHint::FilePath)]
        config: Option<PathBuf>,
        /// Workspace directory to bind inside Bubblewrap.
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        workspace: Option<PathBuf>,
        /// Docker/Podman-style volume mount (`<HOST_PATH>[:ro|:rw]`, defaults to `:ro`).
        #[arg(short = 'v', long = "volume", value_hint = ValueHint::AnyPath)]
        volumes: Vec<String>,
        /// Expose/unmask specific host binaries inside the sandbox (`bat`, `rg`, `fd`, `jq`, etc.).
        #[arg(long = "allow-bin", value_hint = ValueHint::CommandName)]
        allow_bins: Vec<String>,
        /// Enable pre-populated command groups (`coreutils`, `shell-builtins`, `search-tools`, etc.).
        #[arg(
            long = "allow-group",
            value_parser = PossibleValuesParser::new(COMMAND_GROUP_CANDIDATES)
        )]
        allow_groups: Vec<String>,
        /// Mount pre-populated directory groups (`xdg-config`, `agent-state`, `toolchain-caches`, etc.).
        #[arg(long = "mount-group")]
        mount_groups: Vec<String>,
        /// Force complete loopback air-gap (`bwrap --unshare-net`).
        #[arg(long)]
        offline: bool,
        /// Force direct host network namespace inside Bubblewrap.
        #[arg(long = "host-net")]
        host_net: bool,
        /// Print the prepared sandbox shell command without spawning.
        #[arg(long)]
        dry_run: bool,
    },

    /// Start the interactive Cordon Sandbox Control & Execution REPL (`cordon repl`).
    Repl {
        /// Initial workload profile slug.
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`.
        #[arg(short = 'f', long = "config", value_hint = ValueHint::FilePath)]
        config: Option<PathBuf>,
        /// Initial workspace directory.
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        workspace: Option<PathBuf>,
        /// Expose/unmask specific host binaries in the REPL session (`bat`, `rg`, etc.).
        #[arg(long = "allow-bin", value_hint = ValueHint::CommandName)]
        allow_bins: Vec<String>,
        /// Enable pre-populated command groups in the REPL session (`coreutils`, `search-tools`, etc.).
        #[arg(
            long = "allow-group",
            value_parser = PossibleValuesParser::new(COMMAND_GROUP_CANDIDATES)
        )]
        allow_groups: Vec<String>,
        /// Mount pre-populated directory groups in the REPL session (`xdg-config`, `agent-state`, etc.).
        #[arg(long = "mount-group")]
        mount_groups: Vec<String>,
        /// Start REPL in offline air-gap mode (`bwrap --unshare-net`).
        #[arg(long)]
        offline: bool,
        /// Start REPL in direct host network mode.
        #[arg(long = "host-net")]
        host_net: bool,
        /// Dry-run mode inside REPL (`run` / `!<cmd>` prints command instead of spawning).
        #[arg(long)]
        dry_run: bool,
    },

    /// List all 6 built-in universal workload sandbox profiles.
    Profiles,

    /// List all 8 pre-populated command groups (`coreutils`, `search-tools`, etc.) and 6 directory groups (`xdg-config`, etc.).
    Groups,

    /// Manage the tmux-style Cordon plugin ecosystem (`cordon-fish`, `cordon-hud`).
    #[command(visible_alias = "plugins")]
    Plugin {
        /// Plugin subcommand (`list`, `info`).
        #[command(subcommand)]
        action: PluginSubcommand,
    },

    /// Manage reproducible `Cordonfile` / `Cordonfile.toml` / `cordon.json` environment configs.
    Config {
        /// Config action (`list-templates`, `init`, `validate`).
        #[command(subcommand)]
        action: ConfigSubcommand,
    },

    /// Compile and inspect the Bubblewrap (`bwrap`) and `ip netns` launch plan.
    InspectCmd {
        /// Workload profile slug.
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Optional path to a reproducible `Cordonfile`, `Cordonfile.toml`, or `cordon.json`.
        #[arg(short = 'f', long = "config", value_hint = ValueHint::FilePath)]
        config: Option<PathBuf>,
        /// Workspace directory to bind.
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        workspace: Option<PathBuf>,
        /// Docker/Podman-style volume mount (`<HOST_PATH>[:ro|:rw]`, defaults to `:ro`).
        #[arg(short = 'v', long = "volume", value_hint = ValueHint::AnyPath)]
        volumes: Vec<String>,
        /// Additional host paths to bind read-only.
        #[arg(long = "bind-ro", value_hint = ValueHint::DirPath)]
        bind_ro: Vec<String>,
        /// Additional host paths to bind read-write.
        #[arg(long = "bind-rw", value_hint = ValueHint::DirPath)]
        bind_rw: Vec<String>,
        /// Additional host binary paths to mask with `/dev/null`.
        #[arg(long = "mask-bin", value_hint = ValueHint::FilePath)]
        mask_bins: Vec<String>,
        /// Expose/unmask specific host binaries (`bat`, `rg`, etc.).
        #[arg(long = "allow-bin", value_hint = ValueHint::CommandName)]
        allow_bins: Vec<String>,
        /// Enable pre-populated command groups (`coreutils`, `search-tools`, etc.).
        #[arg(
            long = "allow-group",
            value_parser = PossibleValuesParser::new(COMMAND_GROUP_CANDIDATES)
        )]
        allow_groups: Vec<String>,
        /// Mount pre-populated directory groups (`xdg-config`, `agent-state`, etc.).
        #[arg(long = "mount-group")]
        mount_groups: Vec<String>,
        /// Additional environment variables (`KEY=VALUE`) injected into the sandbox.
        #[arg(short = 'e', long = "env")]
        envs: Vec<String>,
        /// Gate 3.5 MicroVM options.
        #[command(flatten)]
        vm: VmCliArgs,
        /// Target command and arguments (optional if `--config` defines `CMD`).
        #[arg(num_args = 0.., trailing_var_arg = true, value_hint = ValueHint::CommandWithArguments)]
        argv: Vec<String>,
    },

    /// Render the AppArmor 4.0 Mandatory Access Control profile.
    RenderApparmor {
        /// Workload profile slug.
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Binary path to attach the AppArmor profile to.
        #[arg(long, default_value = "/usr/local/bin/agent-shell", value_hint = ValueHint::FilePath)]
        attach_path: String,
        /// Render the Gate 3.5 `cordon_<slug>_microvm` variant (grants `/dev/kvm`, `/dev/net/tun`).
        #[arg(long)]
        microvm: bool,
    },

    /// Render the idempotent `ip netns`, `veth`, and `iptables` provisioning commands.
    RenderNetns {
        /// Workload profile slug.
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Also render the Gate 3.5 MicroVM tap pool (`tcvm<n>`, `10.200.255.0/24`).
        #[arg(long)]
        microvm: bool,
        /// Number of MicroVM tap slots to provision (1-16).
        #[arg(long = "tap-pool", default_value_t = TapSlot::DEFAULT_POOL)]
        tap_pool: u8,
        /// Owner uid of the persistent taps (defaults to the invoking user).
        #[arg(long = "tap-owner-uid")]
        tap_owner_uid: Option<u32>,
    },

    /// Gate 3.5 MicroVM operations.
    Vm {
        /// MicroVM action.
        #[command(subcommand)]
        action: VmSubcommand,
    },

    /// Evaluate an outbound HTTP/HTTPS request against L7 domain, DoH, and secret rules.
    EvaluateUrl {
        /// Workload profile slug.
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Outbound URL to inspect.
        #[arg(short, long, value_hint = ValueHint::Url)]
        url: String,
        /// HTTP method (`GET`, `POST`, etc.).
        #[arg(
            short,
            long,
            default_value = "GET",
            value_parser = PossibleValuesParser::new(HTTP_METHOD_CANDIDATES)
        )]
        method: String,
        /// Optional HTTP request body to scan for leaked secrets.
        #[arg(short, long)]
        body: Option<String>,
    },

    /// Verify host kernel LSM capabilities and sandbox toolchain binaries.
    Doctor,

    /// Start the `axum` HTTP Control Plane and WCAG AA Web Dashboard.
    Serve {
        /// Bind address.
        #[arg(long, default_value = "127.0.0.1", value_hint = ValueHint::Hostname)]
        host: String,
        /// Bind TCP port.
        #[arg(long, default_value_t = 8095)]
        port: u16,
    },

    /// Launch the interactive `ratatui` Terminal UI & Sandbox Session Launcher (or `--snapshot` for static frame).
    Tui {
        /// Initial workload profile (`ai-agent`, `untrusted-code`, `package-build`, `network-audit`, `gui-desktop`, `airgapped`).
        #[arg(
            short,
            long,
            default_value = "ai-agent",
            value_parser = PossibleValuesParser::new(PROFILE_CANDIDATES)
        )]
        profile: String,
        /// Initial workspace directory.
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        workspace: Option<PathBuf>,
        /// Render a static non-interactive frame snapshot and exit immediately.
        #[arg(long)]
        snapshot: bool,
    },

    /// Generate shell completion scripts (`bash`, `zsh`, `fish`).
    Completions {
        /// Target shell (`bash`, `zsh`, `fish`, `elvish`, `powershell`).
        #[arg(value_enum)]
        shell: Shell,
        /// Optional output file path to write the generated completion script.
        #[arg(short, long, value_hint = ValueHint::FilePath)]
        output: Option<PathBuf>,
    },
}

/// Emits a structured JSON diagnostic event strictly to `stderr`.
pub fn log_stderr_diagnostic(level: &str, event: &str, detail: &str) {
    let payload = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "level": level,
        "service": "cordon",
        "event": event,
        "detail": detail,
    });
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{payload}");
}

#[allow(clippy::too_many_arguments)]
fn build_plan_from_cli_options(
    profile: &str,
    config_file: Option<&PathBuf>,
    workspace: Option<&PathBuf>,
    volumes: &[String],
    readonly_binds: &[String],
    writable_binds: &[String],
    mask_bins: &[String],
    allow_bins: &[String],
    allow_groups: &[String],
    mount_groups: &[String],
    envs: &[String],
    allow_domains: &[String],
    argv: &[String],
    allow_reserved_env: bool,
    vm: &VmCliArgs,
) -> Result<SandboxLaunchPlan> {
    let mut env_cfg = if let Some(cfg_path) = config_file {
        CordonEnvironmentConfig::from_file(cfg_path)?
    } else {
        CordonEnvironmentConfig {
            base_profile: profile.to_owned(),
            ..CordonEnvironmentConfig::default()
        }
    };
    vm.apply_to(&mut env_cfg);

    for dom in allow_domains {
        if !env_cfg.allowed_domains.contains(dom) {
            env_cfg.allowed_domains.push(dom.clone());
        }
    }
    for bin in allow_bins {
        if !env_cfg.allowed_binaries.contains(bin) {
            env_cfg.allowed_binaries.push(bin.clone());
        }
    }
    for grp in allow_groups {
        if !env_cfg.command_groups.contains(grp) {
            env_cfg.command_groups.push(grp.clone());
        }
    }
    for dgrp in mount_groups {
        if !env_cfg.directory_groups.contains(dgrp) {
            env_cfg.directory_groups.push(dgrp.clone());
        }
    }

    let mut readonly_mounts: Vec<String> = readonly_binds.iter().map(|p| expand_tilde(p)).collect();
    let mut writable_mounts: Vec<String> = writable_binds.iter().map(|p| expand_tilde(p)).collect();
    for vol_spec in volumes {
        let (path, is_rw) = parse_volume_spec(vol_spec)?;
        if is_rw {
            writable_mounts.push(path);
        } else {
            readonly_mounts.push(path);
        }
    }

    let mut parsed_env = BTreeMap::new();
    for raw_env in envs {
        let (k, v) = parse_env_assignment(raw_env)?;
        parsed_env.insert(k, v);
    }

    // CH-03/CH-04 hygiene: reserved env keys are rejected by the compiler unless explicitly
    // allowed; when allowed, record an audit diagnostic listing every overridden key.
    let mut reserved_hits: Vec<String> = Vec::new();
    for key in env_cfg.env.keys().chain(parsed_env.keys()) {
        if RESERVED_ENV_KEYS.contains(&key.as_str()) && !reserved_hits.contains(key) {
            reserved_hits.push(key.clone());
        }
    }
    if allow_reserved_env && !reserved_hits.is_empty() {
        log_stderr_diagnostic(
            "WARN",
            "env.reserved_override_allowed",
            &format!("keys={}", reserved_hits.join(",")),
        );
    }

    let ws_ref = workspace.map(PathBuf::as_path);
    let (_prof, plan) = env_cfg.compile_plan_with_policy(
        ws_ref,
        argv,
        &readonly_mounts,
        &writable_mounts,
        mask_bins,
        &parsed_env,
        allow_reserved_env,
    )?;
    Ok(plan)
}

/// Executes a parsed [`CordonCli`] command and returns the desired process exit code.
#[allow(clippy::too_many_lines)]
pub async fn execute_cli(cli: CordonCli) -> Result<i32> {
    match cli.command {
        Commands::Profiles => {
            let profiles = list_profiles();
            log_stderr_diagnostic(
                "INFO",
                "profiles.list",
                &format!("count={}", profiles.len()),
            );
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "profiles": profiles }))?
                );
            } else {
                for p in &profiles {
                    println!(
                        "{:<16} [{:?} | {:?}] - {}",
                        p.name, p.filesystem_mode, p.network_mode, p.description
                    );
                }
            }
            Ok(0)
        }

        Commands::Groups => {
            let cmd_groups = list_command_group_infos();
            let dir_groups = list_directory_group_infos();
            log_stderr_diagnostic(
                "INFO",
                "groups.list",
                &format!("cmd={},dir={}", cmd_groups.len(), dir_groups.len()),
            );
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "command_groups": cmd_groups,
                        "directory_groups": dir_groups,
                    }))?
                );
            } else {
                let mut stdout = std::io::stdout().lock();
                write_groups_summary(&mut stdout)?;
            }
            Ok(0)
        }

        Commands::Plugin { action } => match action {
            PluginSubcommand::List => {
                let plugins = list_available_plugins_with_workspace(cli.allow_workspace_plugins);
                log_stderr_diagnostic("INFO", "plugin.list", &format!("count={}", plugins.len()));
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({ "plugins": plugins }))?
                    );
                } else {
                    for p in &plugins {
                        println!(
                            "{:<16} ({}) v{} - {}",
                            p.name, p.repo_id, p.version, p.description
                        );
                    }
                }
                Ok(0)
            }
            PluginSubcommand::Info { name } => {
                let plugin = resolve_plugin_with_policy(&name, cli.allow_workspace_plugins)?;
                log_stderr_diagnostic("INFO", "plugin.info", &plugin.name);
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&plugin)?);
                } else {
                    println!(
                        "Plugin:           {} ({}) v{}",
                        plugin.name, plugin.repo_id, plugin.version
                    );
                    println!("Description:      {}", plugin.description);
                    println!("Features:         {:?}", plugin.features);
                    println!("Command Groups:   {:?}", plugin.default_command_groups);
                    println!("Directory Groups: {:?}", plugin.default_directory_groups);
                    println!("Aliases:          {:?}", plugin.aliases);
                }
                Ok(0)
            }
        },

        Commands::Config { action } => match action {
            ConfigSubcommand::ListTemplates => {
                let templates = list_config_templates();
                log_stderr_diagnostic(
                    "INFO",
                    "config.templates",
                    &format!("count={}", templates.len()),
                );
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &serde_json::json!({ "templates": templates })
                        )?
                    );
                } else {
                    for t in &templates {
                        println!(
                            "{:<18} [base: {:<14} | file: {:<24}] - {}",
                            t.slug, t.base_profile, t.default_filename, t.summary
                        );
                    }
                }
                Ok(0)
            }
            ConfigSubcommand::Init {
                template,
                format,
                output,
            } => {
                let cfg = get_config_template(&template)?;
                let rendered = match format.trim().to_ascii_lowercase().as_str() {
                    "cordonfile" | "dockerfile" => cfg.to_cordonfile_string(),
                    "toml" => cfg.to_toml_string(),
                    "json" => serde_json::to_string_pretty(&cfg)?,
                    other => {
                        anyhow::bail!(
                            "Unsupported format '{other}'. Expected 'cordonfile', 'toml', or 'json'."
                        );
                    }
                };
                if let Some(ref out_path) = output {
                    std::fs::write(out_path, &rendered)?;
                    log_stderr_diagnostic(
                        "INFO",
                        "config.init",
                        &format!("wrote={}", out_path.display()),
                    );
                } else {
                    print!("{rendered}");
                }
                Ok(0)
            }
            ConfigSubcommand::Validate { file } => {
                let cfg = CordonEnvironmentConfig::from_file(&file)?;
                let (merged_profile, plan) =
                    cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new())?;
                log_stderr_diagnostic("INFO", "config.validate", &cfg.name);
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "valid": true,
                            "config": cfg,
                            "merged_profile": merged_profile.name,
                            "launch_plan": plan,
                        }))?
                    );
                } else {
                    println!(
                        "VALID: '{}' (base_profile={}, workspace={}) -> {}",
                        cfg.name,
                        cfg.base_profile,
                        plan.canonical_workspace,
                        plan.full_argv.join(" ")
                    );
                }
                Ok(0)
            }
        },

        Commands::InspectCmd {
            profile,
            config,
            workspace,
            volumes,
            bind_ro,
            bind_rw,
            mask_bins,
            allow_bins,
            allow_groups,
            mount_groups,
            envs,
            vm,
            argv,
        } => {
            let plan = build_plan_from_cli_options(
                &profile,
                config.as_ref(),
                workspace.as_ref(),
                &volumes,
                &bind_ro,
                &bind_rw,
                &mask_bins,
                &allow_bins,
                &allow_groups,
                &mount_groups,
                &envs,
                &[],
                &argv,
                cli.allow_reserved_env,
                &vm,
            )?;
            log_stderr_diagnostic("INFO", "sandbox.inspect_cmd", &plan.profile_name);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!("{}", plan.full_argv.join(" "));
            }
            Ok(0)
        }

        Commands::Run {
            profile,
            config,
            workspace,
            volumes,
            bind_ro,
            bind_rw,
            mask_bins,
            allow_bins,
            allow_groups,
            mount_groups,
            envs,
            allow_domains,
            offline,
            host_net,
            vm,
            dry_run,
            argv,
        } => {
            let plan = build_plan_from_cli_options(
                &profile,
                config.as_ref(),
                workspace.as_ref(),
                &volumes,
                &bind_ro,
                &bind_rw,
                &mask_bins,
                &allow_bins,
                &allow_groups,
                &mount_groups,
                &envs,
                &allow_domains,
                &argv,
                cli.allow_reserved_env,
                &vm,
            )?;
            log_stderr_diagnostic("INFO", "sandbox.run", &plan.profile_name);

            if dry_run {
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&plan)?);
                } else if offline || host_net {
                    let (live_argv, _) = prepare_live_execution_argv(&plan, offline, host_net);
                    println!("{}", live_argv.join(" "));
                } else {
                    println!("{}", plan.full_argv.join(" "));
                }
                return Ok(0);
            }

            ensure_live_launch_supported(&plan)?;
            let (live_argv, fallback_notice) =
                prepare_live_execution_argv(&plan, offline, host_net);
            if let Some(ref notice) = fallback_notice {
                log_stderr_diagnostic("WARN", "sandbox.netns_fallback", notice);
            }
            let Some((program, args)) = live_argv.split_first() else {
                return Ok(1);
            };
            let status = Command::new(program).args(args).status()?;
            Ok(status.code().unwrap_or(1))
        }

        Commands::Shell {
            profile,
            config,
            workspace,
            volumes,
            allow_bins,
            allow_groups,
            mount_groups,
            offline,
            host_net,
            dry_run,
        } => {
            let shell_argv = if std::path::Path::new("/bin/bash").exists() {
                vec!["/bin/bash".to_owned(), "--norc".to_owned()]
            } else {
                vec!["/bin/sh".to_owned()]
            };
            let plan = build_plan_from_cli_options(
                &profile,
                config.as_ref(),
                workspace.as_ref(),
                &volumes,
                &[],
                &[],
                &[],
                &allow_bins,
                &allow_groups,
                &mount_groups,
                &[],
                &[],
                &shell_argv,
                cli.allow_reserved_env,
                &VmCliArgs::default(),
            )?;
            log_stderr_diagnostic("INFO", "sandbox.shell", &plan.profile_name);
            let (live_argv, fallback_notice) =
                prepare_live_execution_argv(&plan, offline, host_net);
            if let Some(ref notice) = fallback_notice {
                log_stderr_diagnostic("WARN", "sandbox.netns_fallback", notice);
            }
            if dry_run {
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&plan)?);
                } else {
                    println!("{}", live_argv.join(" "));
                }
                return Ok(0);
            }
            ensure_live_launch_supported(&plan)?;
            let Some((program, args)) = live_argv.split_first() else {
                return Ok(1);
            };
            let status = Command::new(program).args(args).status()?;
            Ok(status.code().unwrap_or(1))
        }

        Commands::Repl {
            profile,
            config,
            workspace,
            allow_bins,
            allow_groups,
            mount_groups,
            offline,
            host_net,
            dry_run,
        } => {
            let net_mode = if offline {
                ReplNetMode::Airgap
            } else if host_net {
                ReplNetMode::Direct
            } else {
                ReplNetMode::Auto
            };
            let mut session = ReplSession::new(&profile, config, workspace, net_mode, dry_run)?;
            for b in allow_bins {
                if !session.allowed_binaries.contains(&b) {
                    session.allowed_binaries.push(b);
                }
            }
            for g in allow_groups {
                if !session.command_groups.contains(&g) {
                    session.command_groups.push(g);
                }
            }
            for mg in mount_groups {
                if !session.directory_groups.contains(&mg) {
                    session.directory_groups.push(mg);
                }
            }
            log_stderr_diagnostic("INFO", "repl.start", &session.profile);
            run_interactive_repl(&mut session)
        }

        Commands::RenderApparmor {
            profile,
            attach_path,
            microvm,
        } => {
            let prof = get_profile(&profile)?;
            let text = if microvm {
                try_render_apparmor_microvm_profile(&prof, &attach_path)?
            } else {
                try_render_apparmor_profile(&prof, &attach_path)?
            };
            log_stderr_diagnostic("INFO", "apparmor.render", &prof.name);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "profile": prof.name,
                        "attach_path": attach_path,
                        "apparmor_policy": text,
                    }))?
                );
            } else {
                print!("{text}");
            }
            Ok(0)
        }

        Commands::RenderNetns {
            profile,
            microvm,
            tap_pool,
            tap_owner_uid,
        } => {
            let prof = get_profile(&profile)?;
            let mut commands = generate_network_setup_commands(&prof);
            if microvm {
                if !(1..=TapSlot::MAX_POOL).contains(&tap_pool) {
                    return Err(CordonError::InvalidInput(format!(
                        "--tap-pool must be between 1 and {}",
                        TapSlot::MAX_POOL
                    ))
                    .into());
                }
                let uid = tap_owner_uid.unwrap_or_else(|| {
                    use std::os::unix::fs::MetadataExt;
                    std::fs::metadata("/proc/self").map_or(0, |m| m.uid())
                });
                commands.extend(generate_microvm_tap_commands(&prof, tap_pool, uid));
            }
            log_stderr_diagnostic("INFO", "netns.render", &prof.name);
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "profile": prof.name,
                        "netns_name": prof.netns_name,
                        "commands": commands,
                    }))?
                );
            } else {
                for cmd in &commands {
                    println!("{cmd}");
                }
            }
            Ok(0)
        }

        Commands::EvaluateUrl {
            profile,
            url,
            method,
            body,
        } => {
            let prof = get_profile(&profile)?;
            let evaluator = CordonPolicyEvaluator::new(prof);
            let decision = evaluator.evaluate_request(&url, &method, body.as_deref());
            log_stderr_diagnostic("INFO", "l7.evaluate", &decision.matched_rule);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&decision)?);
            } else {
                println!(
                    "[{:?}] HTTP {} ({}) - {}",
                    decision.verdict, decision.status_code, decision.matched_rule, decision.reason
                );
            }
            Ok(if decision.verdict == Verdict::Block {
                3
            } else {
                0
            })
        }

        Commands::Vm { action } => match action {
            VmSubcommand::Supervise { run_id, .. } => {
                log_stderr_diagnostic("ERROR", "microvm.supervise", &run_id);
                Err(CordonError::MicroVmUnavailable(
                    "the Gate 3.5 supervisor (cordon-guest-init transport) is not available in this build yet".to_owned(),
                )
                .into())
            }
        },

        Commands::Doctor => {
            let report = run_doctor_checks();
            log_stderr_diagnostic(
                "INFO",
                "doctor.check",
                if report.healthy {
                    "healthy"
                } else {
                    "degraded"
                },
            );
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("Platform: {}", report.platform_summary);
                for check in &report.checks {
                    let badge = if check.passed { "PASS" } else { "WARN" };
                    println!("  [{badge}] {:<20} {}", check.name, check.detail);
                }
            }
            Ok(0)
        }

        Commands::Serve { host, port } => {
            log_stderr_diagnostic("INFO", "control_plane.serve", &format!("{host}:{port}"));
            serve_control_plane(&host, port).await?;
            Ok(0)
        }

        Commands::Tui {
            profile,
            workspace,
            snapshot,
        } => {
            let is_main_thread = std::thread::current().name() == Some("main");
            if !snapshot
                && !cli.json
                && is_main_thread
                && std::io::stdin().is_terminal()
                && std::io::stdout().is_terminal()
            {
                log_stderr_diagnostic("INFO", "tui.interactive", &profile);
                return Ok(run_interactive_tui(&profile, workspace)?);
            }
            let plane = CordonControlPlane::new();
            let rendered = render_tui_snapshot(&plane, 100, 16)?;
            log_stderr_diagnostic("INFO", "tui.render", "snapshot");
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "tui_snapshot": rendered,
                    }))?
                );
            } else {
                println!("{rendered}");
            }
            Ok(0)
        }

        Commands::Completions { shell, output } => {
            let script = render_shell_completions(shell)?;
            let shell_name = format!("{shell:?}").to_ascii_lowercase();
            log_stderr_diagnostic("INFO", "completions.generate", &shell_name);
            if let Some(ref out_path) = output {
                std::fs::write(out_path, &script)?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "shell": shell_name,
                            "output": out_path.display().to_string(),
                            "bytes": script.len(),
                        }))?
                    );
                }
            } else if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "shell": shell_name,
                        "script": script,
                    }))?
                );
            } else {
                print!("{script}");
            }
            Ok(0)
        }
    }
}

/// Renders shell completion scripts for `cordon` and its wrapper scripts (`agent-sandbox`, `agent-shell`).
pub fn render_shell_completions(shell: Shell) -> Result<String> {
    let mut cmd = CordonCli::command();
    let mut buf = Vec::with_capacity(8192);
    generate(shell, &mut cmd, "cordon", &mut buf);
    let mut script = String::from_utf8(buf)?;

    match shell {
        Shell::Bash => {
            script.push_str(
                "\n# PyCentric Cordon wrapper completions (agent-sandbox)\n\
                 complete -F _cordon -o bashdefault -o default agent-sandbox\n",
            );
        }
        Shell::Zsh => {
            if script.starts_with("#compdef cordon\n") {
                script = script.replacen("#compdef cordon\n", "#compdef cordon agent-sandbox\n", 1);
            }
            script.push_str(
                "\n# PyCentric Cordon wrapper completions (agent-sandbox)\n\
                 if (( $+functions[compdef] )); then\n\
                     compdef _cordon cordon agent-sandbox\n\
                 fi\n",
            );
        }
        Shell::Fish => {
            script.push_str(
                "\n# PyCentric Cordon shell candidates & wrapper completions (agent-sandbox & agent-shell)\n\
                 complete -c cordon -n \"__fish_cordon_using_subcommand completions\" -f -a \"bash zsh fish elvish powershell\"\n\
                 complete -c agent-sandbox -w cordon\n\
                 complete -c agent-shell -f -a \"(__fish_complete_subcommand)\"\n",
            );
        }
        _ => {}
    }

    Ok(script)
}
