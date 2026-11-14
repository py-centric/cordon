//! `clap` (derive) CLI and `stdout`/`stderr` stream-split orchestration for Cordon.

mod commands;
mod dispatch;
mod plan;
mod subcommands;

use std::io::Write;
use std::path::PathBuf;

use anyhow::Result;
use chrono::Utc;
use clap::builder::PossibleValuesParser;
use clap::{CommandFactory, Parser, Subcommand, ValueHint};
use clap_complete::{Shell, generate};

pub use commands::Commands;
pub use dispatch::execute_cli;

use crate::config::{CordonEnvironmentConfig, expand_tilde};
use crate::domain::{IsolationBackend, RawMicroVmSpec, VmDiskMode};
use crate::plugins::PLUGIN_CANDIDATES;

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
