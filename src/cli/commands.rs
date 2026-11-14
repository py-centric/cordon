//! `Commands` enum definition for the `cordon` CLI.

use std::path::PathBuf;

use clap::builder::PossibleValuesParser;
use clap::{Subcommand, ValueHint};
use clap_complete::Shell;

use crate::domain::TapSlot;
use crate::groups::COMMAND_GROUP_CANDIDATES;

use super::{
    ConfigSubcommand, HTTP_METHOD_CANDIDATES, PROFILE_CANDIDATES, PluginSubcommand, VmCliArgs,
    VmSubcommand,
};

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

    /// Start the Gate 4 Layer 7 HTTP/HTTPS Policy Enforcement Proxy (`cordon-l7.service`).
    L7Proxy {
        /// Listen socket address (`IP:PORT`).
        #[arg(long, default_value = "10.200.1.1:8080")]
        listen: String,
        /// Optional path to the runtime policy JSON file (defaults to `$CORDON_POLICY_FILE` or `/run/cordon/policy.json`).
        #[arg(long = "policy-file", value_hint = ValueHint::FilePath)]
        policy_file: Option<PathBuf>,
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
