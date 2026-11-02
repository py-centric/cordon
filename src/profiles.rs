//! Built-in universal sandbox profiles for Cordon.

use crate::domain::{CordonProfile, FilesystemMode, NetworkMode, WorkloadKind};
use crate::error::CordonError;
use crate::ports::ProfileCatalogPort;

/// Default high-risk host binaries denied execution (`deny ... x` and `/dev/null` mask).
pub const DEFAULT_DENIED_BINARIES: &[&str] = &[
    "/usr/bin/rm",
    "/usr/bin/shred",
    "/usr/bin/dd",
    "/usr/bin/mkfs",
    "/usr/bin/curl",
    "/usr/bin/wget",
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/netcat",
    "/usr/bin/ssh",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/pkexec",
    "/usr/bin/chmod",
    "/usr/bin/chown",
    "/usr/bin/chroot",
    "/usr/bin/nsenter",
    "/usr/bin/unshare",
];

/// Default sensitive user credential directories denied `rwlkmx` by AppArmor.
pub const DEFAULT_PROTECTED_USER_PATHS: &[&str] = &[
    "@{HOME}/.ssh/**",
    "@{HOME}/.gnupg/**",
    "@{HOME}/.aws/**",
    "@{HOME}/.config/gcloud/**",
    "@{HOME}/.kube/**",
    "@{HOME}/.azure/**",
    "@{HOME}/.docker/config.json",
    "@{HOME}/.npmrc",
    "@{HOME}/.pypirc",
    "@{HOME}/.cargo/credentials.toml",
    "@{HOME}/.netrc",
    "@{HOME}/.mitmproxy/mitmproxy-ca.pem",
    "@{HOME}/.mitmproxy/mitmproxy-ca.p12",
];

fn default_denied_vec() -> Vec<String> {
    DEFAULT_DENIED_BINARIES
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

fn default_protected_vec() -> Vec<String> {
    DEFAULT_PROTECTED_USER_PATHS
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

/// Default approved LLM API hosts permitted to receive mutating HTTP methods (`POST`/`PUT`/`PATCH`/`DELETE`) per FR-5.4.
pub const DEFAULT_POST_ALLOWED_LLM_HOSTS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "api.deepinfra.com",
    "api.fireworks.ai",
    "api.together.xyz",
];

fn default_post_allowed_vec() -> Vec<String> {
    DEFAULT_POST_ALLOWED_LLM_HOSTS
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

fn base_profile(
    name: &str,
    kind: WorkloadKind,
    description: &str,
    filesystem_mode: FilesystemMode,
    network_mode: NetworkMode,
) -> CordonProfile {
    CordonProfile {
        name: name.to_owned(),
        kind,
        description: description.to_owned(),
        filesystem_mode,
        network_mode,
        netns_name: "agent-net".to_owned(),
        host_veth_ip: "10.200.1.1".to_owned(),
        sandbox_veth_ip: "10.200.1.2".to_owned(),
        subnet_cidr: "10.200.1.0/24".to_owned(),
        mitm_port: 8080,
        denied_binaries: default_denied_vec(),
        protected_paths: default_protected_vec(),
        extra_ro_binds: Vec::new(),
        extra_rw_binds: Vec::new(),
        allowed_domains: Vec::new(),
        post_allowed_hosts: Vec::new(),
        denied_domains: Vec::new(),
        protect_git_dir: true,
        isolate_home_tmpfs: false,
        enable_build_scratch: false,
        block_doh: true,
        block_quic_udp_443: true,
        inspect_body_secrets: true,
        allow_gui_wayland: false,
        allow_x11: false,
        allow_gpu_dri: false,
        tmpfs_size_mb: 512,
        unshare_pid: true,
        unshare_ipc: true,
        die_with_parent: true,
        ca_bundle_source: "/var/lib/agent-sandbox/combined-ca-bundle.crt".to_owned(),
    }
}

/// Returns all 6 built-in universal Cordon profiles.
pub fn list_profiles() -> Vec<CordonProfile> {
    let mut ai_agent = base_profile(
        "ai-agent",
        WorkloadKind::AiAgent,
        "Local AI CLI coding agents (opencode, antigravity, claude, aider) with RW workspace, RO .git guard, credential blocking, and full L3-L7 network inspection.",
        FilesystemMode::WorkspaceRw,
        NetworkMode::Inspected,
    );
    ai_agent.allowed_domains = vec![
        "api.anthropic.com".to_owned(),
        "api.openai.com".to_owned(),
        "generativelanguage.googleapis.com".to_owned(),
        "openrouter.ai".to_owned(),
        "api.deepinfra.com".to_owned(),
        "api.fireworks.ai".to_owned(),
        "api.together.xyz".to_owned(),
        "github.com".to_owned(),
        "api.github.com".to_owned(),
        "pypi.org".to_owned(),
        "files.pythonhosted.org".to_owned(),
        "registry.npmjs.org".to_owned(),
        "crates.io".to_owned(),
        "static.crates.io".to_owned(),
    ];
    ai_agent.enable_build_scratch = true;
    ai_agent.post_allowed_hosts = default_post_allowed_vec();

    let mut untrusted_code = base_profile(
        "untrusted-code",
        WorkloadKind::UntrustedCode,
        "Arbitrary untrusted scripts, third-party binaries, or downloaded tools with read-only workspace, ephemeral /tmp, masked $HOME, and zero network access by default.",
        FilesystemMode::WorkspaceRo,
        NetworkMode::None,
    );
    untrusted_code.tmpfs_size_mb = 256;
    untrusted_code.isolate_home_tmpfs = true;

    let mut package_build = base_profile(
        "package-build",
        WorkloadKind::PackageBuild,
        "Supply-chain package installation and build steps (npm install, pip install, cargo build) with RW workspace, local TMPDIR scratch, and GET-only L7 registry allowlisting.",
        FilesystemMode::WorkspaceRw,
        NetworkMode::AllowlistOnly,
    );
    package_build.enable_build_scratch = true;
    package_build.allowed_domains = vec![
        "pypi.org".to_owned(),
        "files.pythonhosted.org".to_owned(),
        "registry.npmjs.org".to_owned(),
        "crates.io".to_owned(),
        "static.crates.io".to_owned(),
        "index.crates.io".to_owned(),
        "github.com".to_owned(),
        "objects.githubusercontent.com".to_owned(),
    ];

    let mut network_audit = base_profile(
        "network-audit",
        WorkloadKind::NetworkAudit,
        "Reverse-engineering and network behavior auditing for closed-source binaries or SDKs with read-only workspace and full PCAP + MITM capture.",
        FilesystemMode::WorkspaceRo,
        NetworkMode::Inspected,
    );
    network_audit.denied_binaries = vec![
        "/usr/bin/rm".to_owned(),
        "/usr/bin/shred".to_owned(),
        "/usr/bin/sudo".to_owned(),
        "/usr/bin/su".to_owned(),
        "/usr/bin/ssh".to_owned(),
        "/usr/bin/scp".to_owned(),
    ];
    network_audit.post_allowed_hosts = default_post_allowed_vec();

    let mut gui_desktop = base_profile(
        "gui-desktop",
        WorkloadKind::GuiDesktop,
        "Sandboxed desktop GUI application with Wayland socket forwarding, GPU DRI access, credential isolation, and L7 traffic inspection.",
        FilesystemMode::WorkspaceRo,
        NetworkMode::Inspected,
    );
    gui_desktop.allow_gui_wayland = true;
    gui_desktop.allow_gpu_dri = true;
    gui_desktop.post_allowed_hosts = default_post_allowed_vec();

    let mut airgapped = base_profile(
        "airgapped",
        WorkloadKind::Airgapped,
        "Strictly offline airgapped execution (--unshare-net) with read-only workspace, masked $HOME, and ephemeral RAM disk.",
        FilesystemMode::StrictRo,
        NetworkMode::None,
    );
    airgapped.tmpfs_size_mb = 128;
    airgapped.isolate_home_tmpfs = true;

    vec![
        ai_agent,
        untrusted_code,
        package_build,
        network_audit,
        gui_desktop,
        airgapped,
    ]
}

/// Looks up a built-in [`CordonProfile`] by slug.
pub fn get_profile(name: &str) -> Result<CordonProfile, CordonError> {
    let profiles = list_profiles();
    for profile in &profiles {
        if profile.name == name {
            return Ok(profile.clone());
        }
    }
    let available = profiles
        .iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(CordonError::UnknownProfile {
        name: name.to_owned(),
        available,
    })
}

/// Default in-memory implementation of [`ProfileCatalogPort`].
#[derive(Debug, Default, Clone, Copy)]
pub struct BuiltinProfileCatalog;

impl ProfileCatalogPort for BuiltinProfileCatalog {
    fn get_profile(&self, name: &str) -> Result<CordonProfile, CordonError> {
        get_profile(name)
    }

    fn list_profiles(&self) -> Vec<CordonProfile> {
        list_profiles()
    }
}
