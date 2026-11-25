//! HTTP Control Plane request and response DTOs (`POST /api/v1/compile`, `GET /api/v1/meta`, etc.).

use serde::{Deserialize, Serialize};

use crate::config::CordonConfigTemplate;
use crate::domain::{AuditEvent, CordonProfile, RawMicroVmSpec};

/// Request payload for `POST /api/v1/compile`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CompileLaunchRequest {
    /// Profile slug (`ai-agent`, `untrusted-code`, etc.).
    pub profile: String,
    /// Workspace directory to bind.
    pub workspace: String,
    /// Command vector to execute inside Bubblewrap.
    pub command: Vec<String>,
    /// Additional binaries to mask with `/dev/null`.
    #[serde(default)]
    pub extra_masked_binaries: Vec<String>,
    /// Additional host paths to bind read-write.
    #[serde(default)]
    pub extra_rw_paths: Vec<String>,
    /// Optional Gate 3.5 MicroVM settings (same schema as the `[vm]` config table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<RawMicroVmSpec>,
}

/// Request payload for `POST /api/v1/compile-config`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CompileConfigRequest {
    /// Raw configuration text (`Cordonfile`, `Cordonfile.toml`, or `cordon.json`).
    pub config_content: String,
    /// Config syntax format (`cordonfile`, `toml`, or `json`).
    #[serde(default = "default_config_format")]
    pub format: String,
    /// Optional workspace override (falls back to `workdir` in config).
    #[serde(default)]
    pub workspace_override: Option<String>,
    /// Optional command override (falls back to `cmd` in config).
    #[serde(default)]
    pub command_override: Vec<String>,
}

fn default_config_format() -> String {
    "cordonfile".to_owned()
}

/// Request payload for `POST /api/v1/evaluate-l7`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvaluateL7Request {
    /// Profile slug (`ai-agent`, `package-build`, etc.).
    pub profile: String,
    /// Outbound URL to inspect.
    pub url: String,
    /// HTTP method (`GET`, `POST`, etc.).
    #[serde(default = "default_http_method")]
    pub method: String,
    /// Optional request body to scan for leaked credentials.
    #[serde(default)]
    pub body: Option<String>,
}

fn default_http_method() -> String {
    "GET".to_owned()
}

/// Query parameters for `GET /api/v1/events`.
#[derive(Debug, Clone, Deserialize)]
pub struct EventsQuery {
    /// Maximum number of events to return.
    #[serde(default = "default_events_limit")]
    pub limit: usize,
}

const fn default_events_limit() -> usize {
    50
}

/// Health status response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Service status (`ok`).
    pub status: String,
    /// Service identifier (`pycentric-cordon`).
    pub service: String,
    /// Package version.
    pub version: String,
    /// Governing ADR identifier (`ADR-L0-SEC-02`).
    pub governing_adr: String,
    /// Active profile count.
    pub profiles_count: usize,
    /// Retained telemetry event count.
    pub buffered_events: usize,
}

/// Legal notices and Corresponding Source metadata (`GET /api/v1/meta`),
/// satisfying AGPL-3.0-only sections 5(d) and 13 for network-facing UIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaResponse {
    /// Service identifier (`pycentric-cordon`).
    pub service: String,
    /// Package version (crate version constant).
    pub version: String,
    /// Licence identifier of the open core (`AGPL-3.0-only`).
    pub licence: String,
    /// URL where the Corresponding Source for this version is published.
    pub corresponding_source: String,
}

impl MetaResponse {
    /// Builds the legal-notice metadata for the running build.
    #[must_use]
    pub fn for_build() -> Self {
        let version = env!("CARGO_PKG_VERSION");
        Self {
            service: "pycentric-cordon".to_owned(),
            version: version.to_owned(),
            licence: "AGPL-3.0-only".to_owned(),
            corresponding_source: format!("https://github.com/pycentric/cordon/tree/v{version}"),
        }
    }
}

/// Profiles catalog response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilesResponse {
    /// List of built-in workload profiles.
    pub profiles: Vec<CordonProfile>,
}

/// Starter templates catalog response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplatesResponse {
    /// List of built-in reproducible `Cordonfile` / `Cordonfile.toml` templates.
    pub templates: Vec<CordonConfigTemplate>,
}

/// Events list response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsResponse {
    /// Recent telemetry audit events.
    pub events: Vec<AuditEvent>,
}

/// AppArmor policy response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppArmorResponse {
    /// Profile slug.
    pub profile: String,
    /// Attachment binary path.
    pub attach_path: String,
    /// Rendered AppArmor 4.0 policy text.
    pub apparmor_policy: String,
}

/// Network namespace setup response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCommandsResponse {
    /// Profile slug.
    pub profile: String,
    /// Network namespace name.
    pub netns_name: String,
    /// Ordered shell commands for `ip netns` and `iptables`.
    pub commands: Vec<String>,
}
