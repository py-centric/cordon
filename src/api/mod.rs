//! Async `axum` HTTP Control Plane and Telemetry Ring Buffer for Cordon.
//!
//! Hardened control plane middleware stack (hand-rolled, no extra dependencies):
//! - Security headers on every response (`nosniff`, `DENY`, `no-referrer`, `no-store`, CSP)
//! - `Host` header validation (421) against the bound authority and loopback names (DNS rebinding)
//! - Optional constant-time bearer auth (`CORDON_API_TOKEN`) on `/api/v1/*` (401 ProblemDetails)
//! - Global `DefaultBodyLimit` (1 MiB) with a tighter 256 KiB cap on `POST /api/v1/evaluate-l7`
//! - Per-remote-addr token-bucket rate limit on POST routes (429 ProblemDetails)

pub mod dto;
pub mod handlers;
pub mod middleware;

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use uuid::Uuid;

use crate::apparmor::AppArmorProfileCompiler;
use crate::config::CordonEnvironmentConfig;
use crate::domain::{
    AuditEvent, CordonProfile, DoctorReport, EnforcementPlane, MicroVmSpec, PolicyDecision,
    SandboxLaunchPlan, Severity, Verdict,
};
use crate::error::CordonError;
use crate::l7_policy::CordonPolicyEvaluator;
use crate::network::NetnsTopologyCompiler;
use crate::ports::{
    AppArmorCompilerPort, AuditSinkPort, L7PolicyEvaluatorPort, NetnsCompilerPort,
    ProfileCatalogPort, SandboxCompilerPort,
};
use crate::profiles::BuiltinProfileCatalog;
use crate::sandbox::BwrapSandboxCompiler;

pub use dto::{
    AppArmorResponse, CompileConfigRequest, CompileLaunchRequest, EvaluateL7Request, EventsQuery,
    EventsResponse, HealthResponse, MetaResponse, NetworkCommandsResponse, ProfilesResponse,
    TemplatesResponse,
};
pub use handlers::{build_router, build_router_with_options, serve_control_plane};
pub use middleware::ControlPlaneOptions;

/// Maximum number of telemetry events retained in the in-memory ring buffer.
pub const MAX_RING_BUFFER_EVENTS: usize = 5000;

/// Global request body limit (1 MiB) applied to every control plane route.
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Tighter request body limit (256 KiB) for `POST /api/v1/evaluate-l7`.
pub const EVALUATE_L7_BODY_LIMIT_BYTES: usize = 256 * 1024;

/// Sustained POST request budget per remote address (requests per minute).
pub const RATE_LIMIT_POSTS_PER_MINUTE: u32 = 30;

/// Content-Security-Policy applied to every response.
///
/// The dashboard JavaScript is served from the same-origin `/app.js` route, so
/// `script-src 'self'` stays strict: zero inline `<script>` blocks and zero inline
/// `on*=` handlers (all wiring uses `addEventListener`). Inline `<style>` blocks and
/// `style=""` attributes remain (static, never derived from data), hence the narrow
/// `style-src 'unsafe-inline'` allowance.
pub const DASHBOARD_CSP: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; \
     font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; \
     frame-ancestors 'none'";

/// Reason marker attached to audit events emitted when the ring buffer evicts evidence.
pub const AUDIT_RING_EVICTED_REASON: &str = "AUDIT_RING_EVICTED";

/// Thread-safe control plane state shared across `axum` handlers and wired through
/// Hexagonal Ports ([`ProfileCatalogPort`], [`SandboxCompilerPort`], [`AppArmorCompilerPort`],
/// [`NetnsCompilerPort`], [`L7PolicyEvaluatorPort`], [`AuditSinkPort`]).
#[derive(Debug, Clone)]
pub struct CordonControlPlane {
    catalog: BuiltinProfileCatalog,
    sandbox: BwrapSandboxCompiler,
    apparmor: AppArmorProfileCompiler,
    network: NetnsTopologyCompiler,
    events: Arc<Mutex<VecDeque<AuditEvent>>>,
    evicted_total: Arc<AtomicU64>,
}

impl Default for CordonControlPlane {
    fn default() -> Self {
        Self::new()
    }
}

impl CordonControlPlane {
    /// Initializes a new [`CordonControlPlane`] with a baseline startup audit event.
    #[must_use]
    pub fn new() -> Self {
        let mut queue = VecDeque::with_capacity(MAX_RING_BUFFER_EVENTS);
        let mut details = BTreeMap::new();
        details.insert("engine".to_owned(), "rust-axum-tokio".to_owned());
        details.insert("apparmor_abi".to_owned(), "4.0".to_owned());

        queue.push_back(AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            plane: EnforcementPlane::Bwrap,
            severity: Severity::Info,
            verdict: Verdict::Allow,
            profile: "ai-agent".to_owned(),
            subject: "Cordon Type-Safe Rust Control Plane initialized".to_owned(),
            details,
        });

        Self {
            catalog: BuiltinProfileCatalog,
            sandbox: BwrapSandboxCompiler,
            apparmor: AppArmorProfileCompiler,
            network: NetnsTopologyCompiler,
            events: Arc::new(Mutex::new(queue)),
            evicted_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns total number of telemetry events evicted from the ring buffer since startup.
    #[must_use]
    pub fn evicted_total(&self) -> u64 {
        self.evicted_total.load(Ordering::Relaxed)
    }

    /// Lists all registered workload profiles through [`ProfileCatalogPort`].
    #[must_use]
    pub fn list_profiles(&self) -> Vec<CordonProfile> {
        self.catalog.list_profiles()
    }

    /// Resolves a workload profile by slug through [`ProfileCatalogPort`].
    pub fn get_profile(&self, slug: &str) -> Result<CordonProfile, CordonError> {
        self.catalog.get_profile(slug)
    }

    /// Returns health metadata for `/health` and `/api/v1/health`.
    #[must_use]
    pub fn health(&self) -> HealthResponse {
        let buffered = self.events.lock().map_or(0, |guard| guard.len());
        HealthResponse {
            status: "ok".to_owned(),
            service: "pycentric-cordon".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            governing_adr: "ADR-L0-SEC-02".to_owned(),
            profiles_count: self.catalog.list_profiles().len(),
            buffered_events: buffered,
        }
    }

    /// Compiles a launch plan through [`SandboxCompilerPort`] and logs an audit event.
    pub fn compile_plan(
        &self,
        req: &CompileLaunchRequest,
    ) -> Result<SandboxLaunchPlan, CordonError> {
        let profile = self.catalog.get_profile(&req.profile)?;
        let microvm = match req.vm {
            Some(ref raw) if raw.backend.is_microvm() => Some(MicroVmSpec::try_from(raw.clone())?),
            _ => None,
        };
        if let Some(ref spec) = microvm {
            spec.validate_for_profile(&profile)?;
        }
        let mut plan = self.sandbox.compile_launch_plan(
            &profile,
            Path::new(&req.workspace),
            &req.command,
            &req.extra_masked_binaries,
            &req.extra_rw_paths,
        )?;
        if let Some(ref spec) = microvm {
            let run_id = Uuid::new_v4().simple().to_string();
            crate::microvm::attach_microvm_plan(&mut plan, &profile, spec, &run_id)?;
        }

        let mut details = BTreeMap::new();
        details.insert(
            "workspace".to_owned(),
            plan.canonical_workspace.as_str().to_owned(),
        );
        details.insert("command".to_owned(), req.command.join(" "));
        self.record_event(AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            plane: EnforcementPlane::Bwrap,
            severity: Severity::Info,
            verdict: Verdict::Allow,
            profile: profile.name,
            subject: "Compiled 5-gate Bubblewrap + netns launch plan".to_owned(),
            details,
        });

        Ok(plan)
    }

    /// Compiles a launch plan from a declarative `Cordonfile`, `Cordonfile.toml`, or `cordon.json` payload.
    pub fn compile_config_plan(
        &self,
        req: &CompileConfigRequest,
    ) -> Result<SandboxLaunchPlan, CordonError> {
        let cfg = match req.format.trim().to_ascii_lowercase().as_str() {
            "cordonfile" | "dockerfile" => {
                CordonEnvironmentConfig::from_cordonfile_str(&req.config_content)?
            }
            "toml" => CordonEnvironmentConfig::from_toml_str(&req.config_content)?,
            "json" => CordonEnvironmentConfig::from_json_str(&req.config_content)?,
            other => {
                return Err(CordonError::InvalidInput(format!(
                    "Unsupported config format '{other}'; expected 'cordonfile', 'toml', or 'json'"
                )));
            }
        };

        let ws_override = req.workspace_override.as_deref().map(Path::new);
        let cmd_override = if !req.command_override.is_empty() {
            req.command_override.clone()
        } else if !cfg.command.is_empty() {
            cfg.command.clone()
        } else {
            vec!["bash".to_owned(), "--norc".to_owned()]
        };

        let (profile, plan) =
            cfg.compile_plan(ws_override, &cmd_override, &[], &[], &[], &BTreeMap::new())?;

        let mut details = BTreeMap::new();
        details.insert("config_name".to_owned(), cfg.name);
        details.insert(
            "workspace".to_owned(),
            plan.canonical_workspace.as_str().to_owned(),
        );
        details.insert("command".to_owned(), cmd_override.join(" "));
        self.record_event(AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            plane: EnforcementPlane::Bwrap,
            severity: Severity::Info,
            verdict: Verdict::Allow,
            profile: profile.name,
            subject: "Compiled reproducible Cordonfile environment launch plan".to_owned(),
            details,
        });

        Ok(plan)
    }

    /// Evaluates an L7 HTTP/HTTPS flow through [`L7PolicyEvaluatorPort`] and records an audit event.
    pub fn evaluate_l7(&self, req: &EvaluateL7Request) -> Result<PolicyDecision, CordonError> {
        let profile = self.catalog.get_profile(&req.profile)?;
        let evaluator = CordonPolicyEvaluator::new(profile.clone());
        let decision = L7PolicyEvaluatorPort::evaluate_request(
            &evaluator,
            &req.url,
            &req.method,
            req.body.as_deref(),
        );

        let severity = match decision.verdict {
            Verdict::Allow => Severity::Info,
            Verdict::Audit => Severity::Warning,
            Verdict::Block => {
                if decision.matched_rule.starts_with("SECRET_") {
                    Severity::Critical
                } else {
                    Severity::Warning
                }
            }
        };

        let mut details = BTreeMap::new();
        details.insert("url".to_owned(), decision.url.clone());
        details.insert("method".to_owned(), decision.method.clone());
        details.insert("rule".to_owned(), decision.matched_rule.clone());
        details.insert(
            "latency_us".to_owned(),
            decision.evaluation_latency_us.to_string(),
        );
        if let Some(ref fp) = decision.secret_fingerprint {
            details.insert("secret_fingerprint".to_owned(), fp.clone());
        }

        self.record_event(AuditEvent {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            plane: EnforcementPlane::Mitmproxy,
            severity,
            verdict: decision.verdict,
            profile: profile.name,
            subject: decision.reason.clone(),
            details,
        });

        Ok(decision)
    }

    /// Runs the 15-point kernel/network/MicroVM doctor diagnostic check through [`SandboxCompilerPort`].
    #[must_use]
    pub fn doctor(&self) -> DoctorReport {
        self.sandbox.run_doctor_checks()
    }

    /// Renders the AppArmor 4.0 policy for `profile_slug` through [`AppArmorCompilerPort`].
    pub fn render_apparmor(&self, profile_slug: &str) -> Result<AppArmorResponse, CordonError> {
        let prof = self.catalog.get_profile(profile_slug)?;
        let attach_path = "/usr/local/bin/agent-shell";
        let policy = self.apparmor.render_apparmor_profile(&prof, attach_path);
        Ok(AppArmorResponse {
            profile: prof.name,
            attach_path: attach_path.to_owned(),
            apparmor_policy: policy,
        })
    }

    /// Renders the `ip netns` + `iptables` network setup commands for `profile_slug` through [`NetnsCompilerPort`].
    pub fn render_network(
        &self,
        profile_slug: &str,
    ) -> Result<NetworkCommandsResponse, CordonError> {
        let prof = self.catalog.get_profile(profile_slug)?;
        let commands = self.network.generate_network_setup_commands(&prof);
        Ok(NetworkCommandsResponse {
            profile: prof.name,
            netns_name: prof.netns_name,
            commands,
        })
    }
}

impl AuditSinkPort for CordonControlPlane {
    fn record_event(&self, event: AuditEvent) {
        let Ok(mut guard) = self.events.lock() else {
            tracing::warn!(
                "audit ring buffer lock poisoned; dropping event (control plane degraded)"
            );
            return;
        };

        let mut evicted_any = false;
        while guard.len() + 1 > MAX_RING_BUFFER_EVENTS {
            let _ = guard.pop_front();
            evicted_any = true;
        }
        guard.push_back(event);

        if evicted_any {
            let total = self.evicted_total.fetch_add(1, Ordering::Relaxed) + 1;
            while guard.len() + 1 > MAX_RING_BUFFER_EVENTS {
                let _ = guard.pop_front();
            }
            let mut details = BTreeMap::new();
            details.insert("reason".to_owned(), AUDIT_RING_EVICTED_REASON.to_owned());
            details.insert("evicted_total".to_owned(), total.to_string());
            details.insert(
                "ring_capacity".to_owned(),
                MAX_RING_BUFFER_EVENTS.to_string(),
            );
            guard.push_back(AuditEvent {
                event_id: Uuid::new_v4().to_string(),
                timestamp: Utc::now().to_rfc3339(),
                plane: EnforcementPlane::Tshark,
                severity: Severity::Warning,
                verdict: Verdict::Audit,
                profile: "ai-agent".to_owned(),
                subject: "Audit ring buffer overflow: oldest telemetry events evicted".to_owned(),
                details,
            });
        }
    }

    fn recent_events(&self, limit: usize) -> Vec<AuditEvent> {
        let capped = limit.clamp(1, MAX_RING_BUFFER_EVENTS);
        if let Ok(guard) = self.events.lock() {
            guard.iter().rev().take(capped).cloned().collect()
        } else {
            Vec::new()
        }
    }
}
