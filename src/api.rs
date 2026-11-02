//! Async `axum` HTTP Control Plane and Telemetry Ring Buffer for Cordon.
//!
//! Hardened control plane middleware stack (hand-rolled, no extra dependencies):
//! - Security headers on every response (`nosniff`, `DENY`, `no-referrer`, `no-store`, CSP)
//! - `Host` header validation (421) against the bound authority and loopback names (DNS rebinding)
//! - Optional constant-time bearer auth (`CORDON_API_TOKEN`) on `/api/v1/*` (401 ProblemDetails)
//! - Global `DefaultBodyLimit` (1 MiB) with a tighter 256 KiB cap on `POST /api/v1/evaluate-l7`
//! - Per-remote-addr token-bucket rate limit on POST routes (429 ProblemDetails)

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::apparmor::render_apparmor_profile;
use crate::config::{CordonConfigTemplate, CordonEnvironmentConfig, list_config_templates};
use crate::dashboard::{render_dashboard_html, render_dashboard_js};
use crate::domain::{
    AuditEvent, CordonProfile, DoctorReport, EnforcementPlane, PolicyDecision, SandboxLaunchPlan,
    Severity, Verdict,
};
use crate::error::{CordonError, Rfc7807ProblemDetails};
use crate::l7_policy::CordonPolicyEvaluator;
use crate::network::generate_network_setup_commands;
use crate::ports::AuditSinkPort;
use crate::profiles::{get_profile, list_profiles};
use crate::sandbox::{compile_launch_plan, run_doctor_checks};

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

/// Thread-safe control plane state shared across `axum` handlers.
#[derive(Debug, Clone)]
pub struct CordonControlPlane {
    events: Arc<Mutex<VecDeque<AuditEvent>>>,
    evicted_total: Arc<AtomicU64>,
}

impl Default for CordonControlPlane {
    fn default() -> Self {
        Self::new()
    }
}

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
    pub fn for_build() -> Self {
        let version = env!("CARGO_PKG_VERSION");
        Self {
            service: "pycentric-cordon".to_owned(),
            version: version.to_owned(),
            licence: "AGPL-3.0-only".to_owned(),
            corresponding_source: format!(
                "https://github.com/pycentric/cordon/tree/v{version}"
            ),
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

/// Reason marker attached to audit events emitted when the ring buffer evicts evidence.
pub const AUDIT_RING_EVICTED_REASON: &str = "AUDIT_RING_EVICTED";

impl CordonControlPlane {
    /// Initializes a new [`CordonControlPlane`] with a baseline startup audit event.
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
            events: Arc::new(Mutex::new(queue)),
            evicted_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns total number of telemetry events evicted from the ring buffer since startup.
    pub fn evicted_total(&self) -> u64 {
        self.evicted_total.load(Ordering::Relaxed)
    }

    /// Returns health metadata for `/health` and `/api/v1/health`.
    pub fn health(&self) -> HealthResponse {
        let buffered = self.events.lock().map_or(0, |guard| guard.len());
        HealthResponse {
            status: "ok".to_owned(),
            service: "pycentric-cordon".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            governing_adr: "ADR-L0-SEC-02".to_owned(),
            profiles_count: list_profiles().len(),
            buffered_events: buffered,
        }
    }

    /// Compiles a launch plan and logs an audit event.
    pub fn compile_plan(
        &self,
        req: &CompileLaunchRequest,
    ) -> Result<SandboxLaunchPlan, CordonError> {
        let profile = get_profile(&req.profile)?;
        let plan = compile_launch_plan(
            &profile,
            Path::new(&req.workspace),
            &req.command,
            &req.extra_masked_binaries,
            &req.extra_rw_paths,
        )?;

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

    /// Evaluates an L7 HTTP/HTTPS flow and records an audit event.
    pub fn evaluate_l7(&self, req: &EvaluateL7Request) -> Result<PolicyDecision, CordonError> {
        let profile = get_profile(&req.profile)?;
        let evaluator = CordonPolicyEvaluator::new(profile.clone());
        let decision = evaluator.evaluate_request(&req.url, &req.method, req.body.as_deref());

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

    /// Runs the 7-point kernel/network doctor diagnostic check.
    pub fn doctor(&self) -> DoctorReport {
        run_doctor_checks()
    }

    /// Renders the AppArmor 4.0 policy for `profile_slug`.
    pub fn render_apparmor(&self, profile_slug: &str) -> Result<AppArmorResponse, CordonError> {
        let prof = get_profile(profile_slug)?;
        let attach_path = "/usr/local/bin/agent-shell";
        let policy = render_apparmor_profile(&prof, attach_path);
        Ok(AppArmorResponse {
            profile: prof.name,
            attach_path: attach_path.to_owned(),
            apparmor_policy: policy,
        })
    }

    /// Renders the `ip netns` + `iptables` network setup commands for `profile_slug`.
    pub fn render_network(
        &self,
        profile_slug: &str,
    ) -> Result<NetworkCommandsResponse, CordonError> {
        let prof = get_profile(profile_slug)?;
        let commands = generate_network_setup_commands(&prof);
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
            tracing::warn!("audit ring buffer lock poisoned; dropping event (control plane degraded)");
            return;
        };

        let mut evicted_any = false;
        while guard.len() + 1 > MAX_RING_BUFFER_EVENTS {
            let _ = guard.pop_front();
            evicted_any = true;
        }
        guard.push_back(event);

        if evicted_any {
            // Evidence loss must itself be auditable: every eviction emits a WARNING
            // audit event (never a silent drop). The warning insertion above its own
            // capacity check is exempt from recursion; `evicted_total` carries the
            // cumulative magnitude of lost evidence.
            let total = self.evicted_total.fetch_add(1, Ordering::Relaxed) + 1;
            while guard.len() + 1 > MAX_RING_BUFFER_EVENTS {
                let _ = guard.pop_front();
            }
            let mut details = BTreeMap::new();
            details.insert("reason".to_owned(), AUDIT_RING_EVICTED_REASON.to_owned());
            details.insert("evicted_total".to_owned(), total.to_string());
            details.insert("ring_capacity".to_owned(), MAX_RING_BUFFER_EVENTS.to_string());
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

/// Configuration for the control plane middleware stack.
#[derive(Debug, Clone, Default)]
pub struct ControlPlaneOptions {
    /// Bearer token required on `/api/v1/*` routes (`CORDON_API_TOKEN`); `None` disables auth.
    pub auth_token: Option<String>,
    /// Expected `Host` authority (`host:port`) accepted in addition to loopback names.
    pub bound_authority: Option<String>,
}

impl ControlPlaneOptions {
    /// Builds options from the `CORDON_API_TOKEN` environment variable.
    pub fn from_env() -> Self {
        Self {
            auth_token: std::env::var("CORDON_API_TOKEN")
                .ok()
                .filter(|token| !token.trim().is_empty()),
            bound_authority: None,
        }
    }
}

/// Hand-rolled token bucket (one per remote address) for POST rate limiting.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Hand-rolled token-bucket rate limiter keyed by remote address.
///
/// Implemented in-house to keep the dependency tree lean. Stale buckets (idle
/// longer than 10 minutes) are pruned opportunistically on every check.
#[derive(Debug)]
struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    burst: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    fn new(burst_per_minute: u32) -> Self {
        let burst = f64::from(burst_per_minute);
        Self {
            buckets: Mutex::new(HashMap::new()),
            burst,
            refill_per_sec: burst / 60.0,
        }
    }

    /// Returns `true` when `key` still has budget, consuming one token on success.
    fn check_and_refill(&self, key: &str) -> bool {
        let Ok(mut guard) = self.buckets.lock() else {
            // Fail closed on a poisoned limiter so rate limiting cannot be bypassed.
            return false;
        };
        let now = Instant::now();
        guard.retain(|_, bucket| now.duration_since(bucket.last_refill) < Duration::from_secs(600));
        let bucket = guard.entry(key.to_owned()).or_insert_with(|| TokenBucket {
            tokens: self.burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Constant-time byte-string comparison (hand-rolled, dependency-free).
///
/// Normalizes on length first so short-circuiting never reveals which prefix matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..max_len {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Extracts the hostname from an HTTP `Host` authority (`host:port`, `[::1]:port`).
fn authority_hostname(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    }
}

/// Validates the `Host` header against the bound authority and loopback names.
///
/// Rejecting foreign hosts (421) defeats DNS rebinding: a malicious DNS name resolving
/// to `127.0.0.1` still sends a `Host` header that is not an accepted loopback name.
fn is_allowed_host(host_value: &str, bound_authority: Option<&str>) -> bool {
    let host = host_value.trim().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    if let Some(bound) = bound_authority.map(str::trim) {
        let bound = bound.to_ascii_lowercase();
        if host == bound {
            return true;
        }
        if authority_hostname(&host) == authority_hostname(&bound) {
            return true;
        }
    }
    matches!(
        authority_hostname(&host),
        "127.0.0.1" | "localhost" | "::1"
    )
}

/// Returns `true` when `path` is an authenticated API route (all of `/api/v1/*`).
///
/// `/healthz` and the other `/health*` probe endpoints sit outside `/api/v1/*` and stay
/// unauthenticated so schedulers and load balancers can poll them without a token.
fn api_route_requires_auth(path: &str) -> bool {
    path.starts_with("/api/v1/")
}

fn extract_trace_id(headers: &HeaderMap) -> String {
    headers
        .get("Trace-ID")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| Uuid::new_v4().to_string(), str::to_owned)
}

fn attach_common_headers(mut response: Response, headers: &HeaderMap, trace_id: &str) -> Response {
    if let Ok(trace_val) = HeaderValue::from_str(trace_id) {
        response.headers_mut().insert("Trace-ID", trace_val);
    }
    if let Some(idem) = headers.get("Idempotency-Key") {
        response
            .headers_mut()
            .insert("Idempotency-Key", idem.clone());
    }
    response
}

fn problem_response(problem: &Rfc7807ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_string(problem).unwrap_or_else(|_| "{}".to_owned());
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if let Ok(trace_val) = HeaderValue::from_str(&problem.trace_id) {
        response.headers_mut().insert("Trace-ID", trace_val);
    }
    response
}

fn middleware_rejection(
    status: StatusCode,
    title: &str,
    detail: &str,
    req: &Request,
) -> Response {
    let trace_id = extract_trace_id(req.headers());
    problem_response(&Rfc7807ProblemDetails::from_status(
        status.as_u16(),
        title,
        detail,
        req.uri().path(),
        &trace_id,
    ))
}

/// Adds baseline security headers to every control plane response.
async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(DASHBOARD_CSP),
    );
    response
}

/// Rejects (421) requests whose `Host` header is not the bound authority or a loopback name.
async fn host_guard_middleware(
    State(bound_authority): State<Option<String>>,
    req: Request,
    next: Next,
) -> Response {
    let allowed = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|host| is_allowed_host(host, bound_authority.as_deref()));
    if !allowed {
        return middleware_rejection(
            StatusCode::MISDIRECTED_REQUEST,
            "Misdirected Request",
            "Host header does not match the bound control plane address",
            &req,
        );
    }
    next.run(req).await
}

/// Requires a constant-time verified `Authorization: Bearer` token on `/api/v1/*` when configured.
async fn auth_middleware(State(auth_token): State<Option<String>>, req: Request, next: Next) -> Response {
    if let Some(expected) = auth_token.as_deref()
        && api_route_requires_auth(req.uri().path())
    {
        let provided = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token);
        let valid = provided
            .is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()));
        if !valid {
            return middleware_rejection(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "Missing or invalid bearer token",
                &req,
            );
        }
    }
    next.run(req).await
}

/// Rejects (413) request bodies above the per-route limit (checked from `Content-Length`).
async fn body_limit_middleware(req: Request, next: Next) -> Response {
    let limit = if req.uri().path().starts_with("/api/v1/evaluate-l7") {
        EVALUATE_L7_BODY_LIMIT_BYTES
    } else {
        MAX_REQUEST_BODY_BYTES
    };
    let oversized = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > u64::try_from(limit).unwrap_or(u64::MAX));
    if oversized {
        return middleware_rejection(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Payload Too Large",
            "Request body exceeds the configured size limit",
            &req,
        );
    }
    next.run(req).await
}

/// Enforces the per-remote-addr token-bucket budget on POST routes (429 on exhaustion).
async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::POST {
        let key = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| "unknown".to_owned(), |ci| ci.0.ip().to_string());
        if !limiter.check_and_refill(&key) {
            return middleware_rejection(
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Requests",
                "Rate limit exceeded for this client",
                &req,
            );
        }
    }
    next.run(req).await
}

async fn handle_dashboard() -> Html<&'static str> {
    Html(render_dashboard_html())
}

async fn handle_app_js() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        render_dashboard_js(),
    )
        .into_response()
}

async fn handle_health(State(state): State<CordonControlPlane>) -> Json<HealthResponse> {
    Json(state.health())
}

/// Serves AGPL-3.0-only legal notices (service, version, licence, Corresponding Source).
async fn handle_meta() -> Json<MetaResponse> {
    Json(MetaResponse::for_build())
}

async fn handle_liveness() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "alive" }))
}

async fn handle_readiness(State(state): State<CordonControlPlane>) -> Json<serde_json::Value> {
    let h = state.health();
    Json(serde_json::json!({
        "status": "ready",
        "profiles_loaded": h.profiles_count,
    }))
}

async fn handle_metrics(State(state): State<CordonControlPlane>) -> impl IntoResponse {
    let h = state.health();
    let events = state.recent_events(MAX_RING_BUFFER_EVENTS);
    let blocked_count = events
        .iter()
        .filter(|e| e.verdict == Verdict::Block)
        .count();
    let body = format!(
        "# HELP cordon_profiles_total Total registered sandbox profiles\n\
         # TYPE cordon_profiles_total gauge\n\
         cordon_profiles_total {}\n\
         # HELP cordon_audit_events_buffered Total buffered audit events\n\
         # TYPE cordon_audit_events_buffered gauge\n\
         cordon_audit_events_buffered {}\n\
         # HELP cordon_audit_events_blocked_total Buffered blocked security events\n\
         # TYPE cordon_audit_events_blocked_total gauge\n\
         cordon_audit_events_blocked_total {}\n",
        h.profiles_count, h.buffered_events, blocked_count
    );
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        body,
    )
}

async fn handle_profiles() -> Json<ProfilesResponse> {
    Json(ProfilesResponse {
        profiles: list_profiles(),
    })
}

async fn handle_profile(
    AxumPath(profile_slug): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match get_profile(&profile_slug) {
        Ok(profile) => attach_common_headers(Json(profile).into_response(), &headers, &trace_id),
        Err(err) => problem_response(
            &err.to_problem_details(&format!("/api/v1/profiles/{profile_slug}"), &trace_id),
        ),
    }
}

async fn handle_templates() -> Json<TemplatesResponse> {
    Json(TemplatesResponse {
        templates: list_config_templates(),
    })
}

async fn handle_doctor(State(state): State<CordonControlPlane>) -> Json<DoctorReport> {
    Json(state.doctor())
}

async fn handle_apparmor(
    State(state): State<CordonControlPlane>,
    AxumPath(profile_slug): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.render_apparmor(&profile_slug) {
        Ok(resp) => attach_common_headers(Json(resp).into_response(), &headers, &trace_id),
        Err(err) => problem_response(
            &err.to_problem_details(&format!("/api/v1/apparmor/{profile_slug}"), &trace_id),
        ),
    }
}

async fn handle_network(
    State(state): State<CordonControlPlane>,
    AxumPath(profile_slug): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.render_network(&profile_slug) {
        Ok(resp) => attach_common_headers(Json(resp).into_response(), &headers, &trace_id),
        Err(err) => problem_response(
            &err.to_problem_details(&format!("/api/v1/network/{profile_slug}"), &trace_id),
        ),
    }
}

async fn handle_events(
    State(state): State<CordonControlPlane>,
    Query(query): Query<EventsQuery>,
) -> Json<EventsResponse> {
    Json(EventsResponse {
        events: state.recent_events(query.limit),
    })
}

async fn handle_compile(
    State(state): State<CordonControlPlane>,
    headers: HeaderMap,
    Json(payload): Json<CompileLaunchRequest>,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.compile_plan(&payload) {
        Ok(plan) => attach_common_headers(Json(plan).into_response(), &headers, &trace_id),
        Err(err) => problem_response(&err.to_problem_details("/api/v1/compile", &trace_id)),
    }
}

async fn handle_compile_config(
    State(state): State<CordonControlPlane>,
    headers: HeaderMap,
    Json(payload): Json<CompileConfigRequest>,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.compile_config_plan(&payload) {
        Ok(plan) => attach_common_headers(Json(plan).into_response(), &headers, &trace_id),
        Err(err) => problem_response(&err.to_problem_details("/api/v1/compile-config", &trace_id)),
    }
}

async fn handle_evaluate_l7(
    State(state): State<CordonControlPlane>,
    headers: HeaderMap,
    Json(payload): Json<EvaluateL7Request>,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.evaluate_l7(&payload) {
        Ok(decision) => attach_common_headers(Json(decision).into_response(), &headers, &trace_id),
        Err(err) => problem_response(&err.to_problem_details("/api/v1/evaluate-l7", &trace_id)),
    }
}

/// Builds the `axum::Router` for the Cordon HTTP Control Plane and Web Dashboard,
/// reading `CORDON_API_TOKEN` from the environment for bearer auth.
pub fn build_router(state: CordonControlPlane) -> Router {
    build_router_with_options(state, ControlPlaneOptions::from_env())
}

/// Builds the `axum::Router` with explicit [`ControlPlaneOptions`] (auth token, bound authority).
///
/// Middleware chain (outermost first): security headers -> host guard -> bearer auth ->
/// body limits -> POST rate limit -> routes. Layer calls below are applied innermost-first.
pub fn build_router_with_options(state: CordonControlPlane, options: ControlPlaneOptions) -> Router {
    let rate_limiter = Arc::new(RateLimiter::new(RATE_LIMIT_POSTS_PER_MINUTE));
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/app.js", get(handle_app_js))
        .route("/health", get(handle_health))
        .route("/healthz", get(handle_health))
        .route("/health/liveness", get(handle_liveness))
        .route("/health/readiness", get(handle_readiness))
        .route("/metrics", get(handle_metrics))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/meta", get(handle_meta))
        .route("/api/v1/profiles", get(handle_profiles))
        .route("/api/v1/profiles/{profile}", get(handle_profile))
        .route("/api/v1/templates", get(handle_templates))
        .route("/api/v1/doctor", get(handle_doctor))
        .route("/api/v1/apparmor/{profile}", get(handle_apparmor))
        .route("/api/v1/network/{profile}", get(handle_network))
        .route("/api/v1/events", get(handle_events))
        .route("/api/v1/compile", post(handle_compile))
        .route("/api/v1/compile-config", post(handle_compile_config))
        .route(
            "/api/v1/evaluate-l7",
            post(handle_evaluate_l7).layer(DefaultBodyLimit::max(EVALUATE_L7_BODY_LIMIT_BYTES)),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(body_limit_middleware))
        .layer(axum::middleware::from_fn_with_state(
            options.auth_token,
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            options.bound_authority,
            host_guard_middleware,
        ))
        .layer(axum::middleware::from_fn(security_headers_middleware))
}

/// Starts the async `axum` HTTP Control Plane on `host:port`.
pub async fn serve_control_plane(host: &str, port: u16) -> Result<(), CordonError> {
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let options = ControlPlaneOptions {
        auth_token: std::env::var("CORDON_API_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty()),
        bound_authority: Some(addr),
    };
    let router = build_router_with_options(CordonControlPlane::new(), options);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
