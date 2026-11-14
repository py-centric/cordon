//! Runtime L7 policy resolution and canonical JSONL audit event emitter.

use std::collections::BTreeMap;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::policy_config::{PolicyConfig, load_policy_file};
use super::split_url;
use crate::domain::{PolicyDecision, Verdict};

/// Canonical JSONL telemetry event schema version.
pub const EVENT_SCHEMA_VERSION: u32 = 1;
/// Canonical L7 policy rule table version.
pub const RULES_VERSION: u32 = 2;
/// Canonical gate index for L7 inspection.
pub const GATE_L7: u8 = 4;
/// Canonical enforcement plane label for L7 events.
pub const PLANE_L7: &str = "mitmproxy";

/// Environment variable pointing to the active L7 policy JSON file.
pub const POLICY_FILE_ENV: &str = "CORDON_POLICY_FILE";
/// Default root-owned runtime L7 policy JSON path.
pub const DEFAULT_POLICY_FILE: &str = "/run/cordon/policy.json";
/// Environment variable overriding the active L7 session identifier.
pub const SESSION_ID_ENV: &str = "CORDON_SESSION_ID";
/// Environment variable required to allow `CORDON_EXTRA_HOSTS` to widen policy.
pub const INSECURE_ENV: &str = "CORDON_ALLOW_INSECURE";
/// Environment variable providing comma-separated extra allowed hosts.
pub const EXTRA_HOSTS_ENV: &str = "CORDON_EXTRA_HOSTS";
/// Legacy environment variable alias for extra allowed hosts.
pub const LEGACY_EXTRA_HOSTS_ENV: &str = "PYCENTRIC_SANDBOX_EXTRA_HOSTS";

/// Rule identifier emitted when `/run/cordon/policy.json` is missing or untrusted.
pub const RULE_POLICY_SOURCE_DEGRADED: &str = "POLICY_SOURCE_DEGRADED";
/// Rule identifier emitted when `CORDON_ALLOW_INSECURE=1` widens the allow-list.
pub const RULE_POLICY_ENV_WIDENED: &str = "POLICY_ENV_WIDENED";
/// Rule identifier emitted when `CORDON_EXTRA_HOSTS` is ignored without `CORDON_ALLOW_INSECURE=1`.
pub const RULE_POLICY_ENV_IGNORED: &str = "POLICY_ENV_OVERRIDE_IGNORED";
/// Rule identifier emitted when a request body's `Content-Encoding` cannot be decoded.
pub const RULE_BODY_UNDECODABLE: &str = "BODY_UNDECODABLE";
/// Rule identifier emitted when a proxy hook fails closed on an internal error.
pub const RULE_HOOK_FAILURE_FAIL_CLOSED: &str = "HOOK_FAILURE_FAIL_CLOSED";
/// Rule identifier emitted when an upstream HTTP response is observed.
pub const RULE_RESPONSE_OBSERVED: &str = "RESPONSE_OBSERVED";

/// Canonical JSONL telemetry record emitted by the L7 enforcement plane (`schema_version: 1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalL7AuditEvent {
    /// Event schema version (`1`).
    pub schema_version: u32,
    /// Unique event UUID.
    pub event_id: String,
    /// RFC 3339 UTC timestamp.
    pub timestamp: String,
    /// Enforcement plane (`mitmproxy`).
    pub plane: String,
    /// Gate index (`4`).
    pub gate: u8,
    /// Severity (`INFO`, `WARNING`, `CRITICAL`).
    pub severity: String,
    /// Verdict (`ALLOW`, `BLOCK`, `AUDIT`).
    pub verdict: String,
    /// Active profile name.
    pub profile: String,
    /// Session identifier.
    pub session_id: String,
    /// Normalized target host.
    pub host: String,
    /// Uppercase HTTP method.
    pub method: String,
    /// Target URL.
    pub url: String,
    /// Canonical rule identifier (`ALLOWLIST_MISS`, `SECRET_*`, `DEFAULT_ALLOW`, etc.).
    pub rule_id: String,
    /// Rule table version (`2`).
    pub rule_version: u32,
    /// Human-readable verdict explanation.
    pub reason: String,
    /// Request or response byte count (never raw payload bytes).
    pub bytes: i64,
    /// Non-reversible 16-hex-char SHA-256 fingerprint of a matched secret span, if any.
    pub secret_fingerprint: Option<String>,
    /// HTTP status code (`200`, `403`, etc.).
    pub status_code: Option<u16>,
}

/// Input parameters for constructing a [`CanonicalL7AuditEvent`].
#[derive(Debug, Clone)]
pub struct L7AuditEventInput<'a> {
    /// Severity (`INFO`, `WARNING`, `CRITICAL`).
    pub severity: &'a str,
    /// Verdict (`ALLOW`, `BLOCK`, `AUDIT`).
    pub verdict: &'a str,
    /// Normalized target host.
    pub host: &'a str,
    /// Uppercase HTTP method.
    pub method: &'a str,
    /// Target URL.
    pub url: &'a str,
    /// Canonical rule identifier.
    pub rule_id: &'a str,
    /// Human-readable verdict explanation.
    pub reason: &'a str,
    /// Request or response byte count.
    pub byte_count: i64,
    /// Non-reversible 16-hex-char SHA-256 fingerprint of a matched secret span, if any.
    pub secret_fingerprint: Option<String>,
    /// Session identifier.
    pub session_id: &'a str,
    /// HTTP status code.
    pub status_code: Option<u16>,
}

/// Effective runtime L7 policy plus any startup audit events (`POLICY_SOURCE_DEGRADED`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    /// Effective L7 policy configuration.
    pub config: PolicyConfig,
    /// Session UUID associated with the runtime policy.
    pub session_id: String,
    /// Startup audit events recording policy source fallback or env-override handling.
    pub events: Vec<CanonicalL7AuditEvent>,
}

/// Builds one canonical JSONL L7 audit event (never includes raw request/response payloads).
#[must_use]
pub fn build_l7_event(
    config: &PolicyConfig,
    input: &L7AuditEventInput<'_>,
) -> CanonicalL7AuditEvent {
    CanonicalL7AuditEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        event_id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        plane: PLANE_L7.to_owned(),
        gate: GATE_L7,
        severity: input.severity.to_owned(),
        verdict: input.verdict.to_owned(),
        profile: config.profile.clone(),
        session_id: if input.session_id.is_empty() {
            "unset".to_owned()
        } else {
            input.session_id.to_owned()
        },
        host: input.host.to_owned(),
        method: input.method.to_owned(),
        url: input.url.to_owned(),
        rule_id: input.rule_id.to_owned(),
        rule_version: RULES_VERSION,
        reason: input.reason.to_owned(),
        bytes: input.byte_count,
        secret_fingerprint: input.secret_fingerprint.clone(),
        status_code: input.status_code,
    }
}

/// Builds the canonical [`CanonicalL7AuditEvent`] corresponding to a [`PolicyDecision`].
#[must_use]
pub fn event_for_decision(
    decision: &PolicyDecision,
    config: &PolicyConfig,
    session_id: &str,
    body_bytes: usize,
) -> CanonicalL7AuditEvent {
    let verdict_str = match decision.verdict {
        Verdict::Allow => "ALLOW",
        Verdict::Block => "BLOCK",
        Verdict::Audit => "AUDIT",
    };
    let severity = if decision.matched_rule.starts_with("SECRET_")
        || decision.matched_rule == RULE_HOOK_FAILURE_FAIL_CLOSED
    {
        "CRITICAL"
    } else if decision.verdict == Verdict::Block {
        "WARNING"
    } else {
        "INFO"
    };
    let (host, _) = split_url(&decision.url);
    let byte_count = i64::try_from(body_bytes).unwrap_or(i64::MAX);
    build_l7_event(
        config,
        &L7AuditEventInput {
            severity,
            verdict: verdict_str,
            host: &host,
            method: &decision.method,
            url: &decision.url,
            rule_id: &decision.matched_rule,
            reason: &decision.reason,
            byte_count,
            secret_fingerprint: decision.secret_fingerprint.clone(),
            session_id,
            status_code: Some(decision.status_code),
        },
    )
}

/// Resolves the active runtime L7 policy from `env`, falling back to the default strict
/// `ai-agent` policy if the file is missing or untrusted.
#[must_use]
pub fn resolve_runtime_policy(env: &BTreeMap<String, String>) -> ResolvedPolicy {
    let mut events = Vec::new();
    let session_id = env
        .get(SESSION_ID_ENV)
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let policy_path_str = env
        .get(POLICY_FILE_ENV)
        .map_or(DEFAULT_POLICY_FILE, String::as_str);
    let policy_path = Path::new(policy_path_str);
    let file_url = format!("file://{policy_path_str}");

    let mut config = if let Some(loaded) = load_policy_file(policy_path) {
        loaded
    } else {
        let fallback = PolicyConfig::default();
        let reason = format!(
            "Policy file '{policy_path_str}' missing or untrusted; falling back to default strict_whitelist policy."
        );
        events.push(build_l7_event(
            &fallback,
            &L7AuditEventInput {
                severity: "WARNING",
                verdict: "BLOCK",
                host: "",
                method: "",
                url: &file_url,
                rule_id: RULE_POLICY_SOURCE_DEGRADED,
                reason: &reason,
                byte_count: 0,
                secret_fingerprint: None,
                session_id: &session_id,
                status_code: None,
            },
        ));
        fallback
    };

    let raw_extra = env
        .get(EXTRA_HOSTS_ENV)
        .or_else(|| env.get(LEGACY_EXTRA_HOSTS_ENV))
        .map_or("", String::as_str);
    let extra_hosts: Vec<String> = raw_extra
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();

    if !extra_hosts.is_empty() {
        if env.get(INSECURE_ENV).map(String::as_str) == Some("1") {
            config = config.with_widened_hosts(&extra_hosts);
            let reason = format!(
                "CORDON_ALLOW_INSECURE=1: allow-list widened by {} env override host(s).",
                extra_hosts.len()
            );
            events.push(build_l7_event(
                &config,
                &L7AuditEventInput {
                    severity: "WARNING",
                    verdict: "ALLOW",
                    host: "",
                    method: "",
                    url: &file_url,
                    rule_id: RULE_POLICY_ENV_WIDENED,
                    reason: &reason,
                    byte_count: 0,
                    secret_fingerprint: None,
                    session_id: &session_id,
                    status_code: None,
                },
            ));
        } else {
            let reason = format!(
                "Ignored {} env override host(s): policy widening requires explicit CORDON_ALLOW_INSECURE=1.",
                extra_hosts.len()
            );
            events.push(build_l7_event(
                &config,
                &L7AuditEventInput {
                    severity: "WARNING",
                    verdict: "BLOCK",
                    host: "",
                    method: "",
                    url: &file_url,
                    rule_id: RULE_POLICY_ENV_IGNORED,
                    reason: &reason,
                    byte_count: 0,
                    secret_fingerprint: None,
                    session_id: &session_id,
                    status_code: None,
                },
            ));
        }
    }

    ResolvedPolicy {
        config,
        session_id,
        events,
    }
}

/// Resolves the runtime L7 policy from `std::env::vars()`.
#[must_use]
pub fn resolve_runtime_policy_from_process_env() -> ResolvedPolicy {
    let env: BTreeMap<String, String> = std::env::vars().collect();
    resolve_runtime_policy(&env)
}
