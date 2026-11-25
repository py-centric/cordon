//! Telemetry, audit event schema, L7 policy verdicts, and doctor readiness report models.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{EnforcementPlane, Severity, Verdict};

/// Layer 7 HTTP/HTTPS inspection verdict produced by the Cordon policy engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Final policy verdict (`ALLOW`, `BLOCK`, `AUDIT`).
    pub verdict: Verdict,
    /// HTTP status code returned to the client (`200` on allow, `403` on block).
    pub status_code: u16,
    /// Human-readable explanation of the policy match.
    pub reason: String,
    /// Identifier of the rule that triggered this decision.
    pub matched_rule: String,
    /// Target URL evaluated.
    pub url: String,
    /// HTTP method evaluated.
    pub method: String,
    /// Policy evaluation latency in microseconds.
    pub evaluation_latency_us: u64,
    /// Non-reversible 16-hex-character SHA-256 prefix of a matched secret span (never raw payload bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_fingerprint: Option<String>,
}

/// Structured telemetry event emitted across L3/L4, L7, AppArmor, or Bubblewrap planes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event UUID.
    pub event_id: String,
    /// RFC 3339 UTC timestamp.
    pub timestamp: String,
    /// Enforcement plane that generated the event.
    pub plane: EnforcementPlane,
    /// Severity tier (`INFO`, `WARNING`, `CRITICAL`).
    pub severity: Severity,
    /// Policy verdict (`ALLOW`, `BLOCK`, `AUDIT`).
    pub verdict: Verdict,
    /// Active profile name.
    pub profile: String,
    /// Concise summary of the event.
    pub subject: String,
    /// Structured metadata key-value pairs.
    pub details: BTreeMap<String, String>,
}

/// Canonical serialized [`AuditEvent`] JSON field names consumed by the web dashboard.
///
/// This module is the single source of truth shared by `src/dashboard` (which injects
/// these names into the generated `/app.js` telemetry table code) and the serde contract
/// tests in `tests/cordon_api_and_cli.rs`, so the dashboard JavaScript and the wire schema
/// cannot drift apart.
pub mod audit_json {
    /// `AuditEvent` field holding the RFC 3339 UTC timestamp.
    pub const TIMESTAMP: &str = "timestamp";
    /// `AuditEvent` field holding the active profile name.
    pub const PROFILE: &str = "profile";
    /// `AuditEvent` field holding the policy verdict.
    pub const VERDICT: &str = "verdict";
    /// `AuditEvent` field holding the concise event summary.
    pub const SUBJECT: &str = "subject";
    /// `AuditEvent` field holding the structured metadata map.
    pub const DETAILS: &str = "details";
    /// `details` map key holding the evaluated URL (dashboard "Target" column).
    pub const DETAIL_URL: &str = "url";
    /// `details` map key holding the matched rule (dashboard "Rule / Detail" column).
    pub const DETAIL_RULE: &str = "rule";
}

/// Top-level [`AuditEvent`] JSON keys dereferenced by the dashboard telemetry table.
///
/// The rendered dashboard JavaScript must only read these keys (through the injected
/// `EVK` map); the contract test asserts every entry exists in the serialized event.
pub const AUDIT_EVENT_DASHBOARD_KEYS: &[&str] = &[
    audit_json::TIMESTAMP,
    audit_json::PROFILE,
    audit_json::VERDICT,
    audit_json::SUBJECT,
    audit_json::DETAILS,
];

/// `details` map keys the dashboard derives its Target and Rule columns from.
pub const AUDIT_DETAIL_DASHBOARD_KEYS: &[&str] = &[audit_json::DETAIL_URL, audit_json::DETAIL_RULE];

/// Single diagnostic check result from `cordon doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Check identifier.
    pub name: String,
    /// Whether the dependency or kernel feature is available.
    pub passed: bool,
    /// Whether this check is required for full 5-gate enforcement.
    pub required: bool,
    /// Diagnostic detail or binary path.
    pub detail: String,
}

/// Aggregated `cordon doctor` diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Overall readiness flag (true if all required checks pass).
    pub healthy: bool,
    /// Kernel version and OS platform summary.
    pub platform_summary: String,
    /// Individual dependency and kernel checks.
    pub checks: Vec<DoctorCheck>,
}
