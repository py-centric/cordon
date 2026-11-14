//! Type-safe Layer 7 HTTP/HTTPS policy engine, runtime policy loader, and secret-egress scanner.
//!
//! This module is the authoritative L7 enforcement and policy-file engine for Cordon,
//! verified against the shared conformance corpus in `tests/golden/l7_corpus.json`.
//!
//! Canonical rule order (first match wins):
//! `NETWORK_MODE_NONE`, `DENY_DOMAIN:<pattern>`, `DOH_RESOLVER_BLOCK`,
//! `WEBSOCKET_UPGRADE_BLOCK`, `ALLOWLIST_MISS`, `UNAUTHORIZED_MUTATING_METHOD`,
//! `STREAMED_BODY_UNSCANNABLE`, `SECRET_*`, `DEFAULT_ALLOW`.

mod policy_config;
mod runtime;
mod scanner;
#[cfg(test)]
mod tests;

pub use self::policy_config::{
    PolicyConfig, load_policy_file, policy_file_is_trusted, write_policy_file,
};
pub use self::runtime::{
    CanonicalL7AuditEvent, DEFAULT_POLICY_FILE, EVENT_SCHEMA_VERSION, EXTRA_HOSTS_ENV, GATE_L7,
    INSECURE_ENV, L7AuditEventInput, LEGACY_EXTRA_HOSTS_ENV, PLANE_L7, POLICY_FILE_ENV,
    RULE_BODY_UNDECODABLE, RULE_HOOK_FAILURE_FAIL_CLOSED, RULE_POLICY_ENV_IGNORED,
    RULE_POLICY_ENV_WIDENED, RULE_POLICY_SOURCE_DEGRADED, RULE_RESPONSE_OBSERVED, RULES_VERSION,
    ResolvedPolicy, SESSION_ID_ENV, build_l7_event, event_for_decision, resolve_runtime_policy,
    resolve_runtime_policy_from_process_env,
};
pub use self::scanner::secret_fingerprint;

use std::collections::BTreeMap;
use std::time::Instant;

use self::scanner::SecretScanner;
use crate::domain::{CordonProfile, NetworkMode, PolicyDecision, Verdict};
use crate::ports::L7PolicyEvaluatorPort;

/// Known DNS-over-HTTPS (DoH) resolver hosts blocked when `block_doh` is enabled.
pub const KNOWN_DOH_HOSTS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "dns.google",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.quad9.net",
    "doh.opendns.com",
];

/// High-value credential headers that must always be inspected.
pub const SENSITIVE_HEADERS: &[&str] = &["authorization", "x-api-key", "x-github-token", "cookie"];

/// URL path prefixes that signal DNS-over-HTTPS tunneling (EC-07).
const DOH_PATH_PREFIXES: &[&str] = &["/dns-query", "/resolve"];

/// HTTP methods restricted to `post_allowed_hosts` (FR-5.4).
const MUTATING_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

pub(super) const RULE_NETWORK_MODE_NONE: &str = "NETWORK_MODE_NONE";
pub(super) const RULE_DNS_OVER_HTTPS: &str = "DOH_RESOLVER_BLOCK";
pub(super) const RULE_WEBSOCKET_UPGRADE: &str = "WEBSOCKET_UPGRADE_BLOCK";
pub(super) const RULE_ALLOWLIST_MISS: &str = "ALLOWLIST_MISS";
pub(super) const RULE_UNAUTHORIZED_MUTATING_METHOD: &str = "UNAUTHORIZED_MUTATING_METHOD";
pub(super) const RULE_STREAMED_BODY_UNSCANNABLE: &str = "STREAMED_BODY_UNSCANNABLE";
pub(super) const RULE_DEFAULT_ALLOW: &str = "DEFAULT_ALLOW";

/// Pure, deterministic L7 HTTP/HTTPS flow policy evaluator.
pub struct CordonPolicyEvaluator {
    profile: CordonProfile,
    scanner: SecretScanner,
}

impl CordonPolicyEvaluator {
    /// Constructs a new [`CordonPolicyEvaluator`] for the given [`CordonProfile`].
    pub fn new(profile: CordonProfile) -> Self {
        Self {
            profile,
            scanner: SecretScanner::new(),
        }
    }

    fn extract_host_and_path(url: &str) -> (String, String) {
        let after_scheme = match url.find("://") {
            Some(idx) => &url[idx + 3..],
            None => url,
        };
        let end = ['/', '?', '#']
            .iter()
            .filter_map(|sep| after_scheme.find(*sep))
            .min();
        let (authority, path) = match end {
            Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
            None => (after_scheme, "/"),
        };
        let host_part = authority.rsplit('@').next_back().unwrap_or(authority);
        (normalize_host(host_part), path.to_owned())
    }

    fn domain_matches(host: &str, pattern: &str) -> bool {
        let clean = normalize_host(pattern.trim_start_matches("*."));
        let normalized = normalize_host(host);
        normalized == clean || normalized.ends_with(&format!(".{clean}"))
    }

    fn matched_domain<'a>(host: &str, patterns: &'a [String]) -> Option<&'a str> {
        patterns
            .iter()
            .find(|pattern| Self::domain_matches(host, pattern))
            .map(String::as_str)
    }

    /// Evaluates an outbound HTTP/HTTPS request (body-only surface).
    pub fn evaluate_request(&self, url: &str, method: &str, body: Option<&str>) -> PolicyDecision {
        self.evaluate_flow(url, method, body, false, &BTreeMap::new())
    }

    /// Evaluates a full HTTP/HTTPS flow: URL/query, request body, and headers.
    pub fn evaluate_flow(
        &self,
        url: &str,
        method: &str,
        body: Option<&str>,
        body_streamed: bool,
        headers: &BTreeMap<String, String>,
    ) -> PolicyDecision {
        let start = Instant::now();
        let (host, path) = Self::extract_host_and_path(url);
        let method_upper = method.trim().to_ascii_uppercase();
        let norm_headers: BTreeMap<String, String> = headers
            .iter()
            .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.clone()))
            .collect();

        // 1. Airgapped / NetworkMode::None
        if self.profile.network_mode == NetworkMode::None {
            return Self::build_decision(
                Verdict::Block,
                "Outbound network is disabled for this Cordon profile.",
                RULE_NETWORK_MODE_NONE,
                url,
                &method_upper,
                start,
                None,
            );
        }

        // 2. Explicit deny-list, enforced BEFORE the allow-list (trailing-dot safe)
        if let Some(denied) = Self::matched_domain(&host, &self.profile.denied_domains) {
            let denied_id = denied.trim_end_matches('.').to_ascii_lowercase();
            return Self::build_decision(
                Verdict::Block,
                &format!("Host '{host}' matched denied domain rule '{denied_id}'."),
                &format!("DENY_DOMAIN:{denied_id}"),
                url,
                &method_upper,
                start,
                None,
            );
        }

        // 3. DNS-over-HTTPS (DoH) bypass prevention (FR-4.4 / EC-07)
        if self.profile.block_doh {
            let accept = norm_headers
                .get("accept")
                .map_or("", String::as_str)
                .to_ascii_lowercase();
            if KNOWN_DOH_HOSTS.contains(&host.as_str())
                || DOH_PATH_PREFIXES
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
                || accept == "application/dns-message"
            {
                return Self::build_decision(
                    Verdict::Block,
                    &format!("Blocked DNS-over-HTTPS (DoH) bypass attempt to '{host}'."),
                    RULE_DNS_OVER_HTTPS,
                    url,
                    &method_upper,
                    start,
                    None,
                );
            }
        }

        // 4. WebSocket upgrades blocked by default
        let upgrade = norm_headers
            .get("upgrade")
            .map_or("", String::as_str)
            .trim()
            .to_ascii_lowercase();
        let connection = norm_headers
            .get("connection")
            .map_or("", String::as_str)
            .trim()
            .to_ascii_lowercase();
        if upgrade == "websocket" || connection.contains("upgrade") {
            return Self::build_decision(
                Verdict::Block,
                &format!("Blocked WebSocket upgrade to '{host}' (blocked by default)."),
                RULE_WEBSOCKET_UPGRADE,
                url,
                &method_upper,
                start,
                None,
            );
        }

        // 5. Domain allowlist enforcement when in AllowlistOnly mode or when allowlist is populated
        if (self.profile.network_mode == NetworkMode::AllowlistOnly
            || !self.profile.allowed_domains.is_empty())
            && Self::matched_domain(&host, &self.profile.allowed_domains).is_none()
        {
            return Self::build_decision(
                Verdict::Block,
                &format!("Host '{host}' is not in the profile's allowed_domains list."),
                RULE_ALLOWLIST_MISS,
                url,
                &method_upper,
                start,
                None,
            );
        }

        // 6. Mutating HTTP method restriction (FR-5.4)
        if MUTATING_METHODS.contains(&method_upper.as_str())
            && (self.profile.network_mode == NetworkMode::AllowlistOnly
                || !self.profile.post_allowed_hosts.is_empty())
            && Self::matched_domain(&host, &self.profile.post_allowed_hosts).is_none()
        {
            return Self::build_decision(
                Verdict::Block,
                &format!(
                    "Blocked mutating HTTP method '{method_upper}' to host '{host}' (FR-5.4)."
                ),
                RULE_UNAUTHORIZED_MUTATING_METHOD,
                url,
                &method_upper,
                start,
                None,
            );
        }

        // 7. Streamed bodies cannot be scanned and must fail closed
        if body_streamed && self.profile.inspect_body_secrets {
            return Self::build_decision(
                Verdict::Block,
                "Request body is streamed/unbuffered and cannot be scanned (fail closed).",
                RULE_STREAMED_BODY_UNSCANNABLE,
                url,
                &method_upper,
                start,
                None,
            );
        }

        // 8. Secret exfiltration scan: body, URL/query, then header values
        if self.profile.inspect_body_secrets {
            let mut surfaces: Vec<&str> = Vec::new();
            if let Some(payload) = body {
                surfaces.push(payload);
            }
            surfaces.push(url);
            for value in norm_headers.values() {
                surfaces.push(value);
            }
            for surface in &surfaces {
                if surface.is_empty() {
                    continue;
                }
                if let Some((rule_id, span)) = self.scanner.scan(surface) {
                    return Self::build_decision(
                        Verdict::Block,
                        &format!(
                            "Blocked potential credential exfiltration matching rule '{rule_id}'."
                        ),
                        rule_id,
                        url,
                        &method_upper,
                        start,
                        Some(secret_fingerprint(&span)),
                    );
                }
            }
        }

        Self::build_decision(
            Verdict::Allow,
            &format!("Permitted outbound {method_upper} request to '{host}'."),
            RULE_DEFAULT_ALLOW,
            url,
            &method_upper,
            start,
            None,
        )
    }

    fn build_decision(
        verdict: Verdict,
        reason: &str,
        matched_rule: &str,
        url: &str,
        method: &str,
        start: Instant,
        secret_fingerprint: Option<String>,
    ) -> PolicyDecision {
        let elapsed_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
        let status_code = if verdict == Verdict::Block { 403 } else { 200 };
        PolicyDecision {
            verdict,
            status_code,
            reason: reason.to_owned(),
            matched_rule: matched_rule.to_owned(),
            url: url.to_owned(),
            method: method.to_owned(),
            evaluation_latency_us: elapsed_us,
            secret_fingerprint,
        }
    }
}

impl L7PolicyEvaluatorPort for CordonPolicyEvaluator {
    fn evaluate_request(&self, url: &str, method: &str, body: Option<&str>) -> PolicyDecision {
        Self::evaluate_request(self, url, method, body)
    }
}

/// Normalizes a host for policy matching: strips IPv6 brackets and `:port`,
/// trims trailing DNS dots, and lowercases (defeats `webhook.site.` bypasses).
pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    let mut cleaned = trimmed;
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            cleaned = &rest[..end];
        }
    } else if trimmed.matches(':').count() == 1
        && let Some((name, port)) = trimmed.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        cleaned = name;
    }
    cleaned.trim_end_matches('.').to_ascii_lowercase()
}

/// Splits a URL into `(normalized_host, path_with_query)`.
pub fn split_url(url: &str) -> (String, String) {
    CordonPolicyEvaluator::extract_host_and_path(url)
}
