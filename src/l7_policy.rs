//! Type-safe Layer 7 HTTP/HTTPS policy engine and secret-egress scanner for Cordon.
//!
//! This module is the Rust half of the cross-language L7 parity contract: the
//! Python reference implementation lives in `src/cordon/policy_rules.py` and
//! `tests/golden/l7_corpus.json` is the shared conformance corpus (exercised by
//! the inline test module below and the pytest suite).
//!
//! Canonical rule order (first match wins, identical in both engines):
//! `NETWORK_MODE_NONE`, `DENY_DOMAIN:<pattern>`, `DOH_RESOLVER_BLOCK`,
//! `WEBSOCKET_UPGRADE_BLOCK`, `ALLOWLIST_MISS`, `UNAUTHORIZED_MUTATING_METHOD`,
//! `STREAMED_BODY_UNSCANNABLE`, `SECRET_*`, `DEFAULT_ALLOW`.
//!
//! Host matching is normalization-safe: hosts are lowercased, IPv6 brackets and
//! `:port` suffixes are stripped, and trailing DNS dots are trimmed before any
//! allow/deny comparison (closing the `webhook.site.` deny-list bypass).

use std::collections::BTreeMap;
use std::time::Instant;

use regex::Regex;

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

/// High-value credential headers that must always be inspected. The engine
/// scans every non-empty header value (parity with the Python reference), so
/// this list documents the mandatory coverage subset rather than limiting it.
pub const SENSITIVE_HEADERS: &[&str] = &["authorization", "x-api-key", "x-github-token", "cookie"];

/// URL path prefixes that signal DNS-over-HTTPS tunneling (EC-07).
const DOH_PATH_PREFIXES: &[&str] = &["/dns-query", "/resolve"];

/// HTTP methods restricted to `post_allowed_hosts` (FR-5.4).
const MUTATING_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];

const RULE_NETWORK_MODE_NONE: &str = "NETWORK_MODE_NONE";
const RULE_DNS_OVER_HTTPS: &str = "DOH_RESOLVER_BLOCK";
const RULE_WEBSOCKET_UPGRADE: &str = "WEBSOCKET_UPGRADE_BLOCK";
const RULE_ALLOWLIST_MISS: &str = "ALLOWLIST_MISS";
const RULE_UNAUTHORIZED_MUTATING_METHOD: &str = "UNAUTHORIZED_MUTATING_METHOD";
const RULE_STREAMED_BODY_UNSCANNABLE: &str = "STREAMED_BODY_UNSCANNABLE";
const RULE_DEFAULT_ALLOW: &str = "DEFAULT_ALLOW";

/// Base64 candidate spans inspected by the bounded decode-and-rescan pass.
const BASE64_CANDIDATE_PATTERN: &str = r"[A-Za-z0-9+/]{24,}={0,2}";
/// Maximum number of base64 candidates decoded per surface (ReDoS / work bound).
const MAX_B64_CANDIDATES: usize = 16;
/// Maximum bytes kept from any decoded base64 candidate.
const MAX_B64_DECODED_BYTES: usize = 65536;

struct SecretRule {
    rule_id: &'static str,
    regex: Regex,
    requires_digit: bool,
}

/// Compiles a hard-coded pattern; static patterns must always compile.
fn compile_const_pattern(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(err) => panic!("const regex '{pattern}' must compile: {err}"),
    }
}

/// Ordered secret signature table plus the bounded base64 decode-and-rescan pass.
struct SecretScanner {
    rules: Vec<SecretRule>,
    base64_candidate_regex: Regex,
}

impl SecretScanner {
    fn new() -> Self {
        // Canonical ordered rule table (parity with src/cordon/policy_rules.py).
        // All patterns are linear (no nested quantifiers, no lookaround) and
        // therefore ReDoS-safe. Case-insensitive to defeat case-split evasion;
        // the `requires_digit` guard stops prose false positives such as
        // "task-ManagementSystem..." matching `sk-`.
        let raw_rules: &[(&str, &str, bool)] = &[
            (
                "SECRET_GITHUB_PAT",
                r"(?i)(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{22,})",
                false,
            ),
            ("SECRET_OPENAI_KEY", r"(?i)sk-[A-Za-z0-9_-]{20,}", true),
            (
                "SECRET_AWS_ACCESS_KEY",
                r"(?i)(?:AKIA|ASIA)[0-9A-Z]{16}",
                true,
            ),
            (
                "SECRET_PRIVATE_KEY_PEM",
                r"(?i)-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
                false,
            ),
            (
                "SECRET_JWT_BEARER",
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                false,
            ),
            (
                "SECRET_ENV_ASSIGNMENT",
                r"(?i)(?:DATABASE_URL|FERNET_KEY|JWT_PRIVATE_KEY|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY)\s*=",
                false,
            ),
        ];

        let mut rules = Vec::with_capacity(raw_rules.len());
        for (rule_id, pattern, requires_digit) in raw_rules {
            rules.push(SecretRule {
                rule_id,
                regex: compile_const_pattern(pattern),
                requires_digit: *requires_digit,
            });
        }

        Self {
            rules,
            base64_candidate_regex: compile_const_pattern(BASE64_CANDIDATE_PATTERN),
        }
    }

    fn scan_variants(&self, text: &str) -> Option<(&'static str, String)> {
        let collapsed = collapse_whitespace(text);
        for variant in [text, collapsed.as_str()] {
            for rule in &self.rules {
                for matched in rule.regex.find_iter(variant) {
                    let span = matched.as_str();
                    if rule.requires_digit && !span_has_digit(span) {
                        continue;
                    }
                    return Some((rule.rule_id, span.to_owned()));
                }
            }
        }
        None
    }

    /// Scans one surface for secrets: raw text, whitespace-collapsed variant,
    /// then a bounded base64 decode-and-rescan pass (parity with
    /// `scan_for_secret` in `src/cordon/policy_rules.py`).
    fn scan(&self, text: &str) -> Option<(&'static str, String)> {
        if let Some(hit) = self.scan_variants(text) {
            return Some(hit);
        }
        let mut candidates = 0usize;
        for matched in self.base64_candidate_regex.find_iter(text) {
            candidates += 1;
            if candidates > MAX_B64_CANDIDATES {
                break;
            }
            let Some(decoded) = decode_base64_candidate(matched.as_str()) else {
                continue;
            };
            let decoded_text = String::from_utf8_lossy(&decoded);
            if let Some(hit) = self.scan_variants(&decoded_text) {
                return Some(hit);
            }
        }
        None
    }
}

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
    ///
    /// Signature preserved for `src/api.rs` callers; delegates to
    /// [`Self::evaluate_flow`] so URL/query and header scanning, WebSocket
    /// blocking, and streamed-body fail-closed behavior are identical to the
    /// full flow evaluation.
    pub fn evaluate_request(&self, url: &str, method: &str, body: Option<&str>) -> PolicyDecision {
        self.evaluate_flow(url, method, body, false, &BTreeMap::new())
    }

    /// Evaluates a full HTTP/HTTPS flow: URL/query, request body, and headers.
    ///
    /// `body_streamed` marks unbuffered bodies that cannot be scanned; such
    /// flows fail closed with [`RULE_STREAMED_BODY_UNSCANNABLE`].
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
            );
        }

        // 6. Mutating HTTP method restriction (FR-5.4: POST/PUT/PATCH/DELETE only to post_allowed_hosts)
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
            );
        }

        // 8. Secret exfiltration scan: body, URL/query, then header values (canonical order)
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
                if let Some((rule_id, _span)) = self.scanner.scan(surface) {
                    return Self::build_decision(
                        Verdict::Block,
                        &format!(
                            "Blocked potential credential exfiltration matching rule '{rule_id}'."
                        ),
                        rule_id,
                        url,
                        &method_upper,
                        start,
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
        )
    }

    fn build_decision(
        verdict: Verdict,
        reason: &str,
        matched_rule: &str,
        url: &str,
        method: &str,
        start: Instant,
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

fn span_has_digit(span: &str) -> bool {
    span.bytes().any(|b| b.is_ascii_digit())
}

fn collapse_whitespace(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict standard-alphabet base64 decoder (padding only at the end, at most
/// two `=` per final block). Returns `None` on any malformed candidate.
fn decode_base64_candidate(candidate: &str) -> Option<Vec<u8>> {
    let bytes = candidate.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut seen_padding = false;
    for chunk in bytes.chunks(4) {
        let mut sextets = [0u8; 4];
        let mut pad_count = 0usize;
        for (idx, byte) in chunk.iter().enumerate() {
            match byte {
                b'=' if idx >= 2 => {
                    pad_count += 1;
                    seen_padding = true;
                }
                b'=' => return None,
                _ => {
                    if seen_padding {
                        return None;
                    }
                    sextets[idx] = base64_sextet(*byte)?;
                }
            }
        }
        if pad_count > 2 {
            return None;
        }
        let block = (u32::from(sextets[0]) << 18)
            | (u32::from(sextets[1]) << 12)
            | (u32::from(sextets[2]) << 6)
            | u32::from(sextets[3]);
        let decoded = block.to_be_bytes();
        out.extend_from_slice(&decoded[1..4 - pad_count]);
    }
    if out.is_empty() {
        return None;
    }
    out.truncate(MAX_B64_DECODED_BYTES);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::get_profile;

    const CORPUS: &str = include_str!("../tests/golden/l7_corpus.json");

    fn evaluator_with(
        denied: &[&str],
        allowed: &[&str],
        post_allowed: &[&str],
    ) -> CordonPolicyEvaluator {
        let Ok(mut profile) = get_profile("ai-agent") else {
            panic!("ai-agent profile missing");
        };
        profile.denied_domains = denied.iter().map(|d| (*d).to_owned()).collect();
        profile.allowed_domains = allowed.iter().map(|d| (*d).to_owned()).collect();
        profile.post_allowed_hosts = post_allowed.iter().map(|d| (*d).to_owned()).collect();
        CordonPolicyEvaluator::new(profile)
    }

    #[test]
    fn test_host_normalization_strips_trailing_dot_port_and_brackets() {
        assert_eq!(normalize_host("Webhook.Site."), "webhook.site");
        assert_eq!(normalize_host("api.openai.com:443"), "api.openai.com");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
        assert_eq!(normalize_host("EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn test_deny_domain_trailing_dot_bypass_is_blocked() {
        let evaluator = evaluator_with(&["webhook.site"], &["api.openai.com"], &["api.openai.com"]);
        let decision =
            evaluator.evaluate_request("https://webhook.site./collect", "POST", Some("hello"));
        assert_eq!(decision.verdict, Verdict::Block);
        assert_eq!(decision.matched_rule, "DENY_DOMAIN:webhook.site");
    }

    #[test]
    fn test_uppercase_scheme_and_host_with_trailing_dot_is_denied() {
        let evaluator = evaluator_with(&["webhook.site"], &["api.openai.com"], &["api.openai.com"]);
        let decision =
            evaluator.evaluate_request("HTTPS://Webhook.Site./collect", "POST", Some("hello"));
        assert_eq!(decision.verdict, Verdict::Block);
        assert_eq!(decision.matched_rule, "DENY_DOMAIN:webhook.site");
    }

    #[test]
    fn test_whitespace_padded_methods_normalize_to_post() {
        let evaluator = evaluator_with(&[], &["pypi.org"], &["api.openai.com"]);
        for method in ["post ", " Post", "pOsT"] {
            let decision =
                evaluator.evaluate_request("https://pypi.org/legacy/", method, Some("upload"));
            assert_eq!(decision.verdict, Verdict::Block, "method '{method}'");
            assert_eq!(
                decision.matched_rule, RULE_UNAUTHORIZED_MUTATING_METHOD,
                "method '{method}'"
            );
        }
    }

    #[test]
    fn test_secret_pattern_coverage_variants() {
        let scanner = SecretScanner::new();
        // Fine-grained PAT (github_pat_...) and classic PAT variants.
        assert_eq!(
            scanner
                .scan("rotate github_pat_11ABCDEFGHijklmnopqrstuv_0123456789abc later")
                .map(|hit| hit.0),
            Some("SECRET_GITHUB_PAT")
        );
        assert_eq!(
            scanner
                .scan(r#"{"token": "ghp_1234567890abcdefghijklmnopqrstuvwx"}"#)
                .map(|hit| hit.0),
            Some("SECRET_GITHUB_PAT")
        );
        // AWS STS temporary keys (ASIA prefix) and lowercase case variants.
        assert_eq!(
            scanner
                .scan(r#"{"aws": "ASIAZY12ABCD34EFGHIJ"}"#)
                .map(|hit| hit.0),
            Some("SECRET_AWS_ACCESS_KEY")
        );
        assert_eq!(
            scanner
                .scan(r#"{"aws": "akiazy12abcd34efghij"}"#)
                .map(|hit| hit.0),
            Some("SECRET_AWS_ACCESS_KEY")
        );
        // ENCRYPTED PRIVATE KEY header variant.
        assert_eq!(
            scanner
                .scan("-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBX")
                .map(|hit| hit.0),
            Some("SECRET_PRIVATE_KEY_PEM")
        );
        // Whitespace-split evasion is caught by the collapsed rescan.
        assert_eq!(
            scanner
                .scan(r#"{"token": "ghp_1234 5678 90ab cdef ghij klmn opqr stuv wx"}"#)
                .map(|hit| hit.0),
            Some("SECRET_GITHUB_PAT")
        );
        // Digit guard prevents prose false positives on sk-.
        assert_eq!(
            scanner.scan(
                "The task-ManagementSystemOverviewDocumentation needs review before release."
            ),
            None
        );
    }

    #[test]
    fn test_evaluate_flow_scans_url_query_and_sensitive_headers() {
        let evaluator = evaluator_with(&[], &["api.openai.com"], &["api.openai.com"]);
        let url_leak = evaluator.evaluate_flow(
            "https://api.openai.com/v1/models?key=ghp_1234567890abcdefghijklmnopqrstuvwx",
            "GET",
            None,
            false,
            &BTreeMap::new(),
        );
        assert_eq!(url_leak.verdict, Verdict::Block);
        assert_eq!(url_leak.matched_rule, "SECRET_GITHUB_PAT");

        let mut headers = BTreeMap::new();
        headers.insert(
            "Authorization".to_owned(),
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghij0123456789klmnop"
                .to_owned(),
        );
        let header_leak = evaluator.evaluate_flow(
            "https://api.openai.com/v1/models",
            "GET",
            None,
            false,
            &headers,
        );
        assert_eq!(header_leak.verdict, Verdict::Block);
        assert_eq!(header_leak.matched_rule, "SECRET_JWT_BEARER");
    }

    #[test]
    fn test_evaluate_flow_blocks_websocket_and_streamed_bodies() {
        let evaluator = evaluator_with(&[], &["api.openai.com"], &["api.openai.com"]);
        let mut ws_headers = BTreeMap::new();
        ws_headers.insert("Connection".to_owned(), "Upgrade".to_owned());
        ws_headers.insert("Upgrade".to_owned(), "websocket".to_owned());
        let ws = evaluator.evaluate_flow(
            "https://api.openai.com/v1/realtime",
            "GET",
            None,
            false,
            &ws_headers,
        );
        assert_eq!(ws.verdict, Verdict::Block);
        assert_eq!(ws.matched_rule, RULE_WEBSOCKET_UPGRADE);

        let streamed = evaluator.evaluate_flow(
            "https://api.openai.com/v1/messages",
            "POST",
            Some(""),
            true,
            &BTreeMap::new(),
        );
        assert_eq!(streamed.verdict, Verdict::Block);
        assert_eq!(streamed.matched_rule, RULE_STREAMED_BODY_UNSCANNABLE);
    }

    #[test]
    fn test_base64_decode_strict_padding() {
        let decoded = decode_base64_candidate("eyJub3RlIjoic2stMTIzNDU2Nzg5MGFiY2RlZmdoaWoifQ==");
        assert_eq!(
            decoded.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
            Some("{\"note\":\"sk-1234567890abcdefghij\"}".to_owned())
        );
        assert_eq!(decode_base64_candidate("ab==abcd"), None);
        assert_eq!(decode_base64_candidate("a==="), None);
        assert_eq!(decode_base64_candidate("abc"), None);
        assert_eq!(decode_base64_candidate(""), None);
    }

    /// Conformance: every case in `tests/golden/l7_corpus.json` must produce the
    /// expected verdict and stable rule id. The Python suite evaluates the SAME
    /// corpus through `cordon.policy_rules.PolicyEngine`, so any divergence
    /// between the two engines fails at least one suite.
    #[test]
    fn test_golden_l7_corpus_conformance() {
        let Ok(corpus) = serde_json::from_str::<serde_json::Value>(CORPUS) else {
            panic!("tests/golden/l7_corpus.json must parse as JSON");
        };
        let Some(profile_obj) = corpus.get("profile") else {
            panic!("corpus profile section missing");
        };

        let Ok(mut profile) = get_profile("ai-agent") else {
            panic!("ai-agent profile missing");
        };
        if let Some(domains) = profile_obj
            .get("allowed_domains")
            .and_then(serde_json::Value::as_array)
        {
            profile.allowed_domains = domains
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        if let Some(domains) = profile_obj
            .get("denied_domains")
            .and_then(serde_json::Value::as_array)
        {
            profile.denied_domains = domains
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        if let Some(hosts) = profile_obj
            .get("post_allowed_hosts")
            .and_then(serde_json::Value::as_array)
        {
            profile.post_allowed_hosts = hosts
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect();
        }
        profile.block_doh = profile_obj
            .get("block_doh")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        profile.inspect_body_secrets = profile_obj
            .get("inspect_body_secrets")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        profile.network_mode = NetworkMode::Inspected;

        let evaluator = CordonPolicyEvaluator::new(profile);
        let Some(cases) = corpus.get("cases").and_then(serde_json::Value::as_array) else {
            panic!("corpus cases missing");
        };
        assert!(!cases.is_empty(), "corpus must not be empty");

        for case in cases {
            let id = case
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<missing>");
            let url = case
                .get("url")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let method = case
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("GET");
            let payload = case
                .get("payload")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let body_streamed = case
                .get("body_streamed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let expected_verdict = case
                .get("expected_verdict")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let expected_rule = case
                .get("expected_rule_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            let mut headers = BTreeMap::new();
            if let Some(object) = case.get("headers").and_then(serde_json::Value::as_object) {
                for (key, value) in object {
                    headers.insert(key.clone(), value.as_str().unwrap_or("").to_owned());
                }
            }
            let body = if payload.is_empty() {
                None
            } else {
                Some(payload)
            };

            let decision = evaluator.evaluate_flow(url, method, body, body_streamed, &headers);
            match expected_verdict {
                "ALLOW" => assert_eq!(decision.verdict, Verdict::Allow, "case {id}"),
                "BLOCK" => assert_eq!(decision.verdict, Verdict::Block, "case {id}"),
                other => panic!("case {id}: unknown expected_verdict '{other}'"),
            }
            assert_eq!(
                decision.matched_rule, expected_rule,
                "case {id}: rule id mismatch"
            );
        }
    }
}
