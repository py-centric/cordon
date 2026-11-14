use std::collections::BTreeMap;

use uuid::Uuid;

use super::scanner::{SecretScanner, decode_base64_candidate};
use super::*;
use crate::profiles::get_profile;

const CORPUS: &str = include_str!("../../tests/golden/l7_corpus.json");

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
    for (input, expected) in [
        (
            "rotate github_pat_11ABCDEFGHijklmnopqrstuv_0123456789abc later",
            Some("SECRET_GITHUB_PAT"),
        ),
        (
            r#"{"token": "ghp_1234567890abcdefghijklmnopqrstuvwx"}"#,
            Some("SECRET_GITHUB_PAT"),
        ),
        (
            r#"{"aws": "ASIAZY12ABCD34EFGHIJ"}"#,
            Some("SECRET_AWS_ACCESS_KEY"),
        ),
        (
            r#"{"aws": "akiazy12abcd34efghij"}"#,
            Some("SECRET_AWS_ACCESS_KEY"),
        ),
        (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBX",
            Some("SECRET_PRIVATE_KEY_PEM"),
        ),
        (
            r#"{"token": "ghp_1234 5678 90ab cdef ghij klmn opqr stuv wx"}"#,
            Some("SECRET_GITHUB_PAT"),
        ),
        (
            "The task-ManagementSystemOverviewDocumentation needs review before release.",
            None,
        ),
    ] {
        assert_eq!(scanner.scan(input).map(|hit| hit.0), expected, "{input}");
    }
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
    for invalid in ["ab==abcd", "a===", "abc", ""] {
        assert_eq!(decode_base64_candidate(invalid), None);
    }
}

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
    let read_list = |key: &str| -> Vec<String> {
        profile_obj
            .get(key)
            .and_then(serde_json::Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    profile.allowed_domains = read_list("allowed_domains");
    profile.denied_domains = read_list("denied_domains");
    profile.post_allowed_hosts = read_list("post_allowed_hosts");
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
        let str_field = |k: &str, def: &'static str| {
            case.get(k)
                .and_then(serde_json::Value::as_str)
                .unwrap_or(def)
        };
        let id = str_field("id", "<missing>");
        let url = str_field("url", "");
        let method = str_field("method", "GET");
        let payload = str_field("payload", "");
        let body_streamed = case
            .get("body_streamed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let expected_verdict = str_field("expected_verdict", "");
        let expected_rule = str_field("expected_rule_id", "");

        let mut headers = BTreeMap::new();
        if let Some(object) = case.get("headers").and_then(serde_json::Value::as_object) {
            for (key, value) in object {
                headers.insert(key.clone(), value.as_str().unwrap_or("").to_owned());
            }
        }
        let body = (!payload.is_empty()).then_some(payload);
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

#[test]
fn test_secret_fingerprint_matches_fips180_4_vectors() {
    assert_eq!(secret_fingerprint(""), "e3b0c44298fc1c14");
    assert_eq!(secret_fingerprint("abc"), "ba7816bf8f01cfea");
}

#[test]
fn test_block_events_carry_rule_id_and_fingerprint_never_payload() {
    let evaluator = evaluator_with(&[], &["api.anthropic.com"], &["api.anthropic.com"]);
    let secret = "sk-1234567890abcdefghijklmnop";
    let payload = format!("leak {secret}");
    let decision = evaluator.evaluate_request(
        "https://api.anthropic.com/v1/messages",
        "POST",
        Some(&payload),
    );
    assert_eq!(decision.verdict, Verdict::Block);
    assert_eq!(decision.matched_rule, "SECRET_OPENAI_KEY");
    let Some(ref fp) = decision.secret_fingerprint else {
        panic!("secret_fingerprint must be populated on secret block");
    };
    assert_eq!(fp.len(), 16);
    assert!(!secret.contains(fp));

    let cfg = PolicyConfig::default();
    let event = event_for_decision(&decision, &cfg, "sess-1", payload.len());
    assert_eq!(event.rule_id, "SECRET_OPENAI_KEY");
    assert_eq!(event.secret_fingerprint.as_deref(), Some(fp.as_str()));
    let serialized = serde_json::to_string(&event).unwrap_or_default();
    assert!(!serialized.contains(secret));
}

#[test]
fn test_cordonfile_policy_wiring_reaches_runtime_policy() {
    use crate::config::CordonEnvironmentConfig;

    let Ok(cfg) = CordonEnvironmentConfig::from_cordonfile_str(
        "FROM ai-agent\n\
         ALLOW_DOMAIN api.vendor.com registry.example.com\n\
         DENY_DOMAIN webhook.site\n\
         POST_ALLOWED_HOST api.vendor.com\n",
    ) else {
        panic!("Cordonfile must parse");
    };
    let Ok(policy) = cfg.resolve_effective_policy() else {
        panic!("effective policy must resolve");
    };
    assert!(policy.strict_whitelist);
    assert!(
        policy
            .allowed_domains
            .contains(&"api.vendor.com".to_owned())
    );
    assert!(policy.denied_domains.contains(&"webhook.site".to_owned()));
    assert!(
        policy
            .post_allowed_hosts
            .contains(&"api.vendor.com".to_owned())
    );

    let dir = std::env::temp_dir().join(format!("cordon-policy-test-{}", Uuid::new_v4()));
    let policy_path = dir.join("policy.json");
    assert!(write_policy_file(&policy, &policy_path).is_ok());

    let mut env = BTreeMap::new();
    env.insert(
        POLICY_FILE_ENV.to_owned(),
        policy_path.to_string_lossy().into_owned(),
    );
    let resolved = resolve_runtime_policy(&env);
    assert_eq!(resolved.events.len(), 0);
    assert_eq!(resolved.config.allowed_domains, policy.allowed_domains);
    assert_eq!(resolved.config.denied_domains, policy.denied_domains);
    assert_eq!(
        resolved.config.post_allowed_hosts,
        policy.post_allowed_hosts
    );

    let evaluator = CordonPolicyEvaluator::new(resolved.config.to_profile());
    let denied = evaluator.evaluate_request("https://webhook.site/collect", "POST", Some("x"));
    assert_eq!(denied.matched_rule, "DENY_DOMAIN:webhook.site");
    let post_blocked =
        evaluator.evaluate_request("https://registry.example.com/upload", "POST", Some("x"));
    assert_eq!(post_blocked.matched_rule, RULE_UNAUTHORIZED_MUTATING_METHOD);
    let allow_get = evaluator.evaluate_request("https://api.vendor.com/ok", "GET", None);
    assert_eq!(allow_get.matched_rule, RULE_DEFAULT_ALLOW);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_env_overrides_cannot_widen_policy_without_insecure_flag() {
    let mut base_env = BTreeMap::new();
    base_env.insert(
        POLICY_FILE_ENV.to_owned(),
        "/nonexistent/cordon-policy.json".to_owned(),
    );
    base_env.insert(EXTRA_HOSTS_ENV.to_owned(), "evil.example.com".to_owned());

    let ignored = resolve_runtime_policy(&base_env);
    assert!(
        !ignored
            .config
            .allowed_domains
            .contains(&"evil.example.com".to_owned())
    );
    assert!(
        ignored
            .events
            .iter()
            .any(|e| e.rule_id == RULE_POLICY_ENV_IGNORED)
    );

    let mut insecure_env = base_env;
    insecure_env.insert(INSECURE_ENV.to_owned(), "1".to_owned());
    let widened = resolve_runtime_policy(&insecure_env);
    assert!(
        widened
            .config
            .allowed_domains
            .contains(&"evil.example.com".to_owned())
    );
    assert!(
        widened
            .events
            .iter()
            .any(|e| e.rule_id == RULE_POLICY_ENV_WIDENED)
    );
}
