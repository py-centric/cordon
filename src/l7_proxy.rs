//! Native Rust Gate 4 Layer 7 HTTP/HTTPS Policy Enforcement Proxy (`cordon l7-proxy`).
//!
//! Runs headless under `systemd` (`cordon-l7.service`), loading the root-owned runtime
//! policy file (`/run/cordon/policy.json` or `$CORDON_POLICY_FILE`), enforcing
//! [`CordonPolicyEvaluator`] rules in-process, and writing canonical `schema_version: 1`
//! JSONL audit records to `stdout` (`/var/log/cordon/audit.jsonl`) per `[INV-STDOUT-JSON]`.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::domain::Verdict;
use crate::l7_policy::{
    CanonicalL7AuditEvent, CordonPolicyEvaluator, POLICY_FILE_ENV, PolicyConfig,
    RULE_BODY_UNDECODABLE, RULES_VERSION, build_l7_event, event_for_decision, normalize_host,
    resolve_runtime_policy,
};

/// Maximum buffered request body size (`5 MiB`, matching `stream_large_bodies=5m`).
pub const MAX_INSPECTED_BODY_BYTES: usize = 5 * 1024 * 1024;

/// Shared state for the Gate 4 L7 policy enforcement service.
#[derive(Clone)]
pub struct L7ProxyState {
    config: PolicyConfig,
    session_id: String,
    evaluator: Arc<CordonPolicyEvaluator>,
    audit_log: Arc<Mutex<Vec<CanonicalL7AuditEvent>>>,
    emit_stdout: bool,
}

impl L7ProxyState {
    /// Builds [`L7ProxyState`] from an explicit [`PolicyConfig`] and `session_id`.
    pub fn new(config: PolicyConfig, session_id: String, emit_stdout: bool) -> Self {
        let profile = config.to_profile();
        Self {
            config,
            session_id,
            evaluator: Arc::new(CordonPolicyEvaluator::new(profile)),
            audit_log: Arc::new(Mutex::new(Vec::new())),
            emit_stdout,
        }
    }

    /// Resolves [`L7ProxyState`] from the environment and an optional `--policy-file` path.
    pub fn from_policy_file(policy_file: Option<&Path>, emit_stdout: bool) -> Self {
        let mut env: BTreeMap<String, String> = std::env::vars().collect();
        if let Some(path) = policy_file {
            env.insert(
                POLICY_FILE_ENV.to_owned(),
                path.to_string_lossy().into_owned(),
            );
        }
        let resolved = resolve_runtime_policy(&env);
        let state = Self::new(resolved.config, resolved.session_id, emit_stdout);
        for event in resolved.events {
            state.record_event(event);
        }
        state
    }

    /// Returns a snapshot of buffered [`CanonicalL7AuditEvent`] records (for testing/inspection).
    pub fn recorded_events(&self) -> Vec<CanonicalL7AuditEvent> {
        self.audit_log
            .lock()
            .map_or_else(|_| Vec::new(), |guard| guard.clone())
    }

    fn record_event(&self, event: CanonicalL7AuditEvent) {
        if self.emit_stdout
            && let Ok(line) = serde_json::to_string(&event)
        {
            let mut stdout = std::io::stdout().lock();
            let _ = writeln!(stdout, "{line}");
            let _ = stdout.flush();
        }
        if let Ok(mut guard) = self.audit_log.lock() {
            if guard.len() >= 1000 {
                let _ = guard.remove(0);
            }
            guard.push(event);
        }
    }
}

/// Builds the `axum::Router` for the Gate 4 L7 enforcement service.
pub fn build_l7_proxy_router(state: L7ProxyState) -> Router {
    Router::new()
        .fallback(handle_proxied_request)
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

async fn handle_proxied_request(State(state): State<L7ProxyState>, req: Request) -> Response {
    let method = req.method().as_str().to_ascii_uppercase();
    let uri = req.uri().clone();

    let mut headers_map = BTreeMap::new();
    for (name, value) in req.headers() {
        if let Ok(val_str) = value.to_str() {
            headers_map.insert(name.as_str().to_ascii_lowercase(), val_str.to_owned());
        }
    }

    let raw_host = uri
        .host()
        .map(str::to_owned)
        .or_else(|| headers_map.get("host").cloned())
        .unwrap_or_default();
    let host = normalize_host(&raw_host);
    let path_and_query = uri
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str);
    let full_url = if uri.scheme().is_some() {
        uri.to_string()
    } else if host.is_empty() {
        format!("http://localhost{path_and_query}")
    } else {
        format!("https://{host}{path_and_query}")
    };

    let content_encoding = headers_map
        .get("content-encoding")
        .map_or("identity", String::as_str)
        .trim()
        .to_ascii_lowercase();

    let body_result = to_bytes(req.into_body(), MAX_INSPECTED_BODY_BYTES).await;
    let Ok(raw_bytes) = body_result else {
        // Streamed or oversized body (> 5 MiB) cannot be buffered for scanning; fail closed.
        let decision =
            state
                .evaluator
                .evaluate_flow(&full_url, &method, Some(""), true, &headers_map);
        let event = event_for_decision(
            &decision,
            &state.config,
            &state.session_id,
            MAX_INSPECTED_BODY_BYTES,
        );
        state.record_event(event);
        return violation_response(
            decision.status_code,
            &decision.matched_rule,
            &decision.reason,
        );
    };

    if !content_encoding.is_empty() && content_encoding != "identity" {
        let reason =
            format!("Request body content-encoding '{content_encoding}' cannot be scanned inline.");
        let event = build_l7_event(
            &state.config,
            &crate::l7_policy::L7AuditEventInput {
                severity: "WARNING",
                verdict: "BLOCK",
                host: &host,
                method: &method,
                url: &full_url,
                rule_id: RULE_BODY_UNDECODABLE,
                reason: &reason,
                byte_count: i64::try_from(raw_bytes.len()).unwrap_or(i64::MAX),
                secret_fingerprint: None,
                session_id: &state.session_id,
                status_code: Some(403),
            },
        );
        state.record_event(event);
        return violation_response(403, RULE_BODY_UNDECODABLE, &reason);
    }

    let body_text = String::from_utf8_lossy(&raw_bytes).into_owned();
    let body_opt = if body_text.is_empty() {
        None
    } else {
        Some(body_text.as_str())
    };
    let decision = state
        .evaluator
        .evaluate_flow(&full_url, &method, body_opt, false, &headers_map);
    let event = event_for_decision(&decision, &state.config, &state.session_id, raw_bytes.len());
    state.record_event(event);

    if decision.verdict == Verdict::Block {
        return violation_response(
            decision.status_code,
            &decision.matched_rule,
            &decision.reason,
        );
    }

    let ok_payload = json!({
        "status": "allowed",
        "rule_id": decision.matched_rule,
        "rule_version": RULES_VERSION,
        "host": host,
        "method": method,
        "url": full_url,
    });
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        )],
        Body::from(ok_payload.to_string()),
    )
        .into_response()
}

fn violation_response(status_code: u16, rule_id: &str, reason: &str) -> Response {
    let status = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
    let payload = json!({
        "error": "CORDON_POLICY_VIOLATION",
        "rule_id": rule_id,
        "rule_version": RULES_VERSION,
        "reason": reason,
    });
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        )],
        Body::from(payload.to_string()),
    )
        .into_response()
}

/// Runs the Gate 4 L7 policy enforcement proxy server on `listen_addr`.
pub async fn run_l7_proxy_server(
    listen_addr: SocketAddr,
    policy_file: Option<&Path>,
) -> Result<()> {
    let state = L7ProxyState::from_policy_file(policy_file, true);
    let router = build_l7_proxy_router(state);
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind Gate 4 L7 proxy on {listen_addr}"))?;
    axum::serve(listener, router)
        .await
        .context("Gate 4 L7 proxy server terminated with error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[tokio::test]
    async fn l7_proxy_blocks_unlisted_domain_and_secret_leak_with_fingerprint() {
        let state = L7ProxyState::new(PolicyConfig::default(), "test-session".to_owned(), false);
        let _router = build_l7_proxy_router(state.clone());

        // 1. Allowed POST to api.anthropic.com
        let ok_req = Request::builder()
            .method(Method::POST)
            .uri("https://api.anthropic.com/v1/messages")
            .header("host", "api.anthropic.com")
            .body(Body::from(r#"{"model":"claude-sonnet-4","messages":[]}"#))
            .unwrap_or_else(|_| panic!("valid request"));
        let ok_resp = handle_proxied_request(State(state.clone()), ok_req).await;
        assert_eq!(ok_resp.status(), StatusCode::OK);

        // 2. Blocked POST to unlisted webhook domain
        let bad_req = Request::builder()
            .method(Method::POST)
            .uri("https://webhook.evil.example/exfil")
            .header("host", "webhook.evil.example")
            .body(Body::from("hello"))
            .unwrap_or_else(|_| panic!("valid request"));
        let bad_resp = handle_proxied_request(State(state.clone()), bad_req).await;
        assert_eq!(bad_resp.status(), StatusCode::FORBIDDEN);

        // 3. Blocked secret leak to allowed LLM endpoint
        let secret = "sk-1234567890abcdefghijklmnop";
        let leak_req = Request::builder()
            .method(Method::POST)
            .uri("https://api.anthropic.com/v1/messages")
            .header("host", "api.anthropic.com")
            .body(Body::from(format!("leak {secret}")))
            .unwrap_or_else(|_| panic!("valid request"));
        let leak_resp = handle_proxied_request(State(state.clone()), leak_req).await;
        assert_eq!(leak_resp.status(), StatusCode::FORBIDDEN);

        let events = state.recorded_events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].verdict, "ALLOW");
        assert_eq!(events[1].rule_id, "ALLOWLIST_MISS");
        assert_eq!(events[2].rule_id, "SECRET_OPENAI_KEY");
        assert!(events[2].secret_fingerprint.is_some());
        let serialized = serde_json::to_string(&events[2]).unwrap_or_default();
        assert!(!serialized.contains(secret));
    }

    #[tokio::test]
    async fn l7_proxy_from_policy_file_and_undecodable_body_fail_closed() {
        let _default_state = L7ProxyState::from_policy_file(None, false);
        let mut cfg = PolicyConfig::default();
        cfg.allowed_domains.push("api.openai.com".to_owned());
        cfg.inspect_body_secrets = true;
        let state = L7ProxyState::new(cfg, "test-session-undecodable".to_owned(), false);
        let _router = build_l7_proxy_router(state.clone());

        let bad_utf8 = Request::builder()
            .method(Method::POST)
            .uri("https://api.openai.com/v1/chat/completions")
            .header("host", "api.openai.com")
            .header("content-encoding", "gzip")
            .body(Body::from(vec![0xff, 0xfe, 0xfd]))
            .unwrap_or_else(|_| panic!("valid request"));
        let resp = handle_proxied_request(State(state.clone()), bad_utf8).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let events = state.recorded_events();
        assert!(events.iter().any(|e| e.rule_id == RULE_BODY_UNDECODABLE));

        // Relative URI with host header -> https://{host}{path}
        let rel_req = Request::builder()
            .method(Method::GET)
            .uri("/v1/models")
            .header("host", "api.openai.com")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("valid request"));
        assert_eq!(
            handle_proxied_request(State(state.clone()), rel_req)
                .await
                .status(),
            StatusCode::OK
        );

        // Relative URI without host header -> http://localhost/... -> blocked
        let no_host_req = Request::builder()
            .method(Method::GET)
            .uri("/secret")
            .body(Body::empty())
            .unwrap_or_else(|_| panic!("valid request"));
        assert_eq!(
            handle_proxied_request(State(state.clone()), no_host_req)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        // Oversized body (> MAX_INSPECTED_BODY_BYTES) -> fail closed
        let huge_req = Request::builder()
            .method(Method::POST)
            .uri("https://api.openai.com/v1/chat/completions")
            .header("host", "api.openai.com")
            .body(Body::from(vec![b'a'; MAX_INSPECTED_BODY_BYTES + 64]))
            .unwrap_or_else(|_| panic!("valid request"));
        assert_eq!(
            handle_proxied_request(State(state), huge_req)
                .await
                .status(),
            StatusCode::FORBIDDEN
        );

        let srv = tokio::spawn(run_l7_proxy_server(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            None,
        ));
        tokio::task::yield_now().await;
        srv.abort();
    }
}
