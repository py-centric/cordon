//! Request body limits, rate limiting, and path-free RFC 7807 problem-detail tests.

mod common;
use common::{
    body_of, get_request, header_of, post_json_request, send_raw, spawn_server, status_of,
};
use cordon::api::{ControlPlaneOptions, EVALUATE_L7_BODY_LIMIT_BYTES, MAX_REQUEST_BODY_BYTES};

/// Global 1 MiB body limit rejects oversized payloads with 413 before handlers run.
#[tokio::test]
async fn test_global_body_limit_rejects_oversized_payloads() {
    let addr = spawn_server(ControlPlaneOptions::default()).await;

    let big_body = format!(
        "{{\"profile\":\"ai-agent\",\"workspace\":\".\",\"command\":[\"{}\"]}}",
        "a".repeat(MAX_REQUEST_BODY_BYTES)
    );
    let req = post_json_request("/api/v1/compile", &big_body);
    let resp = send_raw(addr, &req).await;
    assert_eq!(
        status_of(&resp),
        413,
        "bodies above {MAX_REQUEST_BODY_BYTES} bytes must be rejected"
    );

    // Small bodies still pass the limit check (control).
    let small_body = r#"{"profile":"ai-agent","workspace":".","command":["opencode"]}"#;
    let resp = send_raw(addr, &post_json_request("/api/v1/compile", small_body)).await;
    assert_eq!(status_of(&resp), 200);
}

/// `POST /api/v1/evaluate-l7` carries the tighter 256 KiB limit even below the global cap.
#[tokio::test]
async fn test_evaluate_l7_tight_body_limit() {
    let addr = spawn_server(ControlPlaneOptions::default()).await;

    let oversized_eval = EVALUATE_L7_BODY_LIMIT_BYTES + 32 * 1024;
    assert!(
        oversized_eval < MAX_REQUEST_BODY_BYTES,
        "test must exercise the tight limit below the global cap"
    );
    let body = format!(
        r#"{{"profile":"ai-agent","url":"https://api.openai.com/v1/chat/completions","method":"POST","body":"{}"}}"#,
        "a".repeat(oversized_eval)
    );
    let resp = send_raw(addr, &post_json_request("/api/v1/evaluate-l7", &body)).await;
    assert_eq!(
        status_of(&resp),
        413,
        "evaluate-l7 must enforce the tighter 256 KiB body limit"
    );

    // Small evaluate-l7 bodies pass (control).
    let small = r#"{"profile":"ai-agent","url":"https://api.openai.com/v1/models","method":"GET"}"#;
    let resp = send_raw(addr, &post_json_request("/api/v1/evaluate-l7", small)).await;
    assert_eq!(status_of(&resp), 200);
}

/// Hand-rolled token bucket: 30 POSTs/min per remote address, then 429.
#[tokio::test]
async fn test_post_rate_limit_returns_429_after_burst() {
    let addr = spawn_server(ControlPlaneOptions::default()).await;

    let small = r#"{"profile":"ai-agent","url":"https://api.openai.com/v1/models","method":"GET"}"#;
    let mut last_status = 0_u16;
    let mut saw_429 = false;
    for i in 0..36 {
        let resp = send_raw(addr, &post_json_request("/api/v1/evaluate-l7", small)).await;
        last_status = status_of(&resp);
        if last_status == 429 {
            saw_429 = true;
            assert!(
                i >= 30,
                "rate limiter must allow the configured burst before rejecting (rejected at {i})"
            );
            break;
        }
    }
    assert!(
        saw_429,
        "the POST token bucket must reject with 429 after the burst (last status {last_status})"
    );

    // Read-only routes are not rate limited by the POST budget.
    for _ in 0..40 {
        let resp = send_raw(addr, &get_request("/api/v1/profiles", "")).await;
        assert_eq!(
            status_of(&resp),
            200,
            "GET routes must not consume POST budget"
        );
    }
}

/// RFC 7807 `detail` fields must be stable and path-free (no host filesystem disclosure).
#[tokio::test]
async fn test_problem_details_are_path_free() {
    let addr = spawn_server(ControlPlaneOptions::default()).await;

    let cases: Vec<(u16, String)> = vec![
        (
            404,
            post_json_request(
                "/api/v1/compile",
                r#"{"profile":"missing-profile","workspace":".","command":["opencode"]}"#,
            ),
        ),
        (
            400,
            post_json_request(
                "/api/v1/compile-config",
                r#"{"config_content":"FROM ai-agent","format":"not-a-format","workspace_override":null,"command_override":[]}"#,
            ),
        ),
    ];

    for (expected_status, req) in cases {
        let resp = send_raw(addr, &req).await;
        assert_eq!(status_of(&resp), expected_status);
        assert!(
            header_of(&resp, "content-type")
                .is_some_and(|ct| ct.contains("application/problem+json"))
        );
        let body = body_of(&resp);
        let parsed: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(e) => panic!("problem body is not valid JSON ({e}): {body}"),
        };
        let detail = parsed
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        assert!(!detail.is_empty(), "problem detail must not be empty");
        assert!(
            !detail.contains('/'),
            "problem detail must be path-free, leaked: {detail}"
        );
        assert!(
            !detail.contains('\\'),
            "problem detail must not contain path separators, leaked: {detail}"
        );
        // The correlation id remains available for server-side log lookup.
        assert!(
            parsed
                .get("trace_id")
                .is_some_and(|t| !t.as_str().unwrap_or_default().is_empty()),
            "problem must include a trace id for correlation"
        );
    }

    // Middleware rejections follow the same path-free rule (413 here).
    let oversized = post_json_request(
        "/api/v1/compile",
        &format!(
            "{{\"profile\":\"ai-agent\",\"workspace\":\".\",\"command\":[\"{}\"]}}",
            "a".repeat(MAX_REQUEST_BODY_BYTES)
        ),
    );
    let resp = send_raw(addr, &oversized).await;
    assert_eq!(status_of(&resp), 413);
    let body = body_of(&resp);
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or_default();
    let detail = parsed
        .get("detail")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(!detail.contains('/'), "middleware detail leaked: {detail}");
}
