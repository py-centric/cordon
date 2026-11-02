//! Security middleware tests for the Cordon HTTP control plane: host-header validation
//! (DNS rebinding), bearer auth, security headers / CSP, body limits, and rate limiting.

use std::net::SocketAddr;

use cordon::api::{
    CordonControlPlane, ControlPlaneOptions, DASHBOARD_CSP, EVALUATE_L7_BODY_LIMIT_BYTES,
    MAX_REQUEST_BODY_BYTES, build_router_with_options,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_server(options: ControlPlaneOptions) -> SocketAddr {
    let router = build_router_with_options(CordonControlPlane::default(), options);
    let listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => panic!("Failed to bind ephemeral port: {e}"),
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => panic!("Failed to read local_addr: {e}"),
    };
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    addr
}

async fn send_raw(addr: SocketAddr, request: &str) -> String {
    let mut stream = match TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => panic!("Failed to connect to test server: {e}"),
    };
    let _ = stream.write_all(request.as_bytes()).await;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn status_of(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn body_of(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn header_of<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.split_once("\r\n\r\n").and_then(|(head, _)| {
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
    })
}

fn get_request(path: &str, extra_headers: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra_headers}Connection: close\r\n\r\n")
}

fn post_json_request(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Host header validation must reject foreign hosts with 421 (DNS rebinding defense)
/// while accepting the bound authority and loopback names.
#[tokio::test]
async fn test_host_header_validation_rejects_foreign_hosts() {
    let addr = spawn_server(ControlPlaneOptions {
        auth_token: None,
        bound_authority: Some(format!("127.0.0.1:{}", 0)),
    })
    .await;

    for evil_host in [
        "evil.example.com",
        "attacker.internal",
        "localhost.evil.example.com",
    ] {
        let req = format!(
            "GET /api/v1/events HTTP/1.1\r\nHost: {evil_host}\r\nConnection: close\r\n\r\n"
        );
        let resp = send_raw(addr, &req).await;
        assert_eq!(
            status_of(&resp),
            421,
            "Host '{evil_host}' must be rejected with 421"
        );
    }

    for good_host in ["localhost", "127.0.0.1", "127.0.0.1:8095", "[::1]", "[::1]:8095"] {
        let req =
            format!("GET /api/v1/profiles HTTP/1.1\r\nHost: {good_host}\r\nConnection: close\r\n\r\n");
        let resp = send_raw(addr, &req).await;
        assert_eq!(
            status_of(&resp),
            200,
            "Host '{good_host}' must be accepted"
        );
    }

    // The explicitly bound authority is accepted verbatim (any hostname it declares).
    let addr2 = spawn_server(ControlPlaneOptions {
        auth_token: None,
        bound_authority: Some("cordon.internal:8095".to_owned()),
    })
    .await;
    let req = "GET /api/v1/profiles HTTP/1.1\r\nHost: cordon.internal:8095\r\nConnection: close\r\n\r\n";
    let resp = send_raw(addr2, req).await;
    assert_eq!(status_of(&resp), 200, "bound authority must be accepted");
}

/// When `CORDON_API_TOKEN` semantics are enabled, every `/api/v1/*` route requires a valid
/// bearer token; probe endpoints (`/healthz`) stay open for schedulers.
#[tokio::test]
async fn test_bearer_token_enforced_on_api_routes() {
    let token = "unit-test-token-e7a1".to_owned();
    let addr = spawn_server(ControlPlaneOptions {
        auth_token: Some(token.clone()),
        bound_authority: None,
    })
    .await;

    // Missing token -> 401 ProblemDetails.
    let resp = send_raw(addr, &get_request("/api/v1/events?limit=5", "")).await;
    assert_eq!(status_of(&resp), 401);
    assert!(
        header_of(&resp, "content-type")
            .is_some_and(|ct| ct.contains("application/problem+json")),
        "401 must be an RFC 7807 problem document"
    );

    // Wrong token -> 401.
    let wrong = get_request("/api/v1/events?limit=5", "Authorization: Bearer wrong-token\r\n");
    let resp = send_raw(addr, &wrong).await;
    assert_eq!(status_of(&resp), 401);

    // Malformed scheme -> 401.
    let malformed = get_request("/api/v1/events?limit=5", "Authorization: Basic dXNlcg==\r\n");
    let resp = send_raw(addr, &malformed).await;
    assert_eq!(status_of(&resp), 401);

    // Correct token -> 200.
    let ok = get_request(
        "/api/v1/events?limit=5",
        &format!("Authorization: Bearer {token}\r\n"),
    );
    let resp = send_raw(addr, &ok).await;
    assert_eq!(status_of(&resp), 200);

    // All /api/v1/* routes are gated, including /api/v1/health.
    let resp = send_raw(addr, &get_request("/api/v1/health", "")).await;
    assert_eq!(status_of(&resp), 401);

    // Health probes stay unauthenticated for load balancers and schedulers.
    for probe in ["/healthz", "/health", "/health/liveness", "/health/readiness"] {
        let resp = send_raw(addr, &get_request(probe, "")).await;
        assert_eq!(
            status_of(&resp),
            200,
            "probe endpoint {probe} must stay unauthenticated"
        );
    }
}

/// Security headers (nosniff / DENY / no-referrer / no-store / strict CSP) on all responses.
#[tokio::test]
async fn test_security_headers_and_strict_csp_on_all_responses() {
    let addr = spawn_server(ControlPlaneOptions::default()).await;

    for (path, expected) in [
        ("/", 200),
        ("/app.js", 200),
        ("/api/v1/events?limit=1", 200),
        ("/does-not-exist", 404),
    ] {
        let resp = send_raw(addr, &get_request(path, "")).await;
        assert_eq!(status_of(&resp), expected, "unexpected status for {path}");
        assert_eq!(
            header_of(&resp, "x-content-type-options"),
            Some("nosniff"),
            "missing nosniff on {path}"
        );
        assert_eq!(
            header_of(&resp, "x-frame-options"),
            Some("DENY"),
            "missing DENY on {path}"
        );
        assert_eq!(
            header_of(&resp, "referrer-policy"),
            Some("no-referrer"),
            "missing no-referrer on {path}"
        );
        assert_eq!(
            header_of(&resp, "cache-control"),
            Some("no-store"),
            "missing no-store on {path}"
        );
        let csp = header_of(&resp, "content-security-policy").unwrap_or_default();
        assert!(
            csp.contains("script-src 'self'"),
            "CSP must keep script-src strict on {path}: {csp}"
        );
        assert!(
            !csp.contains("script-src 'self' 'unsafe-inline'"),
            "script-src must not allow unsafe-inline on {path}: {csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"), "CSP on {path}: {csp}");
    }

    // The dashboard shell loads its behavior from the same-origin /app.js route.
    let dash = send_raw(addr, &get_request("/", "")).await;
    assert!(body_of(&dash).contains("src=\"/app.js\""));
    let js = send_raw(addr, &get_request("/app.js", "")).await;
    assert_eq!(status_of(&js), 200);
    assert!(header_of(&js, "content-type")
        .is_some_and(|ct| ct.contains("application/javascript")));
    assert!(body_of(&js).contains("const EVK ="), "EVK key map must be injected");
    assert!(
        DASHBOARD_CSP.contains("default-src 'self'"),
        "CSP constant sanity"
    );
}

/// Global 1 MiB body limit rejects oversized payloads with 413 before handlers run.
#[tokio::test]
async fn test_global_body_limit_rejects_oversized_payloads() {
    let addr = spawn_server(ControlPlaneOptions::default()).await;

    let big_body = format!("{{\"profile\":\"ai-agent\",\"workspace\":\".\",\"command\":[\"{}\"]}}", "a".repeat(MAX_REQUEST_BODY_BYTES));
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
        assert_eq!(status_of(&resp), 200, "GET routes must not consume POST budget");
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
        assert!(header_of(&resp, "content-type")
            .is_some_and(|ct| ct.contains("application/problem+json")));
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
            parsed.get("trace_id").is_some_and(|t| !t.as_str().unwrap_or_default().is_empty()),
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

/// AGPL-3.0-only sections 5(d)/13: `/api/v1/meta` must serve the legal notices
/// and a Corresponding Source URL pinned to the running crate version.
#[tokio::test]
async fn test_meta_endpoint_serves_agpl_legal_notices() {
    let addr = spawn_server(ControlPlaneOptions {
        auth_token: None,
        bound_authority: None,
    })
    .await;

    let resp = send_raw(addr, &get_request("/api/v1/meta", "")).await;
    assert_eq!(status_of(&resp), 200);
    let parsed: serde_json::Value = serde_json::from_str(body_of(&resp)).unwrap_or_default();

    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(
        parsed.get("service").and_then(serde_json::Value::as_str),
        Some("pycentric-cordon"),
        "meta must name the service"
    );
    assert_eq!(
        parsed.get("version").and_then(serde_json::Value::as_str),
        Some(version),
        "meta version must match the crate version"
    );
    assert_eq!(
        parsed.get("licence").and_then(serde_json::Value::as_str),
        Some("AGPL-3.0-only"),
        "meta must declare the AGPL-3.0-only licence identifier"
    );
    assert_eq!(
        parsed
            .get("corresponding_source")
            .and_then(serde_json::Value::as_str),
        Some(format!("https://github.com/pycentric/cordon/tree/v{version}").as_str()),
        "meta must offer Corresponding Source for this exact version"
    );
}
