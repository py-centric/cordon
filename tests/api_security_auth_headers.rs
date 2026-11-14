//! Host-header validation, bearer auth, security headers / CSP, and AGPL meta tests.

mod common;
use common::{body_of, get_request, header_of, send_raw, spawn_server, status_of};
use cordon::api::{ControlPlaneOptions, DASHBOARD_CSP};

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

    for good_host in [
        "localhost",
        "127.0.0.1",
        "127.0.0.1:8095",
        "[::1]",
        "[::1]:8095",
    ] {
        let req = format!(
            "GET /api/v1/profiles HTTP/1.1\r\nHost: {good_host}\r\nConnection: close\r\n\r\n"
        );
        let resp = send_raw(addr, &req).await;
        assert_eq!(status_of(&resp), 200, "Host '{good_host}' must be accepted");
    }

    // The explicitly bound authority is accepted verbatim (any hostname it declares).
    let addr2 = spawn_server(ControlPlaneOptions {
        auth_token: None,
        bound_authority: Some("cordon.internal:8095".to_owned()),
    })
    .await;
    let req =
        "GET /api/v1/profiles HTTP/1.1\r\nHost: cordon.internal:8095\r\nConnection: close\r\n\r\n";
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
        header_of(&resp, "content-type").is_some_and(|ct| ct.contains("application/problem+json")),
        "401 must be an RFC 7807 problem document"
    );

    // Wrong token -> 401.
    let wrong = get_request(
        "/api/v1/events?limit=5",
        "Authorization: Bearer wrong-token\r\n",
    );
    let resp = send_raw(addr, &wrong).await;
    assert_eq!(status_of(&resp), 401);

    // Malformed scheme -> 401.
    let malformed = get_request(
        "/api/v1/events?limit=5",
        "Authorization: Basic dXNlcg==\r\n",
    );
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
    for probe in [
        "/healthz",
        "/health",
        "/health/liveness",
        "/health/readiness",
    ] {
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
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "CSP on {path}: {csp}"
        );
    }

    // The dashboard shell loads its behavior from the same-origin /app.js route.
    let dash = send_raw(addr, &get_request("/", "")).await;
    assert!(body_of(&dash).contains("src=\"/app.js\""));
    let js = send_raw(addr, &get_request("/app.js", "")).await;
    assert_eq!(status_of(&js), 200);
    assert!(header_of(&js, "content-type").is_some_and(|ct| ct.contains("application/javascript")));
    assert!(
        body_of(&js).contains("const EVK ="),
        "EVK key map must be injected"
    );
    assert!(
        DASHBOARD_CSP.contains("default-src 'self'"),
        "CSP constant sanity"
    );
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
