//! Integration tests for Cordon HTTP Control Plane (`axum`), CLI subcommands, Error RFC 7807 mapping, and Hexagonal Ports.

use cordon::api::{
    CompileConfigRequest, CompileLaunchRequest, CordonControlPlane, EvaluateL7Request, build_router,
};
use tokio::net::TcpListener;

mod common;

#[tokio::test]
async fn test_axum_http_control_plane_endpoints() {
    let plane = CordonControlPlane::default();
    let router = build_router(plane);
    let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
        panic!("Failed to bind ephemeral port");
    };
    let Ok(addr) = listener.local_addr() else {
        panic!("Failed to read local_addr");
    };

    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // 1. GET / (Dashboard HTML)
    let dash = common::send_raw(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(dash.contains("200 OK"));
    assert!(dash.contains("Developed by PyCentric"));

    // 2. GET /health, /health/liveness, /health/readiness, /metrics, /api/v1/profiles, /api/v1/templates, /api/v1/doctor, /api/v1/apparmor/ai-agent, /api/v1/network/ai-agent, /api/v1/events
    for path in [
        "/health",
        "/health/liveness",
        "/health/readiness",
        "/metrics",
        "/api/v1/profiles",
        "/api/v1/templates",
        "/api/v1/doctor",
        "/api/v1/apparmor/ai-agent",
        "/api/v1/network/ai-agent",
        "/api/v1/events?limit=5",
    ] {
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let resp = common::send_raw(addr, &req).await;
        assert!(resp.contains("200 OK"), "Endpoint {path} failed: {resp}");
    }

    // 2b. GET /api/v1/apparmor/missing and /api/v1/network/missing (404 Problem Details)
    for bad_path in ["/api/v1/apparmor/missing", "/api/v1/network/missing"] {
        let req =
            format!("GET {bad_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let resp = common::send_raw(addr, &req).await;
        assert!(resp.contains("404 Not Found"));
        assert!(resp.contains("application/problem+json"));
    }

    // 3. POST /api/v1/compile (200 OK + Trace-ID + Idempotency-Key echo)
    let compile_body = serde_json::to_string(&CompileLaunchRequest {
        profile: "ai-agent".to_owned(),
        workspace: ".".to_owned(),
        command: vec!["opencode".to_owned()],
        extra_masked_binaries: Vec::new(),
        extra_rw_paths: Vec::new(),
        vm: None,
    })
    .unwrap_or_default();
    let compile_req = format!(
        "POST /api/v1/compile HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTrace-ID: trace-compile-1\r\nIdempotency-Key: idem-123\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        compile_body.len(),
        compile_body
    );
    let compile_resp = common::send_raw(addr, &compile_req).await;
    assert!(compile_resp.contains("200 OK"));
    assert!(
        compile_resp
            .to_ascii_lowercase()
            .contains("idempotency-key: idem-123")
    );

    // 3b. POST /api/v1/compile-config (200 OK & 400 Invalid Format)
    let cfg_body = serde_json::to_string(&CompileConfigRequest {
        config_content:
            "FROM ai-agent\nNAME opencode-env\nWORKDIR .\nMOUNT /tmp:ro\nCMD [\"opencode\"]\n"
                .to_owned(),
        format: "cordonfile".to_owned(),
        workspace_override: Some(".".to_owned()),
        command_override: Vec::new(),
    })
    .unwrap_or_default();
    let cfg_req = format!(
        "POST /api/v1/compile-config HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        cfg_body.len(),
        cfg_body
    );
    let cfg_resp = common::send_raw(addr, &cfg_req).await;
    assert!(cfg_resp.contains("200 OK"));
    assert!(cfg_resp.contains("opencode"));

    let bad_cfg_body = serde_json::to_string(&CompileConfigRequest {
        config_content: "FROM ai-agent".to_owned(),
        format: "invalid-fmt".to_owned(),
        workspace_override: None,
        command_override: Vec::new(),
    })
    .unwrap_or_default();
    let bad_cfg_req = format!(
        "POST /api/v1/compile-config HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        bad_cfg_body.len(),
        bad_cfg_body
    );
    let bad_cfg_resp = common::send_raw(addr, &bad_cfg_req).await;
    assert!(bad_cfg_resp.contains("400 Bad Request"));

    // 4. POST /api/v1/compile (404 Unknown Profile RFC 7807)
    let bad_compile_body = serde_json::to_string(&CompileLaunchRequest {
        profile: "missing-profile".to_owned(),
        workspace: ".".to_owned(),
        command: vec!["opencode".to_owned()],
        extra_masked_binaries: Vec::new(),
        extra_rw_paths: Vec::new(),
        vm: None,
    })
    .unwrap_or_default();
    let bad_compile_req = format!(
        "POST /api/v1/compile HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        bad_compile_body.len(),
        bad_compile_body
    );
    let bad_compile_resp = common::send_raw(addr, &bad_compile_req).await;
    assert!(bad_compile_resp.contains("404 Not Found"));
    assert!(bad_compile_resp.contains("application/problem+json"));

    // 5. POST /api/v1/evaluate-l7 (200 OK Block secret & 404 Unknown Profile)
    let eval_body = serde_json::to_string(&EvaluateL7Request {
        profile: "ai-agent".to_owned(),
        url: "https://api.openai.com/v1/chat/completions".to_owned(),
        method: "POST".to_owned(),
        body: Some("leak sk-1234567890abcdefghijklmnop".to_owned()),
    })
    .unwrap_or_default();
    let eval_req = format!(
        "POST /api/v1/evaluate-l7 HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nIdempotency-Key: idem-eval-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        eval_body.len(),
        eval_body
    );
    let eval_resp = common::send_raw(addr, &eval_req).await;
    assert!(eval_resp.contains("200 OK"));
    assert!(eval_resp.contains("SECRET_OPENAI_KEY"));
    assert!(
        eval_resp
            .to_ascii_lowercase()
            .contains("idempotency-key: idem-eval-1")
    );

    let bad_eval_body = serde_json::to_string(&EvaluateL7Request {
        profile: "unknown-prof".to_owned(),
        url: "https://api.openai.com/v1/models".to_owned(),
        method: "GET".to_owned(),
        body: None,
    })
    .unwrap_or_default();
    let bad_eval_req = format!(
        "POST /api/v1/evaluate-l7 HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        bad_eval_body.len(),
        bad_eval_body
    );
    let bad_eval_resp = common::send_raw(addr, &bad_eval_req).await;
    assert!(bad_eval_resp.contains("404 Not Found"));
}

/// Serde contract: the exact JSON keys the dashboard `/app.js` dereferences must exist on
/// the serialized [`AuditEvent`]. The key list lives in `cordon::domain` and is injected
/// into the JS at render time, so this test and the dashboard cannot drift apart.
#[test]
fn test_dashboard_audit_event_serde_contract() {
    use cordon::dashboard::{render_dashboard_html, render_dashboard_js};
    use cordon::domain::{
        AUDIT_DETAIL_DASHBOARD_KEYS, AUDIT_EVENT_DASHBOARD_KEYS, AuditEvent, EnforcementPlane,
        Severity, Verdict, audit_json,
    };
    use std::collections::BTreeMap;

    let mut details = BTreeMap::new();
    details.insert(
        audit_json::DETAIL_URL.to_owned(),
        "https://api.openai.com/v1/chat/completions".to_owned(),
    );
    details.insert(
        audit_json::DETAIL_RULE.to_owned(),
        "ALLOW_DOMAIN".to_owned(),
    );
    let event = AuditEvent {
        event_id: "e-1".to_owned(),
        timestamp: "2026-10-31T00:00:00+00:00".to_owned(),
        plane: EnforcementPlane::Mitmproxy,
        severity: Severity::Info,
        verdict: Verdict::Allow,
        profile: "ai-agent".to_owned(),
        subject: "contract test event".to_owned(),
        details,
    };

    let value = serde_json::to_value(&event).unwrap_or_default();

    // Every top-level key the JS reads must exist on the serialized event.
    for key in AUDIT_EVENT_DASHBOARD_KEYS {
        assert!(
            value.get(key).is_some(),
            "AuditEvent JSON is missing key '{key}' consumed by the dashboard JS"
        );
    }
    // The derived Target / Rule columns must resolve from the details map.
    let details_value = value.get(audit_json::DETAILS).cloned().unwrap_or_default();
    for key in AUDIT_DETAIL_DASHBOARD_KEYS {
        assert!(
            details_value.get(key).is_some(),
            "AuditEvent details are missing key '{key}' consumed by the dashboard JS"
        );
    }

    // The generated JS must consume exactly the shared key list (injected `EVK` map)...
    let js = render_dashboard_js();
    for key in AUDIT_EVENT_DASHBOARD_KEYS
        .iter()
        .chain(AUDIT_DETAIL_DASHBOARD_KEYS.iter())
    {
        assert!(
            js.contains(&format!("\"{key}\"")),
            "dashboard JS does not reference shared audit key '{key}'"
        );
    }
    // ...and must never dereference the legacy broken field names or raw fields inline.
    for stale in [
        "timestamp_utc",
        "ev.target",
        "ev.reason",
        "ev.timestamp",
        "ev.subject",
        "ev.profile",
        "ev.verdict",
    ] {
        assert!(
            !js.contains(stale),
            "dashboard JS references stale/inline audit field '{stale}'"
        );
    }

    // The HTML shell must stay CSP-strict: external /app.js, zero inline handlers.
    let html = render_dashboard_html();
    assert!(html.contains("src=\"/app.js\""));
    for handler in ["onclick=", "onchange=", "onerror=", "onload=", "oninput="] {
        assert!(
            !html.contains(handler),
            "dashboard HTML contains inline handler '{handler}' (breaks strict CSP)"
        );
    }
    assert!(!html.contains("<script>"), "no inline scripts allowed");
}

/// Audit ring overflow must never silently drop evidence: evictions emit a WARNING event.
#[test]
fn test_audit_ring_eviction_emits_warning_event() {
    use cordon::api::{AUDIT_RING_EVICTED_REASON, CordonControlPlane, MAX_RING_BUFFER_EVENTS};
    use cordon::domain::{AuditEvent, EnforcementPlane, Severity, Verdict};
    use cordon::ports::AuditSinkPort;
    use std::collections::BTreeMap;

    let plane = CordonControlPlane::default();
    for i in 0..(MAX_RING_BUFFER_EVENTS + 8) {
        plane.record_event(AuditEvent {
            event_id: format!("ev-{i}"),
            timestamp: "2026-10-31T00:00:00+00:00".to_owned(),
            plane: EnforcementPlane::Tshark,
            severity: Severity::Info,
            verdict: Verdict::Allow,
            profile: "ai-agent".to_owned(),
            subject: format!("overflow filler event {i}"),
            details: BTreeMap::new(),
        });
    }

    let events = plane.recent_events(MAX_RING_BUFFER_EVENTS);
    assert!(
        events.len() <= MAX_RING_BUFFER_EVENTS,
        "ring buffer exceeded its capacity"
    );
    let eviction_warnings = events
        .iter()
        .filter(|e| {
            e.severity == Severity::Warning
                && e.details.get("reason").map(String::as_str) == Some(AUDIT_RING_EVICTED_REASON)
        })
        .count();
    assert!(
        eviction_warnings > 0,
        "ring buffer eviction must emit a WARNING audit event (never a silent drop)"
    );
    assert!(plane.evicted_total() >= 1);
}
