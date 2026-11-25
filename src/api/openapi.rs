//! OpenAPI 3.1.0 specification emitter for the Cordon HTTP Control Plane.

use serde_json::{Value, json};

/// Builds the OpenAPI 3.1.0 specification document for the Cordon Control Plane.
#[must_use]
pub fn build_openapi_spec() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "PyCentric Cordon Control Plane API",
            "version": env!("CARGO_PKG_VERSION"),
            "license": {
                "name": "AGPL-3.0-only"
            },
            "description": "Zero-unsafe Rust Linux execution sandbox and L3-L7 network telemetry control plane."
        },
        "servers": [
            { "url": "http://127.0.0.1:8095", "description": "Local loopback control plane" }
        ],
        "paths": {
            "/health": { "get": { "summary": "Control plane health status", "responses": { "200": { "description": "Healthy" } } } },
            "/health/liveness": { "get": { "summary": "Kubernetes/systemd liveness probe", "responses": { "200": { "description": "Alive" } } } },
            "/health/readiness": { "get": { "summary": "Readiness probe", "responses": { "200": { "description": "Ready" } } } },
            "/health/dependencies": { "get": { "summary": "Host LSM and sandbox toolchain diagnostics", "responses": { "200": { "description": "Diagnostics report" } } } },
            "/metrics": { "get": { "summary": "Prometheus text exposition metrics", "responses": { "200": { "description": "Prometheus metrics" } } } },
            "/openapi.json": { "get": { "summary": "OpenAPI 3.1.0 schema document", "responses": { "200": { "description": "OpenAPI 3.1.0 JSON" } } } },
            "/api/v1/health": { "get": { "summary": "API v1 health status", "responses": { "200": { "description": "Healthy" } } } },
            "/api/v1/meta": { "get": { "summary": "Build and AGPL-3.0-only legal notice metadata", "responses": { "200": { "description": "Metadata" } } } },
            "/api/v1/profiles": { "get": { "summary": "List built-in workload isolation profiles", "responses": { "200": { "description": "Profile list" } } } },
            "/api/v1/profiles/{profile}": {
                "get": {
                    "summary": "Retrieve a single workload profile",
                    "parameters": [{ "name": "profile", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Profile" }, "404": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/templates": { "get": { "summary": "List reproducible Cordonfile templates", "responses": { "200": { "description": "Templates" } } } },
            "/api/v1/doctor": { "get": { "summary": "Run host kernel LSM and sandbox toolchain checks", "responses": { "200": { "description": "Doctor report" } } } },
            "/api/v1/apparmor/{profile}": {
                "get": {
                    "summary": "Render AppArmor 4.0 MAC profile",
                    "parameters": [{ "name": "profile", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "AppArmor policy" }, "404": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/network/{profile}": {
                "get": {
                    "summary": "Render Linux network namespace setup commands",
                    "parameters": [{ "name": "profile", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "Network commands" }, "404": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/events": {
                "get": {
                    "summary": "Fetch recent audit telemetry events",
                    "parameters": [{ "name": "limit", "in": "query", "required": false, "schema": { "type": "integer", "minimum": 1 } }],
                    "responses": { "200": { "description": "Audit events" } }
                }
            },
            "/api/v1/compile": {
                "post": {
                    "summary": "Compile a sandbox launch plan",
                    "parameters": [{ "$ref": "#/components/parameters/IdempotencyKey" }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CompileLaunchRequest" } } } },
                    "responses": { "200": { "description": "Compiled launch plan" }, "400": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/compile-config": {
                "post": {
                    "summary": "Compile a sandbox launch plan from Cordonfile/TOML config",
                    "parameters": [{ "$ref": "#/components/parameters/IdempotencyKey" }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CompileConfigRequest" } } } },
                    "responses": { "200": { "description": "Compiled launch plan" }, "400": { "$ref": "#/components/responses/Problem" } }
                }
            },
            "/api/v1/evaluate-l7": {
                "post": {
                    "summary": "Evaluate an outbound HTTP/HTTPS flow against L7 policy",
                    "parameters": [{ "$ref": "#/components/parameters/IdempotencyKey" }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/EvaluateL7Request" } } } },
                    "responses": { "200": { "description": "L7 policy decision" }, "400": { "$ref": "#/components/responses/Problem" } }
                }
            }
        },
        "components": {
            "parameters": {
                "IdempotencyKey": {
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": false,
                    "schema": { "type": "string", "minLength": 1, "maxLength": 128 },
                    "description": "Optional client idempotency correlation key echoed on the response."
                }
            },
            "responses": {
                "Problem": {
                    "description": "RFC 7807 Problem Details",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/ProblemDetails" } } }
                }
            },
            "schemas": {
                "CompileLaunchRequest": {
                    "type": "object",
                    "required": ["workspace_dir", "command"],
                    "properties": {
                        "profile": { "type": "string", "default": "ai-agent" },
                        "workspace_dir": { "type": "string" },
                        "command": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "CompileConfigRequest": {
                    "type": "object",
                    "required": ["config_content", "workspace_dir"],
                    "properties": {
                        "config_content": { "type": "string" },
                        "workspace_dir": { "type": "string" },
                        "format": { "type": "string", "enum": ["cordonfile", "toml"] },
                        "command_override": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "EvaluateL7Request": {
                    "type": "object",
                    "required": ["profile", "url"],
                    "properties": {
                        "url": { "type": "string" },
                        "method": { "type": "string", "default": "GET" },
                        "body": { "type": ["string", "null"] },
                        "profile": { "type": "string", "default": "ai-agent" }
                    }
                },
                "ProblemDetails": {
                    "type": "object",
                    "required": ["type", "title", "status", "detail", "instance", "trace_id"],
                    "properties": {
                        "type": { "type": "string" },
                        "title": { "type": "string" },
                        "status": { "type": "integer" },
                        "detail": { "type": "string" },
                        "instance": { "type": "string" },
                        "trace_id": { "type": "string" }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::build_openapi_spec;

    #[test]
    fn openapi_spec_is_3_1_0_with_core_paths() {
        let spec = build_openapi_spec();
        assert_eq!(spec["openapi"], "3.1.0");
        assert!(spec["paths"]["/openapi.json"]["get"].is_object());
        assert!(spec["paths"]["/api/v1/compile"]["post"].is_object());
        assert!(spec["paths"]["/api/v1/evaluate-l7"]["post"].is_object());
        assert!(spec["components"]["schemas"]["ProblemDetails"].is_object());
    }

    #[tokio::test]
    async fn control_plane_serves_openapi_probes_metrics_and_validates_idempotency_key() {
        use crate::api::{ControlPlaneOptions, CordonControlPlane, build_router_with_options};
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        async fn send_raw(addr: SocketAddr, req: &str) -> String {
            let mut stream = TcpStream::connect(addr)
                .await
                .unwrap_or_else(|e| panic!("connect: {e}"));
            stream
                .write_all(req.as_bytes())
                .await
                .unwrap_or_else(|e| panic!("write: {e}"));
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            String::from_utf8_lossy(&buf).into_owned()
        }

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr: {e}"));
        let router = build_router_with_options(
            CordonControlPlane::new(),
            ControlPlaneOptions {
                auth_token: None,
                bound_authority: Some(addr.to_string()),
            },
        );
        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        for path in [
            "/openapi.json",
            "/",
            "/health/liveness",
            "/health/readiness",
            "/health/dependencies",
            "/metrics",
            "/api/v1/meta",
            "/api/v1/profiles",
            "/api/v1/profiles/ai-agent",
            "/api/v1/templates",
            "/api/v1/events",
            "/api/v1/apparmor/ai-agent",
            "/api/v1/network/ai-agent",
        ] {
            let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
            let resp = send_raw(addr, &req).await;
            assert!(resp.starts_with("HTTP/1.1 200 OK"), "GET {path}: {resp}");
        }

        let opt_req =
            format!("OPTIONS /api/v1/meta HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        let opt_resp = send_raw(addr, &opt_req).await;
        assert!(opt_resp.starts_with("HTTP/1.1 405"), "OPTIONS: {opt_resp}");

        let auth_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|e| panic!("bind auth: {e}"));
        let auth_addr = auth_listener
            .local_addr()
            .unwrap_or_else(|e| panic!("addr: {e}"));
        let auth_router = build_router_with_options(
            CordonControlPlane::new(),
            ControlPlaneOptions {
                auth_token: Some("tok123".to_owned()),
                bound_authority: Some(auth_addr.to_string()),
            },
        );
        let auth_handle = tokio::spawn(async move {
            let _ = axum::serve(
                auth_listener,
                auth_router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        let unauth_resp = send_raw(
            auth_addr,
            &format!("GET /api/v1/meta HTTP/1.1\r\nHost: {auth_addr}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(
            unauth_resp.starts_with("HTTP/1.1 401"),
            "unauth: {unauth_resp}"
        );
        let authed_resp = send_raw(
            auth_addr,
            &format!("GET /api/v1/meta HTTP/1.1\r\nHost: {auth_addr}\r\nAuthorization: Bearer tok123\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(
            authed_resp.starts_with("HTTP/1.1 200 OK"),
            "authed: {authed_resp}"
        );
        auth_handle.abort();

        let compile_body = r#"{"profile":"ai-agent","workspace":".","command":["/bin/true"]}"#;
        let compile_req = format!(
            "POST /api/v1/compile HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{compile_body}",
            compile_body.len()
        );
        let compile_resp = send_raw(addr, &compile_req).await;
        assert!(
            compile_resp.starts_with("HTTP/1.1 200 OK"),
            "compile: {compile_resp}"
        );

        let cfg_body = r#"{"config_content":"FROM ai-agent\nCMD /bin/true","workspace":"."}"#;
        let cfg_req = format!(
            "POST /api/v1/compile-config HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{cfg_body}",
            cfg_body.len()
        );
        let cfg_resp = send_raw(addr, &cfg_req).await;
        assert!(
            cfg_resp.starts_with("HTTP/1.1 200 OK"),
            "compile-config: {cfg_resp}"
        );

        let not_found_req = format!(
            "GET /api/v1/profiles/missing-prof HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        );
        let nf_resp = send_raw(addr, &not_found_req).await;
        assert!(
            nf_resp.starts_with("HTTP/1.1 404 Not Found"),
            "404: {nf_resp}"
        );

        let bad_body = r#"{"url":"https://api.openai.com/v1/models","profile":"ai-agent"}"#;
        let bad_req = format!(
            "POST /api/v1/evaluate-l7 HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nIdempotency-Key:    \r\nConnection: close\r\n\r\n{bad_body}",
            bad_body.len()
        );
        let bad_resp = send_raw(addr, &bad_req).await;
        assert!(bad_resp.starts_with("HTTP/1.1 400 Bad Request"));

        let good_req = format!(
            "POST /api/v1/evaluate-l7 HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nIdempotency-Key: req-key-123\r\nConnection: close\r\n\r\n{bad_body}",
            bad_body.len()
        );
        let good_resp = send_raw(addr, &good_req).await;
        assert!(
            good_resp.starts_with("HTTP/1.1 200 OK"),
            "good_resp: {good_resp}"
        );
        assert!(good_resp.contains("idempotency-key: req-key-123"));
        handle.abort();
    }
}
