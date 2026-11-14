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
                    "required": ["url"],
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
}
