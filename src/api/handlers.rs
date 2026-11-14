//! `axum` route handlers and router builder for the Cordon HTTP Control Plane.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::config::list_config_templates;
use crate::dashboard::{render_dashboard_html, render_dashboard_js};
use crate::domain::{DoctorReport, Verdict};
use crate::error::CordonError;
use crate::ports::AuditSinkPort;

use super::middleware::{
    ControlPlaneOptions, RateLimiter, attach_common_headers, auth_middleware,
    body_limit_middleware, extract_trace_id, host_guard_middleware, problem_response,
    rate_limit_middleware, security_headers_middleware,
};
use super::{
    CompileConfigRequest, CompileLaunchRequest, CordonControlPlane, EVALUATE_L7_BODY_LIMIT_BYTES,
    EvaluateL7Request, EventsQuery, EventsResponse, HealthResponse, MAX_REQUEST_BODY_BYTES,
    MAX_RING_BUFFER_EVENTS, MetaResponse, ProfilesResponse, RATE_LIMIT_POSTS_PER_MINUTE,
    TemplatesResponse,
};

async fn handle_dashboard() -> Html<&'static str> {
    Html(render_dashboard_html())
}

async fn handle_app_js() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        render_dashboard_js(),
    )
        .into_response()
}

async fn handle_health(State(state): State<CordonControlPlane>) -> Json<HealthResponse> {
    Json(state.health())
}

/// Serves AGPL-3.0-only legal notices (service, version, licence, Corresponding Source).
async fn handle_meta() -> Json<MetaResponse> {
    Json(MetaResponse::for_build())
}

async fn handle_liveness() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "alive" }))
}

async fn handle_readiness(State(state): State<CordonControlPlane>) -> Json<serde_json::Value> {
    let h = state.health();
    Json(serde_json::json!({
        "status": "ready",
        "profiles_loaded": h.profiles_count,
    }))
}

async fn handle_metrics(State(state): State<CordonControlPlane>) -> impl IntoResponse {
    let h = state.health();
    let events = state.recent_events(MAX_RING_BUFFER_EVENTS);
    let blocked_count = events
        .iter()
        .filter(|e| e.verdict == Verdict::Block)
        .count();
    let body = format!(
        "# HELP cordon_profiles_total Total registered sandbox profiles\n\
         # TYPE cordon_profiles_total gauge\n\
         cordon_profiles_total {}\n\
         # HELP cordon_audit_events_buffered Total buffered audit events\n\
         # TYPE cordon_audit_events_buffered gauge\n\
         cordon_audit_events_buffered {}\n\
         # HELP cordon_audit_events_blocked_total Buffered blocked security events\n\
         # TYPE cordon_audit_events_blocked_total gauge\n\
         cordon_audit_events_blocked_total {}\n",
        h.profiles_count, h.buffered_events, blocked_count
    );
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        )],
        body,
    )
}

async fn handle_profiles(State(state): State<CordonControlPlane>) -> Json<ProfilesResponse> {
    Json(ProfilesResponse {
        profiles: state.list_profiles(),
    })
}

async fn handle_profile(
    State(state): State<CordonControlPlane>,
    AxumPath(profile_slug): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.get_profile(&profile_slug) {
        Ok(profile) => attach_common_headers(Json(profile).into_response(), &headers, &trace_id),
        Err(err) => problem_response(
            &err.to_problem_details(&format!("/api/v1/profiles/{profile_slug}"), &trace_id),
        ),
    }
}

async fn handle_templates() -> Json<TemplatesResponse> {
    Json(TemplatesResponse {
        templates: list_config_templates(),
    })
}

async fn handle_doctor(State(state): State<CordonControlPlane>) -> Json<DoctorReport> {
    Json(state.doctor())
}

async fn handle_apparmor(
    State(state): State<CordonControlPlane>,
    AxumPath(profile_slug): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.render_apparmor(&profile_slug) {
        Ok(resp) => attach_common_headers(Json(resp).into_response(), &headers, &trace_id),
        Err(err) => problem_response(
            &err.to_problem_details(&format!("/api/v1/apparmor/{profile_slug}"), &trace_id),
        ),
    }
}

async fn handle_network(
    State(state): State<CordonControlPlane>,
    AxumPath(profile_slug): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.render_network(&profile_slug) {
        Ok(resp) => attach_common_headers(Json(resp).into_response(), &headers, &trace_id),
        Err(err) => problem_response(
            &err.to_problem_details(&format!("/api/v1/network/{profile_slug}"), &trace_id),
        ),
    }
}

async fn handle_events(
    State(state): State<CordonControlPlane>,
    Query(query): Query<EventsQuery>,
) -> Json<EventsResponse> {
    Json(EventsResponse {
        events: state.recent_events(query.limit),
    })
}

async fn handle_compile(
    State(state): State<CordonControlPlane>,
    headers: HeaderMap,
    Json(payload): Json<CompileLaunchRequest>,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.compile_plan(&payload) {
        Ok(plan) => attach_common_headers(Json(plan).into_response(), &headers, &trace_id),
        Err(err) => problem_response(&err.to_problem_details("/api/v1/compile", &trace_id)),
    }
}

async fn handle_compile_config(
    State(state): State<CordonControlPlane>,
    headers: HeaderMap,
    Json(payload): Json<CompileConfigRequest>,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.compile_config_plan(&payload) {
        Ok(plan) => attach_common_headers(Json(plan).into_response(), &headers, &trace_id),
        Err(err) => problem_response(&err.to_problem_details("/api/v1/compile-config", &trace_id)),
    }
}

async fn handle_evaluate_l7(
    State(state): State<CordonControlPlane>,
    headers: HeaderMap,
    Json(payload): Json<EvaluateL7Request>,
) -> Response {
    let trace_id = extract_trace_id(&headers);
    match state.evaluate_l7(&payload) {
        Ok(decision) => attach_common_headers(Json(decision).into_response(), &headers, &trace_id),
        Err(err) => problem_response(&err.to_problem_details("/api/v1/evaluate-l7", &trace_id)),
    }
}

/// Builds the `axum::Router` for the Cordon HTTP Control Plane and Web Dashboard,
/// reading `CORDON_API_TOKEN` from the environment for bearer auth.
pub fn build_router(state: CordonControlPlane) -> Router {
    build_router_with_options(state, ControlPlaneOptions::from_env())
}

/// Builds the `axum::Router` with explicit [`ControlPlaneOptions`] (auth token, bound authority).
///
/// Middleware chain (outermost first): security headers -> host guard -> bearer auth ->
/// body limits -> POST rate limit -> routes. Layer calls below are applied innermost-first.
pub fn build_router_with_options(
    state: CordonControlPlane,
    options: ControlPlaneOptions,
) -> Router {
    let rate_limiter = Arc::new(RateLimiter::new(RATE_LIMIT_POSTS_PER_MINUTE));
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/app.js", get(handle_app_js))
        .route("/health", get(handle_health))
        .route("/healthz", get(handle_health))
        .route("/health/liveness", get(handle_liveness))
        .route("/health/readiness", get(handle_readiness))
        .route("/health/dependencies", get(handle_doctor))
        .route("/metrics", get(handle_metrics))
        .route("/api/v1/health", get(handle_health))
        .route("/api/v1/meta", get(handle_meta))
        .route("/api/v1/profiles", get(handle_profiles))
        .route("/api/v1/profiles/{profile}", get(handle_profile))
        .route("/api/v1/templates", get(handle_templates))
        .route("/api/v1/doctor", get(handle_doctor))
        .route("/api/v1/apparmor/{profile}", get(handle_apparmor))
        .route("/api/v1/network/{profile}", get(handle_network))
        .route("/api/v1/events", get(handle_events))
        .route("/api/v1/compile", post(handle_compile))
        .route("/api/v1/compile-config", post(handle_compile_config))
        .route(
            "/api/v1/evaluate-l7",
            post(handle_evaluate_l7).layer(DefaultBodyLimit::max(EVALUATE_L7_BODY_LIMIT_BYTES)),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(body_limit_middleware))
        .layer(axum::middleware::from_fn_with_state(
            options.auth_token,
            auth_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            options.bound_authority,
            host_guard_middleware,
        ))
        .layer(axum::middleware::from_fn(security_headers_middleware))
}

/// Starts the async `axum` HTTP Control Plane on `host:port`.
pub async fn serve_control_plane(host: &str, port: u16) -> Result<(), CordonError> {
    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    let options = ControlPlaneOptions {
        auth_token: std::env::var("CORDON_API_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty()),
        bound_authority: Some(addr),
    };
    let router = build_router_with_options(CordonControlPlane::new(), options);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
