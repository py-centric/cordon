//! Hardened HTTP Control Plane middleware stack (CSP, Host guard, Bearer auth, Body limits, Rate limiting).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::error::Rfc7807ProblemDetails;

use super::{DASHBOARD_CSP, EVALUATE_L7_BODY_LIMIT_BYTES, MAX_REQUEST_BODY_BYTES};

/// Configuration for the control plane middleware stack.
#[derive(Debug, Clone, Default)]
pub struct ControlPlaneOptions {
    /// Bearer token required on `/api/v1/*` routes (`CORDON_API_TOKEN`); `None` disables auth.
    pub auth_token: Option<String>,
    /// Expected `Host` authority (`host:port`) accepted in addition to loopback names.
    pub bound_authority: Option<String>,
}

impl ControlPlaneOptions {
    /// Builds options from the `CORDON_API_TOKEN` environment variable.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            auth_token: std::env::var("CORDON_API_TOKEN")
                .ok()
                .filter(|token| !token.trim().is_empty()),
            bound_authority: None,
        }
    }
}

/// Hand-rolled token bucket (one per remote address) for POST rate limiting.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Hand-rolled token-bucket rate limiter keyed by remote address.
///
/// Implemented in-house to keep the dependency tree lean. Stale buckets (idle
/// longer than 10 minutes) are pruned opportunistically on every check.
#[derive(Debug)]
pub(super) struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    burst: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    pub(super) fn new(burst_per_minute: u32) -> Self {
        let burst = f64::from(burst_per_minute);
        Self {
            buckets: Mutex::new(HashMap::new()),
            burst,
            refill_per_sec: burst / 60.0,
        }
    }

    /// Returns `true` when `key` still has budget, consuming one token on success.
    pub(super) fn check_and_refill(&self, key: &str) -> bool {
        let Ok(mut guard) = self.buckets.lock() else {
            // Fail closed on a poisoned limiter so rate limiting cannot be bypassed.
            return false;
        };
        let now = Instant::now();
        guard.retain(|_, bucket| now.duration_since(bucket.last_refill) < Duration::from_secs(600));
        let bucket = guard.entry(key.to_owned()).or_insert_with(|| TokenBucket {
            tokens: self.burst,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.burst);
        bucket.last_refill = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Constant-time byte-string comparison (hand-rolled, dependency-free).
///
/// Normalizes on length first so short-circuiting never reveals which prefix matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for i in 0..max_len {
        diff |= usize::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Extracts the hostname from an HTTP `Host` authority (`host:port`, `[::1]:port`).
fn authority_hostname(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    }
}

/// Validates the `Host` header against the bound authority and loopback names.
///
/// Rejecting foreign hosts (421) defeats DNS rebinding: a malicious DNS name resolving
/// to `127.0.0.1` still sends a `Host` header that is not an accepted loopback name.
fn is_allowed_host(host_value: &str, bound_authority: Option<&str>) -> bool {
    let host = host_value.trim().to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    if let Some(bound) = bound_authority.map(str::trim) {
        let bound = bound.to_ascii_lowercase();
        if host == bound {
            return true;
        }
        if authority_hostname(&host) == authority_hostname(&bound) {
            return true;
        }
    }
    matches!(authority_hostname(&host), "127.0.0.1" | "localhost" | "::1")
}

/// Returns `true` when `path` is an authenticated API route (all of `/api/v1/*`).
///
/// `/healthz` and the other `/health*` probe endpoints sit outside `/api/v1/*` and stay
/// unauthenticated so schedulers and load balancers can poll them without a token.
fn api_route_requires_auth(path: &str) -> bool {
    path.starts_with("/api/v1/")
}

pub(super) fn extract_trace_id(headers: &HeaderMap) -> String {
    headers
        .get("Trace-ID")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| Uuid::new_v4().to_string(), str::to_owned)
}

pub(super) fn attach_common_headers(
    mut response: Response,
    headers: &HeaderMap,
    trace_id: &str,
) -> Response {
    if let Ok(trace_val) = HeaderValue::from_str(trace_id) {
        response.headers_mut().insert("Trace-ID", trace_val);
    }
    if let Some(idem) = headers.get("Idempotency-Key") {
        response
            .headers_mut()
            .insert("Idempotency-Key", idem.clone());
    }
    response
}

pub(super) fn problem_response(problem: &Rfc7807ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_string(problem).unwrap_or_else(|_| "{}".to_owned());
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if let Ok(trace_val) = HeaderValue::from_str(&problem.trace_id) {
        response.headers_mut().insert("Trace-ID", trace_val);
    }
    response
}

fn middleware_rejection(status: StatusCode, title: &str, detail: &str, req: &Request) -> Response {
    let trace_id = extract_trace_id(req.headers());
    problem_response(&Rfc7807ProblemDetails::from_status(
        status.as_u16(),
        title,
        detail,
        req.uri().path(),
        &trace_id,
    ))
}

/// Adds baseline security headers to every control plane response.
pub(super) async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(DASHBOARD_CSP),
    );
    response
}

/// Rejects (421) requests whose `Host` header is not the bound authority or a loopback name.
pub(super) async fn host_guard_middleware(
    State(bound_authority): State<Option<String>>,
    req: Request,
    next: Next,
) -> Response {
    let allowed = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|host| is_allowed_host(host, bound_authority.as_deref()));
    if !allowed {
        return middleware_rejection(
            StatusCode::MISDIRECTED_REQUEST,
            "Misdirected Request",
            "Host header does not match the bound control plane address",
            &req,
        );
    }
    next.run(req).await
}

/// Requires a constant-time verified `Authorization: Bearer` token on `/api/v1/*` when configured.
pub(super) async fn auth_middleware(
    State(auth_token): State<Option<String>>,
    req: Request,
    next: Next,
) -> Response {
    if let Some(expected) = auth_token.as_deref()
        && api_route_requires_auth(req.uri().path())
    {
        let provided = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, token)| token);
        let valid =
            provided.is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()));
        if !valid {
            return middleware_rejection(
                StatusCode::UNAUTHORIZED,
                "Unauthorized",
                "Missing or invalid bearer token",
                &req,
            );
        }
    }
    next.run(req).await
}

/// Rejects (413) request bodies above the per-route limit (checked from `Content-Length`).
pub(super) async fn body_limit_middleware(req: Request, next: Next) -> Response {
    let limit = if req.uri().path().starts_with("/api/v1/evaluate-l7") {
        EVALUATE_L7_BODY_LIMIT_BYTES
    } else {
        MAX_REQUEST_BODY_BYTES
    };
    let oversized = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > u64::try_from(limit).unwrap_or(u64::MAX));
    if oversized {
        return middleware_rejection(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Payload Too Large",
            "Request body exceeds the configured size limit",
            &req,
        );
    }
    next.run(req).await
}

/// Enforces the per-remote-addr token-bucket budget on POST routes (429 on exhaustion).
pub(super) async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    if req.method() == Method::POST {
        let key = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| "unknown".to_owned(), |ci| ci.0.ip().to_string());
        if !limiter.check_and_refill(&key) {
            return middleware_rejection(
                StatusCode::TOO_MANY_REQUESTS,
                "Too Many Requests",
                "Rate limit exceeded for this client",
                &req,
            );
        }
    }
    next.run(req).await
}
