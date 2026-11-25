//! WCAG 2.1 AA Tri-Theme Web Dashboard renderer for the Cordon Control Plane.
//!
//! Complies with PyCentric Frontend, Fullstack, and Behavioral Psychology Standards:
//! - Three theme modes: Adaptive Light, Adaptive Dark, High Contrast (7:1 ratio)
//! - `@media (prefers-reduced-motion: reduce)` support
//! - Minimum 48x48px interactive touch targets
//! - Responsive Compact (<600px), Medium (600-840px), and Expanded (>840px) grid
//! - Multi-locale JSON i18n dictionary (`en`, `af`, `zu`) with zero hardcoded UI text in markup
//! - Interactive 5-Gate Kernel Architecture Rail (`role="tablist"`) in canonical gate order
//!   (1 netns, 2 AppArmor, 3 Bubblewrap, 4 iptables -> mitmproxy, 5 tshark)
//! - Fogg Behavior Model (`B=MAP`) 1-click L7 attack preset scenarios + payload secret scanner
//! - Safe DOM manipulation (`textContent` / `createElement`, zero unsafe `innerHTML`)
//! - Strict `Content-Security-Policy`: the application JavaScript is served from the
//!   same-origin `/app.js` route (`script-src 'self'`); zero inline `<script>` blocks and
//!   zero inline `on*=` handlers (all wiring uses `addEventListener`).
//! - [`crate::domain::audit_json`] field names are injected into `/app.js` at render time so
//!   the telemetry table and the serialized [`crate::domain::AuditEvent`] schema cannot drift.
//! - Explicit "Developed by PyCentric" attribution footer

use crate::domain::{AUDIT_EVENT_DASHBOARD_KEYS, audit_json};

/// Static dashboard HTML shell embedded at compile time from `index.html`.
const DASHBOARD_HTML: &str = include_str!("index.html");

/// Static dashboard application JavaScript body embedded at compile time from `app.js`.
///
/// Every `AuditEvent` field read goes through the injected `EVK` map (see
/// [`render_dashboard_js`]); the serde contract test in `tests/cordon_api_and_cli.rs`
/// asserts those keys exist on the serialized event so the two cannot drift apart.
const DASHBOARD_JS_BODY: &str = include_str!("app.js");

/// Renders the complete single-page responsive Web Dashboard HTML shell.
///
/// The shell loads its behavior from the same-origin [`render_dashboard_js`] payload at
/// `/app.js`, keeping `script-src 'self'` strict under the dashboard CSP.
#[must_use]
pub const fn render_dashboard_html() -> &'static str {
    DASHBOARD_HTML
}

/// Renders the dashboard application JavaScript served at `/app.js`.
///
/// The [`crate::domain::audit_json`] field names are injected as the `EVK` map (built from
/// [`AUDIT_EVENT_DASHBOARD_KEYS`] and [`crate::domain::AUDIT_DETAIL_DASHBOARD_KEYS`]) so the
/// telemetry table code and the serialized [`crate::domain::AuditEvent`] schema share one
/// source of truth.
#[must_use]
pub fn render_dashboard_js() -> String {
    let mut key_map = serde_json::Map::new();
    for key in AUDIT_EVENT_DASHBOARD_KEYS {
        key_map.insert((*key).to_owned(), serde_json::Value::from(*key));
    }
    key_map.insert(
        "detailUrl".to_owned(),
        serde_json::Value::from(audit_json::DETAIL_URL),
    );
    key_map.insert(
        "detailRule".to_owned(),
        serde_json::Value::from(audit_json::DETAIL_RULE),
    );
    let key_map = serde_json::Value::Object(key_map);
    format!("const EVK = {key_map};\n{DASHBOARD_JS_BODY}")
}
