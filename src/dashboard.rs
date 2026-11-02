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

/// Renders the complete single-page responsive Web Dashboard HTML shell.
///
/// The shell loads its behavior from the same-origin [`render_dashboard_js`] payload at
/// `/app.js`, keeping `script-src 'self'` strict under the dashboard CSP.
pub fn render_dashboard_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cordon | Universal Sandbox &amp; Network Inspection Control Plane</title>
  <!-- DOM-safety policy: /app.js renders all dynamic data with textContent and
       replaceChildren() only (never innerHTML or document.write), and wires every
       interactive control with addEventListener (zero inline on*= handlers). -->
  <style>
    :root, [data-theme="light"] {
      --bg-primary: #f8fafc;
      --bg-card: #ffffff;
      --bg-subtle: #f1f5f9;
      --fg-primary: #0f172a;
      --fg-secondary: #334155;
      --border-color: #cbd5e1;
      --accent: #1d4ed8;
      --accent-fg: #ffffff;
      --badge-allow: #15803d;
      --badge-block: #b91c1c;
    }
    [data-theme="dark"] {
      --bg-primary: #0f172a;
      --bg-card: #1e293b;
      --bg-subtle: #0b1120;
      --fg-primary: #f8fafc;
      --fg-secondary: #cbd5e1;
      --border-color: #334155;
      --accent: #38bdf8;
      --accent-fg: #0f172a;
      --badge-allow: #4ade80;
      --badge-block: #f87171;
    }
    [data-theme="high-contrast"] {
      --bg-primary: #000000;
      --bg-card: #000000;
      --bg-subtle: #000000;
      --fg-primary: #ffffff;
      --fg-secondary: #ffff00;
      --border-color: #ffffff;
      --accent: #ffff00;
      --accent-fg: #000000;
      --badge-allow: #00ff00;
      --badge-block: #ff5555;
    }
    * { box-sizing: border-box; }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }
    }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, sans-serif;
      background: var(--bg-primary);
      color: var(--fg-primary);
      line-height: 1.5;
    }
    header, main, footer {
      max-width: 1280px;
      margin: 0 auto;
      padding: 1rem 1.5rem;
    }
    header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      border-bottom: 2px solid var(--border-color);
    }
    .theme-controls {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
      align-items: center;
    }
    button, input, select, textarea {
      min-height: 48px;
      min-width: 48px;
      padding: 0.5rem 1rem;
      border-radius: 0.5rem;
      border: 2px solid var(--border-color);
      background: var(--bg-card);
      color: var(--fg-primary);
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
    }
    textarea {
      width: 100%;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-weight: 400;
      cursor: text;
    }
    button.primary, button[aria-selected="true"] {
      background: var(--accent);
      color: var(--accent-fg);
      border-color: var(--accent);
    }
    button:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible {
      outline: 3px solid var(--accent);
      outline-offset: 2px;
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 1.25rem;
      margin-top: 1.25rem;
    }
    @media (min-width: 600px) {
      .grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (min-width: 841px) {
      .grid { grid-template-columns: repeat(3, 1fr); }
    }
    .card {
      background: var(--bg-card);
      border: 2px solid var(--border-color);
      border-radius: 0.75rem;
      padding: 1.25rem;
    }
    .gate-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin-bottom: 1rem;
    }
    .preset-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      margin: 0.75rem 0;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.85rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      background: var(--bg-subtle);
      padding: 0.75rem;
      border-radius: 0.5rem;
      border: 1px solid var(--border-color);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }
    th, td {
      text-align: left;
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid var(--border-color);
    }
    .verdict-ALLOW { color: var(--badge-allow); font-weight: 700; }
    .verdict-BLOCK { color: var(--badge-block); font-weight: 700; }
    footer {
      margin-top: 2rem;
      border-top: 2px solid var(--border-color);
      text-align: center;
      color: var(--fg-secondary);
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <header role="banner">
    <div>
      <h1 id="i18n-title" style="margin:0;font-size:1.5rem;"></h1>
      <p id="i18n-subtitle" style="margin:0.25rem 0 0;color:var(--fg-secondary);"></p>
    </div>
    <nav class="theme-controls" aria-label="Theme and Locale Switcher">
      <select id="locale-select" aria-label="Select Interface Language">
        <option value="en">EN</option>
        <option value="af">AF</option>
        <option value="zu">ZU</option>
      </select>
      <button type="button" aria-label="Switch to Light Theme" id="btn-light"></button>
      <button type="button" aria-label="Switch to Dark Theme" id="btn-dark"></button>
      <button type="button" aria-label="Switch to High Contrast Theme" id="btn-hc"></button>
    </nav>
  </header>

  <main role="main">
    <section class="card" style="margin-top:1.25rem;" aria-labelledby="gates-heading">
      <h2 id="gates-heading" style="margin-top:0;"></h2>
      <div class="gate-tabs" role="tablist" aria-label="5-Gate Kernel Sandbox Architecture">
        <button type="button" role="tab" id="tab-gate-0" aria-selected="true" aria-controls="gate-panel"></button>
        <button type="button" role="tab" id="tab-gate-1" aria-selected="false" aria-controls="gate-panel"></button>
        <button type="button" role="tab" id="tab-gate-2" aria-selected="false" aria-controls="gate-panel"></button>
        <button type="button" role="tab" id="tab-gate-3" aria-selected="false" aria-controls="gate-panel"></button>
        <button type="button" role="tab" id="tab-gate-4" aria-selected="false" aria-controls="gate-panel"></button>
      </div>
      <div id="gate-panel" role="tabpanel" class="mono" aria-live="polite"></div>
    </section>

    <section aria-labelledby="profiles-heading" style="margin-top:1.5rem;">
      <h2 id="profiles-heading"></h2>
      <div id="profiles-grid" class="grid" role="list"></div>
    </section>

    <section class="card" style="margin-top:1.5rem;" aria-labelledby="sim-heading">
      <h2 id="sim-heading" style="margin-top:0;"></h2>
      <div class="preset-bar" role="group" aria-label="1-Click Attack Simulation Presets">
        <button type="button" id="btn-preset-allow"></button>
        <button type="button" id="btn-preset-doh"></button>
        <button type="button" id="btn-preset-pkg"></button>
        <button type="button" id="btn-preset-secret"></button>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:0.75rem;align-items:center;">
        <label for="sim-profile" id="lbl-profile"></label>
        <select id="sim-profile" aria-label="Select Sandbox Profile"></select>
        <select id="sim-method" aria-label="Select HTTP Method">
          <option value="POST">POST</option>
          <option value="GET">GET</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
        </select>
        <input id="sim-url" type="url" value="https://api.openai.com/v1/chat/completions" style="flex:1;min-width:260px;" aria-label="Target Outbound URL" />
        <button type="button" class="primary" id="btn-eval" aria-label="Evaluate Outbound L7 Flow"></button>
        <button type="button" id="btn-compile" aria-label="Compile Sandbox Launch Plan"></button>
      </div>
      <div style="margin-top:0.75rem;">
        <label for="sim-body" id="lbl-body" style="display:block;margin-bottom:0.25rem;font-weight:600;"></label>
        <textarea id="sim-body" rows="2" aria-label="Simulated HTTP Request Body"></textarea>
      </div>
      <pre id="sim-output" class="mono" style="margin-top:1rem;" aria-live="polite"></pre>
    </section>

    <section class="card" style="margin-top:1.5rem;" aria-labelledby="events-heading">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:0.5rem;">
        <h2 id="events-heading" style="margin:0;"></h2>
        <button type="button" id="btn-refresh-events" aria-label="Refresh Audit Telemetry"></button>
      </div>
      <div style="overflow-x:auto;margin-top:0.75rem;">
        <table aria-label="Audit Telemetry Events">
          <thead>
            <tr>
              <th id="th-time"></th>
              <th id="th-profile"></th>
              <th id="th-verdict"></th>
              <th id="th-target"></th>
              <th id="th-reason"></th>
            </tr>
          </thead>
          <tbody id="events-tbody"></tbody>
        </table>
      </div>
    </section>
  </main>

  <footer role="contentinfo">
    <span id="i18n-footer">Developed by PyCentric | Cordon Layer 0 Security Engine (Rust Edition) | AGPL-3.0-only | Source: https://github.com/pycentric/cordon</span>
  </footer>

  <script src="/app.js" defer></script>
</body>
</html>"#
}

/// Static dashboard application JavaScript body served at `/app.js`.
///
/// Every `AuditEvent` field read below goes through the injected `EVK` map (see
/// [`render_dashboard_js`]); the serde contract test in `tests/cordon_api_and_cli.rs`
/// asserts those keys exist on the serialized event so the two cannot drift apart.
const DASHBOARD_JS_BODY: &str = r#""use strict";

    const GATES_DATA = [
      "Gate 1 [ip netns + veth]: Dedicated network namespace (agent-net) over veth pair (10.200.1.0/24) with route_localnet=1, forcing TCP 80/443 into transparent proxy port 8080, redirecting DNS to 10.200.1.1:53, rejecting UDP 443 QUIC/HTTP3, and dropping all other FORWARD traffic.",
      "Gate 2 [AppArmor 4.0 MAC]: Mandatory Access Control (abi <abi/4.0>) confining bwrap, denying capability sys_admin/net_admin/net_raw/sys_ptrace, blocking raw sockets, denying W^X execution on /tmp and /dev/shm, and protecting ~/.ssh, ~/.aws, and ~/.gnupg at the Linux LSM layer.",
      "Gate 3 [Bubblewrap Namespaces]: Unprivileged user/mount/pid/ipc/uts namespaces (--unshare-all --die-with-parent), masking destructive binaries (/usr/bin/rm, /usr/bin/shred, /usr/bin/dd) onto /dev/null, enforcing EC-01 read-only .git protection, and refusing / or $HOME read-write mounts.",
      "Gate 4 [iptables -> mitmproxy L7 Policy]: iptables NAT redirection of TCP 80/443 into the mitmproxy policy engine: default-deny domain allowlist, DoH resolver block (1.1.1.1, 8.8.8.8, /dns-query), FR-5.4 mutating HTTP method restriction (POST/PUT/PATCH/DELETE allowed only on designated LLM endpoints, blocked on package registries), and 9-pattern secret exfiltration scanner.",
      "Gate 5 [tshark PCAP Ring Buffer]: Continuous tshark L3-L4 packet capture (-b filesize:102400 -b files:10, 1 GB cap) paired with structured JSONL audit logs and Prometheus telemetry."
    ];

    const I18N = {
      en: {
        title: "Cordon Control Plane (Type-Safe Rust)",
        subtitle: "5-Gate Kernel Sandbox (ip netns + AppArmor 4.0 + Bubblewrap) & L3-L7 Network Telemetry",
        btnLight: "Light",
        btnDark: "Dark",
        btnHc: "High Contrast (7:1)",
        gatesHeading: "5-Gate Kernel & Network Defense-in-Depth Architecture",
        gateTabs: ["Gate 1: Netns + iptables", "Gate 2: AppArmor 4.0", "Gate 3: Bubblewrap FS", "Gate 4: iptables + L7 MITM", "Gate 5: PCAP Telemetry"],
        profilesHeading: "Universal Workload Sandbox Profiles",
        simHeading: "Interactive Layer 7 Policy, Mutating Method & Secret Egress Simulator",
        presetAllow: "Preset: Allowed LLM POST",
        presetDoh: "Preset: Block DoH Bypass",
        presetPkg: "Preset: Block PyPI POST Exfil",
        presetSecret: "Preset: Block Secret Key Leak",
        lblProfile: "Profile:",
        lblBody: "Simulated HTTP Request Body (Scanned by 9 Secret Signatures):",
        btnEval: "Evaluate L7 Flow",
        btnCompile: "Preview Launch Plan",
        eventsHeading: "Live Control Plane Audit Telemetry Stream",
        btnRefreshEvents: "Refresh Telemetry",
        thTime: "Timestamp",
        thProfile: "Profile",
        thVerdict: "Verdict",
        thTarget: "Target",
        thReason: "Rule / Detail",
        footer: "Developed by PyCentric | Cordon Layer 0 Security Engine (Rust Edition) | AGPL-3.0-only | Source: https://github.com/pycentric/cordon"
      },
      af: {
        title: "Cordon Beheerplatform (Tipe-Veilige Rust)",
        subtitle: "5-Hek Kern-Sandput (ip netns + AppArmor 4.0 + Bubblewrap) & L3-L7 Netwerk Telemetrie",
        btnLight: "Lig",
        btnDark: "Donker",
        btnHc: "Hoë Kontras (7:1)",
        gatesHeading: "5-Hek Kern & Netwerk Verdediging-in-Diepte Argitektuur",
        gateTabs: ["Hek 1: Netns + iptables", "Hek 2: AppArmor 4.0", "Hek 3: Bubblewrap FS", "Hek 4: iptables + L7 MITM", "Hek 5: PCAP Telemetrie"],
        profilesHeading: "Universele Werklading Sandput Profiele",
        simHeading: "Interaktiewe Laag 7 Beleid & Geheime Uittog Simulator",
        presetAllow: "Vooraf: Toegelate LLM POST",
        presetDoh: "Vooraf: Blokkeer DoH Omseiling",
        presetPkg: "Vooraf: Blokkeer PyPI POST",
        presetSecret: "Vooraf: Blokkeer Sleutel Lek",
        lblProfile: "Profiel:",
        lblBody: "Gesimuleerde HTTP Versoek Inhoud:",
        btnEval: "Evalueer L7 Vloei",
        btnCompile: "Voorskou Loodsplan",
        eventsHeading: "Lewendige Oudit Telemetrie Stroom",
        btnRefreshEvents: "Verfris Telemetrie",
        thTime: "Tydstip",
        thProfile: "Profiel",
        thVerdict: "Uitspraak",
        thTarget: "Teiken",
        thReason: "Reël / Besonderhede",
        footer: "Developed by PyCentric | Cordon Laag 0 Sekuriteitsenjin (Rust Uitgawe) | AGPL-3.0-only | Bron: https://github.com/pycentric/cordon"
      },
      zu: {
        title: "Cordon Indawo Yokulawula (Type-Safe Rust)",
        subtitle: "amasango-5 Kernel Sandbox (ip netns + AppArmor 4.0 + Bubblewrap) & L3-L7 Telemetry",
        btnLight: "Ukukhanya",
        btnDark: "Ubumnyama",
        btnHc: "Umahluko Ophezulu (7:1)",
        gatesHeading: "Amasango-5 Okuzivikela Kwe-Kernel Nenethiwekhi",
        gateTabs: ["Isango 1: Netns + iptables", "Isango 2: AppArmor 4.0", "Isango 3: Bubblewrap FS", "Isango 4: iptables + L7 MITM", "Isango 5: PCAP Telemetry"],
        profilesHeading: "Amaphrofayili e-Sandbox",
        simHeading: "Isifanisi Senqubomgomo ye-Layer 7 Nokuvuza Kwemfihlo",
        presetAllow: "Isibonelo: Imvume LLM POST",
        presetDoh: "Isibonelo: Vimba i-DoH",
        presetPkg: "Isibonelo: Vimba i-PyPI POST",
        presetSecret: "Isibonelo: Vimba Imfihlo",
        lblProfile: "Iphrofayili:",
        lblBody: "okuqukethwe kwe-HTTP:",
        btnEval: "Hlola i-L7 Flow",
        btnCompile: "Buka Uhlelo",
        eventsHeading: "Ukusakazwa Kwe-Audit Telemetry",
        btnRefreshEvents: "Vuselela",
        thTime: "Isikhathi",
        thProfile: "Iphrofayili",
        thVerdict: "Isinqumo",
        thTarget: "Inhloso",
        thReason: "Umthetho / Imininingwane",
        footer: "Developed by PyCentric | Cordon Layer 0 Security Engine (Rust Edition) | AGPL-3.0-only | Source: https://github.com/pycentric/cordon"
      }
    };

    function applyLocale(lang) {
      const t = I18N[lang] || I18N.en;
      document.documentElement.setAttribute("lang", lang);
      document.getElementById("i18n-title").textContent = t.title;
      document.getElementById("i18n-subtitle").textContent = t.subtitle;
      document.getElementById("btn-light").textContent = t.btnLight;
      document.getElementById("btn-dark").textContent = t.btnDark;
      document.getElementById("btn-hc").textContent = t.btnHc;
      document.getElementById("gates-heading").textContent = t.gatesHeading;
      for (let i = 0; i < 5; i++) {
        document.getElementById("tab-gate-" + i).textContent = t.gateTabs[i];
      }
      document.getElementById("profiles-heading").textContent = t.profilesHeading;
      document.getElementById("sim-heading").textContent = t.simHeading;
      document.getElementById("btn-preset-allow").textContent = t.presetAllow;
      document.getElementById("btn-preset-doh").textContent = t.presetDoh;
      document.getElementById("btn-preset-pkg").textContent = t.presetPkg;
      document.getElementById("btn-preset-secret").textContent = t.presetSecret;
      document.getElementById("lbl-profile").textContent = t.lblProfile;
      document.getElementById("lbl-body").textContent = t.lblBody;
      document.getElementById("btn-eval").textContent = t.btnEval;
      document.getElementById("btn-compile").textContent = t.btnCompile;
      document.getElementById("events-heading").textContent = t.eventsHeading;
      document.getElementById("btn-refresh-events").textContent = t.btnRefreshEvents;
      document.getElementById("th-time").textContent = t.thTime;
      document.getElementById("th-profile").textContent = t.thProfile;
      document.getElementById("th-verdict").textContent = t.thVerdict;
      document.getElementById("th-target").textContent = t.thTarget;
      document.getElementById("th-reason").textContent = t.thReason;
      document.getElementById("i18n-footer").textContent = t.footer;
    }

    function selectGate(idx) {
      for (let i = 0; i < 5; i++) {
        const btn = document.getElementById("tab-gate-" + i);
        btn.setAttribute("aria-selected", i === idx ? "true" : "false");
      }
      document.getElementById("gate-panel").textContent = GATES_DATA[idx] || GATES_DATA[0];
    }

    function setTheme(mode) {
      document.documentElement.setAttribute("data-theme", mode);
    }

    function applyPreset(kind) {
      const urlInput = document.getElementById("sim-url");
      const methodSel = document.getElementById("sim-method");
      const bodyInput = document.getElementById("sim-body");
      if (kind === "allow_llm") {
        urlInput.value = "https://api.openai.com/v1/chat/completions";
        methodSel.value = "POST";
        bodyInput.value = '{"model":"gpt-4o","messages":[{"role":"user","content":"Audit sandbox safety"}]}';
      } else if (kind === "block_doh") {
        urlInput.value = "https://1.1.1.1/dns-query";
        methodSel.value = "GET";
        bodyInput.value = "";
      } else if (kind === "block_pkg_post") {
        urlInput.value = "https://pypi.org/legacy/";
        methodSel.value = "POST";
        bodyInput.value = "exfiltrated_archive_payload";
      } else if (kind === "block_secret") {
        urlInput.value = "https://api.openai.com/v1/chat/completions";
        methodSel.value = "POST";
        bodyInput.value = "Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwx";
      }
      evaluateFlow();
    }

    // Same-origin fetch wrapper that attaches the optional bearer token (CORDON_API_TOKEN)
    // and prompts for it once if the control plane answers 401.
    async function apiFetch(path, opts) {
      const withAuth = (base) => {
        const merged = Object.assign({}, base || {});
        const headers = Object.assign({}, (base && base.headers) || {});
        const token = sessionStorage.getItem("cordon_api_token");
        if (token) {
          headers["Authorization"] = "Bearer " + token;
        }
        merged.headers = headers;
        return merged;
      };
      let res = await fetch(path, withAuth(opts));
      if (res.status === 401) {
        const token = window.prompt("Cordon API token required (CORDON_API_TOKEN):");
        if (token) {
          sessionStorage.setItem("cordon_api_token", token);
          res = await fetch(path, withAuth(opts));
        }
      }
      return res;
    }

    async function loadProfiles() {
      const res = await apiFetch("/api/v1/profiles");
      const data = await res.json();
      const grid = document.getElementById("profiles-grid");
      const sel = document.getElementById("sim-profile");
      grid.replaceChildren();
      sel.replaceChildren();
      for (const p of data.profiles) {
        const card = document.createElement("article");
        card.className = "card";
        card.setAttribute("role", "listitem");

        const h3 = document.createElement("h3");
        h3.style.marginTop = "0";
        h3.textContent = p.name;

        const desc = document.createElement("p");
        desc.style.color = "var(--fg-secondary)";
        desc.style.fontSize = "0.9rem";
        desc.textContent = p.description;

        const meta = document.createElement("div");
        meta.className = "mono";
        meta.textContent = "FS: " + p.filesystem_mode + " | NET: " + p.network_mode + " | .git RO: " + p.protect_git_dir;

        card.appendChild(h3);
        card.appendChild(desc);
        card.appendChild(meta);
        grid.appendChild(card);

        const opt = document.createElement("option");
        opt.value = p.name;
        opt.textContent = p.name;
        sel.appendChild(opt);
      }
    }

    async function evaluateFlow() {
      const profile = document.getElementById("sim-profile").value || "ai-agent";
      const url = document.getElementById("sim-url").value;
      const method = document.getElementById("sim-method").value || "POST";
      const rawBody = document.getElementById("sim-body").value;
      const body = rawBody.trim().length > 0 ? rawBody : null;
      const res = await apiFetch("/api/v1/evaluate-l7", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ profile, url, method, body })
      });
      const out = await res.json();
      document.getElementById("sim-output").textContent = JSON.stringify(out, null, 2);
      loadEvents();
    }

    async function compilePlanPreview() {
      const profile = document.getElementById("sim-profile").value || "ai-agent";
      const res = await apiFetch("/api/v1/compile", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          profile,
          workspace: ".",
          command: ["opencode", "--version"],
          extra_masked_binaries: [],
          extra_rw_paths: []
        })
      });
      const out = await res.json();
      document.getElementById("sim-output").textContent = JSON.stringify(out, null, 2);
      loadEvents();
    }

    async function loadEvents() {
      const res = await apiFetch("/api/v1/events?limit=10");
      const data = await res.json();
      const tbody = document.getElementById("events-tbody");
      tbody.replaceChildren();
      for (const ev of (data.events || [])) {
        const tr = document.createElement("tr");
        const tdTime = document.createElement("td");
        tdTime.textContent = ev[EVK.timestamp] || "";
        const tdProf = document.createElement("td");
        tdProf.textContent = ev[EVK.profile] || "";
        const tdVerd = document.createElement("td");
        tdVerd.className = "verdict-" + ev[EVK.verdict];
        tdVerd.textContent = ev[EVK.verdict] || "";
        const details = ev[EVK.details] || {};
        const tdTarg = document.createElement("td");
        tdTarg.textContent = details[EVK.detailUrl] || ev[EVK.subject] || "";
        const tdReas = document.createElement("td");
        tdReas.textContent = details[EVK.detailRule] || ev[EVK.subject] || "";
        tr.appendChild(tdTime);
        tr.appendChild(tdProf);
        tr.appendChild(tdVerd);
        tr.appendChild(tdTarg);
        tr.appendChild(tdReas);
        tbody.appendChild(tr);
      }
    }

    function bindControls() {
      document.getElementById("locale-select").addEventListener("change", (event) => applyLocale(event.target.value));
      document.getElementById("btn-light").addEventListener("click", () => setTheme("light"));
      document.getElementById("btn-dark").addEventListener("click", () => setTheme("dark"));
      document.getElementById("btn-hc").addEventListener("click", () => setTheme("high-contrast"));
      for (let i = 0; i < 5; i++) {
        document.getElementById("tab-gate-" + i).addEventListener("click", () => selectGate(i));
      }
      document.getElementById("btn-preset-allow").addEventListener("click", () => applyPreset("allow_llm"));
      document.getElementById("btn-preset-doh").addEventListener("click", () => applyPreset("block_doh"));
      document.getElementById("btn-preset-pkg").addEventListener("click", () => applyPreset("block_pkg_post"));
      document.getElementById("btn-preset-secret").addEventListener("click", () => applyPreset("block_secret"));
      document.getElementById("btn-eval").addEventListener("click", evaluateFlow);
      document.getElementById("btn-compile").addEventListener("click", compilePlanPreview);
      document.getElementById("btn-refresh-events").addEventListener("click", loadEvents);
    }

    bindControls();
    applyLocale("en");
    selectGate(0);
    loadProfiles().then(() => loadEvents());
"#;

/// Renders the dashboard application JavaScript served at `/app.js`.
///
/// The [`crate::domain::audit_json`] field names are injected as the `EVK` map (built from
/// [`AUDIT_EVENT_DASHBOARD_KEYS`] and [`crate::domain::AUDIT_DETAIL_DASHBOARD_KEYS`]) so the
/// telemetry table code and the serialized [`crate::domain::AuditEvent`] schema share one
/// source of truth.
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
