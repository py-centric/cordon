"use strict";

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
