//! Comprehensive integration and unit test suite for Cordon (Type-Safe Rust Edition).

use std::path::Path;

use clap::Parser;
use cordon::api::{CompileLaunchRequest, CordonControlPlane, EvaluateL7Request, build_router};
use cordon::apparmor::render_apparmor_profile;
use cordon::cli::{CordonCli, execute_cli};
use cordon::dashboard::{render_dashboard_html, render_dashboard_js};
use cordon::domain::{CanonicalPath, FilesystemMode, NetworkMode, Verdict, WorkloadKind, ZarCents};
use cordon::error::CordonError;
use cordon::l7_policy::CordonPolicyEvaluator;
use cordon::network::{
    build_mitmproxy_command, build_tshark_command, generate_network_setup_commands,
};
use cordon::ports::AuditSinkPort;
use cordon::profiles::{get_profile, list_profiles};
use cordon::sandbox::{compile_launch_plan, run_doctor_checks};
use cordon::tui::render_tui_snapshot;

#[test]
fn test_six_universal_profiles_catalog() {
    let profiles = list_profiles();
    assert_eq!(profiles.len(), 6);

    let ai = get_profile("ai-agent");
    assert!(ai.is_ok());
    if let Ok(p) = ai {
        assert_eq!(p.kind, WorkloadKind::AiAgent);
        assert_eq!(p.filesystem_mode, FilesystemMode::WorkspaceRw);
        assert_eq!(p.network_mode, NetworkMode::Inspected);
    }

    let untrusted = get_profile("untrusted-code");
    assert!(untrusted.is_ok());
    if let Ok(p) = untrusted {
        assert_eq!(p.kind, WorkloadKind::UntrustedCode);
        assert_eq!(p.filesystem_mode, FilesystemMode::WorkspaceRo);
        assert_eq!(p.network_mode, NetworkMode::None);
    }

    let pkg = get_profile("package-build");
    assert!(pkg.is_ok());
    if let Ok(p) = pkg {
        assert_eq!(p.kind, WorkloadKind::PackageBuild);
        assert_eq!(p.network_mode, NetworkMode::AllowlistOnly);
    }

    let audit = get_profile("network-audit");
    assert!(audit.is_ok());
    if let Ok(p) = audit {
        assert_eq!(p.kind, WorkloadKind::NetworkAudit);
        assert_eq!(p.filesystem_mode, FilesystemMode::WorkspaceRo);
    }

    let gui = get_profile("gui-desktop");
    assert!(gui.is_ok());
    if let Ok(p) = gui {
        assert_eq!(p.kind, WorkloadKind::GuiDesktop);
        assert!(p.allow_gui_wayland);
        assert!(p.allow_gpu_dri);
        assert!(!p.allow_x11);
    }

    let airgapped = get_profile("airgapped");
    assert!(airgapped.is_ok());
    if let Ok(p) = airgapped {
        assert_eq!(p.kind, WorkloadKind::Airgapped);
        assert_eq!(p.filesystem_mode, FilesystemMode::StrictRo);
        assert_eq!(p.network_mode, NetworkMode::None);
    }

    assert!(get_profile("nonexistent-profile").is_err());
}

#[test]
fn test_canonical_path_and_zar_cents_newtypes() {
    let resolved = CanonicalPath::resolve(Path::new("."));
    assert!(resolved.is_ok());
    if let Ok(cpath) = resolved {
        assert!(cpath.as_str().starts_with('/'));
    }

    let empty = CanonicalPath::resolve(Path::new("   "));
    assert!(empty.is_err());

    let cents = ZarCents(14_500_000);
    assert_eq!(cents.0, 14_500_000);
}

#[test]
fn test_compile_launch_plan_ai_agent_and_untrusted() {
    let Ok(ai_profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let cmd = vec!["opencode".to_owned(), "--version".to_owned()];
    let mask = vec!["/usr/bin/nmap".to_owned()];
    let Ok(plan) = compile_launch_plan(&ai_profile, Path::new("."), &cmd, &mask, &[]) else {
        panic!("compile_launch_plan failed");
    };

    assert_eq!(plan.profile_name, "ai-agent");
    assert_eq!(
        plan.netns_exec_argv,
        vec!["ip", "netns", "exec", "agent-net"]
    );
    assert!(plan.bwrap_argv.contains(&"--unshare-pid".to_owned()));
    assert!(plan.bwrap_argv.contains(&"--die-with-parent".to_owned()));
    assert!(plan.masked_binaries.contains(&"/usr/bin/rm".to_owned()));
    assert!(plan.masked_binaries.contains(&"/usr/bin/nmap".to_owned()));
    assert!(plan.env_overrides.contains_key("NODE_EXTRA_CA_CERTS"));
    assert!(plan.env_overrides.contains_key("SSL_CERT_FILE"));
    assert!(
        plan.env_overrides
            .get("TMPDIR")
            .is_some_and(|v| v.ends_with("/.cordon-build-tmp"))
    );
    assert_eq!(plan.gates_applied.len(), 5);
    let bwrap_joined = plan.bwrap_argv.join(" ");
    assert!(bwrap_joined.contains(".git"));

    // Verify EC-01 / Root mount refusal: mounting `/` read-write is rejected
    let root_mount_err = compile_launch_plan(&ai_profile, Path::new("/"), &cmd, &[], &[]);
    assert!(matches!(
        root_mount_err,
        Err(CordonError::UnsafeWorkspaceMount { .. })
    ));

    let Ok(untrusted) = get_profile("untrusted-code") else {
        panic!("untrusted-code profile missing");
    };
    let Ok(untrusted_plan) = compile_launch_plan(
        &untrusted,
        Path::new("."),
        &["python3".to_owned(), "script.py".to_owned()],
        &[],
        &[],
    ) else {
        panic!("untrusted compile failed");
    };
    assert_eq!(untrusted_plan.netns_exec_argv.len(), 0);
    assert!(
        untrusted_plan
            .bwrap_argv
            .contains(&"--unshare-net".to_owned())
    );

    let empty_err = compile_launch_plan(&ai_profile, Path::new("."), &[], &[], &[]);
    assert!(matches!(empty_err, Err(CordonError::EmptyCommand)));
}

#[test]
fn test_apparmor_4_0_profile_rendering() {
    let Ok(profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let rendered = render_apparmor_profile(&profile, "/usr/local/bin/agent-shell");
    assert!(rendered.contains("abi <abi/4.0>,"));
    assert!(rendered.contains("userns,"));
    assert!(rendered.contains("mount,"));
    assert!(rendered.contains("/usr/bin/bwrap ix,"));
    assert!(rendered.contains("deny capability sys_admin,"));
    assert!(rendered.contains("deny capability sys_ptrace,"));
    assert!(rendered.contains("deny ptrace,"));
    assert!(rendered.contains("deny signal peer=unconfined,"));
    assert!(rendered.contains("deny /tmp/** x,"));
    assert!(rendered.contains("deny /var/tmp/** x,"));
    assert!(rendered.contains("deny /dev/shm/** x,"));
    assert!(rendered.contains("@{HOME}/**/target/** rix,"));
    assert!(rendered.contains("deny /usr/bin/rm x,"));
    assert!(rendered.contains("deny @{HOME}/.ssh/** rwlkmx,"));
    assert!(rendered.contains("deny @{HOME}/.mitmproxy/mitmproxy-ca.pem rwlkmx,"));
    assert!(rendered.contains("deny /etc/apparmor.d/** rwlkmx,"));
    assert!(rendered.contains("deny network raw,"));
}

#[test]
fn test_network_namespace_and_iptables_commands() {
    let Ok(profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let cmds = generate_network_setup_commands(&profile);
    let joined = cmds.join("\n");
    assert!(joined.contains("ip netns add agent-net"));
    assert!(joined.contains("sysctl -w net.ipv4.conf.veth-host.route_localnet=1"));
    assert!(joined.contains("--dports 80,443 -j REDIRECT --to-ports 8080"));
    assert!(joined.contains("--dport 53 -j DNAT --to-destination 10.200.1.1:53"));
    assert!(joined.contains("--dport 443 -j REJECT --reject-with icmp-port-unreachable"));
    assert!(joined.contains("iptables -A FORWARD -i veth-host -j DROP"));

    let mitm = build_mitmproxy_command(&profile, "/etc/cordon/addon.py", false);
    assert_eq!(mitm[0], "mitmdump");
    assert!(mitm.contains(&"transparent".to_owned()));

    let tshark = build_tshark_command(&profile, "/var/log/cordon");
    assert_eq!(tshark[0], "tshark");
    assert!(tshark.contains(&"filesize:102400".to_owned()));
}

#[test]
fn test_l7_policy_evaluator_doh_secrets_and_allowlist() {
    let Ok(profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let evaluator = CordonPolicyEvaluator::new(profile);

    // 1. Allowed LLM API call
    let ok_decision = evaluator.evaluate_request(
        "https://api.openai.com/v1/chat/completions",
        "POST",
        Some(r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#),
    );
    assert_eq!(ok_decision.verdict, Verdict::Allow);
    assert_eq!(ok_decision.status_code, 200);

    // 2. DoH bypass attempt (/dns-query and /resolve)
    let doh_decision = evaluator.evaluate_request("https://1.1.1.1/dns-query", "GET", None);
    assert_eq!(doh_decision.verdict, Verdict::Block);
    assert_eq!(doh_decision.matched_rule, "DOH_RESOLVER_BLOCK");

    let doh_resolve_path =
        evaluator.evaluate_request("https://api.openai.com/resolve?name=evil.com", "GET", None);
    assert_eq!(doh_resolve_path.verdict, Verdict::Block);
    assert_eq!(doh_resolve_path.matched_rule, "DOH_RESOLVER_BLOCK");

    // 3. Unlisted domain blocked
    let unlisted =
        evaluator.evaluate_request("https://evil-exfil.example.com/upload", "POST", None);
    assert_eq!(unlisted.verdict, Verdict::Block);
    assert_eq!(unlisted.matched_rule, "ALLOWLIST_MISS");

    // 4. FR-5.4: Package registry GET allowed, but POST blocked to prevent archive exfiltration
    let pypi_get = evaluator.evaluate_request("https://pypi.org/simple/requests/", "GET", None);
    assert_eq!(pypi_get.verdict, Verdict::Allow);

    let pypi_post = evaluator.evaluate_request(
        "https://pypi.org/legacy/",
        "POST",
        Some("exfiltrated_tarball"),
    );
    assert_eq!(pypi_post.verdict, Verdict::Block);
    assert_eq!(pypi_post.matched_rule, "UNAUTHORIZED_MUTATING_METHOD");

    // 5. Secret exfiltration inside allowed domain body blocked
    let secret_leak = evaluator.evaluate_request(
        "https://api.openai.com/v1/chat/completions",
        "POST",
        Some("Bearer token ghp_1234567890abcdefghijklmnopqrstuvwx"),
    );
    assert_eq!(secret_leak.verdict, Verdict::Block);
    assert_eq!(secret_leak.matched_rule, "SECRET_GITHUB_PAT");

    let env_secret_leak = evaluator.evaluate_request(
        "https://api.openai.com/v1/chat/completions",
        "POST",
        Some("OPENAI_API_KEY=supersecretvalue1234567890"),
    );
    assert_eq!(env_secret_leak.verdict, Verdict::Block);
    assert_eq!(env_secret_leak.matched_rule, "SECRET_ENV_ASSIGNMENT");
}

#[test]
fn test_control_plane_and_tui_snapshot() {
    let plane = CordonControlPlane::new();
    let health = plane.health();
    assert_eq!(health.status, "ok");
    assert_eq!(health.profiles_count, 6);
    assert_eq!(health.governing_adr, "ADR-L0-SEC-02");

    let doctor = plane.doctor();
    assert!(doctor.checks.len() >= 7);

    let aa = plane.render_apparmor("ai-agent");
    assert!(aa.is_ok());

    let net = plane.render_network("ai-agent");
    assert!(net.is_ok());

    let compile_res = plane.compile_plan(&CompileLaunchRequest {
        profile: "package-build".to_owned(),
        workspace: ".".to_owned(),
        command: vec!["cargo".to_owned(), "build".to_owned()],
        extra_masked_binaries: Vec::new(),
        extra_rw_paths: Vec::new(),
    });
    assert!(compile_res.is_ok());

    let eval_res = plane.evaluate_l7(&EvaluateL7Request {
        profile: "package-build".to_owned(),
        url: "https://crates.io/api/v1/crates".to_owned(),
        method: "GET".to_owned(),
        body: None,
    });
    assert!(eval_res.is_ok());
    if let Ok(d) = eval_res {
        assert_eq!(d.verdict, Verdict::Allow);
    }

    let events = plane.recent_events(10);
    assert!(events.len() >= 3);

    let snapshot = render_tui_snapshot(&plane, 100, 16);
    assert!(snapshot.is_ok());
    if let Ok(text) = snapshot {
        assert!(text.contains("CORDON"));
        assert!(text.contains("Developed by PyCentric"));
    }

    let html = render_dashboard_html();
    assert!(html.contains("Developed by PyCentric"));
    assert!(html.contains("data-theme=\"high-contrast\""));
    assert!(html.contains("prefers-reduced-motion: reduce"));
    assert!(html.contains("role=\"tablist\""));
    let js = render_dashboard_js();
    assert!(js.contains("replaceChildren()"));
    assert!(!js.contains("innerHTML"));
    assert!(html.contains("min-height: 48px"));

    let _router = build_router(plane);
}

#[tokio::test]
async fn test_cli_execution_and_doctor() {
    let report = run_doctor_checks();
    assert!(report.checks.len() >= 7);

    let cli_profiles = CordonCli::parse_from(["cordon", "--json", "profiles"]);
    let code = execute_cli(cli_profiles).await;
    assert!(matches!(code, Ok(0)));

    let cli_eval = CordonCli::parse_from([
        "cordon",
        "--json",
        "evaluate-url",
        "--profile",
        "ai-agent",
        "--url",
        "https://1.1.1.1/dns-query",
    ]);
    let block_code = execute_cli(cli_eval).await;
    assert!(matches!(block_code, Ok(3)));
}

#[test]
fn test_sandbox_isolation_hardening_remediations() {
    use cordon::sandbox::{
        FORBIDDEN_RW_SYSTEM_PATHS, SYSTEM_CA_BUNDLE_TARGETS, prepare_live_execution_argv,
    };

    let Ok(ai_profile) = get_profile("ai-agent") else {
        panic!("ai-agent profile missing");
    };
    let cmd = vec!["opencode".to_owned(), "--version".to_owned()];
    let Ok(plan) = compile_launch_plan(&ai_profile, Path::new("."), &cmd, &[], &[]) else {
        panic!("compile_launch_plan failed");
    };

    // Finding 1: Unprivileged netns fallback fails closed to --unshare-net unless force_host_net is set
    let (live_fail_closed, notice) = prepare_live_execution_argv(&plan, false, false);
    assert!(notice.is_some());
    assert!(live_fail_closed.contains(&"--unshare-net".to_owned()));

    let (live_host_net, _) = prepare_live_execution_argv(&plan, false, true);
    assert!(!live_host_net.contains(&"--unshare-net".to_owned()));

    // Finding 2: --tmpfs $HOME is always mounted before workspace bind even when workspace is under $HOME
    let Ok(untrusted_profile) = get_profile("untrusted-code") else {
        panic!("untrusted-code profile missing");
    };
    let Ok(untrusted_plan) =
        compile_launch_plan(&untrusted_profile, Path::new("."), &cmd, &[], &[])
    else {
        panic!("untrusted compile_launch_plan failed");
    };
    if let Ok(home) = std::env::var("HOME")
        && let Ok(canon_home) = CanonicalPath::resolve(Path::new(&home))
    {
        let tmpfs_home_pos = untrusted_plan
            .bwrap_argv
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == canon_home.as_str());
        let bind_ws_pos = untrusted_plan.bwrap_argv.windows(2).position(|w| {
            w[0] == "--ro-bind" && w[1] == untrusted_plan.canonical_workspace.as_str()
        });
        assert!(tmpfs_home_pos.is_some());
        assert!(bind_ws_pos.is_some());
        if let (Some(t_pos), Some(b_pos)) = (tmpfs_home_pos, bind_ws_pos) {
            assert!(t_pos < b_pos);
        }
    }

    // Finding 3: --new-session is present alongside --die-with-parent to isolate TTY (TIOCSTI mitigation)
    assert!(plan.bwrap_argv.contains(&"--new-session".to_owned()));

    // Finding 4: Binary masking is preserved in prepare_live_execution_argv for AiAgent profiles
    if Path::new("/usr/bin/rm").exists() {
        let rm_masked = live_fail_closed
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == "/dev/null" && w[2] == "/usr/bin/rm");
        assert!(rm_masked);
    }

    // Finding 5: Critical system paths are rejected as writable workspaces or extra writable mounts,
    // and all SYSTEM_CA_BUNDLE_TARGETS are overlaid in compile_launch_plan
    for sys_target in SYSTEM_CA_BUNDLE_TARGETS {
        assert!(plan.bwrap_argv.contains(&(*sys_target).to_owned()));
    }
    for forbidden in FORBIDDEN_RW_SYSTEM_PATHS {
        if Path::new(forbidden).exists() {
            let bad_ws = compile_launch_plan(&ai_profile, Path::new(forbidden), &cmd, &[], &[]);
            assert!(
                matches!(bad_ws, Err(CordonError::UnsafeWorkspaceMount { .. })),
                "Expected UnsafeWorkspaceMount for workspace {forbidden}"
            );
            let bad_extra = compile_launch_plan(
                &ai_profile,
                Path::new("."),
                &cmd,
                &[],
                &[(*forbidden).to_owned()],
            );
            assert!(
                matches!(bad_extra, Err(CordonError::UnsafeWorkspaceMount { .. })),
                "Expected UnsafeWorkspaceMount for extra_rw_path {forbidden}"
            );
        }
    }

    // Finding 6: Doctor report includes kernel_tiocsti_disabled check
    let doc = run_doctor_checks();
    assert!(
        doc.checks
            .iter()
            .any(|c| c.name == "kernel_tiocsti_disabled")
    );

    // Finding 7: .git, .git/hooks, and .husky are protected read-only in WorkspaceRw
    let ws = plan.canonical_workspace.as_str();
    assert!(plan.bwrap_argv.contains(&format!("{ws}/.git")));
    assert!(plan.bwrap_argv.contains(&format!("{ws}/.git/hooks")));
    assert!(plan.bwrap_argv.contains(&format!("{ws}/.husky")));

    // Finding 8: Network setup disables IPv6 in netns and drops IPv6 forward traffic
    let net_cmds = generate_network_setup_commands(&ai_profile).join("\n");
    assert!(net_cmds.contains("net.ipv6.conf.all.disable_ipv6=1"));
    assert!(net_cmds.contains("ip6tables -C FORWARD -i veth-host -j DROP"));
}

#[test]
fn test_interactive_tui_navigation_and_session_launching() {
    use cordon::repl::ReplNetMode;
    use cordon::tui::{
        TuiApp, TuiLaunchAction, TuiPane, draw_interactive_tui, handle_tui_key_event,
    };
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    let mut app = TuiApp::new("ai-agent", None);
    assert_eq!(app.active_pane, TuiPane::Profiles);
    assert_eq!(app.active_profile_name(), "ai-agent");

    // Navigate down in Profiles pane -> untrusted-code
    handle_tui_key_event(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(app.active_profile_name(), "untrusted-code");

    // Tab to Configs -> Groups -> Telemetry -> Profiles
    handle_tui_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.active_pane, TuiPane::Configs);
    handle_tui_key_event(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.active_pane, TuiPane::Groups);

    // Toggle a command group with Space
    let initial_groups_len = app.enabled_command_groups.len();
    handle_tui_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
    );
    assert_ne!(app.enabled_command_groups.len(), initial_groups_len);

    // Cycle network mode with 'n' and run doctor check with 'd'
    handle_tui_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
    );
    assert_eq!(app.net_mode, ReplNetMode::Airgap);
    handle_tui_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
    );
    assert!(app.status_message.contains("Host Doctor:"));

    // Queue SandboxShell ('s') and InteractiveRepl ('r')
    handle_tui_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
    );
    assert_eq!(
        app.pending_launch.take(),
        Some(TuiLaunchAction::SandboxShell)
    );

    handle_tui_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
    );
    assert_eq!(
        app.pending_launch.take(),
        Some(TuiLaunchAction::InteractiveRepl)
    );

    // Open custom command input ('c'), type 'opencode --version', and press Enter
    handle_tui_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE),
    );
    assert!(app.input_mode);
    for ch in "opencode --version".chars() {
        handle_tui_key_event(
            &mut app,
            KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE),
        );
    }
    handle_tui_key_event(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(!app.input_mode);
    assert_eq!(
        app.pending_launch.take(),
        Some(TuiLaunchAction::CustomCommand(vec![
            "opencode".to_owned(),
            "--version".to_owned(),
        ]))
    );

    // Render interactive frame via TestBackend
    let backend = TestBackend::new(120, 28);
    let Ok(mut term) = Terminal::new(backend) else {
        panic!("Failed to create TestBackend terminal");
    };
    assert!(term.draw(|f| draw_interactive_tui(f, &app)).is_ok());

    // Quit with 'q'
    handle_tui_key_event(
        &mut app,
        KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
    );
    assert!(app.should_quit);

    // Verify prepare_live_execution_argv never passes a symlink destination to bwrap across all 6 profiles
    for profile in list_profiles() {
        let Ok(plan) = compile_launch_plan(
            &profile,
            Path::new("/tmp"),
            &["/bin/bash".to_owned()],
            &[],
            &[],
        ) else {
            panic!("Failed to compile launch plan for {}", profile.name);
        };
        let (live_argv, _) = cordon::sandbox::prepare_live_execution_argv(&plan, false, false);
        let mut idx = 0;
        while idx < live_argv.len() {
            if matches!(
                live_argv[idx].as_str(),
                "--ro-bind" | "--ro-bind-try" | "--bind" | "--dev-bind"
            ) && idx + 2 < live_argv.len()
            {
                let dst = &live_argv[idx + 2];
                if dst != "/" {
                    let meta = std::fs::symlink_metadata(dst);
                    assert!(
                        meta.is_ok_and(|m| !m.file_type().is_symlink()),
                        "bwrap destination must not be a symlink: {dst}"
                    );
                }
                idx += 3;
            } else {
                idx += 1;
            }
        }
    }
}
