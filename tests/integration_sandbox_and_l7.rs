//! Comprehensive integration and unit test suite for Cordon (Type-Safe Rust Edition).

use std::path::Path;

use cordon::apparmor::render_apparmor_profile;
use cordon::domain::{CanonicalPath, FilesystemMode, NetworkMode, Verdict, WorkloadKind, ZarCents};
use cordon::error::CordonError;
use cordon::l7_policy::CordonPolicyEvaluator;
use cordon::network::{
    build_mitmproxy_command, build_tshark_command, generate_network_setup_commands,
};
use cordon::profiles::{get_profile, list_profiles};
use cordon::sandbox::compile_launch_plan;

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
