//! Integration tests for Cordon HTTP Control Plane (`axum`), CLI subcommands, Error RFC 7807 mapping, and Hexagonal Ports.

use std::path::Path;

use clap::Parser;
use cordon::api::{
    CompileConfigRequest, CompileLaunchRequest, CordonControlPlane, EvaluateL7Request, build_router,
};
use cordon::apparmor::AppArmorProfileCompiler;
use cordon::cli::{CordonCli, execute_cli};
use cordon::config::{
    CordonEnvironmentConfig, expand_tilde, get_config_template, list_config_templates,
    parse_volume_spec,
};
use cordon::domain::{CanonicalPath, Verdict};
use cordon::error::CordonError;
use cordon::l7_policy::CordonPolicyEvaluator;
use cordon::network::{NetnsTopologyCompiler, build_mitmproxy_command};
use cordon::ports::{
    AppArmorCompilerPort, L7PolicyEvaluatorPort, NetnsCompilerPort, ProfileCatalogPort,
    SandboxCompilerPort,
};
use cordon::profiles::BuiltinProfileCatalog;
use cordon::sandbox::BwrapSandboxCompiler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn test_error_rfc7807_problem_details_and_canonical_paths() {
    let errors = [
        (CordonError::InvalidProfileName("BAD!".to_owned()), 400_u16),
        (CordonError::EmptyCommand, 400_u16),
        (
            CordonError::InvalidNetworkConfig("bad subnet".to_owned()),
            400_u16,
        ),
        (CordonError::InvalidInput("bad field".to_owned()), 400_u16),
        (
            CordonError::UnknownProfile {
                name: "missing".to_owned(),
                available: "ai-agent".to_owned(),
            },
            404_u16,
        ),
        (
            CordonError::PathResolutionFailed {
                path: String::new(),
                reason: "empty".to_owned(),
            },
            422_u16,
        ),
        (
            CordonError::UnsafeWorkspaceMount {
                path: "/".to_owned(),
            },
            422_u16,
        ),
        (
            CordonError::Io(std::io::Error::other("disk error")),
            500_u16,
        ),
    ];

    for (err, expected_status) in errors {
        let problem = err.to_problem_details("/api/v1/test", "trace-123");
        assert_eq!(problem.status, expected_status);
        assert_eq!(problem.instance, "/api/v1/test");
        assert_eq!(problem.trace_id, "trace-123");
        assert!(problem.problem_type.contains(&expected_status.to_string()));
    }

    let static_path = CanonicalPath::from_trusted_static("/usr/bin/bwrap");
    assert_eq!(static_path.as_str(), "/usr/bin/bwrap");
    assert_eq!(format!("{static_path}"), "/usr/bin/bwrap");

    let abs_lexical = CanonicalPath::resolve(Path::new("/nonexistent_cordon_dir/a/./b/../c"));
    assert!(abs_lexical.is_ok());
    if let Ok(p) = abs_lexical {
        assert_eq!(p.as_str(), "/nonexistent_cordon_dir/a/c");
    }

    let rel_lexical = CanonicalPath::resolve(Path::new("nonexistent_rel_cordon/x/../y"));
    assert!(rel_lexical.is_ok());
    if let Ok(p) = rel_lexical {
        assert!(p.as_str().ends_with("/nonexistent_rel_cordon/y"));
    }
}

#[test]
fn test_hexagonal_ports_and_additional_profile_branches() {
    let catalog = BuiltinProfileCatalog;
    let all = catalog.list_profiles();
    assert_eq!(all.len(), 6);
    assert!(catalog.get_profile("INVALID_UPPERCASE").is_err());

    let Ok(mut gui_profile) = catalog.get_profile("gui-desktop") else {
        panic!("gui-desktop missing");
    };
    gui_profile.extra_ro_binds.push("/etc".to_owned());
    gui_profile.extra_rw_binds.push("/tmp".to_owned());
    gui_profile
        .denied_domains
        .push("*.malware.example".to_owned());

    let compiler = BwrapSandboxCompiler;
    let doctor = compiler.run_doctor_checks();
    assert_ne!(doctor.platform_summary, "");

    let cmd = vec!["firefox".to_owned()];
    let plan = compiler.compile_launch_plan(
        &gui_profile,
        Path::new("."),
        &cmd,
        &["/usr/bin/nc".to_owned()],
        &[".".to_owned()],
    );
    assert!(plan.is_ok());
    if let Ok(p) = plan {
        assert!(p.bwrap_argv.contains(&"/dev/dri".to_owned()));
    }

    // Verify unsafe writable mount refusal on extra_rw_paths ("/")
    let bad_rw_plan =
        compiler.compile_launch_plan(&gui_profile, Path::new("."), &cmd, &[], &["/".to_owned()]);
    assert!(matches!(
        bad_rw_plan,
        Err(CordonError::UnsafeWorkspaceMount { .. })
    ));

    let aa_compiler = AppArmorProfileCompiler;
    let aa_text = aa_compiler.render_apparmor_profile(&gui_profile, "/usr/local/bin/gui-shell");
    assert!(aa_text.contains("profile cordon_gui_desktop /usr/local/bin/gui-shell"));

    let net_compiler = NetnsTopologyCompiler;
    let net_cmds = net_compiler.generate_network_setup_commands(&gui_profile);
    assert!(net_cmds.len() >= 10);

    let mitmweb_cmd = build_mitmproxy_command(&gui_profile, "/etc/cordon/addon.py", true);
    assert_eq!(mitmweb_cmd[0], "mitmweb");

    let l7_port: Box<dyn L7PolicyEvaluatorPort> = Box::new(CordonPolicyEvaluator::new(gui_profile));
    let denied_res = l7_port.evaluate_request("https://sub.malware.example/payload", "GET", None);
    assert_eq!(denied_res.verdict, Verdict::Block);
    assert!(denied_res.matched_rule.starts_with("DENY_DOMAIN:"));

    let Ok(airgapped) = catalog.get_profile("airgapped") else {
        panic!("airgapped missing");
    };
    let air_eval = CordonPolicyEvaluator::new(airgapped);
    let air_res = air_eval.evaluate_request("https://example.com", "GET", None);
    assert_eq!(air_res.verdict, Verdict::Block);
    assert_eq!(air_res.matched_rule, "NETWORK_MODE_NONE");
}

#[test]
fn test_reproducible_cordonfile_toml_json_and_templates() {
    let templates = list_config_templates();
    assert_eq!(templates.len(), 4);

    for slug in ["opencode", "antigravity", "python-sandbox", "package-build"] {
        let Ok(tpl_cfg) = get_config_template(slug) else {
            panic!("Failed to retrieve template {slug}");
        };
        let cf_str = tpl_cfg.to_cordonfile_string();
        let toml_str = tpl_cfg.to_toml_string();
        let json_str = serde_json::to_string_pretty(&tpl_cfg).unwrap_or_default();

        let parsed_cf = CordonEnvironmentConfig::from_cordonfile_str(&cf_str);
        assert!(parsed_cf.is_ok(), "Cordonfile parse failed for {slug}");
        let parsed_toml = CordonEnvironmentConfig::from_toml_str(&toml_str);
        assert!(parsed_toml.is_ok(), "TOML parse failed for {slug}");
        let parsed_json = CordonEnvironmentConfig::from_json_str(&json_str);
        assert!(parsed_json.is_ok(), "JSON parse failed for {slug}");

        if let Ok(cfg) = parsed_cf {
            assert!(cfg.build_profile().is_ok());
        }
    }

    assert!(get_config_template("unknown-template").is_err());

    // Validate all 7 repository config files in configs/
    for file_path in [
        "configs/Cordonfile.opencode",
        "configs/opencode.cordon.toml",
        "configs/Cordonfile.antigravity",
        "configs/antigravity.cordon.toml",
        "configs/Cordonfile.python",
        "configs/python-sandbox.cordon.toml",
        "configs/package-build.cordon.toml",
    ] {
        let loaded = CordonEnvironmentConfig::from_file(Path::new(file_path));
        assert!(loaded.is_ok(), "Failed to load {file_path}: {loaded:?}");
        if let Ok(cfg) = loaded {
            assert!(cfg.build_profile().is_ok());
        }
    }

    // Test volume specs and tilde expansion
    assert_eq!(
        parse_volume_spec("/opt/data:ro").ok(),
        Some(("/opt/data".to_owned(), false))
    );
    assert_eq!(
        parse_volume_spec("/tmp/work:rw").ok(),
        Some(("/tmp/work".to_owned(), true))
    );
    assert_eq!(
        parse_volume_spec("/opt/default").ok(),
        Some(("/opt/default".to_owned(), false))
    );
    assert_eq!(
        parse_volume_spec("/opt/same:/opt/same").ok(),
        Some(("/opt/same".to_owned(), false))
    );
    assert_eq!(
        parse_volume_spec("/opt/same:/opt/same:rw").ok(),
        Some(("/opt/same".to_owned(), true))
    );
    assert!(parse_volume_spec("   ").is_err());
    assert!(parse_volume_spec("/host:/different").is_err());
    assert!(parse_volume_spec("/host:/different:ro").is_err());
    assert!(parse_volume_spec("/a:/b:/c:/d").is_err());
    assert_ne!(expand_tilde("~"), "");
    assert!(expand_tilde("~/cache").ends_with("/cache"));
    assert_eq!(expand_tilde("/abs/path"), "/abs/path");

    // Test full Cordonfile directives, serialization, and TOML round-trip
    let full_cf = "\
FROM ai-agent
NAME custom-full
DESCRIPTION Full directive coverage
WORKDIR .
FS_MODE workspace_ro
NET_MODE allowlist_only
PROTECT_GIT true
ISOLATE_HOME true
BUILD_SCRATCH true
VOLUME_RO /usr
VOLUME_RW /tmp
MASK_BIN /usr/bin/nc
ALLOW_DOMAIN api.openai.com
ALLOW_POST api.openai.com
DENY_DOMAIN pastebin.com
ENV TEST_KEY=TEST_VAL
CMD python3 -I script.py
";
    let Ok(parsed_full) = CordonEnvironmentConfig::from_cordonfile_str(full_cf) else {
        panic!("full Cordonfile failed");
    };
    assert_eq!(parsed_full.command, vec!["python3", "-I", "script.py"]);
    let rendered_cf = parsed_full.to_cordonfile_string();
    assert!(rendered_cf.contains("VOLUME_RO \"/usr\""));
    assert!(rendered_cf.contains("VOLUME_RW \"/tmp\""));
    assert!(rendered_cf.contains("MASK_BIN \"/usr/bin/nc\""));
    let rendered_toml = parsed_full.to_toml_string();
    let reparsed_toml = CordonEnvironmentConfig::from_toml_str(&rendered_toml);
    assert!(reparsed_toml.is_ok());

    let extra_toml = "\
[sandbox]
name = \"toml-extra\"
base_profile = \"ai-agent\"
filesystem_mode = \"strict_ro\"
network_mode = \"direct\"
tmpfs_size_mb = 512
";
    let Ok(parsed_extra_toml) = CordonEnvironmentConfig::from_toml_str(extra_toml) else {
        panic!("extra TOML failed");
    };
    assert!(parsed_extra_toml.build_profile().is_ok());

    assert!(CordonEnvironmentConfig::from_cordonfile_str("FROM\n").is_err());
    assert!(CordonEnvironmentConfig::from_cordonfile_str("FS_MODE bad_mode\n").is_err());
    assert!(CordonEnvironmentConfig::from_cordonfile_str("NET_MODE bad_net\n").is_err());
    assert!(CordonEnvironmentConfig::from_cordonfile_str("ENV NO_EQUALS\n").is_err());
    assert!(CordonEnvironmentConfig::from_cordonfile_str("ENV =missing_key\n").is_err());
    assert!(CordonEnvironmentConfig::from_cordonfile_str("UNKNOWN_DIR val\n").is_err());
    assert!(CordonEnvironmentConfig::from_toml_str("[unclosed\nkey = [\"a\"\n").is_err());
    assert!(CordonEnvironmentConfig::from_toml_str("no_equals_line\n").is_err());
    assert!(CordonEnvironmentConfig::from_toml_str("[sandbox]\nunknown_scalar = 1\n").is_err());
    assert!(CordonEnvironmentConfig::from_toml_str("[sandbox]\nunknown_arr = [\"x\"]\n").is_err());
    assert!(CordonEnvironmentConfig::from_toml_str("[sandbox]\ntmpfs_size_mb = bad\n").is_err());
}

#[tokio::test]
async fn test_all_cli_subcommands_json_and_human_modes() {
    let tmp_out = "/tmp/cordon-test-init-Cordonfile";
    let _ = std::fs::remove_file(tmp_out);

    let invocations: &[&[&str]] = &[
        &["cordon", "profiles"],
        &["cordon", "--json", "profiles"],
        &[
            "cordon",
            "inspect-cmd",
            "--profile",
            "ai-agent",
            "--",
            "opencode",
        ],
        &[
            "cordon",
            "--json",
            "inspect-cmd",
            "--profile",
            "ai-agent",
            "--",
            "opencode",
        ],
        &[
            "cordon",
            "run",
            "--dry-run",
            "--profile",
            "untrusted-code",
            "--",
            "python3",
            "-V",
        ],
        &[
            "cordon",
            "--json",
            "run",
            "--dry-run",
            "--profile",
            "untrusted-code",
            "--",
            "python3",
            "-V",
        ],
        &[
            "cordon",
            "run",
            "-f",
            "configs/Cordonfile.opencode",
            "-v",
            "/tmp:ro",
            "-v",
            "/tmp:rw",
            "--bind-ro",
            "/usr",
            "-e",
            "FOO=BAR",
            "--allow-domain",
            "custom.llm.example",
            "--dry-run",
        ],
        &[
            "cordon",
            "--json",
            "run",
            "-f",
            "configs/Cordonfile.antigravity",
            "--dry-run",
        ],
        &["cordon", "config", "list-templates"],
        &["cordon", "--json", "config", "list-templates"],
        &[
            "cordon",
            "config",
            "init",
            "--template",
            "opencode",
            "--format",
            "cordonfile",
        ],
        &[
            "cordon",
            "--json",
            "config",
            "init",
            "--template",
            "antigravity",
            "--format",
            "toml",
            "--output",
            tmp_out,
        ],
        &[
            "cordon",
            "config",
            "validate",
            "--file",
            "configs/Cordonfile.opencode",
        ],
        &[
            "cordon",
            "--json",
            "config",
            "validate",
            "--file",
            "configs/opencode.cordon.toml",
        ],
        &["cordon", "render-apparmor", "--profile", "ai-agent"],
        &[
            "cordon",
            "--json",
            "render-apparmor",
            "--profile",
            "ai-agent",
        ],
        &["cordon", "render-netns", "--profile", "ai-agent"],
        &["cordon", "--json", "render-netns", "--profile", "ai-agent"],
        &[
            "cordon",
            "evaluate-url",
            "--profile",
            "ai-agent",
            "--url",
            "https://api.openai.com/v1/models",
        ],
        &["cordon", "doctor"],
        &["cordon", "--json", "doctor"],
        &["cordon", "tui"],
        &["cordon", "--json", "tui"],
        &["cordon", "completions", "bash"],
        &["cordon", "completions", "zsh"],
        &["cordon", "completions", "fish"],
        &["cordon", "--json", "completions", "fish"],
        &[
            "cordon",
            "--json",
            "completions",
            "bash",
            "--output",
            tmp_out,
        ],
        &["cordon", "completions", "zsh", "--output", tmp_out],
        &["cordon", "groups"],
        &["cordon", "--json", "groups"],
        &["cordon", "plugin", "list"],
        &["cordon", "--json", "plugin", "list"],
        &["cordon", "plugin", "info", "cordon-fish"],
        &["cordon", "--json", "plugin", "info", "cordon-hud"],
        &[
            "cordon",
            "shell",
            "--allow-bin",
            "bat",
            "--allow-group",
            "search-tools",
            "--mount-group",
            "xdg-config",
            "--dry-run",
        ],
        &["cordon", "--json", "shell", "--offline", "--dry-run"],
        &[
            "cordon",
            "run",
            "--allow-bin",
            "bat",
            "--allow-bin",
            "rg",
            "--allow-group",
            "search-tools",
            "--mount-group",
            "xdg-config",
            "--offline",
            "--dry-run",
            "opencode",
        ],
        &["cordon", "exec", "--host-net", "--dry-run", "opencode"],
    ];

    for args in invocations {
        let parsed = CordonCli::parse_from(*args);
        let res = execute_cli(parsed).await;
        assert!(matches!(res, Ok(0)), "CLI failed for args: {args:?}");
    }

    let _ = std::fs::remove_file(tmp_out);

    // Verify rendered Bash, Zsh, Fish, and Elvish completion scripts contain profile/template/wrapper rules
    let bash_script =
        cordon::cli::render_shell_completions(clap_complete::Shell::Bash).unwrap_or_default();
    assert!(bash_script.contains("ai-agent"));
    assert!(bash_script.contains("opencode"));
    assert!(bash_script.contains("complete -F _cordon -o bashdefault -o default agent-sandbox"));

    let zsh_script =
        cordon::cli::render_shell_completions(clap_complete::Shell::Zsh).unwrap_or_default();
    assert!(zsh_script.starts_with("#compdef cordon agent-sandbox\n"));
    assert!(zsh_script.contains("ai-agent"));
    assert!(zsh_script.contains("antigravity"));
    assert!(zsh_script.contains("compdef _cordon cordon agent-sandbox"));

    let fish_script =
        cordon::cli::render_shell_completions(clap_complete::Shell::Fish).unwrap_or_default();
    assert!(fish_script.contains("ai-agent"));
    assert!(fish_script.contains("python-sandbox"));
    assert!(fish_script.contains("complete -c agent-sandbox -w cordon"));
    assert!(fish_script.contains("complete -c agent-shell -f"));

    let elvish_script =
        cordon::cli::render_shell_completions(clap_complete::Shell::Elvish).unwrap_or_default();
    assert!(elvish_script.contains("cordon"));

    // Invalid -e format should return Err
    let bad_env_cli = CordonCli::parse_from([
        "cordon",
        "run",
        "--dry-run",
        "-e",
        "INVALID_ENV",
        "--",
        "opencode",
    ]);
    assert!(execute_cli(bad_env_cli).await.is_err());

    let bin_out = std::process::Command::new(env!("CARGO_BIN_EXE_cordon"))
        .args(["--json", "profiles"])
        .output();
    assert!(bin_out.is_ok());
    if let Ok(out) = bin_out {
        assert!(out.status.success());
    }
}

#[test]
fn test_cordon_interactive_repl_and_live_execution_argv() {
    use cordon::repl::{ReplNetMode, ReplSession, run_repl_with_io};
    use cordon::sandbox::prepare_live_execution_argv;
    use std::io::Cursor;

    let Ok(mut session) = ReplSession::new("ai-agent", None, None, ReplNetMode::Auto, true) else {
        panic!("Failed to create ReplSession");
    };

    let repl_script = "\
# Comment line
help
status
profiles
templates
use untrusted-code
use unknown-profile
load configs/Cordonfile.opencode
load /nonexistent/Cordonfile
cd .
mount /tmp:ro
mount /tmp:rw
mount /bad:/dest
env FOO=BAR
env INVALID_ENV
allow api.custom.example
net direct
net airgap
net netns
net auto
net badmode
plan opencode --version
eval https://api.openai.com/v1/chat/completions POST sk-1234567890abcdefghijklmnop
doctor
!python3 -V
run opencode
shell
clear
unknown_cmd
exit
";
    let mut output_buf = Vec::new();
    let res = run_repl_with_io(
        &mut session,
        Cursor::new(repl_script.as_bytes()),
        &mut output_buf,
    );
    assert!(matches!(res, Ok(0)));
    let out_str = String::from_utf8_lossy(&output_buf);
    assert!(out_str.contains("Cordon Interactive Sandbox REPL Commands:"));
    assert!(out_str.contains("Switched active profile to 'untrusted-code'."));
    assert!(out_str.contains("Loaded config 'configs/Cordonfile.opencode'"));
    assert!(out_str.contains("SECRET_OPENAI_KEY"));
    assert!(out_str.contains("[dry-run] bwrap"));
    assert!(out_str.contains("Cleared session mounts"));

    // Verify prepare_live_execution_argv strips netns when unprivileged and injects --unshare-net when offline
    let Ok(plan) = session.compile_session_plan(&["opencode".to_owned()]) else {
        panic!("compile_session_plan failed");
    };
    let (live_auto, notice) = prepare_live_execution_argv(&plan, false, false);
    assert_eq!(live_auto.first().map(String::as_str), Some("bwrap"));
    assert!(notice.is_some());

    let (live_offline, _) = prepare_live_execution_argv(&plan, true, false);
    assert!(live_offline.contains(&"--unshare-net".to_owned()));
}

async fn send_raw_http(addr: std::net::SocketAddr, request: &str) -> String {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        panic!("Failed to connect to test server");
    };
    let _ = stream.write_all(request.as_bytes()).await;
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

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
    let dash = send_raw_http(
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
        let resp = send_raw_http(addr, &req).await;
        assert!(resp.contains("200 OK"), "Endpoint {path} failed: {resp}");
    }

    // 2b. GET /api/v1/apparmor/missing and /api/v1/network/missing (404 Problem Details)
    for bad_path in ["/api/v1/apparmor/missing", "/api/v1/network/missing"] {
        let req =
            format!("GET {bad_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let resp = send_raw_http(addr, &req).await;
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
    })
    .unwrap_or_default();
    let compile_req = format!(
        "POST /api/v1/compile HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nTrace-ID: trace-compile-1\r\nIdempotency-Key: idem-123\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        compile_body.len(),
        compile_body
    );
    let compile_resp = send_raw_http(addr, &compile_req).await;
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
    let cfg_resp = send_raw_http(addr, &cfg_req).await;
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
    let bad_cfg_resp = send_raw_http(addr, &bad_cfg_req).await;
    assert!(bad_cfg_resp.contains("400 Bad Request"));

    // 4. POST /api/v1/compile (404 Unknown Profile RFC 7807)
    let bad_compile_body = serde_json::to_string(&CompileLaunchRequest {
        profile: "missing-profile".to_owned(),
        workspace: ".".to_owned(),
        command: vec!["opencode".to_owned()],
        extra_masked_binaries: Vec::new(),
        extra_rw_paths: Vec::new(),
    })
    .unwrap_or_default();
    let bad_compile_req = format!(
        "POST /api/v1/compile HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        bad_compile_body.len(),
        bad_compile_body
    );
    let bad_compile_resp = send_raw_http(addr, &bad_compile_req).await;
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
    let eval_resp = send_raw_http(addr, &eval_req).await;
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
    let bad_eval_resp = send_raw_http(addr, &bad_eval_req).await;
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
