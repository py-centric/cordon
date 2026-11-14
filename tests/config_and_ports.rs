//! Integration tests for Cordon HTTP Control Plane (`axum`), CLI subcommands, Error RFC 7807 mapping, and Hexagonal Ports.

use std::path::Path;

use cordon::apparmor::AppArmorProfileCompiler;
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

mod common;

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
