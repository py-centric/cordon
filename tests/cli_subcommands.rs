//! Integration tests for Cordon HTTP Control Plane (`axum`), CLI subcommands, Error RFC 7807 mapping, and Hexagonal Ports.

use clap::Parser;
use cordon::cli::{CordonCli, execute_cli};

mod common;

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
