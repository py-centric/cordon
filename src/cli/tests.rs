use clap::Parser;
use clap_complete::Shell;

use super::subcommands::{handle_completions, handle_doctor, handle_evaluate_url, handle_vm};
use super::{CordonCli, VmSubcommand, execute_cli};

#[test]
fn subcommands_eval_vm_doctor_and_completions() -> anyhow::Result<()> {
    assert_eq!(
        handle_evaluate_url(
            "ai-agent",
            "https://api.github.com/repos",
            "GET",
            None,
            true
        )?,
        0
    );
    assert_eq!(
        handle_evaluate_url(
            "ai-agent",
            "https://api.github.com/repos",
            "GET",
            None,
            false
        )?,
        0
    );
    assert!(
        handle_vm(VmSubcommand::Supervise {
            run_id: "r1".to_owned(),
            spec_json: "{}".to_owned(),
            tap: "tcvm0".to_owned(),
            forward_env: String::new(),
            argv: vec!["/bin/true".to_owned()],
        })
        .is_err()
    );
    assert_eq!(handle_doctor(true)?, 0);
    assert_eq!(handle_doctor(false)?, 0);

    let out_file = std::env::temp_dir().join(format!("cordon-comp-{}.bash", uuid::Uuid::new_v4()));
    assert_eq!(handle_completions(Shell::Bash, Some(&out_file), true)?, 0);
    assert!(out_file.exists());
    let _ = std::fs::remove_file(&out_file);
    assert_eq!(handle_completions(Shell::Zsh, None, true)?, 0);
    Ok(())
}

#[tokio::test]
async fn dispatch_cli_executes_read_only_and_dry_run_commands() {
    let cases: &[&[&str]] = &[
        &["cordon", "--json", "doctor"],
        &["cordon", "doctor"],
        &["cordon", "--json", "profiles"],
        &["cordon", "profiles"],
        &["cordon", "--json", "groups"],
        &["cordon", "groups"],
        &["cordon", "--json", "config", "list-templates"],
        &["cordon", "config", "list-templates"],
        &[
            "cordon",
            "--json",
            "config",
            "validate",
            "-f",
            "configs/Cordonfile.python",
        ],
        &[
            "cordon",
            "config",
            "validate",
            "-f",
            "configs/Cordonfile.python",
        ],
        &[
            "cordon",
            "config",
            "init",
            "--template",
            "python-sandbox",
            "--format",
            "cordonfile",
        ],
        &[
            "cordon",
            "config",
            "init",
            "--template",
            "python-sandbox",
            "--format",
            "toml",
        ],
        &[
            "cordon",
            "config",
            "init",
            "--template",
            "python-sandbox",
            "--format",
            "json",
        ],
        &["cordon", "render-apparmor", "-p", "ai-agent"],
        &[
            "cordon",
            "--json",
            "render-apparmor",
            "-p",
            "ai-agent",
            "--microvm",
        ],
        &["cordon", "render-netns", "-p", "ai-agent"],
        &[
            "cordon",
            "--json",
            "render-netns",
            "-p",
            "ai-agent",
            "--microvm",
            "--tap-pool",
            "2",
        ],
        &[
            "cordon",
            "--json",
            "run",
            "-f",
            "configs/Cordonfile.python",
            "-w",
            ".",
            "--dry-run",
        ],
        &[
            "cordon",
            "run",
            "-p",
            "ai-agent",
            "-w",
            ".",
            "--offline",
            "--dry-run",
            "--",
            "/bin/true",
        ],
        &[
            "cordon",
            "run",
            "-p",
            "ai-agent",
            "-w",
            ".",
            "--host-net",
            "--dry-run",
            "--",
            "/bin/true",
        ],
        &[
            "cordon",
            "--json",
            "inspect-cmd",
            "-p",
            "ai-agent",
            "-w",
            ".",
            "--",
            "/bin/true",
        ],
        &[
            "cordon",
            "inspect-cmd",
            "-p",
            "ai-agent",
            "-w",
            ".",
            "--",
            "/bin/true",
        ],
        &["cordon", "shell", "-p", "ai-agent", "-w", ".", "--dry-run"],
        &[
            "cordon",
            "--json",
            "shell",
            "-p",
            "ai-agent",
            "-w",
            ".",
            "--dry-run",
        ],
        &[
            "cordon",
            "--json",
            "evaluate-url",
            "--url",
            "https://api.openai.com/v1/models",
            "--method",
            "POST",
            "--body",
            "{}",
        ],
        &["cordon", "--json", "plugin", "list"],
        &["cordon", "plugin", "list"],
        &["cordon", "--json", "plugin", "info", "cordon-hud"],
        &["cordon", "plugin", "info", "cordon-hud"],
        &["cordon", "--json", "tui", "--snapshot"],
        &["cordon", "tui", "--snapshot"],
        &["cordon", "completions", "bash"],
    ];
    for argv in cases {
        let cli =
            CordonCli::try_parse_from(*argv).unwrap_or_else(|e| panic!("parse {argv:?}: {e}"));
        let code = execute_cli(cli)
            .await
            .unwrap_or_else(|e| panic!("dispatch {argv:?}: {e}"));
        assert_eq!(code, 0, "command {argv:?} failed");
    }

    let out_cfg = std::env::temp_dir().join(format!("cordon-init-{}.toml", uuid::Uuid::new_v4()));
    let out_str = out_cfg.to_string_lossy().into_owned();
    let cli_init = CordonCli::try_parse_from([
        "cordon",
        "config",
        "init",
        "--template",
        "opencode",
        "--format",
        "toml",
        "--output",
        &out_str,
    ])
    .unwrap_or_else(|e| panic!("parse init: {e}"));
    let init_code = execute_cli(cli_init)
        .await
        .unwrap_or_else(|e| panic!("exec init: {e}"));
    assert_eq!(init_code, 0);
    assert!(out_cfg.exists());
    let _ = std::fs::remove_file(&out_cfg);
}
