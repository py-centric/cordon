//! Top-level CLI command dispatcher and execution handlers (`run`, `shell`, `inspect-cmd`, `repl`, `tui`, `serve`, `l7-proxy`).

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;

use crate::api::{CordonControlPlane, serve_control_plane};
use crate::config::CordonEnvironmentConfig;
use crate::error::CordonError;
use crate::l7_policy::{POLICY_FILE_ENV, write_policy_file};
use crate::l7_proxy::run_l7_proxy_server;
use crate::repl::{ReplNetMode, ReplSession, run_interactive_repl};
use crate::sandbox::prepare_live_execution_argv;
use crate::tui::{render_tui_snapshot, run_interactive_tui};

use super::plan::{CliPlanCompileInput, build_plan_from_cli_options, ensure_live_launch_supported};
use super::subcommands::{
    handle_completions, handle_config, handle_doctor, handle_evaluate_url, handle_groups,
    handle_plugin, handle_profiles, handle_render_apparmor, handle_render_netns, handle_vm,
};
use super::{Commands, CordonCli, VmCliArgs, log_stderr_diagnostic};

const fn resolve_net_mode(offline: bool, host_net: bool) -> ReplNetMode {
    if offline {
        ReplNetMode::Airgap
    } else if host_net {
        ReplNetMode::Direct
    } else {
        ReplNetMode::Auto
    }
}

fn execute_run_command(
    input: &CliPlanCompileInput<'_>,
    net_mode: ReplNetMode,
    dry_run: bool,
    json: bool,
) -> Result<i32> {
    let offline = net_mode == ReplNetMode::Airgap;
    let host_net = net_mode == ReplNetMode::Direct;
    let plan = build_plan_from_cli_options(input)?;
    log_stderr_diagnostic("INFO", "sandbox.run", &plan.profile_name);

    if dry_run {
        if json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else if offline || host_net {
            let (live_argv, _) = prepare_live_execution_argv(&plan, offline, host_net);
            println!("{}", live_argv.join(" "));
        } else {
            println!("{}", plan.full_argv.join(" "));
        }
        return Ok(0);
    }

    ensure_live_launch_supported(&plan)?;
    if let Some(cfg_path) = input.config_file
        && let Ok(policy_path) = std::env::var(POLICY_FILE_ENV)
        && !policy_path.trim().is_empty()
    {
        let mut env_cfg = CordonEnvironmentConfig::from_file(cfg_path)?;
        for dom in input.allow_domains {
            if !env_cfg.allowed_domains.contains(dom) {
                env_cfg.allowed_domains.push(dom.clone());
            }
        }
        let policy_cfg = env_cfg.resolve_effective_policy()?;
        let _ = write_policy_file(&policy_cfg, std::path::Path::new(policy_path.trim()))?;
    }
    let (live_argv, fallback_notice) = prepare_live_execution_argv(&plan, offline, host_net);
    if let Some(ref notice) = fallback_notice {
        log_stderr_diagnostic("WARN", "sandbox.netns_fallback", notice);
    }
    let Some((program, args)) = live_argv.split_first() else {
        return Ok(1);
    };
    let status = Command::new(program).args(args).status()?;
    Ok(status.code().unwrap_or(1))
}

fn execute_shell_command(
    input: &CliPlanCompileInput<'_>,
    net_mode: ReplNetMode,
    dry_run: bool,
    json: bool,
) -> Result<i32> {
    let offline = net_mode == ReplNetMode::Airgap;
    let host_net = net_mode == ReplNetMode::Direct;
    let plan = build_plan_from_cli_options(input)?;
    log_stderr_diagnostic("INFO", "sandbox.shell", &plan.profile_name);
    let (live_argv, fallback_notice) = prepare_live_execution_argv(&plan, offline, host_net);
    if let Some(ref notice) = fallback_notice {
        log_stderr_diagnostic("WARN", "sandbox.netns_fallback", notice);
    }
    if dry_run {
        if json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        } else {
            println!("{}", live_argv.join(" "));
        }
        return Ok(0);
    }
    ensure_live_launch_supported(&plan)?;
    let Some((program, args)) = live_argv.split_first() else {
        return Ok(1);
    };
    let status = Command::new(program).args(args).status()?;
    Ok(status.code().unwrap_or(1))
}

fn execute_tui_command(
    profile: &str,
    workspace: Option<PathBuf>,
    snapshot: bool,
    json: bool,
) -> Result<i32> {
    let is_main_thread = std::thread::current().name() == Some("main");
    if !snapshot
        && !json
        && is_main_thread
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
    {
        log_stderr_diagnostic("INFO", "tui.interactive", profile);
        return Ok(run_interactive_tui(profile, workspace)?);
    }
    let plane = CordonControlPlane::new();
    let rendered = render_tui_snapshot(&plane, 100, 16)?;
    log_stderr_diagnostic("INFO", "tui.render", "snapshot");
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "tui_snapshot": rendered,
            }))?
        );
    } else {
        println!("{rendered}");
    }
    Ok(0)
}

/// Executes a parsed [`CordonCli`] command and returns the desired process exit code.
pub async fn execute_cli(cli: CordonCli) -> Result<i32> {
    match cli.command {
        Commands::Profiles => handle_profiles(cli.json),
        Commands::Groups => handle_groups(cli.json),
        Commands::Plugin { action } => handle_plugin(action, cli.json, cli.allow_workspace_plugins),
        Commands::Config { action } => handle_config(action, cli.json),
        Commands::InspectCmd {
            profile,
            config,
            workspace,
            volumes,
            bind_ro,
            bind_rw,
            mask_bins,
            allow_bins,
            allow_groups,
            mount_groups,
            envs,
            vm,
            argv,
        } => {
            let plan = build_plan_from_cli_options(&CliPlanCompileInput {
                profile: &profile,
                config_file: config.as_ref(),
                workspace: workspace.as_ref(),
                volumes: &volumes,
                readonly_binds: &bind_ro,
                writable_binds: &bind_rw,
                mask_bins: &mask_bins,
                allow_bins: &allow_bins,
                allow_groups: &allow_groups,
                mount_groups: &mount_groups,
                envs: &envs,
                allow_domains: &[],
                argv: &argv,
                allow_reserved_env: cli.allow_reserved_env,
                vm: &vm,
            })?;
            log_stderr_diagnostic("INFO", "sandbox.inspect_cmd", &plan.profile_name);
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!("{}", plan.full_argv.join(" "));
            }
            Ok(0)
        }
        Commands::Run {
            profile,
            config,
            workspace,
            volumes,
            bind_ro,
            bind_rw,
            mask_bins,
            allow_bins,
            allow_groups,
            mount_groups,
            envs,
            allow_domains,
            offline,
            host_net,
            vm,
            dry_run,
            argv,
        } => execute_run_command(
            &CliPlanCompileInput {
                profile: &profile,
                config_file: config.as_ref(),
                workspace: workspace.as_ref(),
                volumes: &volumes,
                readonly_binds: &bind_ro,
                writable_binds: &bind_rw,
                mask_bins: &mask_bins,
                allow_bins: &allow_bins,
                allow_groups: &allow_groups,
                mount_groups: &mount_groups,
                envs: &envs,
                allow_domains: &allow_domains,
                argv: &argv,
                allow_reserved_env: cli.allow_reserved_env,
                vm: &vm,
            },
            resolve_net_mode(offline, host_net),
            dry_run,
            cli.json,
        ),
        Commands::Shell {
            profile,
            config,
            workspace,
            volumes,
            allow_bins,
            allow_groups,
            mount_groups,
            offline,
            host_net,
            dry_run,
        } => {
            let shell_argv = if std::path::Path::new("/bin/bash").exists() {
                vec!["/bin/bash".to_owned(), "--norc".to_owned()]
            } else {
                vec!["/bin/sh".to_owned()]
            };
            let default_vm = VmCliArgs::default();
            execute_shell_command(
                &CliPlanCompileInput {
                    profile: &profile,
                    config_file: config.as_ref(),
                    workspace: workspace.as_ref(),
                    volumes: &volumes,
                    readonly_binds: &[],
                    writable_binds: &[],
                    mask_bins: &[],
                    allow_bins: &allow_bins,
                    allow_groups: &allow_groups,
                    mount_groups: &mount_groups,
                    envs: &[],
                    allow_domains: &[],
                    argv: &shell_argv,
                    allow_reserved_env: cli.allow_reserved_env,
                    vm: &default_vm,
                },
                resolve_net_mode(offline, host_net),
                dry_run,
                cli.json,
            )
        }
        Commands::Repl {
            profile,
            config,
            workspace,
            allow_bins,
            allow_groups,
            mount_groups,
            offline,
            host_net,
            dry_run,
        } => {
            let net_mode = resolve_net_mode(offline, host_net);
            let mut session = ReplSession::new(&profile, config, workspace, net_mode, dry_run)?;
            for b in allow_bins {
                if !session.allowed_binaries.contains(&b) {
                    session.allowed_binaries.push(b);
                }
            }
            for g in allow_groups {
                if !session.command_groups.contains(&g) {
                    session.command_groups.push(g);
                }
            }
            for mg in mount_groups {
                if !session.directory_groups.contains(&mg) {
                    session.directory_groups.push(mg);
                }
            }
            log_stderr_diagnostic("INFO", "repl.start", &session.profile);
            run_interactive_repl(&mut session)
        }
        Commands::RenderApparmor {
            profile,
            attach_path,
            microvm,
        } => handle_render_apparmor(&profile, &attach_path, microvm, cli.json),
        Commands::RenderNetns {
            profile,
            microvm,
            tap_pool,
            tap_owner_uid,
        } => handle_render_netns(&profile, microvm, tap_pool, tap_owner_uid, cli.json),
        Commands::EvaluateUrl {
            profile,
            url,
            method,
            body,
        } => handle_evaluate_url(&profile, &url, &method, body.as_deref(), cli.json),
        Commands::Vm { action } => handle_vm(action),
        Commands::Doctor => handle_doctor(cli.json),
        Commands::Serve { host, port } => {
            log_stderr_diagnostic("INFO", "control_plane.serve", &format!("{host}:{port}"));
            serve_control_plane(&host, port).await?;
            Ok(0)
        }
        Commands::L7Proxy {
            listen,
            policy_file,
        } => {
            let addr: std::net::SocketAddr = listen.parse().map_err(|e| {
                CordonError::InvalidInput(format!("invalid --listen address '{listen}': {e}"))
            })?;
            log_stderr_diagnostic("INFO", "l7_proxy.serve", &listen);
            run_l7_proxy_server(addr, policy_file.as_deref()).await?;
            Ok(0)
        }
        Commands::Tui {
            profile,
            workspace,
            snapshot,
        } => execute_tui_command(&profile, workspace, snapshot, cli.json),
        Commands::Completions { shell, output } => {
            handle_completions(shell, output.as_deref(), cli.json)
        }
    }
}
