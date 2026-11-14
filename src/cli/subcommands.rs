//! Subcommand handlers for `cordon` CLI (`profiles`, `groups`, `plugin`, `config`, `render-*`, `evaluate-url`, `doctor`, `completions`).

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use clap_complete::Shell;

use crate::apparmor::{try_render_apparmor_microvm_profile, try_render_apparmor_profile};
use crate::config::{CordonEnvironmentConfig, get_config_template, list_config_templates};
use crate::domain::{TapSlot, Verdict};
use crate::error::CordonError;
use crate::groups::{list_command_group_infos, list_directory_group_infos};
use crate::l7_policy::CordonPolicyEvaluator;
use crate::network::{generate_microvm_tap_commands, generate_network_setup_commands};
use crate::plugins::{list_available_plugins_with_workspace, resolve_plugin_with_policy};
use crate::profiles::{get_profile, list_profiles};
use crate::repl::write_groups_summary;
use crate::sandbox::run_doctor_checks;

use super::{
    ConfigSubcommand, PluginSubcommand, VmSubcommand, log_stderr_diagnostic,
    render_shell_completions,
};

pub fn handle_profiles(json: bool) -> Result<i32> {
    let profiles = list_profiles();
    log_stderr_diagnostic(
        "INFO",
        "profiles.list",
        &format!("count={}", profiles.len()),
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "profiles": profiles }))?
        );
    } else {
        for p in &profiles {
            println!(
                "{:<16} [{:?} | {:?}] - {}",
                p.name, p.filesystem_mode, p.network_mode, p.description
            );
        }
    }
    Ok(0)
}

pub fn handle_groups(json: bool) -> Result<i32> {
    let cmd_groups = list_command_group_infos();
    let dir_groups = list_directory_group_infos();
    log_stderr_diagnostic(
        "INFO",
        "groups.list",
        &format!("cmd={},dir={}", cmd_groups.len(), dir_groups.len()),
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "command_groups": cmd_groups,
                "directory_groups": dir_groups,
            }))?
        );
    } else {
        let mut stdout = std::io::stdout().lock();
        write_groups_summary(&mut stdout)?;
    }
    Ok(0)
}

pub fn handle_plugin(
    action: PluginSubcommand,
    json: bool,
    allow_workspace_plugins: bool,
) -> Result<i32> {
    match action {
        PluginSubcommand::List => {
            let plugins = list_available_plugins_with_workspace(allow_workspace_plugins);
            log_stderr_diagnostic("INFO", "plugin.list", &format!("count={}", plugins.len()));
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "plugins": plugins }))?
                );
            } else {
                for p in &plugins {
                    println!(
                        "{:<16} ({}) v{} - {}",
                        p.name, p.repo_id, p.version, p.description
                    );
                }
            }
            Ok(0)
        }
        PluginSubcommand::Info { name } => {
            let plugin = resolve_plugin_with_policy(&name, allow_workspace_plugins)?;
            log_stderr_diagnostic("INFO", "plugin.info", &plugin.name);
            if json {
                println!("{}", serde_json::to_string_pretty(&plugin)?);
            } else {
                println!(
                    "Plugin:           {} ({}) v{}",
                    plugin.name, plugin.repo_id, plugin.version
                );
                println!("Description:      {}", plugin.description);
                println!("Features:         {:?}", plugin.features);
                println!("Command Groups:   {:?}", plugin.default_command_groups);
                println!("Directory Groups: {:?}", plugin.default_directory_groups);
                println!("Aliases:          {:?}", plugin.aliases);
            }
            Ok(0)
        }
    }
}

pub fn handle_config(action: ConfigSubcommand, json: bool) -> Result<i32> {
    match action {
        ConfigSubcommand::ListTemplates => {
            let templates = list_config_templates();
            log_stderr_diagnostic(
                "INFO",
                "config.templates",
                &format!("count={}", templates.len()),
            );
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "templates": templates }))?
                );
            } else {
                for t in &templates {
                    println!(
                        "{:<18} [base: {:<14} | file: {:<24}] - {}",
                        t.slug, t.base_profile, t.default_filename, t.summary
                    );
                }
            }
            Ok(0)
        }
        ConfigSubcommand::Init {
            template,
            format,
            output,
        } => {
            let cfg = get_config_template(&template)?;
            let rendered = match format.trim().to_ascii_lowercase().as_str() {
                "cordonfile" | "dockerfile" => cfg.to_cordonfile_string(),
                "toml" => cfg.to_toml_string(),
                "json" => serde_json::to_string_pretty(&cfg)?,
                other => {
                    anyhow::bail!(
                        "Unsupported format '{other}'. Expected 'cordonfile', 'toml', or 'json'."
                    );
                }
            };
            if let Some(ref out_path) = output {
                std::fs::write(out_path, &rendered)?;
                log_stderr_diagnostic(
                    "INFO",
                    "config.init",
                    &format!("wrote={}", out_path.display()),
                );
            } else {
                print!("{rendered}");
            }
            Ok(0)
        }
        ConfigSubcommand::Validate { file } => {
            let cfg = CordonEnvironmentConfig::from_file(&file)?;
            let (merged_profile, plan) =
                cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new())?;
            log_stderr_diagnostic("INFO", "config.validate", &cfg.name);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "valid": true,
                        "config": cfg,
                        "merged_profile": merged_profile.name,
                        "launch_plan": plan,
                    }))?
                );
            } else {
                println!(
                    "VALID: '{}' (base_profile={}, workspace={}) -> {}",
                    cfg.name,
                    cfg.base_profile,
                    plan.canonical_workspace,
                    plan.full_argv.join(" ")
                );
            }
            Ok(0)
        }
    }
}

pub fn handle_render_apparmor(
    profile: &str,
    attach_path: &str,
    microvm: bool,
    json: bool,
) -> Result<i32> {
    let prof = get_profile(profile)?;
    let text = if microvm {
        try_render_apparmor_microvm_profile(&prof, attach_path)?
    } else {
        try_render_apparmor_profile(&prof, attach_path)?
    };
    log_stderr_diagnostic("INFO", "apparmor.render", &prof.name);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "profile": prof.name,
                "attach_path": attach_path,
                "apparmor_policy": text,
            }))?
        );
    } else {
        print!("{text}");
    }
    Ok(0)
}

pub fn handle_render_netns(
    profile: &str,
    microvm: bool,
    tap_pool: u8,
    tap_owner_uid: Option<u32>,
    json: bool,
) -> Result<i32> {
    let prof = get_profile(profile)?;
    let mut commands = generate_network_setup_commands(&prof);
    if microvm {
        if !(1..=TapSlot::MAX_POOL).contains(&tap_pool) {
            return Err(CordonError::InvalidInput(format!(
                "--tap-pool must be between 1 and {}",
                TapSlot::MAX_POOL
            ))
            .into());
        }
        let uid = tap_owner_uid.unwrap_or_else(|| {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata("/proc/self").map_or(0, |m| m.uid())
        });
        commands.extend(generate_microvm_tap_commands(&prof, tap_pool, uid));
    }
    log_stderr_diagnostic("INFO", "netns.render", &prof.name);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "profile": prof.name,
                "netns_name": prof.netns_name,
                "commands": commands,
            }))?
        );
    } else {
        for cmd in &commands {
            println!("{cmd}");
        }
    }
    Ok(0)
}

pub fn handle_evaluate_url(
    profile: &str,
    url: &str,
    method: &str,
    body: Option<&str>,
    json: bool,
) -> Result<i32> {
    let prof = get_profile(profile)?;
    let evaluator = CordonPolicyEvaluator::new(prof);
    let decision = evaluator.evaluate_request(url, method, body);
    log_stderr_diagnostic("INFO", "l7.evaluate", &decision.matched_rule);
    if json {
        println!("{}", serde_json::to_string_pretty(&decision)?);
    } else {
        println!(
            "[{:?}] HTTP {} ({}) - {}",
            decision.verdict, decision.status_code, decision.matched_rule, decision.reason
        );
    }
    Ok(if decision.verdict == Verdict::Block {
        3
    } else {
        0
    })
}

pub fn handle_vm(action: VmSubcommand) -> Result<i32> {
    match action {
        VmSubcommand::Supervise { run_id, .. } => {
            log_stderr_diagnostic("ERROR", "microvm.supervise", &run_id);
            Err(CordonError::MicroVmUnavailable(
                "the Gate 3.5 supervisor (cordon-guest-init transport) is not available in this build yet".to_owned(),
            )
            .into())
        }
    }
}

pub fn handle_doctor(json: bool) -> Result<i32> {
    let report = run_doctor_checks();
    log_stderr_diagnostic(
        "INFO",
        "doctor.check",
        if report.healthy {
            "healthy"
        } else {
            "degraded"
        },
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Platform: {}", report.platform_summary);
        for check in &report.checks {
            let badge = if check.passed { "PASS" } else { "WARN" };
            println!("  [{badge}] {:<20} {}", check.name, check.detail);
        }
    }
    Ok(0)
}

pub fn handle_completions(shell: Shell, output: Option<&Path>, json: bool) -> Result<i32> {
    let script = render_shell_completions(shell)?;
    let shell_name = format!("{shell:?}").to_ascii_lowercase();
    log_stderr_diagnostic("INFO", "completions.generate", &shell_name);
    if let Some(out_path) = output {
        std::fs::write(out_path, &script)?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "shell": shell_name,
                    "output": out_path.display().to_string(),
                    "bytes": script.len(),
                }))?
            );
        }
    } else if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "shell": shell_name,
                "script": script,
            }))?
        );
    } else {
        print!("{script}");
    }
    Ok(0)
}
