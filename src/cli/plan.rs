//! CLI plan compilation options and live launch guards.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;

use crate::config::{
    CordonEnvironmentConfig, PlanCompileOptions, RESERVED_ENV_KEYS, expand_tilde,
    parse_env_assignment, parse_volume_spec,
};
use crate::domain::SandboxLaunchPlan;
use crate::error::CordonError;

use super::{VmCliArgs, log_stderr_diagnostic};

/// Bundled CLI parameters for compiling a [`SandboxLaunchPlan`].
pub struct CliPlanCompileInput<'a> {
    pub profile: &'a str,
    pub config_file: Option<&'a PathBuf>,
    pub workspace: Option<&'a PathBuf>,
    pub volumes: &'a [String],
    pub readonly_binds: &'a [String],
    pub writable_binds: &'a [String],
    pub mask_bins: &'a [String],
    pub allow_bins: &'a [String],
    pub allow_groups: &'a [String],
    pub mount_groups: &'a [String],
    pub envs: &'a [String],
    pub allow_domains: &'a [String],
    pub argv: &'a [String],
    pub allow_reserved_env: bool,
    pub vm: &'a VmCliArgs,
}

/// Refuses live execution of MicroVM plans until the guest agent and supervisor ship
/// (`--dry-run`, `inspect-cmd`, and the API compile plans normally).
pub fn ensure_live_launch_supported(plan: &SandboxLaunchPlan) -> Result<(), CordonError> {
    if plan.microvm.is_some() {
        return Err(CordonError::MicroVmUnavailable(
            "live MicroVM launch is not available in this build yet; use --dry-run or inspect-cmd to review the Gate 3.5 plan".to_owned(),
        ));
    }
    Ok(())
}

/// Compiles a [`SandboxLaunchPlan`] from CLI flags and an optional environment config file.
pub fn build_plan_from_cli_options(input: &CliPlanCompileInput<'_>) -> Result<SandboxLaunchPlan> {
    let mut env_cfg = if let Some(cfg_path) = input.config_file {
        CordonEnvironmentConfig::from_file(cfg_path)?
    } else {
        CordonEnvironmentConfig {
            base_profile: input.profile.to_owned(),
            ..CordonEnvironmentConfig::default()
        }
    };
    input.vm.apply_to(&mut env_cfg);

    for dom in input.allow_domains {
        if !env_cfg.allowed_domains.contains(dom) {
            env_cfg.allowed_domains.push(dom.clone());
        }
    }
    for bin in input.allow_bins {
        if !env_cfg.allowed_binaries.contains(bin) {
            env_cfg.allowed_binaries.push(bin.clone());
        }
    }
    for grp in input.allow_groups {
        if !env_cfg.command_groups.contains(grp) {
            env_cfg.command_groups.push(grp.clone());
        }
    }
    for dgrp in input.mount_groups {
        if !env_cfg.directory_groups.contains(dgrp) {
            env_cfg.directory_groups.push(dgrp.clone());
        }
    }

    let mut readonly_mounts: Vec<String> = input
        .readonly_binds
        .iter()
        .map(|p| expand_tilde(p))
        .collect();
    let mut writable_mounts: Vec<String> = input
        .writable_binds
        .iter()
        .map(|p| expand_tilde(p))
        .collect();
    for vol_spec in input.volumes {
        let (path, is_rw) = parse_volume_spec(vol_spec)?;
        if is_rw {
            writable_mounts.push(path);
        } else {
            readonly_mounts.push(path);
        }
    }

    let mut parsed_env = BTreeMap::new();
    for raw_env in input.envs {
        let (k, v) = parse_env_assignment(raw_env)?;
        parsed_env.insert(k, v);
    }

    // CH-03/CH-04 hygiene: reserved env keys are rejected by the compiler unless explicitly
    // allowed; when allowed, record an audit diagnostic listing every overridden key.
    let mut reserved_hits: Vec<String> = Vec::new();
    for key in env_cfg.env.keys().chain(parsed_env.keys()) {
        if RESERVED_ENV_KEYS.contains(&key.as_str()) && !reserved_hits.contains(key) {
            reserved_hits.push(key.clone());
        }
    }
    if input.allow_reserved_env && !reserved_hits.is_empty() {
        log_stderr_diagnostic(
            "WARN",
            "env.reserved_override_allowed",
            &format!("keys={}", reserved_hits.join(",")),
        );
    }

    let ws_ref = input.workspace.map(PathBuf::as_path);
    let (_prof, plan) = env_cfg.compile_plan_with_policy(&PlanCompileOptions {
        workspace_override: ws_ref,
        cli_command_override: input.argv,
        readonly_mounts: &readonly_mounts,
        writable_mounts: &writable_mounts,
        extra_masked_bins: input.mask_bins,
        extra_env: &parsed_env,
        allow_reserved_env: input.allow_reserved_env,
    })?;
    Ok(plan)
}
