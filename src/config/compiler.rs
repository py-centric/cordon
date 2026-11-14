//! Profile merging and launch-plan compilation for [`CordonEnvironmentConfig`].

use std::collections::BTreeMap;
use std::path::Path;

use crate::domain::{CordonProfile, MicroVmSpec, SandboxLaunchPlan};
use crate::error::CordonError;
use crate::groups::{
    apply_allowed_binary_to_profile, apply_command_group_to_profile,
    apply_directory_group_to_profile,
};
use crate::profiles::get_profile;
use crate::sandbox::compile_launch_plan_with_masks;

use super::{CordonEnvironmentConfig, PlanCompileOptions, RESERVED_ENV_KEYS, expand_tilde};

impl CordonEnvironmentConfig {
    /// Validates the optional `[vm]` settings into a [`MicroVmSpec`].
    pub fn microvm_spec(&self) -> Result<Option<MicroVmSpec>, CordonError> {
        match self.vm {
            Some(ref raw) if raw.backend.is_microvm() => {
                MicroVmSpec::try_from(raw.clone()).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Merges this environment configuration onto its `base_profile` to produce a concrete [`CordonProfile`].
    pub fn build_profile(&self) -> Result<CordonProfile, CordonError> {
        let mut profile = get_profile(&self.base_profile)?;
        if let Some(ref desc) = self.description {
            profile.description.clone_from(desc);
        }
        if let Some(fs_mode) = self.filesystem_mode {
            profile.filesystem_mode = fs_mode;
        }
        if let Some(net_mode) = self.network_mode {
            profile.network_mode = net_mode;
        }
        if let Some(protect_git) = self.protect_git_dir {
            profile.protect_git_dir = protect_git;
        }
        if let Some(isolate_home) = self.isolate_home_tmpfs {
            profile.isolate_home_tmpfs = isolate_home;
        }
        if let Some(scratch) = self.enable_build_scratch {
            profile.enable_build_scratch = scratch;
        }
        if let Some(tmp_mb) = self.tmpfs_size_mb {
            profile.tmpfs_size_mb = tmp_mb;
        }

        for ro in &self.ro_binds {
            let expanded = expand_tilde(ro);
            if !profile.extra_ro_binds.contains(&expanded) {
                profile.extra_ro_binds.push(expanded);
            }
        }
        for rw in &self.rw_binds {
            let expanded = expand_tilde(rw);
            if !profile.extra_rw_binds.contains(&expanded) {
                profile.extra_rw_binds.push(expanded);
            }
        }
        for mask in &self.mask_binaries {
            let expanded = expand_tilde(mask);
            if !profile.denied_binaries.contains(&expanded) {
                profile.denied_binaries.push(expanded);
            }
        }
        for grp in &self.command_groups {
            let _ = apply_command_group_to_profile(&mut profile, grp)?;
        }
        for bin in &self.allowed_binaries {
            let _ = apply_allowed_binary_to_profile(&mut profile, bin);
        }
        for dir_grp in &self.directory_groups {
            let _ = apply_directory_group_to_profile(&mut profile, dir_grp, None)?;
        }
        for dom in &self.allowed_domains {
            if !profile.allowed_domains.contains(dom) {
                profile.allowed_domains.push(dom.clone());
            }
        }
        for post_dom in &self.post_allowed_hosts {
            if !profile.post_allowed_hosts.contains(post_dom) {
                profile.post_allowed_hosts.push(post_dom.clone());
            }
        }
        for denied in &self.denied_domains {
            if !profile.denied_domains.contains(denied) {
                profile.denied_domains.push(denied.clone());
            }
        }

        Ok(profile)
    }

    /// Derives the runtime [`crate::l7_policy::PolicyConfig`] serialized to `/run/cordon/policy.json`.
    pub fn resolve_effective_policy(&self) -> Result<crate::l7_policy::PolicyConfig, CordonError> {
        let profile = self.build_profile()?;
        Ok(crate::l7_policy::PolicyConfig::from_profile(&profile))
    }

    /// Compiles a verified [`SandboxLaunchPlan`] from this environment config and optional CLI overrides.
    pub fn compile_plan(
        &self,
        workspace_override: Option<&Path>,
        cli_command_override: &[String],
        readonly_mounts: &[String],
        writable_mounts: &[String],
        extra_masked_bins: &[String],
        extra_env: &BTreeMap<String, String>,
    ) -> Result<(CordonProfile, SandboxLaunchPlan), CordonError> {
        self.compile_plan_with_policy(&PlanCompileOptions {
            workspace_override,
            cli_command_override,
            readonly_mounts,
            writable_mounts,
            extra_masked_bins,
            extra_env,
            allow_reserved_env: false,
        })
    }

    /// Compiles a [`SandboxLaunchPlan`] with an explicit [`PlanCompileOptions`] policy.
    pub fn compile_plan_with_policy(
        &self,
        options: &PlanCompileOptions<'_>,
    ) -> Result<(CordonProfile, SandboxLaunchPlan), CordonError> {
        let mut profile = self.build_profile()?;
        let microvm = self.microvm_spec()?;
        if let Some(ref spec) = microvm {
            spec.validate_for_profile(&profile)?;
        }
        for ro in options.readonly_mounts {
            let expanded = expand_tilde(ro);
            if !profile.extra_ro_binds.contains(&expanded) {
                profile.extra_ro_binds.push(expanded);
            }
        }

        let effective_cmd = if options.cli_command_override.is_empty() {
            &self.command
        } else {
            options.cli_command_override
        };

        let expanded_ws = expand_tilde(&self.workspace);
        let ws_path = options
            .workspace_override
            .unwrap_or_else(|| Path::new(&expanded_ws));
        let expanded_extra_rw: Vec<String> = options
            .writable_mounts
            .iter()
            .map(|p| expand_tilde(p))
            .collect();

        let mut plan = compile_launch_plan_with_masks(
            &profile,
            ws_path,
            effective_cmd,
            options.extra_masked_bins,
            &expanded_extra_rw,
            &self.masked_dirs,
        )?;

        let mut merged_env = self.env.clone();
        for (k, v) in options.extra_env {
            merged_env.insert(k.clone(), v.clone());
        }
        if !options.allow_reserved_env {
            for key in merged_env.keys() {
                if RESERVED_ENV_KEYS.contains(&key.as_str()) {
                    return Err(CordonError::InvalidInput(format!(
                        "Environment variable '{key}' is reserved by Cordon's trusted CA/proxy and runtime hardening layer; remove it from the config/CLI env or pass --allow-reserved-env to override (audited)"
                    )));
                }
            }
        }
        if !merged_env.is_empty() {
            let split_pos = plan
                .bwrap_argv
                .iter()
                .position(|arg| arg == "--chdir")
                .unwrap_or(plan.bwrap_argv.len());
            let mut env_flags = Vec::with_capacity(merged_env.len() * 3);
            for (k, v) in &merged_env {
                plan.env_overrides.insert(k.clone(), v.clone());
                env_flags.extend(["--setenv".to_owned(), k.clone(), v.clone()]);
            }
            plan.bwrap_argv.splice(split_pos..split_pos, env_flags);
            let mut full = plan.netns_exec_argv.clone();
            full.extend(crate::sandbox::aa_exec_confinement_prefix(
                &plan.profile_name,
            ));
            full.extend(plan.bwrap_argv.clone());
            plan.full_argv = full;
        }

        if let Some(ref spec) = microvm {
            let run_id = uuid::Uuid::new_v4().simple().to_string();
            crate::microvm::attach_microvm_plan(&mut plan, &profile, spec, &run_id)?;
        }

        Ok((profile, plan))
    }
}
