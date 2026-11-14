//! Dockerfile/Containerfile-style `Cordonfile` parser and serializer.

use std::fmt::Write as _;

use super::toml_format::{apply_vm_key, apply_vm_rate_limit_key, parse_kv_pairs, parse_vm_backend};
use super::{
    CordonEnvironmentConfig, expand_tilde, parse_env_assignment, parse_fs_mode, parse_net_mode,
    parse_string_array_literal, parse_volume_spec,
};
use crate::domain::{RawMicroVmSpec, VmRateLimits};
use crate::error::CordonError;

impl CordonEnvironmentConfig {
    /// Parses a Dockerfile/Containerfile-style `Cordonfile` string.
    pub fn from_cordonfile_str(raw: &str) -> Result<Self, CordonError> {
        let mut cfg = Self::default();
        for (line_idx, raw_line) in raw.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((directive, rest)) = line.split_once(char::is_whitespace) else {
                return Err(CordonError::InvalidInput(format!(
                    "Cordonfile line {}: missing argument after directive '{line}'",
                    line_idx + 1
                )));
            };
            cfg.apply_cordonfile_directive(line_idx + 1, directive, rest)?;
        }
        Ok(cfg)
    }

    fn apply_cordonfile_directive(
        &mut self,
        line_num: usize,
        directive: &str,
        rest: &str,
    ) -> Result<(), CordonError> {
        let arg = rest.trim().trim_matches('"').trim_matches('\'');
        match directive.to_ascii_uppercase().as_str() {
            "FROM" | "PROFILE" => arg.clone_into(&mut self.base_profile),
            "NAME" => arg.clone_into(&mut self.name),
            "DESCRIPTION" => self.description = Some(arg.to_owned()),
            "WORKDIR" => self.workspace = expand_tilde(arg),
            "FS_MODE" => self.filesystem_mode = Some(parse_fs_mode(arg)?),
            "NET_MODE" => self.network_mode = Some(parse_net_mode(arg)?),
            "PROTECT_GIT" => self.protect_git_dir = Some(arg.eq_ignore_ascii_case("true")),
            "ISOLATE_HOME" => self.isolate_home_tmpfs = Some(arg.eq_ignore_ascii_case("true")),
            "BUILD_SCRATCH" => {
                self.enable_build_scratch = Some(arg.eq_ignore_ascii_case("true"));
            }
            "MOUNT" => {
                let (mounted_path, is_rw) = parse_volume_spec(arg)?;
                if is_rw {
                    self.rw_binds.push(mounted_path);
                } else {
                    self.ro_binds.push(mounted_path);
                }
            }
            "VOLUME_RO" => self.ro_binds.push(expand_tilde(arg)),
            "VOLUME_RW" => self.rw_binds.push(expand_tilde(arg)),
            "MASK_BIN" | "MASK" => push_whitespace_items(&mut self.mask_binaries, rest, true),
            "ALLOW_BIN" | "EXPOSE_BIN" => {
                push_whitespace_items(&mut self.allowed_binaries, rest, false);
            }
            "ALLOW_GROUP" | "COMMAND_GROUP" => {
                push_whitespace_items(&mut self.command_groups, rest, false);
            }
            "MOUNT_GROUP" | "DIR_GROUP" => {
                push_whitespace_items(&mut self.directory_groups, rest, false);
            }
            "PLUGIN" => push_whitespace_items(&mut self.plugins, rest, false),
            "MASK_DIR" => push_whitespace_items(&mut self.masked_dirs, rest, true),
            "ALLOW_DOMAIN" => push_whitespace_items(&mut self.allowed_domains, rest, false),
            "ALLOW_POST" | "POST_ALLOWED_HOST" => {
                push_whitespace_items(&mut self.post_allowed_hosts, rest, false);
            }
            "DENY_DOMAIN" => push_whitespace_items(&mut self.denied_domains, rest, false),
            "ENV" => {
                let (k, v) = parse_env_assignment(rest)?;
                self.env.insert(k, v);
            }
            "VM_BACKEND" => {
                self.vm.get_or_insert_with(RawMicroVmSpec::default).backend =
                    parse_vm_backend(arg)?;
            }
            "VM_RESOURCES" => {
                let vm = self.vm.get_or_insert_with(RawMicroVmSpec::default);
                for (k, v) in parse_kv_pairs("VM_RESOURCES", rest)? {
                    if !matches!(k.as_str(), "vcpus" | "memory_mib" | "disk_mode") {
                        return Err(CordonError::InvalidInput(format!(
                            "Cordonfile line {line_num}: VM_RESOURCES accepts vcpus, memory_mib, disk_mode; got '{k}'"
                        )));
                    }
                    apply_vm_key(vm, &k, &v)?;
                }
            }
            "VM_KERNEL" => {
                apply_vm_key(
                    self.vm.get_or_insert_with(RawMicroVmSpec::default),
                    "kernel_image",
                    arg,
                )?;
            }
            "VM_ROOTFS" => {
                apply_vm_key(
                    self.vm.get_or_insert_with(RawMicroVmSpec::default),
                    "rootfs_image",
                    arg,
                )?;
            }
            "VM_SNAPSHOT" => {
                apply_vm_key(
                    self.vm.get_or_insert_with(RawMicroVmSpec::default),
                    "snapshot",
                    arg,
                )?;
            }
            "VM_RATE_LIMIT" => {
                let vm = self.vm.get_or_insert_with(RawMicroVmSpec::default);
                let limits = vm.rate_limits.get_or_insert_with(VmRateLimits::default);
                for (k, v) in parse_kv_pairs("VM_RATE_LIMIT", rest)? {
                    apply_vm_rate_limit_key(limits, &k, &v)?;
                }
            }
            "CMD" => {
                let trimmed_rest = rest.trim();
                if trimmed_rest.starts_with('[') {
                    self.command = parse_string_array_literal(trimmed_rest);
                } else {
                    self.command = trimmed_rest.split_whitespace().map(str::to_owned).collect();
                }
            }
            other => {
                return Err(CordonError::InvalidInput(format!(
                    "Cordonfile line {line_num}: unsupported directive '{other}'"
                )));
            }
        }
        Ok(())
    }

    /// Serializes this configuration into a Dockerfile-style executable `Cordonfile`.
    pub fn to_cordonfile_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "#!/usr/bin/env -S cordon run -f");
        let _ = writeln!(
            out,
            "# Reproducible Cordon Environment (Cordonfile) - Governed by ADR-L0-SEC-02"
        );
        let _ = writeln!(out, "FROM {}", self.base_profile);
        let _ = writeln!(out, "NAME \"{}\"", self.name);
        if let Some(ref desc) = self.description {
            let _ = writeln!(out, "DESCRIPTION \"{desc}\"");
        }
        let _ = writeln!(out, "WORKDIR \"{}\"", self.workspace);
        if !self.command_groups.is_empty() {
            let _ = writeln!(out, "ALLOW_GROUP {}", self.command_groups.join(" "));
        }
        if !self.allowed_binaries.is_empty() {
            let _ = writeln!(out, "ALLOW_BIN {}", self.allowed_binaries.join(" "));
        }
        if !self.directory_groups.is_empty() {
            let _ = writeln!(out, "MOUNT_GROUP {}", self.directory_groups.join(" "));
        }
        if !self.plugins.is_empty() {
            let _ = writeln!(out, "PLUGIN {}", self.plugins.join(" "));
        }
        for ro in &self.ro_binds {
            let _ = writeln!(out, "VOLUME_RO \"{ro}\"");
        }
        for rw in &self.rw_binds {
            let _ = writeln!(out, "VOLUME_RW \"{rw}\"");
        }
        for mask in &self.mask_binaries {
            let _ = writeln!(out, "MASK_BIN \"{mask}\"");
        }
        for mask_dir in &self.masked_dirs {
            let _ = writeln!(out, "MASK_DIR \"{mask_dir}\"");
        }
        for dom in &self.allowed_domains {
            let _ = writeln!(out, "ALLOW_DOMAIN \"{dom}\"");
        }
        for post_dom in &self.post_allowed_hosts {
            let _ = writeln!(out, "ALLOW_POST \"{post_dom}\"");
        }
        for (k, v) in &self.env {
            let _ = writeln!(out, "ENV {k}=\"{v}\"");
        }
        if let Some(ref vm) = self.vm {
            write_vm_cordonfile_directives(&mut out, vm);
        }
        if !self.command.is_empty() {
            let quoted: Vec<String> = self.command.iter().map(|c| format!("\"{c}\"")).collect();
            let _ = writeln!(out, "CMD [{}]", quoted.join(", "));
        }
        out
    }
}

fn push_whitespace_items(target: &mut Vec<String>, rest: &str, expand: bool) {
    for item in rest.split_whitespace() {
        let cleaned = item.trim_matches('"').trim_matches('\'');
        if !cleaned.is_empty() {
            if expand {
                target.push(expand_tilde(cleaned));
            } else {
                target.push(cleaned.to_owned());
            }
        }
    }
}

fn write_vm_cordonfile_directives(out: &mut String, vm: &RawMicroVmSpec) {
    let _ = writeln!(out, "VM_BACKEND {}", vm.backend.as_str());
    let mut resources = Vec::new();
    if let Some(v) = vm.vcpus {
        resources.push(format!("vcpus={v}"));
    }
    if let Some(m) = vm.memory_mib {
        resources.push(format!("memory_mib={m}"));
    }
    if let Some(d) = vm.disk_mode {
        resources.push(format!("disk_mode={}", d.as_str()));
    }
    if !resources.is_empty() {
        let _ = writeln!(out, "VM_RESOURCES {}", resources.join(" "));
    }
    if let Some(ref k) = vm.kernel_image {
        let _ = writeln!(out, "VM_KERNEL \"{k}\"");
    }
    if let Some(ref r) = vm.rootfs_image {
        let _ = writeln!(out, "VM_ROOTFS \"{r}\"");
    }
    if let Some(ref snap) = vm.snapshot {
        let _ = writeln!(out, "VM_SNAPSHOT {snap}");
    }
    if let Some(ref limits) = vm.rate_limits {
        let mut parts = Vec::new();
        if let Some(v) = limits.disk_iops {
            parts.push(format!("disk_iops={v}"));
        }
        if let Some(v) = limits.disk_bandwidth_mib_s {
            parts.push(format!("disk_mib_s={v}"));
        }
        if let Some(v) = limits.net_bandwidth_mbit_s {
            parts.push(format!("net_mbit_s={v}"));
        }
        if !parts.is_empty() {
            let _ = writeln!(out, "VM_RATE_LIMIT {}", parts.join(" "));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cordonfile_parses_all_directives_and_roundtrips() {
        let raw = r#"
# Comment
FROM ai-agent
NAME test-env
DESCRIPTION "Test environment"
WORKDIR .
FS_MODE workspace_ro
NET_MODE inspected
PROTECT_GIT true
ISOLATE_HOME true
BUILD_SCRATCH false
MOUNT /tmp:ro
MOUNT /var/tmp:rw
VOLUME_RO /etc/ssl
VOLUME_RW /tmp/out
MASK_BIN curl
ALLOW_BIN rg jq
ALLOW_GROUP coreutils
MOUNT_GROUP xdg-config:ro
PLUGIN cordon-hud
MASK_DIR /home/user/.ssh
ALLOW_DOMAIN api.openai.com
ALLOW_POST api.anthropic.com
DENY_DOMAIN evil.example
ENV FOO=bar
VM_BACKEND firecracker
VM_RESOURCES vcpus=2 memory_mib=512 disk_mode=ephemeral-tmpfs
VM_RATE_LIMIT disk_iops=100 disk_mib_s=50 net_mbit_s=100
CMD ["/bin/true"]
"#;
        let cfg = CordonEnvironmentConfig::from_cordonfile_str(raw)
            .unwrap_or_else(|e| panic!("parse cordonfile: {e}"));
        assert_eq!(cfg.name, "test-env");
        assert_eq!(cfg.base_profile, "ai-agent");
        assert_eq!(cfg.protect_git_dir, Some(true));
        assert_eq!(cfg.isolate_home_tmpfs, Some(true));
        assert_eq!(cfg.enable_build_scratch, Some(false));
        let rendered = cfg.to_cordonfile_string();
        assert!(rendered.contains("FROM ai-agent"));
        assert!(rendered.contains("test-env"));
        assert!(rendered.contains("VM_BACKEND"));
        assert!(rendered.contains("VM_RESOURCES"));
        assert!(rendered.contains("VM_RATE_LIMIT"));

        assert!(CordonEnvironmentConfig::from_cordonfile_str("FROM").is_err());
        assert!(CordonEnvironmentConfig::from_cordonfile_str("VM_RESOURCES bad=1").is_err());
    }
}
