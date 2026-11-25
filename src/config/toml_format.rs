//! Declarative `Cordonfile.toml` / `cordon.toml` parser, serializer, and `[vm]` helpers.

use std::fmt::Write as _;

use super::{
    CordonEnvironmentConfig, expand_tilde, parse_fs_mode, parse_net_mode,
    parse_string_array_literal,
};
use crate::domain::{IsolationBackend, RawMicroVmSpec, VmDiskMode, VmRateLimits};
use crate::error::CordonError;

pub(super) fn parse_vm_backend(val: &str) -> Result<IsolationBackend, CordonError> {
    match val.trim().to_ascii_lowercase().as_str() {
        "native-bwrap" | "native" | "bwrap" => Ok(IsolationBackend::NativeBwrap),
        "qemu-microvm" | "qemu" => Ok(IsolationBackend::QemuMicrovm),
        "firecracker" => Ok(IsolationBackend::Firecracker),
        "krun" => Ok(IsolationBackend::Krun),
        other => Err(CordonError::InvalidInput(format!(
            "Unknown vm backend '{other}'. Expected 'native-bwrap', 'qemu-microvm', 'firecracker', or 'krun'."
        ))),
    }
}

pub(super) fn parse_vm_disk_mode(val: &str) -> Result<VmDiskMode, CordonError> {
    match val.trim().to_ascii_lowercase().as_str() {
        "virtio-fs-live" => Ok(VmDiskMode::VirtioFsLive),
        "ephemeral-tmpfs" => Ok(VmDiskMode::EphemeralTmpfs),
        "btrfs-cow-overlay" => Ok(VmDiskMode::BtrfsCowOverlay),
        "snapshot-restore" => Ok(VmDiskMode::SnapshotRestore),
        other => Err(CordonError::InvalidInput(format!(
            "Unknown vm disk_mode '{other}'. Expected 'virtio-fs-live', 'ephemeral-tmpfs', 'btrfs-cow-overlay', or 'snapshot-restore'."
        ))),
    }
}

fn parse_vm_number<T: std::str::FromStr>(key: &str, val: &str) -> Result<T, CordonError> {
    val.trim().parse::<T>().map_err(|_| {
        CordonError::InvalidInput(format!("Invalid vm {key} '{val}': expected an integer"))
    })
}

fn parse_vm_nonzero(key: &str, val: &str) -> Result<std::num::NonZeroU32, CordonError> {
    std::num::NonZeroU32::new(parse_vm_number::<u32>(key, val)?).ok_or_else(|| {
        CordonError::InvalidInput(format!("Invalid vm {key} '{val}': must be greater than 0"))
    })
}

/// Applies one `[vm]` key to a raw MicroVM spec (shared by TOML and `VM_RESOURCES`).
pub(super) fn apply_vm_key(
    vm: &mut RawMicroVmSpec,
    key: &str,
    val: &str,
) -> Result<(), CordonError> {
    match key {
        "backend" => vm.backend = parse_vm_backend(val)?,
        "vcpus" => vm.vcpus = Some(parse_vm_number::<u8>(key, val)?),
        "memory_mib" => vm.memory_mib = Some(parse_vm_number::<u32>(key, val)?),
        "disk_mode" => vm.disk_mode = Some(parse_vm_disk_mode(val)?),
        "kernel_image" => vm.kernel_image = Some(expand_tilde(val)),
        "rootfs_image" => vm.rootfs_image = Some(expand_tilde(val)),
        "snapshot" => vm.snapshot = Some(val.trim().to_owned()),
        other => {
            return Err(CordonError::InvalidInput(format!(
                "Unknown vm key '{other}'. Expected backend, vcpus, memory_mib, disk_mode, kernel_image, rootfs_image, or snapshot."
            )));
        }
    }
    Ok(())
}

/// Applies one rate-limit key (TOML `[vm.rate_limits]` names or `VM_RATE_LIMIT` short aliases).
pub(super) fn apply_vm_rate_limit_key(
    limits: &mut VmRateLimits,
    key: &str,
    val: &str,
) -> Result<(), CordonError> {
    match key {
        "disk_iops" | "iops" => limits.disk_iops = Some(parse_vm_nonzero(key, val)?),
        "disk_bandwidth_mib_s" | "disk_mib_s" => {
            limits.disk_bandwidth_mib_s = Some(parse_vm_nonzero(key, val)?);
        }
        "net_bandwidth_mbit_s" | "net_mbit_s" => {
            limits.net_bandwidth_mbit_s = Some(parse_vm_nonzero(key, val)?);
        }
        other => {
            return Err(CordonError::InvalidInput(format!(
                "Unknown vm rate limit '{other}'. Expected disk_iops, disk_bandwidth_mib_s, or net_bandwidth_mbit_s."
            )));
        }
    }
    Ok(())
}

/// Parses whitespace-separated `key=value` pairs (`VM_RESOURCES`, `VM_RATE_LIMIT`).
pub(super) fn parse_kv_pairs(
    directive: &str,
    rest: &str,
) -> Result<Vec<(String, String)>, CordonError> {
    rest.split_whitespace()
        .map(|item| {
            let cleaned = item.trim_matches('"').trim_matches('\'');
            cleaned
                .split_once('=')
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                .filter(|(k, v)| !k.is_empty() && !v.is_empty())
                .ok_or_else(|| {
                    CordonError::InvalidInput(format!(
                        "{directive}: expected key=value pairs, got '{cleaned}'"
                    ))
                })
        })
        .collect()
}

impl CordonEnvironmentConfig {
    /// Parses a declarative `Cordonfile.toml` / `cordon.toml` configuration string.
    pub fn from_toml_str(raw: &str) -> Result<Self, CordonError> {
        let mut cfg = Self::default();
        let mut section = String::new();
        let mut pending_key: Option<String> = None;
        let mut pending_array_buf = String::new();

        for (line_idx, raw_line) in raw.lines().enumerate() {
            let without_comment = match raw_line.find('#') {
                Some(idx) => &raw_line[..idx],
                None => raw_line,
            };
            let line = without_comment.trim();
            if line.is_empty() {
                continue;
            }

            if let Some(ref key) = pending_key {
                pending_array_buf.push(' ');
                pending_array_buf.push_str(line);
                if line.ends_with(']') {
                    let arr = parse_string_array_literal(&pending_array_buf);
                    Self::apply_toml_array(&mut cfg, &section, key, arr)?;
                    pending_key = None;
                    pending_array_buf.clear();
                }
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                continue;
            }

            let Some((raw_k, raw_v)) = line.split_once('=') else {
                return Err(CordonError::InvalidInput(format!(
                    "TOML line {}: expected key = value, got '{line}'",
                    line_idx + 1
                )));
            };
            let key = raw_k.trim().trim_matches('"').trim_matches('\'');
            let val = raw_v.trim();

            if val.starts_with('[') && !val.ends_with(']') {
                pending_key = Some(key.to_owned());
                val.clone_into(&mut pending_array_buf);
                continue;
            }

            if val.starts_with('[') && val.ends_with(']') {
                let arr = parse_string_array_literal(val);
                Self::apply_toml_array(&mut cfg, &section, key, arr)?;
            } else {
                Self::apply_toml_scalar(&mut cfg, &section, key, val)?;
            }
        }

        if pending_key.is_some() {
            return Err(CordonError::InvalidInput(
                "Unclosed multi-line array in TOML configuration".to_owned(),
            ));
        }

        Ok(cfg)
    }

    fn apply_toml_array(
        cfg: &mut Self,
        section: &str,
        key: &str,
        arr: Vec<String>,
    ) -> Result<(), CordonError> {
        let expand_all = |items: Vec<String>| items.into_iter().map(|p| expand_tilde(&p));
        match (section, key) {
            ("mounts" | "filesystem" | "", "ro" | "ro_binds" | "readonly_mounts") => {
                cfg.ro_binds.extend(expand_all(arr));
            }
            ("mounts" | "filesystem" | "", "rw" | "rw_binds" | "writable_mounts") => {
                cfg.rw_binds.extend(expand_all(arr));
            }
            ("security" | "filesystem" | "", "mask_binaries" | "masked_binaries") => {
                cfg.mask_binaries.extend(expand_all(arr));
            }
            (
                "security" | "filesystem" | "groups" | "sandbox" | "",
                "allowed_binaries" | "allow_bins",
            ) => cfg.allowed_binaries.extend(arr),
            ("security" | "groups" | "sandbox" | "", "command_groups" | "allow_groups") => {
                cfg.command_groups.extend(arr);
            }
            (
                "mounts" | "filesystem" | "groups" | "sandbox" | "",
                "directory_groups" | "mount_groups",
            ) => cfg.directory_groups.extend(arr),
            ("plugins" | "sandbox" | "", "plugins" | "enabled") => cfg.plugins.extend(arr),
            ("security" | "filesystem" | "", "masked_dirs") => {
                cfg.masked_dirs.extend(expand_all(arr));
            }
            ("network" | "", "allowed_domains") => cfg.allowed_domains.extend(arr),
            ("network" | "", "post_allowed_hosts") => cfg.post_allowed_hosts.extend(arr),
            ("network" | "", "denied_domains") => cfg.denied_domains.extend(arr),
            ("command" | "runtime" | "sandbox" | "", "entrypoint" | "command" | "cmd") => {
                cfg.command = arr;
            }
            _ => {
                return Err(CordonError::InvalidInput(format!(
                    "Unknown TOML array key '[{section}].{key}'"
                )));
            }
        }
        Ok(())
    }

    fn apply_toml_scalar(
        cfg: &mut Self,
        section: &str,
        key: &str,
        raw_val: &str,
    ) -> Result<(), CordonError> {
        let clean = raw_val.trim().trim_matches('"').trim_matches('\'');
        if section == "env" {
            cfg.env.insert(key.to_owned(), clean.to_owned());
            return Ok(());
        }
        if section == "vm" {
            return apply_vm_key(
                cfg.vm.get_or_insert_with(RawMicroVmSpec::default),
                key,
                clean,
            );
        }
        if section == "vm.rate_limits" {
            let vm = cfg.vm.get_or_insert_with(RawMicroVmSpec::default);
            let limits = vm.rate_limits.get_or_insert_with(VmRateLimits::default);
            return apply_vm_rate_limit_key(limits, key, clean);
        }
        match (section, key) {
            ("sandbox" | "environment" | "", "name") => clean.clone_into(&mut cfg.name),
            ("sandbox" | "environment" | "", "base_profile" | "profile") => {
                clean.clone_into(&mut cfg.base_profile);
            }
            ("sandbox" | "environment" | "", "description") => {
                cfg.description = Some(clean.to_owned());
            }
            ("sandbox" | "environment" | "", "workspace" | "workdir") => {
                cfg.workspace = expand_tilde(clean);
            }
            ("sandbox" | "environment" | "", "filesystem_mode") => {
                cfg.filesystem_mode = Some(parse_fs_mode(clean)?);
            }
            ("sandbox" | "environment" | "network" | "", "network_mode") => {
                cfg.network_mode = Some(parse_net_mode(clean)?);
            }
            ("sandbox" | "security" | "", "protect_git_dir") => {
                cfg.protect_git_dir = Some(clean.eq_ignore_ascii_case("true"));
            }
            ("sandbox" | "security" | "", "isolate_home_tmpfs") => {
                cfg.isolate_home_tmpfs = Some(clean.eq_ignore_ascii_case("true"));
            }
            ("sandbox" | "security" | "", "enable_build_scratch") => {
                cfg.enable_build_scratch = Some(clean.eq_ignore_ascii_case("true"));
            }
            ("sandbox" | "", "tmpfs_size_mb") => {
                cfg.tmpfs_size_mb = Some(clean.parse::<u32>().map_err(|_| {
                    CordonError::InvalidInput(format!("Invalid tmpfs_size_mb '{clean}'"))
                })?);
            }
            _ => {
                return Err(CordonError::InvalidInput(format!(
                    "Unknown TOML key '[{section}].{key}'"
                )));
            }
        }
        Ok(())
    }

    /// Serializes this configuration into a declarative `Cordonfile.toml`.
    pub fn to_toml_string(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "#!/usr/bin/env -S cordon run -f\n# Reproducible Cordon Environment (Cordonfile.toml) - Governed by ADR-L0-SEC-02\n[sandbox]\nname = \"{}\"\nbase_profile = \"{}\"",
            self.name, self.base_profile
        );
        write_opt(&mut out, "description", self.description.as_deref(), true);
        let _ = writeln!(out, "workspace = \"{}\"", self.workspace);
        write_opt(&mut out, "protect_git_dir", self.protect_git_dir, false);
        write_opt(
            &mut out,
            "isolate_home_tmpfs",
            self.isolate_home_tmpfs,
            false,
        );
        write_opt(
            &mut out,
            "enable_build_scratch",
            self.enable_build_scratch,
            false,
        );

        if !self.command_groups.is_empty()
            || !self.allowed_binaries.is_empty()
            || !self.directory_groups.is_empty()
        {
            let _ = writeln!(out, "\n[groups]");
            write_toml_string_array(&mut out, "command_groups", &self.command_groups, false);
            write_toml_string_array(&mut out, "allowed_binaries", &self.allowed_binaries, false);
            write_toml_string_array(&mut out, "directory_groups", &self.directory_groups, false);
        }

        let _ = writeln!(out, "\n[mounts]");
        write_toml_string_array(&mut out, "ro", &self.ro_binds, true);
        write_toml_string_array(&mut out, "rw", &self.rw_binds, true);

        if !self.mask_binaries.is_empty() || !self.masked_dirs.is_empty() {
            let _ = writeln!(out, "\n[security]");
            write_toml_string_array(&mut out, "mask_binaries", &self.mask_binaries, true);
            write_toml_string_array(&mut out, "masked_dirs", &self.masked_dirs, true);
        }

        if !self.allowed_domains.is_empty() || !self.post_allowed_hosts.is_empty() {
            let _ = writeln!(out, "\n[network]");
            write_toml_string_array(&mut out, "allowed_domains", &self.allowed_domains, false);
            let hosts = &self.post_allowed_hosts;
            write_toml_string_array(&mut out, "post_allowed_hosts", hosts, false);
        }

        if !self.env.is_empty() {
            let _ = writeln!(out, "\n[env]");
            for (k, v) in &self.env {
                let _ = writeln!(out, "{k} = \"{v}\"");
            }
        }
        if let Some(ref vm) = self.vm {
            write_vm_toml_section(&mut out, vm);
        }
        if !self.command.is_empty() {
            let _ = writeln!(out, "\n[command]");
            write_toml_string_array(&mut out, "entrypoint", &self.command, true);
        }
        out
    }
}

fn write_toml_string_array(out: &mut String, key: &str, items: &[String], always_emit: bool) {
    if !items.is_empty() || always_emit {
        let quoted: Vec<String> = items.iter().map(|s| format!("\"{s}\"")).collect();
        let _ = writeln!(out, "{key} = [{}]", quoted.join(", "));
    }
}

fn write_opt<T: std::fmt::Display>(out: &mut String, key: &str, val: Option<T>, quote: bool) {
    if let Some(v) = val {
        let _ = if quote {
            writeln!(out, "{key} = \"{v}\"")
        } else {
            writeln!(out, "{key} = {v}")
        };
    }
}

fn write_vm_toml_section(out: &mut String, vm: &RawMicroVmSpec) {
    let _ = writeln!(out, "\n[vm]\nbackend = \"{}\"", vm.backend.as_str());
    write_opt(out, "vcpus", vm.vcpus, false);
    write_opt(out, "memory_mib", vm.memory_mib, false);
    write_opt(out, "disk_mode", vm.disk_mode.map(VmDiskMode::as_str), true);
    write_opt(out, "kernel_image", vm.kernel_image.as_deref(), true);
    write_opt(out, "rootfs_image", vm.rootfs_image.as_deref(), true);
    write_opt(out, "snapshot", vm.snapshot.as_deref(), true);
    if let Some(ref l) = vm.rate_limits {
        let _ = writeln!(out, "\n[vm.rate_limits]");
        write_opt(out, "disk_iops", l.disk_iops, false);
        write_opt(out, "disk_bandwidth_mib_s", l.disk_bandwidth_mib_s, false);
        write_opt(out, "net_bandwidth_mbit_s", l.net_bandwidth_mbit_s, false);
    }
}
