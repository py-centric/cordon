//! OP-CORDON-004: Deterministic escalation handoff contract from Cordon Gate 1-3
//! to `pc-sandboxd` (Firecracker MicroVM or gVisor `runsc`) for high-risk profiles.
//!
//! Pure, zero-unsafe, zero-panic planner: emits a versioned JSON contract consumed
//! by `pc-sandboxd` without spawning hypervisors directly.

use serde::{Deserialize, Serialize};

use crate::domain::{CordonProfile, IsolationBackend, MicroVmSpec, NetworkMode};
use crate::error::CordonError;

/// Schema version for `OP-CORDON-004` `pc-sandboxd` escalation envelopes.
pub const ESCALATION_SCHEMA_VERSION: &str = "1.0.0";

/// Default vCPU allocation when escalating without an explicit `[vm]` spec.
pub const DEFAULT_ESCALATION_VCPUS: u8 = 2;

/// Default memory allocation (MiB) when escalating without an explicit `[vm]` spec.
pub const DEFAULT_ESCALATION_MEMORY_MIB: u32 = 1024;

/// Built-in profile slugs that warrant automatic `pc-sandboxd` escalation under `OP-CORDON-004`.
pub const HEAVY_ESCALATION_PROFILES: &[&str] = &[
    "package-build",
    "network-audit",
    "webcrawler-untrusted",
    "code_envs",
    "untrusted-code",
];

/// Target Tier 2/3 runtime selected by `OP-CORDON-004`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxdRuntime {
    /// Firecracker KVM MicroVM (Tier 3 hardware boundary).
    Firecracker,
    /// QEMU `-M microvm` KVM MicroVM (Tier 3 hardware boundary).
    QemuMicrovm,
    /// gVisor `runsc` user-space kernel (Tier 2 fallback when `/dev/kvm` is absent).
    GvisorRunsc,
}

/// Deterministic `OP-CORDON-004` handoff payload consumed by `pc-sandboxd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcSandboxdEscalationPlan {
    /// Contract schema version (`1.0.0`).
    pub schema_version: String,
    /// Target escalation daemon identifier (`pc-sandboxd`).
    pub target_daemon: String,
    /// Selected Tier 2/3 runtime.
    pub runtime: SandboxdRuntime,
    /// Source Cordon profile slug.
    pub profile: String,
    /// Human-readable reason explaining why escalation was selected.
    pub reason: String,
    /// Allocated guest vCPUs.
    pub vcpus: u8,
    /// Allocated guest memory in MiB.
    pub memory_mib: u32,
    /// Network isolation mode propagated from the Cordon profile.
    pub network_mode: NetworkMode,
    /// L7 allowed domains propagated from the Cordon profile.
    pub allowed_domains: Vec<String>,
    /// Explicitly denied domains propagated from the Cordon profile.
    pub denied_domains: Vec<String>,
    /// Command vector to execute inside the escalated sandbox.
    pub command: Vec<String>,
}

/// Returns `true` when `profile_name` is designated for Tier 2/3 `pc-sandboxd` escalation.
pub fn requires_sandboxd_escalation(profile_name: &str) -> bool {
    let normalized = profile_name.trim().to_ascii_lowercase();
    HEAVY_ESCALATION_PROFILES.contains(&normalized.as_str())
}

/// Compiles a deterministic `OP-CORDON-004` escalation plan for `pc-sandboxd`.
pub fn build_sandboxd_escalation_plan(
    profile: &CordonProfile,
    vm_spec: Option<&MicroVmSpec>,
    command: &[String],
    kvm_available: bool,
) -> Result<PcSandboxdEscalationPlan, CordonError> {
    if command.is_empty() {
        return Err(CordonError::EmptyCommand);
    }

    let (runtime, vcpus, memory_mib, reason) = if let Some(spec) = vm_spec {
        let rt = match spec.backend() {
            IsolationBackend::Firecracker if kvm_available => SandboxdRuntime::Firecracker,
            IsolationBackend::QemuMicrovm if kvm_available => SandboxdRuntime::QemuMicrovm,
            IsolationBackend::Firecracker
            | IsolationBackend::QemuMicrovm
            | IsolationBackend::Krun
            | IsolationBackend::NativeBwrap => SandboxdRuntime::GvisorRunsc,
        };
        let why = if kvm_available {
            format!(
                "Explicit MicroVM spec ({}) escalated via OP-CORDON-004",
                spec.backend().as_str()
            )
        } else {
            "KVM unavailable on host; OP-CORDON-004 selected fail-closed gVisor runsc fallback"
                .to_owned()
        };
        (rt, spec.vcpus().get(), spec.memory_mib().get(), why)
    } else {
        let rt = if kvm_available {
            SandboxdRuntime::Firecracker
        } else {
            SandboxdRuntime::GvisorRunsc
        };
        let why = if requires_sandboxd_escalation(&profile.name) {
            format!(
                "Heavy workload profile '{}' escalated to pc-sandboxd per OP-CORDON-004",
                profile.name
            )
        } else {
            format!(
                "Explicit operator escalation requested for profile '{}'",
                profile.name
            )
        };
        (
            rt,
            DEFAULT_ESCALATION_VCPUS,
            DEFAULT_ESCALATION_MEMORY_MIB,
            why,
        )
    };

    Ok(PcSandboxdEscalationPlan {
        schema_version: ESCALATION_SCHEMA_VERSION.to_owned(),
        target_daemon: "pc-sandboxd".to_owned(),
        runtime,
        profile: profile.name.clone(),
        reason,
        vcpus,
        memory_mib,
        network_mode: profile.network_mode,
        allowed_domains: profile.allowed_domains.clone(),
        denied_domains: profile.denied_domains.clone(),
        command: command.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{RawMicroVmSpec, VmDiskMode};
    use crate::profiles::get_profile;

    #[test]
    fn heavy_profiles_trigger_escalation_predicate() {
        assert!(requires_sandboxd_escalation("package-build"));
        assert!(requires_sandboxd_escalation("network-audit"));
        assert!(requires_sandboxd_escalation("webcrawler-untrusted"));
        assert!(requires_sandboxd_escalation("code_envs"));
        assert!(requires_sandboxd_escalation("untrusted-code"));
        assert!(!requires_sandboxd_escalation("ai-agent"));
    }

    #[test]
    fn escalation_rejects_empty_command() {
        let Ok(profile) = get_profile("package-build") else {
            panic!("package-build profile missing");
        };
        let err = build_sandboxd_escalation_plan(&profile, None, &[], true);
        assert!(matches!(err, Err(CordonError::EmptyCommand)));
    }

    #[test]
    fn escalation_selects_firecracker_with_kvm_and_gvisor_without_kvm() {
        let Ok(profile) = get_profile("package-build") else {
            panic!("package-build profile missing");
        };
        let cmd = vec!["cargo".to_owned(), "build".to_owned()];

        let Ok(fc_plan) = build_sandboxd_escalation_plan(&profile, None, &cmd, true) else {
            panic!("firecracker escalation failed");
        };
        assert_eq!(fc_plan.runtime, SandboxdRuntime::Firecracker);
        assert_eq!(fc_plan.target_daemon, "pc-sandboxd");
        assert_eq!(fc_plan.vcpus, DEFAULT_ESCALATION_VCPUS);
        assert_eq!(fc_plan.memory_mib, DEFAULT_ESCALATION_MEMORY_MIB);
        assert!(fc_plan.reason.contains("OP-CORDON-004"));

        let Ok(gv_plan) = build_sandboxd_escalation_plan(&profile, None, &cmd, false) else {
            panic!("gvisor escalation failed");
        };
        assert_eq!(gv_plan.runtime, SandboxdRuntime::GvisorRunsc);
    }

    #[test]
    fn escalation_honors_explicit_microvm_spec_and_fallback() {
        let Ok(profile) = get_profile("ai-agent") else {
            panic!("ai-agent profile missing");
        };
        let raw = RawMicroVmSpec {
            backend: IsolationBackend::QemuMicrovm,
            vcpus: Some(4),
            memory_mib: Some(2048),
            disk_mode: Some(VmDiskMode::VirtioFsLive),
            kernel_image: Some("/var/lib/cordon/kernels/vmlinux".to_owned()),
            rootfs_image: None,
            snapshot: None,
            rate_limits: None,
        };
        let Ok(spec) = MicroVmSpec::try_from(raw) else {
            panic!("valid microvm spec failed");
        };
        let cmd = vec!["true".to_owned()];

        let Ok(qemu_plan) = build_sandboxd_escalation_plan(&profile, Some(&spec), &cmd, true)
        else {
            panic!("qemu plan failed");
        };
        assert_eq!(qemu_plan.runtime, SandboxdRuntime::QemuMicrovm);
        assert_eq!(qemu_plan.vcpus, 4);
        assert_eq!(qemu_plan.memory_mib, 2048);

        let Ok(fallback) = build_sandboxd_escalation_plan(&profile, Some(&spec), &cmd, false)
        else {
            panic!("fallback plan failed");
        };
        assert_eq!(fallback.runtime, SandboxdRuntime::GvisorRunsc);
        assert!(fallback.reason.contains("KVM unavailable"));

        let Ok(non_heavy) = build_sandboxd_escalation_plan(&profile, None, &cmd, true) else {
            panic!("non-heavy explicit plan failed");
        };
        assert!(non_heavy.reason.contains("Explicit operator escalation"));
    }
}
