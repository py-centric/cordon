//! OP-CORDON-004 live `pc-sandboxd` runtime bridge and merged audit trail.
//!
//! Translates a validated [`PcSandboxdEscalationPlan`] into a deterministic
//! `pc sandbox spawn` argv invocation (zero shell interpolation) and merges
//! Cordon `tshark`/`mitmproxy` events with `pc-sandboxd` runtime events.

use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::error::CordonError;
use crate::microvm::escalation::{PcSandboxdEscalationPlan, SandboxdRuntime};

/// Single audit event emitted either by Cordon (`tshark`/`mitmproxy`) or `pc-sandboxd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxdAuditEvent {
    /// ISO-8601 UTC timestamp string used for deterministic chronological sorting.
    pub ts_utc: String,
    /// Origin subsystem (`cordon.netns`, `cordon.mitmproxy`, `cordon.tshark`, `pc-sandboxd`).
    pub source: String,
    /// Structured event kind (`egress.allow`, `egress.deny`, `microvm.boot`, `microvm.exit`).
    pub event: String,
    /// Human-readable detail payload.
    pub detail: String,
}

/// Execution receipt returned by [`dispatch_to_sandboxd`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxdDispatchReceipt {
    /// Selected runtime slug (`firecracker`, `qemu-microvm`, or `gvisor-runsc`).
    pub runtime: String,
    /// Exact argv dispatched to `pc` without shell interpolation.
    pub argv: Vec<String>,
    /// True when executed in dry-run verification mode.
    pub dry_run: bool,
    /// Subprocess exit code (`0` in dry-run mode).
    pub exit_code: i32,
    /// Captured stdout from `pc sandbox spawn`.
    pub stdout: String,
    /// Captured stderr from `pc sandbox spawn`.
    pub stderr: String,
    /// Merged chronological audit events.
    pub audit_trail: Vec<SandboxdAuditEvent>,
}

/// Format [`SandboxdRuntime`] into its canonical CLI flag value.
pub fn runtime_slug(runtime: SandboxdRuntime) -> &'static str {
    match runtime {
        SandboxdRuntime::Firecracker => "firecracker",
        SandboxdRuntime::QemuMicrovm => "qemu-microvm",
        SandboxdRuntime::GvisorRunsc => "gvisor-runsc",
    }
}

/// Compile a deterministic argv vector for `pc sandbox spawn` (zero shell).
pub fn build_pc_sandbox_argv(plan: &PcSandboxdEscalationPlan) -> Vec<String> {
    let mut argv = vec![
        "sandbox".to_owned(),
        "spawn".to_owned(),
        "--runtime".to_owned(),
        runtime_slug(plan.runtime).to_owned(),
        "--profile".to_owned(),
        plan.profile.clone(),
        "--vcpus".to_owned(),
        plan.vcpus.to_string(),
        "--memory-mib".to_owned(),
        plan.memory_mib.to_string(),
    ];
    for domain in &plan.allowed_domains {
        argv.push("--allow-domain".to_owned());
        argv.push(domain.clone());
    }
    argv.push("--".to_owned());
    argv.extend(plan.command.iter().cloned());
    argv
}

/// Merge Cordon network/inspection events and `pc-sandboxd` events chronologically.
pub fn merge_audit_trail(
    cordon_events: &[SandboxdAuditEvent],
    sandboxd_events: &[SandboxdAuditEvent],
) -> Vec<SandboxdAuditEvent> {
    let mut merged = Vec::with_capacity(cordon_events.len() + sandboxd_events.len());
    merged.extend(cordon_events.iter().cloned());
    merged.extend(sandboxd_events.iter().cloned());
    merged.sort_by(|a, b| {
        a.ts_utc
            .cmp(&b.ts_utc)
            .then_with(|| a.source.cmp(&b.source))
    });
    merged
}

/// Dispatch an escalation plan to `pc-sandboxd` via `pc sandbox spawn` (or dry-run).
pub fn dispatch_to_sandboxd(
    plan: &PcSandboxdEscalationPlan,
    cordon_events: &[SandboxdAuditEvent],
    dry_run: bool,
) -> Result<SandboxdDispatchReceipt, CordonError> {
    if plan.command.is_empty() {
        return Err(CordonError::EmptyCommand);
    }
    let argv = build_pc_sandbox_argv(plan);
    let rt = runtime_slug(plan.runtime).to_owned();

    if dry_run {
        let synthetic = vec![SandboxdAuditEvent {
            ts_utc: "2026-11-25T00:00:00Z".to_owned(),
            source: "pc-sandboxd".to_owned(),
            event: "microvm.dry_run".to_owned(),
            detail: format!("Planned {rt} escalation for profile '{}'", plan.profile),
        }];
        return Ok(SandboxdDispatchReceipt {
            runtime: rt,
            argv,
            dry_run: true,
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            audit_trail: merge_audit_trail(cordon_events, &synthetic),
        });
    }

    let output = Command::new("pc").args(&argv).output()?;

    let exit_code = output.status.code().unwrap_or(1);
    let synthetic = vec![SandboxdAuditEvent {
        ts_utc: "2026-11-25T00:00:01Z".to_owned(),
        source: "pc-sandboxd".to_owned(),
        event: if exit_code == 0 {
            "microvm.exit_ok".to_owned()
        } else {
            "microvm.exit_err".to_owned()
        },
        detail: format!("pc sandbox spawn ({rt}) exited with code {exit_code}"),
    }];
    Ok(SandboxdDispatchReceipt {
        runtime: rt,
        argv,
        dry_run: false,
        exit_code,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        audit_trail: merge_audit_trail(cordon_events, &synthetic),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::microvm::escalation::build_sandboxd_escalation_plan;
    use crate::profiles::get_profile;

    #[test]
    fn builds_deterministic_pc_sandbox_argv_and_merges_audit_trail() {
        let Ok(profile) = get_profile("package-build") else {
            panic!("package-build profile missing");
        };
        let cmd = vec!["cargo".to_owned(), "test".to_owned()];
        let Ok(plan) = build_sandboxd_escalation_plan(&profile, None, &cmd, false) else {
            panic!("escalation plan failed");
        };
        let argv = build_pc_sandbox_argv(&plan);
        assert!(argv.starts_with(&["sandbox".to_owned(), "spawn".to_owned()]));
        assert!(argv.contains(&"gvisor-runsc".to_owned()));
        assert!(argv.ends_with(&["--".to_owned(), "cargo".to_owned(), "test".to_owned()]));

        let cordon_ev = vec![SandboxdAuditEvent {
            ts_utc: "2026-11-24T23:59:59Z".to_owned(),
            source: "cordon.tshark".to_owned(),
            event: "egress.allow".to_owned(),
            detail: "crates.io:443".to_owned(),
        }];
        let Ok(receipt) = dispatch_to_sandboxd(&plan, &cordon_ev, true) else {
            panic!("dry-run dispatch failed");
        };
        assert!(receipt.dry_run);
        assert_eq!(receipt.exit_code, 0);
        assert_eq!(receipt.audit_trail.len(), 2);
        assert_eq!(receipt.audit_trail[0].source, "cordon.tshark");
        assert_eq!(receipt.audit_trail[1].source, "pc-sandboxd");
    }
}
