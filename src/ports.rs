//! Hexagonal Architecture Ports (Traits) for Cordon.

use std::path::Path;

use crate::domain::{AuditEvent, CordonProfile, DoctorReport, PolicyDecision, SandboxLaunchPlan};
use crate::error::CordonError;

/// Driver port for querying workload isolation profiles.
pub trait ProfileCatalogPort: Send + Sync {
    /// Returns a cloned profile by its canonical slug (`ai-agent`, `untrusted-code`, etc.).
    fn get_profile(&self, name: &str) -> Result<CordonProfile, CordonError>;

    /// Lists all registered workload profiles in deterministic order.
    fn list_profiles(&self) -> Vec<CordonProfile>;
}

/// Driven port for compiling Bubblewrap and network namespace launch plans.
pub trait SandboxCompilerPort: Send + Sync {
    /// Compiles an immutable [`SandboxLaunchPlan`] from a profile, workspace, and command.
    fn compile_launch_plan(
        &self,
        profile: &CordonProfile,
        workspace_dir: &Path,
        command: &[String],
        extra_masked_binaries: &[String],
        extra_rw_paths: &[String],
    ) -> Result<SandboxLaunchPlan, CordonError>;

    /// Executes host toolchain and Linux kernel LSM diagnostic checks.
    fn run_doctor_checks(&self) -> DoctorReport;
}

/// Driven port for generating AppArmor 4.0 Mandatory Access Control profiles.
pub trait AppArmorCompilerPort: Send + Sync {
    /// Renders an AppArmor 4.0 policy for the specified attachment binary path.
    fn render_apparmor_profile(&self, profile: &CordonProfile, attach_path: &str) -> String;
}

/// Driven port for generating Linux Network Namespace (`ip netns`) and `iptables` rules.
pub trait NetnsCompilerPort: Send + Sync {
    /// Generates idempotent shell commands to provision the `veth` pair and NAT rules.
    fn generate_network_setup_commands(&self, profile: &CordonProfile) -> Vec<String>;
}

/// Driven port for evaluating Layer 7 HTTP/HTTPS flows against domain, DoH, and secret rules.
pub trait L7PolicyEvaluatorPort: Send + Sync {
    /// Evaluates an outbound HTTP/HTTPS flow and returns a deterministic [`PolicyDecision`].
    fn evaluate_request(&self, url: &str, method: &str, body: Option<&str>) -> PolicyDecision;
}

/// Driven port for recording structured security telemetry events.
pub trait AuditSinkPort: Send + Sync {
    /// Appends an [`AuditEvent`] to the bounded telemetry ring buffer.
    fn record_event(&self, event: AuditEvent);

    /// Retrieves recent [`AuditEvent`] entries up to `limit`.
    fn recent_events(&self, limit: usize) -> Vec<AuditEvent>;
}
