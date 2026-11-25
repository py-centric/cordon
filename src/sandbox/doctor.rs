//! Non-destructive 15-point host environment and kernel capability checks (`cordon doctor`).

use std::path::Path;

use super::policy::{
    AGENT_SHELL_APPARMOR_PROFILE, find_binary_on_path, loaded_apparmor_profile_names,
};
use crate::domain::{DoctorCheck, DoctorReport};

/// Runs non-destructive host environment and kernel capability checks (`cordon doctor`).
pub fn run_doctor_checks() -> DoctorReport {
    let required_binaries: &[(&str, bool, &str)] = &[
        (
            "bwrap",
            true,
            "Bubblewrap unprivileged mount/PID namespace engine",
        ),
        ("ip", true, "iproute2 network namespace and veth management"),
        (
            "iptables",
            true,
            "Netfilter NAT PREROUTING and UDP 443 QUIC rejection",
        ),
        (
            "aa-status",
            false,
            "AppArmor Mandatory Access Control inspection utility",
        ),
        (
            "mitmproxy",
            false,
            "Layer 7 HTTPS TLS interception and policy engine",
        ),
        ("tshark", false, "Layer 3/4 Wireshark CLI PCAP capture tap"),
        ("rustc", true, "Type-safe Rust compiler toolchain"),
    ];

    let mut checks = Vec::with_capacity(required_binaries.len() + 8);
    for (bin_name, required, desc) in required_binaries {
        if let Some(found) = find_binary_on_path(bin_name) {
            checks.push(DoctorCheck {
                name: (*bin_name).to_owned(),
                passed: true,
                required: *required,
                detail: format!("{desc} ({found})"),
            });
        } else {
            checks.push(DoctorCheck {
                name: (*bin_name).to_owned(),
                passed: false,
                required: *required,
                detail: format!("{desc} (missing on PATH)"),
            });
        }
    }

    let apparmor_enabled = Path::new("/sys/module/apparmor/parameters/enabled").exists();
    checks.push(DoctorCheck {
        name: "kernel_apparmor_lsm".to_owned(),
        passed: apparmor_enabled,
        required: false,
        detail: if apparmor_enabled {
            "AppArmor LSM kernel module enabled".to_owned()
        } else {
            "/sys/module/apparmor not mounted or disabled in current namespace".to_owned()
        },
    });

    let aa_exec_present = find_binary_on_path("aa-exec").is_some();
    checks.push(DoctorCheck {
        name: "apparmor_aa_exec".to_owned(),
        passed: aa_exec_present,
        required: false,
        detail: if aa_exec_present {
            "aa-exec profile transition utility available on PATH".to_owned()
        } else {
            "aa-exec missing on PATH; Gate 2 confinement cannot be attached at spawn".to_owned()
        },
    });

    let loaded_profiles = loaded_apparmor_profile_names();
    let attachable_profile = loaded_profiles
        .iter()
        .find(|name| name.as_str() == AGENT_SHELL_APPARMOR_PROFILE || name.starts_with("cordon_"));
    checks.push(DoctorCheck {
        name: "apparmor_confinement".to_owned(),
        passed: aa_exec_present && attachable_profile.is_some(),
        required: false,
        detail: match attachable_profile {
            Some(profile_name) if aa_exec_present => {
                format!("Gate 2 attachable via aa-exec -p {profile_name}")
            }
            Some(profile_name) => {
                format!("profile '{profile_name}' loaded but aa-exec missing on PATH")
            }
            None => {
                "no cordon/agent_shell AppArmor profile loaded; launches will report Gate 2 as not applied".to_owned()
            }
        },
    });

    let tiocsti_disabled = std::fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti")
        .map_or(true, |v| v.trim() == "0");
    checks.push(DoctorCheck {
        name: "kernel_tiocsti_disabled".to_owned(),
        passed: tiocsti_disabled,
        required: false,
        detail: if tiocsti_disabled {
            "TTY TIOCSTI ioctl disabled in kernel and isolated via bwrap --new-session".to_owned()
        } else {
            "legacy_tiocsti=1 on host; mitigated via bwrap --new-session setsid() isolation"
                .to_owned()
        },
    });

    checks.extend(crate::microvm::microvm_doctor_checks(find_binary_on_path));

    let healthy = checks.iter().filter(|c| c.required).all(|c| c.passed);
    let platform_summary = format!(
        "{}-{} (rust-cordon v{})",
        std::env::consts::OS,
        std::env::consts::ARCH,
        env!("CARGO_PKG_VERSION")
    );

    DoctorReport {
        healthy,
        platform_summary,
        checks,
    }
}
