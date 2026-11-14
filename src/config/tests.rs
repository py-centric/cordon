use std::collections::BTreeMap;

use super::*;
use crate::domain::{IsolationBackend, VmDiskMode};
use crate::error::CordonError;

#[test]
fn mask_dir_directive_and_toml_key_round_trip() {
    let cf =
        "FROM ai-agent\nNAME mask-test\nWORKDIR .\nMASK_DIR /opt/masked ~/.ssh\nCMD [\"true\"]\n";
    let cfg = CordonEnvironmentConfig::from_cordonfile_str(cf).unwrap_or_default();
    assert_eq!(cfg.masked_dirs.len(), 2);
    assert!(cfg.masked_dirs.contains(&"/opt/masked".to_owned()));

    let toml = "[security]\nmasked_dirs = [\"/opt/masked\", \"/var/lib/x\"]\n";
    let cfg_toml = CordonEnvironmentConfig::from_toml_str(toml).unwrap_or_default();
    assert!(cfg_toml.masked_dirs.contains(&"/opt/masked".to_owned()));
    assert!(cfg_toml.masked_dirs.contains(&"/var/lib/x".to_owned()));

    let rendered = cfg.to_cordonfile_string();
    assert!(rendered.contains("MASK_DIR \"/opt/masked\""));
    let rendered_toml = cfg.to_toml_string();
    assert!(rendered_toml.contains("masked_dirs = ["));
    assert!(
        CordonEnvironmentConfig::from_toml_str(&rendered_toml)
            .is_ok_and(|c| c.masked_dirs.len() == 2)
    );
}

#[test]
fn reserved_env_keys_are_rejected_by_default() {
    for key in RESERVED_ENV_KEYS {
        let mut cfg = CordonEnvironmentConfig {
            command: vec!["true".to_owned()],
            ..Default::default()
        };
        cfg.env.insert((*key).to_owned(), "evil".to_owned());
        let result = cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new());
        match result {
            Err(CordonError::InvalidInput(msg)) => {
                assert!(msg.contains(key), "message must name the key: {msg}");
            }
            other => panic!("expected InvalidInput for {key}, got {:?}", other.err()),
        }

        // CLI-supplied env follows the same policy.
        let mut cli_env = BTreeMap::new();
        cli_env.insert((*key).to_owned(), "evil".to_owned());
        let cli_result = CordonEnvironmentConfig::default().compile_plan(
            None,
            &["true".to_owned()],
            &[],
            &[],
            &[],
            &cli_env,
        );
        assert!(matches!(cli_result, Err(CordonError::InvalidInput(_))));
    }
}

#[test]
fn reserved_env_allowed_with_explicit_override() {
    let mut cfg = CordonEnvironmentConfig {
        command: vec!["true".to_owned()],
        ..Default::default()
    };
    cfg.env
        .insert("SSL_CERT_FILE".to_owned(), "/tmp/evil.pem".to_owned());
    let empty_env = BTreeMap::new();
    let result = cfg.compile_plan_with_policy(&PlanCompileOptions {
        workspace_override: None,
        cli_command_override: &[],
        readonly_mounts: &[],
        writable_mounts: &[],
        extra_masked_bins: &[],
        extra_env: &empty_env,
        allow_reserved_env: true,
    });
    assert!(result.is_ok());
}

#[test]
fn benign_env_keys_pass_the_reserved_filter() {
    let mut cfg = CordonEnvironmentConfig {
        command: vec!["true".to_owned()],
        ..Default::default()
    };
    cfg.env
        .insert("OPENCODE_SANDBOX".to_owned(), "cordon".to_owned());
    let result = cfg.compile_plan(None, &[], &[], &[], &[], &BTreeMap::new());
    assert!(result.is_ok());
}

#[test]
fn reserved_env_key_set_matches_canonical_list() {
    let expected = [
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
        "DENO_CERT",
        "RUSTLS_NATIVE_CERTS",
        "CARGO_HTTP_CAINFO",
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "BASH_ENV",
        "ENV",
        "PERL5OPT",
        "PERL5LIB",
        "GIT_SSH_COMMAND",
        "GIT_EXEC_PATH",
    ];
    let mut sorted_const = RESERVED_ENV_KEYS.to_vec();
    sorted_const.sort_unstable();
    let mut sorted_expected = expected.to_vec();
    sorted_expected.sort_unstable();
    assert_eq!(sorted_const, sorted_expected);
}

const VM_TOML: &str = r#"
[sandbox]
name = "fc-audit"
base_profile = "untrusted-code"

[vm]
backend = "firecracker"   # sealed block VM
vcpus = 2
memory_mib = 1024
disk_mode = "ephemeral-tmpfs"
kernel_image = "/var/lib/cordon/kernels/vmlinux-microvm"
rootfs_image = "/var/lib/cordon/images/alpine-audit.erofs"

[vm.rate_limits]
disk_iops = 5000
disk_bandwidth_mib_s = 250
net_bandwidth_mbit_s = 100
"#;

const VM_CORDONFILE: &str = r#"FROM untrusted-code
VM_BACKEND firecracker
VM_RESOURCES vcpus=2 memory_mib=1024 disk_mode=ephemeral-tmpfs
VM_KERNEL /var/lib/cordon/kernels/vmlinux-microvm
VM_ROOTFS /var/lib/cordon/images/alpine-audit.erofs
VM_RATE_LIMIT disk_iops=5000 disk_mib_s=250 net_mbit_s=100
CMD ["python3", "-I", "analyze.py"]
"#;

#[test]
fn vm_toml_and_cordonfile_parse_to_the_same_spec() {
    let Ok(toml) = CordonEnvironmentConfig::from_toml_str(VM_TOML) else {
        panic!("vm TOML must parse");
    };
    let Ok(cordonfile) = CordonEnvironmentConfig::from_cordonfile_str(VM_CORDONFILE) else {
        panic!("vm Cordonfile must parse");
    };
    assert_eq!(toml.vm, cordonfile.vm);
    let Some(ref vm) = toml.vm else {
        panic!("vm section missing");
    };
    assert_eq!(vm.backend, IsolationBackend::Firecracker);
    assert_eq!(vm.vcpus, Some(2));
    assert_eq!(
        vm.rate_limits
            .and_then(|l| l.net_bandwidth_mbit_s)
            .map(std::num::NonZeroU32::get),
        Some(100)
    );
    let spec = toml.microvm_spec();
    assert!(spec.is_ok_and(|s| s.is_some_and(|s| s.disk_mode() == VmDiskMode::EphemeralTmpfs)));
}

#[test]
fn vm_settings_round_trip_through_both_serializers() {
    let Ok(cfg) = CordonEnvironmentConfig::from_toml_str(VM_TOML) else {
        panic!("vm TOML must parse");
    };
    let toml_again = CordonEnvironmentConfig::from_toml_str(&cfg.to_toml_string());
    assert!(toml_again.is_ok_and(|c| c.vm == cfg.vm));
    let cf_again = CordonEnvironmentConfig::from_cordonfile_str(&cfg.to_cordonfile_string());
    assert!(cf_again.is_ok_and(|c| c.vm == cfg.vm));
    let json_again =
        CordonEnvironmentConfig::from_json_str(&serde_json::to_string(&cfg).unwrap_or_default());
    assert!(json_again.is_ok_and(|c| c.vm == cfg.vm));
}

#[test]
fn configs_without_vm_serialize_unchanged() {
    let cfg = CordonEnvironmentConfig::default();
    assert!(!cfg.to_toml_string().contains("[vm]"));
    assert!(!cfg.to_cordonfile_string().contains("VM_"));
    let json = serde_json::to_value(&cfg).unwrap_or_default();
    assert!(json.get("vm").is_none());
    assert!(cfg.microvm_spec().is_ok_and(|s| s.is_none()));
}

#[test]
fn invalid_vm_settings_are_rejected() {
    for bad in [
        "[vm]\nbackend = \"vmware\"\n",
        "[vm]\nvsock_cid = 3\n",
        "[vm]\nvcpus = many\n",
        "[vm.rate_limits]\ndisk_iops = 0\n",
        "[vm.rate_limits]\nnet_bandwidth_mbps = 10\n",
    ] {
        assert!(
            CordonEnvironmentConfig::from_toml_str(bad).is_err(),
            "{bad}"
        );
    }
    for bad in [
        "VM_RESOURCES vcpus\n",
        "VM_RESOURCES kernel_image=/boot/vmlinuz\n",
        "VM_RATE_LIMIT net_mbps=10\n",
        "VM_BACKEND hyperv\n",
    ] {
        assert!(
            CordonEnvironmentConfig::from_cordonfile_str(bad).is_err(),
            "{bad}"
        );
    }
    let incompatible = "VM_BACKEND firecracker\nVM_RESOURCES disk_mode=virtio-fs-live\nVM_KERNEL /var/lib/cordon/kernels/vmlinux\n";
    let Ok(cfg) = CordonEnvironmentConfig::from_cordonfile_str(incompatible) else {
        panic!("syntax is valid");
    };
    assert!(matches!(
        cfg.microvm_spec(),
        Err(CordonError::IncompatibleVmDiskMode { .. })
    ));
}

#[test]
fn native_bwrap_backend_means_no_microvm() {
    let Ok(cfg) = CordonEnvironmentConfig::from_toml_str("[vm]\nbackend = \"native-bwrap\"\n")
    else {
        panic!("native-bwrap TOML must parse");
    };
    assert!(cfg.microvm_spec().is_ok_and(|s| s.is_none()));
}

#[test]
fn compile_plan_cross_validates_vm_against_profile() {
    let src = "FROM ai-agent\nNET_MODE direct\nVM_BACKEND qemu-microvm\nVM_KERNEL /var/lib/cordon/kernels/vmlinux\nCMD [\"true\"]\n";
    let Ok(cfg) = CordonEnvironmentConfig::from_cordonfile_str(src) else {
        panic!("syntax is valid");
    };
    let ws = std::env::temp_dir();
    let result = cfg.compile_plan(Some(&ws), &[], &[], &[], &[], &BTreeMap::new());
    assert!(matches!(result, Err(CordonError::UnsupportedVmOption(_))));
}
