//! Integration tests for Cordon HTTP Control Plane (`axum`), CLI subcommands, Error RFC 7807 mapping, and Hexagonal Ports.

use clap::Parser;
use cordon::api::{CordonControlPlane, build_router};
use cordon::cli::{CordonCli, execute_cli};
use cordon::error::CordonError;
use tokio::net::TcpListener;

mod common;

fn microvm_error_variant(err: &CordonError) -> &'static str {
    match err {
        CordonError::IncompatibleVmDiskMode { .. } => "IncompatibleVmDiskMode",
        CordonError::UnsafeMicroVmImage { .. } => "UnsafeMicroVmImage",
        CordonError::UnsupportedVmOption(_) => "UnsupportedVmOption",
        CordonError::InvalidInput(_) => "InvalidInput",
        _ => "Other",
    }
}

#[test]
fn microvm_golden_spec_contract_cases() {
    use cordon::domain::{MicroVmSpec, RawMicroVmSpec};
    let raw = std::fs::read_to_string("tests/golden/microvm_spec_cases.json").unwrap_or_default();
    let Ok(golden) = serde_json::from_str::<serde_json::Value>(&raw) else {
        panic!("golden fixture must be valid JSON");
    };
    let Some(cases) = golden["cases"].as_array() else {
        panic!("golden fixture must list cases");
    };
    assert!(cases.len() >= 10);
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let expect = case["expect"].as_str().unwrap_or("?");
        let Ok(raw_spec) = serde_json::from_value::<RawMicroVmSpec>(case["spec"].clone()) else {
            panic!("{name}: spec must match the raw wire schema");
        };
        match MicroVmSpec::from_raw_with_home(&raw_spec, None) {
            Ok(spec) => {
                assert_eq!(expect, "ok", "{name}: expected {expect}");
                let normalized = serde_json::to_value(&spec).unwrap_or_default();
                assert_eq!(
                    normalized, case["normalized"],
                    "{name}: normalized form drifted"
                );
            }
            Err(err) => assert_eq!(microvm_error_variant(&err), expect, "{name}: {err}"),
        }
    }
    let backends: Vec<String> = [
        cordon::domain::IsolationBackend::NativeBwrap,
        cordon::domain::IsolationBackend::QemuMicrovm,
        cordon::domain::IsolationBackend::Firecracker,
        cordon::domain::IsolationBackend::Krun,
    ]
    .iter()
    .map(|b| b.as_str().to_owned())
    .collect();
    assert_eq!(
        serde_json::to_value(&backends).unwrap_or_default(),
        golden["wire_names"]["backends"]
    );
}

#[test]
fn microvm_errors_map_to_stable_rfc7807_details() {
    for (err, status) in [
        (
            CordonError::IncompatibleVmDiskMode {
                backend: "firecracker".to_owned(),
                disk_mode: "virtio-fs-live".to_owned(),
            },
            422,
        ),
        (
            CordonError::UnsafeMicroVmImage {
                path: "/home/secret/.ssh/id_ed25519".to_owned(),
                reason: "outside allowlist".to_owned(),
            },
            422,
        ),
        (CordonError::UnsupportedVmOption("x".to_owned()), 422),
        (
            CordonError::MicroVmUnavailable("no /dev/kvm".to_owned()),
            503,
        ),
    ] {
        let problem = err.to_problem_details("/api/v1/compile", "trace-vm");
        assert_eq!(problem.status, status);
        assert!(
            !problem.detail.contains("/home/secret"),
            "no host paths in client detail"
        );
    }
}

#[tokio::test]
async fn microvm_compile_endpoint_returns_plan_or_422() {
    let router = build_router(CordonControlPlane::default());
    let Ok(listener) = TcpListener::bind("127.0.0.1:0").await else {
        panic!("Failed to bind ephemeral port");
    };
    let Ok(addr) = listener.local_addr() else {
        panic!("Failed to read local_addr");
    };
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let post = |body: String| {
        format!(
            "POST /api/v1/compile HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    };

    let ok_body = serde_json::json!({
        "profile": "network-audit",
        "workspace": ".",
        "command": ["./sample"],
        "vm": {
            "backend": "firecracker",
            "kernel_image": "/var/lib/cordon/kernels/vmlinux",
            "rootfs_image": "/var/lib/cordon/images/base.erofs"
        }
    })
    .to_string();
    let ok_resp = common::send_raw(addr, &post(ok_body)).await;
    assert!(ok_resp.contains("200 OK"), "{ok_resp}");
    assert!(ok_resp.contains("\"microvm\""));
    assert!(ok_resp.contains("Gate 3.5: KVM MicroVM (firecracker"));
    assert!(ok_resp.contains("/snapshot/load") || ok_resp.contains("InstanceStart"));

    let native_body = serde_json::json!({
        "profile": "ai-agent", "workspace": ".", "command": ["true"]
    })
    .to_string();
    let native_resp = common::send_raw(addr, &post(native_body)).await;
    assert!(native_resp.contains("200 OK"));
    assert!(
        !native_resp.contains("\"microvm\""),
        "native plans keep their JSON shape"
    );

    let bad_body = serde_json::json!({
        "profile": "ai-agent",
        "workspace": ".",
        "command": ["true"],
        "vm": {
            "backend": "firecracker",
            "disk_mode": "virtio-fs-live",
            "kernel_image": "/var/lib/cordon/kernels/vmlinux"
        }
    })
    .to_string();
    let bad_resp = common::send_raw(addr, &post(bad_body)).await;
    assert!(bad_resp.contains("422"), "{bad_resp}");
    assert!(bad_resp.contains("application/problem+json"));
}

#[tokio::test]
async fn microvm_live_run_is_refused_with_unavailable() {
    let ws = std::env::temp_dir();
    let ws_str = ws.to_string_lossy().into_owned();
    let cli = CordonCli::parse_from([
        "cordon",
        "run",
        "-p",
        "untrusted-code",
        "-w",
        &ws_str,
        "--vm-backend",
        "firecracker",
        "--vm-kernel",
        "/var/lib/cordon/kernels/vmlinux",
        "--vm-rootfs",
        "/var/lib/cordon/images/base.erofs",
        "--",
        "true",
    ]);
    let result = execute_cli(cli).await;
    let Err(err) = result else {
        panic!("live MicroVM run must be refused");
    };
    assert!(matches!(
        err.downcast_ref::<CordonError>(),
        Some(CordonError::MicroVmUnavailable(_))
    ));

    let dry = CordonCli::parse_from([
        "cordon",
        "--json",
        "run",
        "--dry-run",
        "-p",
        "untrusted-code",
        "-w",
        &ws_str,
        "--vm-backend",
        "firecracker",
        "--vm-kernel",
        "/var/lib/cordon/kernels/vmlinux",
        "--vm-rootfs",
        "/var/lib/cordon/images/base.erofs",
        "--",
        "true",
    ]);
    assert!(execute_cli(dry).await.is_ok_and(|code| code == 0));
}
