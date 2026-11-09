"""Gate 3.5 MicroVM contract tests: Python reference stack vs the shared golden fixture.

The same fixture is asserted by the Rust engine in ``tests/cordon_api_and_cli.rs``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cordon.microvm import (
    IsolationBackend,
    MicroVmError,
    RawMicroVmSpec,
    VmDiskMode,
    VmRateLimits,
    firecracker_disk_rate_limiter,
    firecracker_net_rate_limiter,
    tap_slot,
    validate_image_path,
    validate_microvm_spec,
)

GOLDEN = json.loads((Path(__file__).parent / "golden" / "microvm_spec_cases.json").read_text())


def test_wire_names_match_golden() -> None:
    assert [b.value for b in IsolationBackend] == GOLDEN["wire_names"]["backends"]
    assert [m.value for m in VmDiskMode] == GOLDEN["wire_names"]["disk_modes"]


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda c: c["name"])
def test_golden_spec_cases(case: dict) -> None:
    raw = RawMicroVmSpec.model_validate(case["spec"])
    if case["expect"] == "ok":
        assert validate_microvm_spec(raw, home=None) == case["normalized"]
    else:
        with pytest.raises(MicroVmError) as excinfo:
            validate_microvm_spec(raw, home=None)
        assert excinfo.value.variant == case["expect"]


def test_unknown_vm_keys_are_rejected() -> None:
    with pytest.raises(ValueError):
        RawMicroVmSpec.model_validate({"backend": "firecracker", "vsock_cid": 3})


def test_image_allowlist_and_symlinks(tmp_path: Path) -> None:
    home = tmp_path / "home"
    real = tmp_path / "real"
    real.mkdir()
    (home / ".local/share/cordon").mkdir(parents=True)
    (home / ".local/share/cordon/kernels").symlink_to(real)
    (real / "vmlinux").write_bytes(b"k")
    with pytest.raises(MicroVmError, match="symbolic link"):
        validate_image_path(str(home / ".local/share/cordon/kernels/vmlinux"), "kernel", str(home))
    with pytest.raises(MicroVmError, match="allowlisted"):
        validate_image_path("/etc/passwd", "kernel", str(home))
    assert validate_image_path("/boot/vmlinuz-linux", "kernel", None) == "/boot/vmlinuz-linux"


def test_rate_limiter_units_match_rust() -> None:
    limits = VmRateLimits(disk_iops=5000, disk_bandwidth_mib_s=250, net_bandwidth_mbit_s=100)
    assert firecracker_disk_rate_limiter(limits) == {
        "bandwidth": {"size": 250 * 1_048_576, "refill_time": 1000},
        "ops": {"size": 5000, "refill_time": 1000},
    }
    assert firecracker_net_rate_limiter(limits) == {"bandwidth": {"size": 12_500_000, "refill_time": 1000}}
    assert firecracker_disk_rate_limiter(VmRateLimits()) is None


def test_tap_slots_avoid_the_veth_subnet() -> None:
    assert tap_slot(0) == {"device": "tcvm0", "gateway": "10.200.255.1", "guest_cidr": "10.200.255.2/30"}
    assert tap_slot(3)["gateway"] == "10.200.255.13"
    with pytest.raises(MicroVmError):
        tap_slot(16)
