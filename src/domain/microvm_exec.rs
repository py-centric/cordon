//! Gate 3.5 MicroVM execution plan, tap slot, and guest envelope types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::microvm::{IsolationBackend, VmDiskMode};
use super::microvm_plan::MicroVmSpec;
use super::{CanonicalPath, NetworkMode};
use crate::error::CordonError;

/// One slot of the per-netns MicroVM tap pool (`tcvm<n>`, one `/30` per slot inside
/// `10.200.255.0/24`). The veth pair keeps `10.200.1.0/24`; guest traffic is masqueraded to the
/// sandbox veth address inside the netns so host-side Gate 4/5 rules apply unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TapSlot(u8);

impl TapSlot {
    /// Maximum tap pool size (slots `0..16` fit in `10.200.255.0/26`).
    pub const MAX_POOL: u8 = 16;
    /// Default tap pool size provisioned by the netns setup.
    pub const DEFAULT_POOL: u8 = 4;
    /// Supernet carved into per-slot `/30` links.
    pub const SUPERNET: &'static str = "10.200.255.0/24";

    /// Validates a slot index (`0..MAX_POOL`).
    pub fn new(index: u8) -> Result<Self, CordonError> {
        if index < Self::MAX_POOL {
            Ok(Self(index))
        } else {
            Err(CordonError::InvalidNetworkConfig(format!(
                "tap slot {index} out of range (0..{})",
                Self::MAX_POOL
            )))
        }
    }

    /// Slot index.
    #[must_use]
    pub const fn index(self) -> u8 {
        self.0
    }

    /// Tap device name (`tcvm<n>`).
    #[must_use]
    pub fn device(self) -> String {
        format!("tcvm{}", self.0)
    }

    /// Netns-side gateway address (`10.200.255.(4n+1)`).
    #[must_use]
    pub fn gateway(self) -> String {
        format!("10.200.255.{}", u16::from(self.0) * 4 + 1)
    }

    /// Guest address (`10.200.255.(4n+2)`).
    #[must_use]
    pub fn guest_addr(self) -> String {
        format!("10.200.255.{}", u16::from(self.0) * 4 + 2)
    }

    /// Guest address in CIDR form (`10.200.255.(4n+2)/30`).
    #[must_use]
    pub fn guest_cidr(self) -> String {
        format!("{}/30", self.guest_addr())
    }
}

/// Guest NIC configuration delivered in the [`GuestExecEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestNetConfig {
    /// Guest address in CIDR form.
    pub addr: String,
    /// Default gateway (netns side of the tap).
    pub gw: String,
    /// Resolver address (host veth; the host DNS DNAT applies regardless of destination).
    pub dns: String,
}

/// Versioned command envelope sent to `cordon-guest-init` over the control channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestExecEnvelope {
    /// Protocol version.
    pub v: u8,
    /// Command vector executed in the guest.
    pub argv: Vec<String>,
    /// Working directory in the guest.
    pub cwd: String,
    /// Environment for the guest command (CA overlay keys included under L7 inspection).
    pub env: BTreeMap<String, String>,
    /// Guest NIC configuration (`None` = loopback only, fail-closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net: Option<GuestNetConfig>,
    /// Sandbox-side CA bundle path the supervisor reads and forwards for block-device guests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_bundle_from: Option<String>,
    /// Run the command on the guest console as a TTY.
    pub tty: bool,
    /// Guest uid (filled at launch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Guest gid (filled at launch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,
    /// Base64 host entropy for guest RNG reseeding (filled at launch; mandatory on restore).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy_b64: Option<String>,
}

impl GuestExecEnvelope {
    /// Current protocol version.
    pub const VERSION: u8 = 1;
    /// Maximum encoded frame size in bytes.
    pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
}

/// One Firecracker API request issued over the VMM's Unix API socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirecrackerApiCall {
    /// HTTP method (`PUT` / `PATCH`).
    pub method: String,
    /// Request path (`/machine-config`, `/drives/rootfs`, ...).
    pub path: String,
    /// JSON request body.
    pub body: serde_json::Value,
}

/// Compiled, deterministic Gate 3.5 execution plan, run *inside* the Gate 1-3 launch plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroVmExecutionPlan {
    /// Isolation backend.
    pub backend: IsolationBackend,
    /// Disk mode.
    pub disk_mode: VmDiskMode,
    /// Validated spec this plan was compiled from.
    pub spec: MicroVmSpec,
    /// Per-run identifier used for run-scoped host files (overlay clones).
    pub run_id: String,
    /// Tap slot used by the guest NIC (`None` = no NIC, loopback-only guest).
    pub tap_slot: Option<TapSlot>,
    /// virtiofsd argv (virtio-fs-live only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtiofsd_argv: Option<Vec<String>>,
    /// VMM argv (`qemu-system-x86_64 ...` or `firecracker --api-sock ...`).
    pub vmm_argv: Vec<String>,
    /// Ordered Firecracker API calls (empty for QEMU).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub firecracker_api: Vec<FirecrackerApiCall>,
    /// Host device nodes bound into the Gate 3 mount namespace.
    pub device_binds: Vec<String>,
    /// Control channel socket path inside the Gate 3 namespace.
    pub control_socket: String,
    /// Command envelope delivered to `cordon-guest-init`.
    pub envelope: GuestExecEnvelope,
}

/// Inputs for compiling one MicroVM plan (everything except the validated spec).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmCompileContext {
    /// Canonical workspace (guest working directory).
    pub workspace: CanonicalPath,
    /// Guest command vector.
    pub command: Vec<String>,
    /// Environment from the Gate 3 plan (CA overlay and config env).
    pub env: BTreeMap<String, String>,
    /// Effective network mode.
    pub network_mode: NetworkMode,
    /// Guest resolver (host veth address).
    pub dns: String,
    /// Tap slot for the guest NIC (`None` = loopback-only guest).
    pub tap_slot: Option<TapSlot>,
    /// Run identifier for run-scoped files.
    pub run_id: String,
    /// Attach the guest command to the console as a TTY.
    pub tty: bool,
}
