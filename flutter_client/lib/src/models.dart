/// Typed models for the Cordon control plane JSON contract
/// (`src/api.rs`, `src/domain.rs`).
///
/// Deserialization is hand-written (no `build_runner` / `json_serializable`
/// churn) and tolerant of missing fields so a server-side additive change can
/// never crash the companion UI.
library;

/// Policy verdict wire values emitted by the L7 policy engine.
enum PolicyVerdict {
  allow('ALLOW'),
  block('BLOCK'),
  audit('AUDIT');

  const PolicyVerdict(this.wire);

  /// Wire value as serialized by the Rust control plane.
  final String wire;

  /// Parses a wire value, falling back to [PolicyVerdict.audit] for unknowns.
  static PolicyVerdict parse(String? raw) => values.firstWhere(
        (value) => value.wire == raw?.trim().toUpperCase(),
        orElse: () => PolicyVerdict.audit,
      );
}

/// Severity tier of a telemetry audit event.
enum EventSeverity {
  info('INFO'),
  warning('WARNING'),
  critical('CRITICAL');

  const EventSeverity(this.wire);

  /// Wire value as serialized by the Rust control plane.
  final String wire;

  /// Parses a wire value, falling back to [EventSeverity.info] for unknowns.
  static EventSeverity parse(String? raw) => values.firstWhere(
        (value) => value.wire == raw?.trim().toUpperCase(),
        orElse: () => EventSeverity.info,
      );
}

/// Enforcement plane that generated a telemetry event.
enum EnforcementPlane {
  bwrap('bwrap'),
  apparmor('apparmor'),
  netns('netns'),
  microvm('microvm'),
  mitmproxy('mitmproxy'),
  tshark('tshark');

  const EnforcementPlane(this.wire);

  /// Wire value as serialized by the Rust control plane.
  final String wire;

  /// Parses a wire value, falling back to [EnforcementPlane.bwrap] for unknowns.
  static EnforcementPlane parse(String? raw) => values.firstWhere(
        (value) => value.wire == raw?.trim().toLowerCase(),
        orElse: () => EnforcementPlane.bwrap,
      );
}

/// Gate 3.5 hardware / process isolation backend (`IsolationBackend`).
enum IsolationBackend {
  nativeBwrap('native-bwrap'),
  qemuMicrovm('qemu-microvm'),
  firecracker('firecracker'),
  krun('krun');

  const IsolationBackend(this.wire);

  final String wire;

  static IsolationBackend parse(String? raw) => values.firstWhere(
        (value) => value.wire == raw?.trim().toLowerCase(),
        orElse: () => IsolationBackend.nativeBwrap,
      );
}

/// Gate 3.5 guest rootfs and workspace persistence mode (`VmDiskMode`).
enum VmDiskMode {
  virtioFsLive('virtio-fs-live'),
  ephemeralTmpfs('ephemeral-tmpfs'),
  btrfsCowOverlay('btrfs-cow-overlay'),
  snapshotRestore('snapshot-restore');

  const VmDiskMode(this.wire);

  final String wire;

  static VmDiskMode parse(String? raw) => values.firstWhere(
        (value) => value.wire == raw?.trim().toLowerCase(),
        orElse: () => VmDiskMode.virtioFsLive,
      );
}

/// Gate 3.5 MicroVM configuration (`MicroVmSpec`).
class MicroVmSpec {
  const MicroVmSpec({
    required this.backend,
    required this.vcpus,
    required this.memoryMib,
    required this.diskMode,
    this.kernelImage,
    this.rootfsImage,
    this.snapshot,
  });

  final IsolationBackend backend;
  final int vcpus;
  final int memoryMib;
  final VmDiskMode diskMode;
  final String? kernelImage;
  final String? rootfsImage;
  final String? snapshot;

  factory MicroVmSpec.fromJson(Map<String, dynamic> json) => MicroVmSpec(
        backend: IsolationBackend.parse(_string(json, 'backend')),
        vcpus: _int(json, 'vcpus', 2),
        memoryMib: _int(json, 'memory_mib', 512),
        diskMode: VmDiskMode.parse(_string(json, 'disk_mode')),
        kernelImage: json['kernel_image'] as String?,
        rootfsImage: json['rootfs_image'] as String?,
        snapshot: json['snapshot'] as String?,
      );
}

String _string(Map<String, dynamic> json, String key, [String fallback = '']) {
  final value = json[key];
  return value is String ? value : fallback;
}

int _int(Map<String, dynamic> json, String key, [int fallback = 0]) {
  final value = json[key];
  return value is num ? value.toInt() : fallback;
}

bool _bool(Map<String, dynamic> json, String key, [bool fallback = false]) {
  final value = json[key];
  return value is bool ? value : fallback;
}

List<String> _stringList(Map<String, dynamic> json, String key) {
  final value = json[key];
  if (value is List) {
    return value.whereType<String>().toList(growable: false);
  }
  return const [];
}

Map<String, String> _stringMap(Map<String, dynamic> json, String key) {
  final value = json[key];
  if (value is Map) {
    return value.map((k, v) => MapEntry(k.toString(), v.toString()));
  }
  return const {};
}

/// Health status payload (`GET /healthz`, `GET /api/v1/health`).
class HealthResponse {
  const HealthResponse({
    required this.status,
    required this.service,
    required this.version,
    required this.governingAdr,
    required this.profilesCount,
    required this.bufferedEvents,
  });

  final String status;
  final String service;
  final String version;
  final String governingAdr;
  final int profilesCount;
  final int bufferedEvents;

  factory HealthResponse.fromJson(Map<String, dynamic> json) => HealthResponse(
        status: _string(json, 'status', 'unknown'),
        service: _string(json, 'service'),
        version: _string(json, 'version'),
        governingAdr: _string(json, 'governing_adr'),
        profilesCount: _int(json, 'profiles_count'),
        bufferedEvents: _int(json, 'buffered_events'),
      );
}

/// Immutable sandbox and network policy profile (`CordonProfile`).
class CordonProfile {
  const CordonProfile({
    required this.name,
    required this.kind,
    required this.description,
    required this.filesystemMode,
    required this.networkMode,
    required this.netnsName,
    required this.subnetCidr,
    required this.mitmPort,
    required this.allowedDomains,
    required this.postAllowedHosts,
    required this.deniedDomains,
    required this.protectGitDir,
    required this.blockDoh,
    required this.inspectBodySecrets,
    required this.unsharePid,
    required this.unshareIpc,
    this.microvm,
  });

  final String name;
  final String kind;
  final String description;
  final String filesystemMode;
  final String networkMode;
  final String netnsName;
  final String subnetCidr;
  final int mitmPort;
  final List<String> allowedDomains;
  final List<String> postAllowedHosts;
  final List<String> deniedDomains;
  final bool protectGitDir;
  final bool blockDoh;
  final bool inspectBodySecrets;
  final bool unsharePid;
  final bool unshareIpc;
  final MicroVmSpec? microvm;

  factory CordonProfile.fromJson(Map<String, dynamic> json) {
    final vmRaw = json['microvm'];
    return CordonProfile(
      name: _string(json, 'name'),
      kind: _string(json, 'kind'),
      description: _string(json, 'description'),
      filesystemMode: _string(json, 'filesystem_mode'),
      networkMode: _string(json, 'network_mode'),
      netnsName: _string(json, 'netns_name'),
      subnetCidr: _string(json, 'subnet_cidr'),
      mitmPort: _int(json, 'mitm_port'),
      allowedDomains: _stringList(json, 'allowed_domains'),
      postAllowedHosts: _stringList(json, 'post_allowed_hosts'),
      deniedDomains: _stringList(json, 'denied_domains'),
      protectGitDir: _bool(json, 'protect_git_dir'),
      blockDoh: _bool(json, 'block_doh'),
      inspectBodySecrets: _bool(json, 'inspect_body_secrets'),
      unsharePid: _bool(json, 'unshare_pid'),
      unshareIpc: _bool(json, 'unshare_ipc'),
      microvm: vmRaw is Map<String, dynamic>
          ? MicroVmSpec.fromJson(vmRaw)
          : null,
    );
  }
}

/// Layer 7 policy verdict (`PolicyDecision`).
class PolicyDecision {
  const PolicyDecision({
    required this.verdict,
    required this.statusCode,
    required this.reason,
    required this.matchedRule,
    required this.url,
    required this.method,
    required this.evaluationLatencyUs,
    this.secretFingerprint,
  });

  final PolicyVerdict verdict;
  final int statusCode;
  final String reason;
  final String matchedRule;
  final String url;
  final String method;
  final int evaluationLatencyUs;
  final String? secretFingerprint;

  factory PolicyDecision.fromJson(Map<String, dynamic> json) => PolicyDecision(
        verdict: PolicyVerdict.parse(_string(json, 'verdict')),
        statusCode: _int(json, 'status_code'),
        reason: _string(json, 'reason'),
        matchedRule: _string(json, 'matched_rule'),
        url: _string(json, 'url'),
        method: _string(json, 'method'),
        evaluationLatencyUs: _int(json, 'evaluation_latency_us'),
        secretFingerprint: json['secret_fingerprint'] as String?,
      );
}

/// Structured telemetry event (`AuditEvent`).
class AuditEvent {
  const AuditEvent({
    required this.eventId,
    required this.timestamp,
    required this.plane,
    required this.severity,
    required this.verdict,
    required this.profile,
    required this.subject,
    required this.details,
  });

  final String eventId;
  final String timestamp;
  final EnforcementPlane plane;
  final EventSeverity severity;
  final PolicyVerdict verdict;
  final String profile;
  final String subject;
  final Map<String, String> details;

  factory AuditEvent.fromJson(Map<String, dynamic> json) => AuditEvent(
        eventId: _string(json, 'event_id'),
        timestamp: _string(json, 'timestamp'),
        plane: EnforcementPlane.parse(_string(json, 'plane')),
        severity: EventSeverity.parse(_string(json, 'severity')),
        verdict: PolicyVerdict.parse(_string(json, 'verdict')),
        profile: _string(json, 'profile'),
        subject: _string(json, 'subject'),
        details: _stringMap(json, 'details'),
      );
}

/// Deterministic 5-gate / 6-gate execution plan (`SandboxLaunchPlan`).
class SandboxLaunchPlan {
  const SandboxLaunchPlan({
    required this.profileName,
    required this.workloadKind,
    required this.canonicalWorkspace,
    required this.fullArgv,
    required this.maskedBinaries,
    required this.envOverrides,
    required this.gatesApplied,
    required this.networkMode,
    required this.filesystemMode,
    this.isolationBackend = IsolationBackend.nativeBwrap,
  });

  final String profileName;
  final String workloadKind;
  final String canonicalWorkspace;
  final List<String> fullArgv;
  final List<String> maskedBinaries;
  final Map<String, String> envOverrides;
  final List<String> gatesApplied;
  final String networkMode;
  final String filesystemMode;
  final IsolationBackend isolationBackend;

  factory SandboxLaunchPlan.fromJson(Map<String, dynamic> json) =>
      SandboxLaunchPlan(
        profileName: _string(json, 'profile_name'),
        workloadKind: _string(json, 'workload_kind'),
        canonicalWorkspace: _string(json, 'canonical_workspace'),
        fullArgv: _stringList(json, 'full_argv'),
        maskedBinaries: _stringList(json, 'masked_binaries'),
        envOverrides: _stringMap(json, 'env_overrides'),
        gatesApplied: _stringList(json, 'gates_applied'),
        networkMode: _string(json, 'network_mode'),
        filesystemMode: _string(json, 'filesystem_mode'),
        isolationBackend: IsolationBackend.parse(
          json['isolation_backend'] as String?,
        ),
      );
}
