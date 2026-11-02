// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'Cordon Control Plane';

  @override
  String get appSubtitle => '5-Gate Kernel Sandbox & L3-L7 Network Inspection';

  @override
  String get navProfiles => 'Profiles';

  @override
  String get navGates => '5-Gate Rail';

  @override
  String get navSimulator => 'L7 Simulator';

  @override
  String get navConfig => 'Config Preview';

  @override
  String get navTelemetry => 'Audit Stream';

  @override
  String get themeLight => 'Light';

  @override
  String get themeDark => 'Dark';

  @override
  String get themeHighContrast => 'High Contrast (7:1)';

  @override
  String get semanticLocaleToggle => 'Switch interface language';

  @override
  String get settingsLabel => 'Display settings';

  @override
  String get healthChecking => 'Checking control plane...';

  @override
  String healthOnline(String version) {
    return 'Control plane online (v$version)';
  }

  @override
  String get healthOffline => 'Control plane unreachable';

  @override
  String get loadingLabel => 'Loading';

  @override
  String get retryLabel => 'Retry';

  @override
  String get errorTitle => 'Request failed';

  @override
  String connectionErrorMessage(String baseUrl) {
    return 'Cannot reach the Cordon control plane at $baseUrl.';
  }

  @override
  String get timeoutErrorMessage =>
      'The request timed out. Is the control plane busy?';

  @override
  String serverErrorMessage(int status, String message) {
    return 'HTTP $status: $message';
  }

  @override
  String get unexpectedErrorMessage =>
      'Unexpected response from the control plane.';

  @override
  String get profilesTitle => 'Sandbox Profiles';

  @override
  String get profilesEmpty =>
      'No sandbox profiles are registered on this control plane.';

  @override
  String profileCardLabel(String slug) {
    return 'Sandbox profile $slug';
  }

  @override
  String profileMeta(String fsMode, String netMode, String gitProtected) {
    return 'FS: $fsMode | NET: $netMode | .git RO: $gitProtected';
  }

  @override
  String get profileUseInSimulator => 'Simulate';

  @override
  String profileUseInSimulatorSemantics(String slug) {
    return 'Use profile $slug in the L7 Simulator';
  }

  @override
  String get gatesTitle => '5-Gate Rail';

  @override
  String gateLabel(int number) {
    return 'Gate $number';
  }

  @override
  String get gate1Title => 'Gate 1: Network Namespace & iptables';

  @override
  String get gate1Body =>
      'Dedicated ip netns + iptables enforcement: agent-net 10.200.1.2/24 with route_localnet=1, TCP 80/443 REDIRECT to :8080, UDP 443 QUIC REJECT, and fail-closed FORWARD DROP.';

  @override
  String get gate2Title => 'Gate 2: AppArmor 4.0 MAC';

  @override
  String get gate2Body =>
      'Mandatory Access Control (abi <abi/4.0>) denying capability sys_admin, net_admin, and sys_ptrace, blocking /tmp execution, and protecting ~/.ssh, ~/.aws, and ~/.gnupg.';

  @override
  String get gate3Title => 'Gate 3: Bubblewrap VFS';

  @override
  String get gate3Body =>
      'Unprivileged mount, pid, and ipc namespaces (--ro-bind / /) masking 20 destructive binaries with /dev/null, refusing / or HOME read-write mounts, and binding .git read-only (EC-01).';

  @override
  String get gate4Title => 'Gate 4: Layer 7 mitmproxy';

  @override
  String get gate4Body =>
      'Default-deny domain allowlist, DoH block, FR-5.4 mutating HTTP verb guard (POST blocked on package registries), and 9-pattern secret exfiltration scanner.';

  @override
  String get gate5Title => 'Gate 5: tshark PCAP Ring Buffer';

  @override
  String get gate5Body =>
      'Bounded 1 GB rotating L3/L4 packet capture paired with structured JSONL audit logs and Prometheus telemetry.';

  @override
  String get simulatorTitle => 'L7 Policy Simulator';

  @override
  String get simProfileLabel => 'Profile';

  @override
  String get simProfileEmpty => 'No profiles available on this control plane.';

  @override
  String get simUrlLabel => 'Target URL';

  @override
  String get simUrlRequired => 'Target URL is required';

  @override
  String get simMethodLabel => 'HTTP Method';

  @override
  String get simBodyLabel => 'Request Body (optional)';

  @override
  String get simBodyHint => 'Payload scanned for leaked credentials';

  @override
  String get evaluateFlowButton => 'Evaluate L7 Flow';

  @override
  String get presetAllowLlm => 'Preset: Allowed LLM POST';

  @override
  String get presetBlockDoh => 'Preset: Block DoH Bypass';

  @override
  String get presetBlockPyPiPost => 'Preset: Block PyPI POST';

  @override
  String get presetBlockSecret => 'Preset: Block Secret Leak';

  @override
  String get simIdlePrompt =>
      'Configure a flow, then press Evaluate L7 Flow to query the live policy engine.';

  @override
  String simRequestSummary(String method, String url) {
    return '$method $url';
  }

  @override
  String get simVerdictLabel => 'Verdict';

  @override
  String simVerdictSummary(String verdict, int status, String rule) {
    return '$verdict ($status) | Rule: $rule';
  }

  @override
  String get simReasonLabel => 'Reason';

  @override
  String simLatencyLabel(int micros) {
    return 'Evaluation latency: $micros us';
  }

  @override
  String get configTitle => 'Launch Plan Preview';

  @override
  String get configContentLabel => 'Cordonfile Content';

  @override
  String get configContentRequired => 'Cordonfile content is required';

  @override
  String get configFormatLabel => 'Format';

  @override
  String get compileButton => 'Preview Launch Plan';

  @override
  String get configIdlePrompt =>
      'Paste a Cordonfile, Cordonfile.toml, or cordon.json, then preview its deterministic 5-gate sandbox launch plan.';

  @override
  String get planProfileLabel => 'Profile';

  @override
  String get planWorkspaceLabel => 'Workspace';

  @override
  String get planGatesLabel => 'Gates Applied';

  @override
  String get planCommandLabel => 'Command';

  @override
  String get formatCordonfile => 'Cordonfile';

  @override
  String get formatToml => 'Cordonfile.toml';

  @override
  String get formatJson => 'cordon.json';

  @override
  String get eventsTitle => 'Audit Stream';

  @override
  String get eventsRefresh => 'Refresh';

  @override
  String get eventsEmpty =>
      'No audit events recorded yet. Evaluate an L7 flow to generate telemetry.';

  @override
  String eventCardLabel(String subject) {
    return 'Audit event: $subject';
  }

  @override
  String eventMeta(String plane, String severity, String verdict) {
    return '$plane | $severity | $verdict';
  }

  @override
  String get attributionFooter =>
      'Developed by PyCentric | Cordon Layer 0 Security Engine (ADR-L0-SEC-02) | AGPL-3.0-only | Source: https://github.com/pycentric/cordon';
}
