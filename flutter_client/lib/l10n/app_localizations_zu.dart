// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Zulu (`zu`).
class AppLocalizationsZu extends AppLocalizations {
  AppLocalizationsZu([String locale = 'zu']) : super(locale);

  @override
  String get appTitle => 'Isistimu Yokulawula ye-Cordon';

  @override
  String get appSubtitle =>
      'I-Sandbox Ye-Kernel Yamasango Ayi-5 & Ukuhlolwa Kwenethiwekhi L3-L7';

  @override
  String get navProfiles => 'Ama-Profile';

  @override
  String get navGates => 'Umgudu Wamasango Ayi-5';

  @override
  String get navSimulator => 'Umsimuli We-L7';

  @override
  String get navConfig => 'Ukubuka Kwekhonfig';

  @override
  String get navTelemetry => 'Ukugeleza Kwe-Audit';

  @override
  String get themeLight => 'Ukukhanya';

  @override
  String get themeDark => 'Kumnyama';

  @override
  String get themeHighContrast => 'Umehluko Omkhulu (7:1)';

  @override
  String get semanticLocaleToggle => 'Shintsha ulimi lomsebenzisi';

  @override
  String get settingsLabel => 'Izilungiselelo zokubonisa';

  @override
  String get healthChecking => 'Ihlola isistimu yokulawula...';

  @override
  String healthOnline(String version) {
    return 'Isistimu yokulawula iyatholakala (v$version)';
  }

  @override
  String get healthOffline => 'Isistimu yokulawula ayifinyeleleki';

  @override
  String get loadingLabel => 'Iyalayisha';

  @override
  String get retryLabel => 'Zama futhi';

  @override
  String get errorTitle => 'Isicelo sehlulekile';

  @override
  String connectionErrorMessage(String baseUrl) {
    return 'Ayikwazi ukufinyelela isistimu yokulawula ye-Cordon ku-$baseUrl.';
  }

  @override
  String get timeoutErrorMessage =>
      'Isicelo siphelelwe isikhathi. Ingabe isistimu yokulawula ibhizi?';

  @override
  String serverErrorMessage(int status, String message) {
    return 'HTTP $status: $message';
  }

  @override
  String get unexpectedErrorMessage =>
      'Impendulo engalindelekile ivela esistimini yokulawula.';

  @override
  String get profilesTitle => 'Ama-Profile E-Sandbox';

  @override
  String get profilesEmpty =>
      'Awekho ama-profile e-sandbox abhalisiwe kulesi sistimu yokulawula.';

  @override
  String profileCardLabel(String slug) {
    return 'I-profile ye-sandbox $slug';
  }

  @override
  String profileMeta(String fsMode, String netMode, String gitProtected) {
    return 'FS: $fsMode | NET: $netMode | .git RO: $gitProtected';
  }

  @override
  String get profileUseInSimulator => 'Simula';

  @override
  String profileUseInSimulatorSemantics(String slug) {
    return 'Sebenzisa i-profile $slug ku-L7 Simulator';
  }

  @override
  String get gatesTitle => 'Umgudu Wamasango Ayi-5';

  @override
  String gateLabel(int number) {
    return 'Isango $number';
  }

  @override
  String get gate1Title => 'Isango 1: Inethiwekhi Ye-Netns & iptables';

  @override
  String get gate1Body =>
      'Ukusetshenziswa okuqinile kwe-ip netns + iptables: i-agent-net 10.200.1.2/24 ne-route_localnet=1, TCP 80/443 REDIRECT ku-:8080, UDP 443 QUIC REJECT, ne- FORWARD DROP uma kunephutha.';

  @override
  String get gate2Title => 'Isango 2: AppArmor 4.0 MAC';

  @override
  String get gate2Body =>
      'Ukulawulwa Kwenqubomgomo Okuphoqelelwe (abi <abi/4.0>) okwenqabela amandla e-sys_admin, net_admin, ne-sys_ptrace, kuvimba ukusebenza kwe-/tmp, futhi kuvikele ~/.ssh, ~/.aws, ne-~/.gnupg.';

  @override
  String get gate3Title => 'Isango 3: Bubblewrap VFS';

  @override
  String get gate3Body =>
      'Ama-namespace e-mount, pid, ne-ipc angenalo amalungelo (--ro-bind / /) afihla ama-binary ayi-20 abulalayo nge-/dev/null, enqabela i-/ noma HOME mounts zokufunda nokubhala, futhi ibophe i-.git ngokufunda-kuphela (EC-01).';

  @override
  String get gate4Title => 'Isango 4: Umgudu 7 we-mitmproxy';

  @override
  String get gate4Body =>
      'Ukwenqabela okuzenzakalelayo kwedomain allowlist, i-DoH block, isivimbelo se-FR-5.4 se-HTTP mutating verb (i-POST ivinjelwe kuma-registry amaphakethe), ne-9-pattern secret exfiltration scanner.';

  @override
  String get gate5Title => 'Isango 5: I-tshark PCAP Ring Buffer';

  @override
  String get gate5Body =>
      'Ukubamba amaphakethe e-L3/L4 ajikelezayo e-1 GB elinganisiwe ehlanganiswe nama-JSONL audit logs ahlelekile ne-Prometheus telemetry.';

  @override
  String get simulatorTitle => 'Umsimuli Wenqubomgomo Ye-L7';

  @override
  String get simProfileLabel => 'I-Profile';

  @override
  String get simProfileEmpty =>
      'Awekho ama-profile atholakala kulesi sistimu yokulawula.';

  @override
  String get simUrlLabel => 'I-URL Yenhloso';

  @override
  String get simUrlRequired => 'I-URL yenhloso iyadingeka';

  @override
  String get simMethodLabel => 'Indlela Ye-HTTP';

  @override
  String get simBodyLabel => 'Umzimba Wesicelo (ngokuzithandela)';

  @override
  String get simBodyHint =>
      'I-payload iskenwa ukuze kutholakale izimfihlo ezivuzayo';

  @override
  String get evaluateFlowButton => 'Hlola Ukugeleza Kwe-L7';

  @override
  String get presetAllowLlm => 'Okuhleliwe: LLM POST Evunyelwe';

  @override
  String get presetBlockDoh => 'Okuhleliwe: Vimba Ukweqa Kwe-DoH';

  @override
  String get presetBlockPyPiPost => 'Okuhleliwe: Vimba I-PyPI POST';

  @override
  String get presetBlockSecret => 'Okuhleliwe: Vimba Ukuvuza Kwezimfihlo';

  @override
  String get simIdlePrompt =>
      'Hlela ukugeleza, bese ucindezela Hlola Ukugeleza Kwe-L7 ukubuza injini yezinqubomgomo ephilayo.';

  @override
  String simRequestSummary(String method, String url) {
    return '$method $url';
  }

  @override
  String get simVerdictLabel => 'Isinqumo';

  @override
  String simVerdictSummary(String verdict, int status, String rule) {
    return '$verdict ($status) | Umthetho: $rule';
  }

  @override
  String get simReasonLabel => 'Isizathu';

  @override
  String simLatencyLabel(int micros) {
    return 'Ukubambezeleka kokuhlola: $micros us';
  }

  @override
  String get configTitle => 'Ukubuka Kwe-Plan Yokusebenza';

  @override
  String get configContentLabel => 'Okuqukethwe Kwe-Cordonfile';

  @override
  String get configContentRequired => 'Okuqukethwe kwe-Cordonfile kuyadingeka';

  @override
  String get configFormatLabel => 'Ifomethi';

  @override
  String get compileButton => 'Buka I-Plan Yokusebenza';

  @override
  String get configIdlePrompt =>
      'Namathisela i-Cordonfile, i-Cordonfile.toml, noma i-cordon.json, bese ubuka i-plan yayo ye-sandbox yamasango ayi-5.';

  @override
  String get planProfileLabel => 'I-Profile';

  @override
  String get planWorkspaceLabel => 'Indawo Yokusebenza';

  @override
  String get planGatesLabel => 'Amasango Asetshenzisiwe';

  @override
  String get planCommandLabel => 'Umyalo';

  @override
  String get formatCordonfile => 'Cordonfile';

  @override
  String get formatToml => 'Cordonfile.toml';

  @override
  String get formatJson => 'cordon.json';

  @override
  String get eventsTitle => 'Ukugeleza Kwe-Audit';

  @override
  String get eventsRefresh => 'Buyekeza';

  @override
  String get eventsEmpty =>
      'Ayikho i-audit event irekhodiwe okwamanje. Hlola ukugeleza kwe-L7 ukwenza i-telemetry.';

  @override
  String eventCardLabel(String subject) {
    return 'I-audit event: $subject';
  }

  @override
  String eventMeta(String plane, String severity, String verdict) {
    return '$plane | $severity | $verdict';
  }

  @override
  String get attributionFooter =>
      'Developed by PyCentric | Cordon Layer 0 Security Engine (ADR-L0-SEC-02) | AGPL-3.0-only | Source: https://github.com/pycentric/cordon';
}
