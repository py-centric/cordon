// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for Afrikaans (`af`).
class AppLocalizationsAf extends AppLocalizations {
  AppLocalizationsAf([String locale = 'af']) : super(locale);

  @override
  String get appTitle => 'Cordon Beheerplatform';

  @override
  String get appSubtitle => '5-Hek Kern-Sandput & L3-L7 Netwerk Inspeksie';

  @override
  String get navProfiles => 'Profiele';

  @override
  String get navGates => '5-Hek Argitektuur';

  @override
  String get navSimulator => 'L7 Simulator';

  @override
  String get navConfig => 'Konfigurasie Voorskou';

  @override
  String get navTelemetry => 'Oudit Stroom';

  @override
  String get themeLight => 'Lig';

  @override
  String get themeDark => 'Donker';

  @override
  String get themeHighContrast => 'Hoë Kontras (7:1)';

  @override
  String get semanticLocaleToggle => 'Wissel koppelvlak taal';

  @override
  String get settingsLabel => 'Vertoon instellings';

  @override
  String get healthChecking => 'Kontroleer beheerplatform...';

  @override
  String healthOnline(String version) {
    return 'Beheerplatform aanlyn (v$version)';
  }

  @override
  String get healthOffline => 'Beheerplatform onbereikbaar';

  @override
  String get loadingLabel => 'Laai tans';

  @override
  String get retryLabel => 'Probeer weer';

  @override
  String get errorTitle => 'Versoek het misluk';

  @override
  String connectionErrorMessage(String baseUrl) {
    return 'Kan nie die Cordon-beheerplatform by $baseUrl bereik nie.';
  }

  @override
  String get timeoutErrorMessage =>
      'Die versoek het uitgetel. Is die beheerplatform besig?';

  @override
  String serverErrorMessage(int status, String message) {
    return 'HTTP $status: $message';
  }

  @override
  String get unexpectedErrorMessage =>
      'Onverwagte reaksie van die beheerplatform.';

  @override
  String get profilesTitle => 'Sandput Profiele';

  @override
  String get profilesEmpty =>
      'Geen sandput-profiele is op hierdie beheerplatform geregistreer nie.';

  @override
  String profileCardLabel(String slug) {
    return 'Sandput-profiel $slug';
  }

  @override
  String profileMeta(String fsMode, String netMode, String gitProtected) {
    return 'FS: $fsMode | NET: $netMode | .git RO: $gitProtected';
  }

  @override
  String get profileUseInSimulator => 'Simuleer';

  @override
  String profileUseInSimulatorSemantics(String slug) {
    return 'Gebruik profiel $slug in die L7 Simulator';
  }

  @override
  String get gatesTitle => '5-Hek Argitektuur';

  @override
  String gateLabel(int number) {
    return 'Hek $number';
  }

  @override
  String get gate1Title => 'Hek 1: Netwerk Namespace & iptables';

  @override
  String get gate1Body =>
      'Toegewyde ip netns + iptables afdwinging: agent-net 10.200.1.2/24 met route_localnet=1, TCP 80/443 REDIRECT na :8080, UDP 443 QUIC REJECT, en fout-toe FORWARD DROP.';

  @override
  String get gate2Title => 'Hek 2: AppArmor 4.0 MAC';

  @override
  String get gate2Body =>
      'Verpligte Toegangsbeheer (abi <abi/4.0>) wat die vermoëns sys_admin, net_admin en sys_ptrace weier, /tmp-uitvoering blokkeer, en ~/.ssh, ~/.aws en ~/.gnupg beskerm.';

  @override
  String get gate3Title => 'Hek 3: Bubblewrap VFS';

  @override
  String get gate3Body =>
      'Onbevoorregte mount-, pid- en ipc-namespaces (--ro-bind / /) wat 20 destruktiewe binaries met /dev/null masker, / of HOME lees-skryf mounts weier, en .git lees-alleen bind (EC-01).';

  @override
  String get gate4Title => 'Hek 4: Laag 7 mitmproxy';

  @override
  String get gate4Body =>
      'Standaard-ween domein toelatelys, DoH blok, FR-5.4 muterende HTTP-metode wagwag (POST geblokkeer op pakketregisters), en 9-patroon geheime-eksfiltreer skandeerder.';

  @override
  String get gate5Title => 'Hek 5: tshark PCAP Ringbuffer';

  @override
  String get gate5Body =>
      'Begrensde 1 GB roterende L3/L4 pakketvaslegging gepaar met gestruktureerde JSONL oudit-logs en Prometheus telemetrie.';

  @override
  String get simulatorTitle => 'L7 Beleid Simulator';

  @override
  String get simProfileLabel => 'Profiel';

  @override
  String get simProfileEmpty =>
      'Geen profiele beskikbaar op hierdie beheerplatform nie.';

  @override
  String get simUrlLabel => 'Doel URL';

  @override
  String get simUrlRequired => 'Doel URL is verpligtend';

  @override
  String get simMethodLabel => 'HTTP Metode';

  @override
  String get simBodyLabel => 'Versoek Liggaam (opsioneel)';

  @override
  String get simBodyHint => 'Vrag word geskandeer vir uitgelekte geloofsbriewe';

  @override
  String get evaluateFlowButton => 'Evalueer L7 Vloei';

  @override
  String get presetAllowLlm => 'Vooraf: Toegelate LLM POST';

  @override
  String get presetBlockDoh => 'Vooraf: Blokkeer DoH';

  @override
  String get presetBlockPyPiPost => 'Vooraf: Blokkeer PyPI POST';

  @override
  String get presetBlockSecret => 'Vooraf: Blokkeer Sleutel Lek';

  @override
  String get simIdlePrompt =>
      'Stel \'n vloei op, druk dan Evalueer L7 Vloei om die live beleidsenjin te raadpleeg.';

  @override
  String simRequestSummary(String method, String url) {
    return '$method $url';
  }

  @override
  String get simVerdictLabel => 'Uitspraak';

  @override
  String simVerdictSummary(String verdict, int status, String rule) {
    return '$verdict ($status) | Reël: $rule';
  }

  @override
  String get simReasonLabel => 'Rede';

  @override
  String simLatencyLabel(int micros) {
    return 'Evaluasie vertraging: $micros us';
  }

  @override
  String get configTitle => 'Lanseringsplan Voorskou';

  @override
  String get configContentLabel => 'Cordonfile Inhoud';

  @override
  String get configContentRequired => 'Cordonfile inhoud is verpligtend';

  @override
  String get configFormatLabel => 'Formaat';

  @override
  String get compileButton => 'Voorskou Lanseringsplan';

  @override
  String get configIdlePrompt =>
      'Plak \'n Cordonfile, Cordonfile.toml, of cordon.json, voorskou dan sy deterministiese 5-hek sandput lanseringsplan.';

  @override
  String get planProfileLabel => 'Profiel';

  @override
  String get planWorkspaceLabel => 'Werkspasie';

  @override
  String get planGatesLabel => 'Hekke Toegepas';

  @override
  String get planCommandLabel => 'Bevel';

  @override
  String get formatCordonfile => 'Cordonfile';

  @override
  String get formatToml => 'Cordonfile.toml';

  @override
  String get formatJson => 'cordon.json';

  @override
  String get eventsTitle => 'Oudit Stroom';

  @override
  String get eventsRefresh => 'Verfris';

  @override
  String get eventsEmpty =>
      'Nog geen oudit-geleenthede aangeteken nie. Evalueer \'n L7 vloei om telemetrie te genereer.';

  @override
  String eventCardLabel(String subject) {
    return 'Oudit-gebeurtenis: $subject';
  }

  @override
  String eventMeta(String plane, String severity, String verdict) {
    return '$plane | $severity | $verdict';
  }

  @override
  String get attributionFooter =>
      'Developed by PyCentric | Cordon Laag 0 Sekuriteitsenjin (ADR-L0-SEC-02) | AGPL-3.0-only | Bron: https://github.com/pycentric/cordon';
}
