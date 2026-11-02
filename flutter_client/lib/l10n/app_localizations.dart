import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_af.dart';
import 'app_localizations_en.dart';
import 'app_localizations_zu.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('af'),
    Locale('en'),
    Locale('zu'),
  ];

  /// No description provided for @appTitle.
  ///
  /// In en, this message translates to:
  /// **'Cordon Control Plane'**
  String get appTitle;

  /// No description provided for @appSubtitle.
  ///
  /// In en, this message translates to:
  /// **'5-Gate Kernel Sandbox & L3-L7 Network Inspection'**
  String get appSubtitle;

  /// No description provided for @navProfiles.
  ///
  /// In en, this message translates to:
  /// **'Profiles'**
  String get navProfiles;

  /// No description provided for @navGates.
  ///
  /// In en, this message translates to:
  /// **'5-Gate Rail'**
  String get navGates;

  /// No description provided for @navSimulator.
  ///
  /// In en, this message translates to:
  /// **'L7 Simulator'**
  String get navSimulator;

  /// No description provided for @navConfig.
  ///
  /// In en, this message translates to:
  /// **'Config Preview'**
  String get navConfig;

  /// No description provided for @navTelemetry.
  ///
  /// In en, this message translates to:
  /// **'Audit Stream'**
  String get navTelemetry;

  /// No description provided for @themeLight.
  ///
  /// In en, this message translates to:
  /// **'Light'**
  String get themeLight;

  /// No description provided for @themeDark.
  ///
  /// In en, this message translates to:
  /// **'Dark'**
  String get themeDark;

  /// No description provided for @themeHighContrast.
  ///
  /// In en, this message translates to:
  /// **'High Contrast (7:1)'**
  String get themeHighContrast;

  /// No description provided for @semanticLocaleToggle.
  ///
  /// In en, this message translates to:
  /// **'Switch interface language'**
  String get semanticLocaleToggle;

  /// No description provided for @settingsLabel.
  ///
  /// In en, this message translates to:
  /// **'Display settings'**
  String get settingsLabel;

  /// No description provided for @healthChecking.
  ///
  /// In en, this message translates to:
  /// **'Checking control plane...'**
  String get healthChecking;

  /// Health indicator when the API responds
  ///
  /// In en, this message translates to:
  /// **'Control plane online (v{version})'**
  String healthOnline(String version);

  /// No description provided for @healthOffline.
  ///
  /// In en, this message translates to:
  /// **'Control plane unreachable'**
  String get healthOffline;

  /// No description provided for @loadingLabel.
  ///
  /// In en, this message translates to:
  /// **'Loading'**
  String get loadingLabel;

  /// No description provided for @retryLabel.
  ///
  /// In en, this message translates to:
  /// **'Retry'**
  String get retryLabel;

  /// No description provided for @errorTitle.
  ///
  /// In en, this message translates to:
  /// **'Request failed'**
  String get errorTitle;

  /// Connection failure message
  ///
  /// In en, this message translates to:
  /// **'Cannot reach the Cordon control plane at {baseUrl}.'**
  String connectionErrorMessage(String baseUrl);

  /// No description provided for @timeoutErrorMessage.
  ///
  /// In en, this message translates to:
  /// **'The request timed out. Is the control plane busy?'**
  String get timeoutErrorMessage;

  /// RFC 7807 problem details summary
  ///
  /// In en, this message translates to:
  /// **'HTTP {status}: {message}'**
  String serverErrorMessage(int status, String message);

  /// No description provided for @unexpectedErrorMessage.
  ///
  /// In en, this message translates to:
  /// **'Unexpected response from the control plane.'**
  String get unexpectedErrorMessage;

  /// No description provided for @profilesTitle.
  ///
  /// In en, this message translates to:
  /// **'Sandbox Profiles'**
  String get profilesTitle;

  /// No description provided for @profilesEmpty.
  ///
  /// In en, this message translates to:
  /// **'No sandbox profiles are registered on this control plane.'**
  String get profilesEmpty;

  /// Screen-reader label for a profile card
  ///
  /// In en, this message translates to:
  /// **'Sandbox profile {slug}'**
  String profileCardLabel(String slug);

  /// Profile containment posture summary line
  ///
  /// In en, this message translates to:
  /// **'FS: {fsMode} | NET: {netMode} | .git RO: {gitProtected}'**
  String profileMeta(String fsMode, String netMode, String gitProtected);

  /// No description provided for @profileUseInSimulator.
  ///
  /// In en, this message translates to:
  /// **'Simulate'**
  String get profileUseInSimulator;

  /// Screen-reader label for the per-card simulate action
  ///
  /// In en, this message translates to:
  /// **'Use profile {slug} in the L7 Simulator'**
  String profileUseInSimulatorSemantics(String slug);

  /// No description provided for @gatesTitle.
  ///
  /// In en, this message translates to:
  /// **'5-Gate Rail'**
  String get gatesTitle;

  /// Gate selector button label
  ///
  /// In en, this message translates to:
  /// **'Gate {number}'**
  String gateLabel(int number);

  /// No description provided for @gate1Title.
  ///
  /// In en, this message translates to:
  /// **'Gate 1: Network Namespace & iptables'**
  String get gate1Title;

  /// No description provided for @gate1Body.
  ///
  /// In en, this message translates to:
  /// **'Dedicated ip netns + iptables enforcement: agent-net 10.200.1.2/24 with route_localnet=1, TCP 80/443 REDIRECT to :8080, UDP 443 QUIC REJECT, and fail-closed FORWARD DROP.'**
  String get gate1Body;

  /// No description provided for @gate2Title.
  ///
  /// In en, this message translates to:
  /// **'Gate 2: AppArmor 4.0 MAC'**
  String get gate2Title;

  /// No description provided for @gate2Body.
  ///
  /// In en, this message translates to:
  /// **'Mandatory Access Control (abi <abi/4.0>) denying capability sys_admin, net_admin, and sys_ptrace, blocking /tmp execution, and protecting ~/.ssh, ~/.aws, and ~/.gnupg.'**
  String get gate2Body;

  /// No description provided for @gate3Title.
  ///
  /// In en, this message translates to:
  /// **'Gate 3: Bubblewrap VFS'**
  String get gate3Title;

  /// No description provided for @gate3Body.
  ///
  /// In en, this message translates to:
  /// **'Unprivileged mount, pid, and ipc namespaces (--ro-bind / /) masking 20 destructive binaries with /dev/null, refusing / or HOME read-write mounts, and binding .git read-only (EC-01).'**
  String get gate3Body;

  /// No description provided for @gate4Title.
  ///
  /// In en, this message translates to:
  /// **'Gate 4: Layer 7 mitmproxy'**
  String get gate4Title;

  /// No description provided for @gate4Body.
  ///
  /// In en, this message translates to:
  /// **'Default-deny domain allowlist, DoH block, FR-5.4 mutating HTTP verb guard (POST blocked on package registries), and 9-pattern secret exfiltration scanner.'**
  String get gate4Body;

  /// No description provided for @gate5Title.
  ///
  /// In en, this message translates to:
  /// **'Gate 5: tshark PCAP Ring Buffer'**
  String get gate5Title;

  /// No description provided for @gate5Body.
  ///
  /// In en, this message translates to:
  /// **'Bounded 1 GB rotating L3/L4 packet capture paired with structured JSONL audit logs and Prometheus telemetry.'**
  String get gate5Body;

  /// No description provided for @simulatorTitle.
  ///
  /// In en, this message translates to:
  /// **'L7 Policy Simulator'**
  String get simulatorTitle;

  /// No description provided for @simProfileLabel.
  ///
  /// In en, this message translates to:
  /// **'Profile'**
  String get simProfileLabel;

  /// No description provided for @simProfileEmpty.
  ///
  /// In en, this message translates to:
  /// **'No profiles available on this control plane.'**
  String get simProfileEmpty;

  /// No description provided for @simUrlLabel.
  ///
  /// In en, this message translates to:
  /// **'Target URL'**
  String get simUrlLabel;

  /// No description provided for @simUrlRequired.
  ///
  /// In en, this message translates to:
  /// **'Target URL is required'**
  String get simUrlRequired;

  /// No description provided for @simMethodLabel.
  ///
  /// In en, this message translates to:
  /// **'HTTP Method'**
  String get simMethodLabel;

  /// No description provided for @simBodyLabel.
  ///
  /// In en, this message translates to:
  /// **'Request Body (optional)'**
  String get simBodyLabel;

  /// No description provided for @simBodyHint.
  ///
  /// In en, this message translates to:
  /// **'Payload scanned for leaked credentials'**
  String get simBodyHint;

  /// No description provided for @evaluateFlowButton.
  ///
  /// In en, this message translates to:
  /// **'Evaluate L7 Flow'**
  String get evaluateFlowButton;

  /// No description provided for @presetAllowLlm.
  ///
  /// In en, this message translates to:
  /// **'Preset: Allowed LLM POST'**
  String get presetAllowLlm;

  /// No description provided for @presetBlockDoh.
  ///
  /// In en, this message translates to:
  /// **'Preset: Block DoH Bypass'**
  String get presetBlockDoh;

  /// No description provided for @presetBlockPyPiPost.
  ///
  /// In en, this message translates to:
  /// **'Preset: Block PyPI POST'**
  String get presetBlockPyPiPost;

  /// No description provided for @presetBlockSecret.
  ///
  /// In en, this message translates to:
  /// **'Preset: Block Secret Leak'**
  String get presetBlockSecret;

  /// No description provided for @simIdlePrompt.
  ///
  /// In en, this message translates to:
  /// **'Configure a flow, then press Evaluate L7 Flow to query the live policy engine.'**
  String get simIdlePrompt;

  /// Echo of the evaluated request line
  ///
  /// In en, this message translates to:
  /// **'{method} {url}'**
  String simRequestSummary(String method, String url);

  /// No description provided for @simVerdictLabel.
  ///
  /// In en, this message translates to:
  /// **'Verdict'**
  String get simVerdictLabel;

  /// Policy decision summary line
  ///
  /// In en, this message translates to:
  /// **'{verdict} ({status}) | Rule: {rule}'**
  String simVerdictSummary(String verdict, int status, String rule);

  /// No description provided for @simReasonLabel.
  ///
  /// In en, this message translates to:
  /// **'Reason'**
  String get simReasonLabel;

  /// Server-measured policy evaluation latency
  ///
  /// In en, this message translates to:
  /// **'Evaluation latency: {micros} us'**
  String simLatencyLabel(int micros);

  /// No description provided for @configTitle.
  ///
  /// In en, this message translates to:
  /// **'Launch Plan Preview'**
  String get configTitle;

  /// No description provided for @configContentLabel.
  ///
  /// In en, this message translates to:
  /// **'Cordonfile Content'**
  String get configContentLabel;

  /// No description provided for @configContentRequired.
  ///
  /// In en, this message translates to:
  /// **'Cordonfile content is required'**
  String get configContentRequired;

  /// No description provided for @configFormatLabel.
  ///
  /// In en, this message translates to:
  /// **'Format'**
  String get configFormatLabel;

  /// No description provided for @compileButton.
  ///
  /// In en, this message translates to:
  /// **'Preview Launch Plan'**
  String get compileButton;

  /// No description provided for @configIdlePrompt.
  ///
  /// In en, this message translates to:
  /// **'Paste a Cordonfile, Cordonfile.toml, or cordon.json, then preview its deterministic 5-gate sandbox launch plan.'**
  String get configIdlePrompt;

  /// No description provided for @planProfileLabel.
  ///
  /// In en, this message translates to:
  /// **'Profile'**
  String get planProfileLabel;

  /// No description provided for @planWorkspaceLabel.
  ///
  /// In en, this message translates to:
  /// **'Workspace'**
  String get planWorkspaceLabel;

  /// No description provided for @planGatesLabel.
  ///
  /// In en, this message translates to:
  /// **'Gates Applied'**
  String get planGatesLabel;

  /// No description provided for @planCommandLabel.
  ///
  /// In en, this message translates to:
  /// **'Command'**
  String get planCommandLabel;

  /// No description provided for @formatCordonfile.
  ///
  /// In en, this message translates to:
  /// **'Cordonfile'**
  String get formatCordonfile;

  /// No description provided for @formatToml.
  ///
  /// In en, this message translates to:
  /// **'Cordonfile.toml'**
  String get formatToml;

  /// No description provided for @formatJson.
  ///
  /// In en, this message translates to:
  /// **'cordon.json'**
  String get formatJson;

  /// No description provided for @eventsTitle.
  ///
  /// In en, this message translates to:
  /// **'Audit Stream'**
  String get eventsTitle;

  /// No description provided for @eventsRefresh.
  ///
  /// In en, this message translates to:
  /// **'Refresh'**
  String get eventsRefresh;

  /// No description provided for @eventsEmpty.
  ///
  /// In en, this message translates to:
  /// **'No audit events recorded yet. Evaluate an L7 flow to generate telemetry.'**
  String get eventsEmpty;

  /// Screen-reader label for an audit event card
  ///
  /// In en, this message translates to:
  /// **'Audit event: {subject}'**
  String eventCardLabel(String subject);

  /// Audit event metadata line
  ///
  /// In en, this message translates to:
  /// **'{plane} | {severity} | {verdict}'**
  String eventMeta(String plane, String severity, String verdict);

  /// No description provided for @attributionFooter.
  ///
  /// In en, this message translates to:
  /// **'Developed by PyCentric | Cordon Layer 0 Security Engine (ADR-L0-SEC-02) | AGPL-3.0-only | Source: https://github.com/pycentric/cordon'**
  String get attributionFooter;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['af', 'en', 'zu'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'af':
      return AppLocalizationsAf();
    case 'en':
      return AppLocalizationsEn();
    case 'zu':
      return AppLocalizationsZu();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
