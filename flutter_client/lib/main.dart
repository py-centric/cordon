import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import 'src/async_value.dart';
import 'src/cordon_api_client.dart';
import 'src/models.dart';
import 'src/panes/config_pane.dart';
import 'src/panes/events_pane.dart';
import 'src/panes/gates_pane.dart';
import 'src/panes/profiles_pane.dart';
import 'src/panes/simulator_pane.dart';
import 'src/theme.dart';

void main() {
  runApp(const CordonCompanionApp());
}

/// Root application widget. An external [CordonApiClient] can be injected for
/// tests (mocked HTTP); otherwise a real client against `AppConfig.apiBaseUrl`
/// is created and owned by this widget.
class CordonCompanionApp extends StatefulWidget {
  const CordonCompanionApp({super.key, this.apiClient});

  final CordonApiClient? apiClient;

  @override
  State<CordonCompanionApp> createState() => _CordonCompanionAppState();
}

class _CordonCompanionAppState extends State<CordonCompanionApp> {
  CordonThemePreset _themePreset = CordonThemePreset.dark;
  Locale _locale = const Locale('en');
  late final CordonApiClient _client;
  late final bool _ownsClient;

  static const List<Locale> _supportedLocales = [
    Locale('en'),
    Locale('af'),
    Locale('zu'),
  ];

  @override
  void initState() {
    super.initState();
    _ownsClient = widget.apiClient == null;
    _client = widget.apiClient ?? CordonApiClient();
  }

  @override
  void dispose() {
    if (_ownsClient) {
      _client.dispose();
    }
    super.dispose();
  }

  Locale _cycleLocale(Locale current) {
    final index =
        _supportedLocales.indexWhere((l) => l.languageCode == current.languageCode);
    return _supportedLocales[(index + 1) % _supportedLocales.length];
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      onGenerateTitle: (context) => AppLocalizations.of(context).appTitle,
      theme: buildCordonTheme(_themePreset),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      locale: _locale,
      home: CordonDashboardScaffold(
        client: _client,
        themePreset: _themePreset,
        onThemeChanged: (next) => setState(() => _themePreset = next),
        onLocaleChanged: (next) => setState(() => _locale = next),
        onCycleLocale: () => setState(() => _locale = _cycleLocale(_locale)),
      ),
    );
  }
}

/// Adaptive dashboard shell: BottomNavigationBar (compact), NavigationRail
/// (medium), permanent NavigationDrawer sidebar (expanded / ultra-wide with a
/// centered 1440dp max-content container).
class CordonDashboardScaffold extends StatefulWidget {
  const CordonDashboardScaffold({
    super.key,
    required this.client,
    required this.themePreset,
    required this.onThemeChanged,
    required this.onLocaleChanged,
    required this.onCycleLocale,
  });

  final CordonApiClient client;
  final CordonThemePreset themePreset;
  final ValueChanged<CordonThemePreset> onThemeChanged;
  final ValueChanged<Locale> onLocaleChanged;
  final VoidCallback onCycleLocale;

  @override
  State<CordonDashboardScaffold> createState() =>
      _CordonDashboardScaffoldState();
}

class _CordonDashboardScaffoldState extends State<CordonDashboardScaffold> {
  int _selectedIndex = 0;
  String? _selectedProfileSlug;
  int _telemetryEpoch = 0;
  final Set<int> _visitedTabs = {0};
  AsyncValue<HealthResponse> _health = const AsyncValue.loading();

  static const int _profilesTab = 0;
  static const int _simulatorTab = 2;

  @override
  void initState() {
    super.initState();
    _loadHealth();
  }

  Future<void> _loadHealth() async {
    setState(() => _health = const AsyncValue.loading());
    try {
      final health = await widget.client.fetchHealth();
      if (!mounted) return;
      setState(() => _health = AsyncValue.success(health));
    } catch (error) {
      if (!mounted) return;
      setState(() => _health = AsyncValue.failure(error));
    }
  }

  void _onDestinationSelected(int index) {
    setState(() {
      _selectedIndex = index;
      _visitedTabs.add(index);
    });
  }

  void _selectProfileForSimulator(String slug) {
    setState(() {
      _selectedProfileSlug = slug;
      _selectedIndex = _simulatorTab;
      _visitedTabs.add(_simulatorTab);
    });
  }

  Widget _buildPane(int index) {
    switch (index) {
      case _profilesTab:
        return ProfilesPane(
          client: widget.client,
          gridColumns: _gridColumnsFor(context),
          activeProfileSlug: _selectedProfileSlug,
          onProfileSelected: _selectProfileForSimulator,
        );
      case 1:
        return const GatesPane();
      case _simulatorTab:
        return SimulatorPane(
          client: widget.client,
          selectedProfileSlug: _selectedProfileSlug,
          onProfileChanged: (slug) =>
              setState(() => _selectedProfileSlug = slug),
          onEvaluationSucceeded: () => setState(() => _telemetryEpoch++),
        );
      case 3:
        return ConfigPane(client: widget.client);
      default:
        return EventsPane(
          client: widget.client,
          telemetryEpoch: _telemetryEpoch,
        );
    }
  }

  int _gridColumnsFor(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    if (width < 600) return 1;
    if (width < 840) return 2;
    return 3;
  }

  List<(IconData, String)> _destinationLabels(AppLocalizations l10n) => [
        (Icons.security, l10n.navProfiles),
        (Icons.layers, l10n.navGates),
        (Icons.network_check, l10n.navSimulator),
        (Icons.description, l10n.navConfig),
        (Icons.receipt_long, l10n.navTelemetry),
      ];

  Widget _buildHealthBar(AppLocalizations l10n) {
    final scheme = Theme.of(context).colorScheme;
    final health = _health;
    final (Color dot, String text) = switch (health.status) {
      AsyncStatus.loading => (scheme.outline, l10n.healthChecking),
      AsyncStatus.failure => (scheme.error, l10n.healthOffline),
      AsyncStatus.success => (
          scheme.tertiary,
          l10n.healthOnline(health.data?.version ?? ''),
        ),
    };

    return Container(
      key: const Key('health-indicator'),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      color: scheme.surfaceContainerHighest,
      child: Row(
        children: [
          Container(
            width: 10,
            height: 10,
            decoration: BoxDecoration(
              color: dot,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              key: const Key('health-indicator-text'),
              style: Theme.of(context).textTheme.labelMedium,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAttributionFooter(AppLocalizations l10n) {
    return Container(
      key: const Key('pycentric-attribution-footer'),
      padding: const EdgeInsets.all(12),
      child: Center(
        child: Text(
          l10n.attributionFooter,
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.labelSmall,
        ),
      ),
    );
  }

  Widget _buildContent(AppLocalizations l10n) {
    final tabs = (_visitedTabs.toList()..sort());
    return Column(
      children: [
        _buildHealthBar(l10n),
        Expanded(
          child: IndexedStack(
            index: tabs.indexOf(_selectedIndex),
            children: [
              for (final tab in tabs)
                KeyedSubtree(key: ValueKey('pane-$tab'), child: _buildPane(tab)),
            ],
          ),
        ),
        _buildAttributionFooter(l10n),
      ],
    );
  }

  Widget _buildThemeMenu(AppLocalizations l10n) {
    Widget entry(IconData icon, String label, bool selected) => Row(
          children: [
            Icon(selected ? Icons.check : icon, size: 18),
            const SizedBox(width: 8),
            Flexible(
              child: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
            ),
          ],
        );

    return PopupMenuButton<String>(
      key: const Key('display-menu'),
      tooltip: l10n.settingsLabel,
      icon: const Icon(Icons.palette),
      onSelected: (value) {
        switch (value) {
          case 'theme_light':
            widget.onThemeChanged(CordonThemePreset.light);
          case 'theme_dark':
            widget.onThemeChanged(CordonThemePreset.dark);
          case 'theme_high_contrast':
            widget.onThemeChanged(CordonThemePreset.highContrast);
        }
      },
      itemBuilder: (context) => [
        PopupMenuItem(
          value: 'theme_light',
          child: entry(
            Icons.light_mode,
            l10n.themeLight,
            widget.themePreset == CordonThemePreset.light,
          ),
        ),
        PopupMenuItem(
          value: 'theme_dark',
          child: entry(
            Icons.dark_mode,
            l10n.themeDark,
            widget.themePreset == CordonThemePreset.dark,
          ),
        ),
        PopupMenuItem(
          value: 'theme_high_contrast',
          child: entry(
            Icons.contrast,
            l10n.themeHighContrast,
            widget.themePreset == CordonThemePreset.highContrast,
          ),
        ),
      ],
    );
  }

  Widget _buildLocaleToggle(AppLocalizations l10n) {
    final code = Localizations.localeOf(context).languageCode.toUpperCase();
    return Semantics(
      button: true,
      label: l10n.semanticLocaleToggle,
      child: TextButton(
        key: const Key('locale-toggle'),
        onPressed: widget.onCycleLocale,
        child: Text(code),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final width = MediaQuery.sizeOf(context).width;
    final isCompact = width < 600;
    final isExpanded = width >= 840;

    final destinations = _destinationLabels(l10n);
    final content = _buildContent(l10n);

    final appBar = AppBar(
      title: Text(l10n.appTitle),
      actions: [
        _buildLocaleToggle(l10n),
        _buildThemeMenu(l10n),
      ],
    );

    if (isCompact) {
      return Scaffold(
        appBar: appBar,
        body: content,
        bottomNavigationBar: NavigationBar(
          selectedIndex: _selectedIndex,
          onDestinationSelected: _onDestinationSelected,
          destinations: [
            for (final (icon, label) in destinations)
              NavigationDestination(icon: Icon(icon), label: label),
          ],
        ),
      );
    }

    if (!isExpanded) {
      // Medium tier (600-840dp): compact icon rail + 2-column content.
      return Scaffold(
        appBar: appBar,
        body: Row(
          children: [
            NavigationRail(
              selectedIndex: _selectedIndex,
              onDestinationSelected: _onDestinationSelected,
              labelType: NavigationRailLabelType.selected,
              destinations: [
                for (final (icon, label) in destinations)
                  NavigationRailDestination(
                    icon: Icon(icon),
                    label: Text(label),
                  ),
              ],
            ),
            const VerticalDivider(thickness: 1, width: 1),
            Expanded(child: content),
          ],
        ),
      );
    }

    // Expanded / ultra-wide tier (>= 840dp): permanent sidebar with a centered
    // max-content container (capped at 1440dp).
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          SizedBox(
            width: 260,
            child: NavigationDrawer(
              selectedIndex: _selectedIndex,
              onDestinationSelected: _onDestinationSelected,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(28, 16, 28, 8),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        l10n.appTitle,
                        style: Theme.of(context).textTheme.titleLarge?.copyWith(
                              fontWeight: FontWeight.bold,
                            ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        l10n.appSubtitle,
                        style: Theme.of(context).textTheme.labelSmall,
                      ),
                    ],
                  ),
                ),
                for (final (icon, label) in destinations)
                  NavigationDrawerDestination(
                    icon: Icon(icon),
                    label: Flexible(
                      child: Text(
                        label,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ),
              ],
            ),
          ),
          const VerticalDivider(thickness: 1, width: 1),
          Expanded(
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1440),
                child: content,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
