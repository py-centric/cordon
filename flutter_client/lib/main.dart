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
import 'src/widgets/dashboard_chrome.dart';

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
/// (medium), permanent/collapsible NavigationDrawer sidebar (expanded /
/// ultra-wide with a centered 1440dp max-content container).
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
  bool _sidebarCollapsed = false;
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

  Widget _buildContent() {
    final tabs = (_visitedTabs.toList()..sort());
    return Column(
      children: [
        CordonHealthBar(health: _health),
        Expanded(
          child: IndexedStack(
            index: tabs.indexOf(_selectedIndex),
            children: [
              for (final tab in tabs)
                KeyedSubtree(key: ValueKey('pane-$tab'), child: _buildPane(tab)),
            ],
          ),
        ),
        const CordonAttributionFooter(),
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
    final isUltraWide = width >= 1200;

    final destinations = _destinationLabels(l10n);
    final content = _buildContent();

    final appBar = AppBar(
      leading: isUltraWide
          ? IconButton(
              key: const Key('sidebar-collapse-toggle'),
              icon: Icon(
                _sidebarCollapsed ? Icons.menu_open : Icons.view_sidebar,
              ),
              onPressed: () =>
                  setState(() => _sidebarCollapsed = !_sidebarCollapsed),
            )
          : null,
      title: Text(l10n.appTitle),
      actions: [
        _buildLocaleToggle(l10n),
        CordonThemeMenu(
          themePreset: widget.themePreset,
          onThemeChanged: widget.onThemeChanged,
        ),
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

    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          CordonExpandedSidebar(
            selectedIndex: _selectedIndex,
            onDestinationSelected: _onDestinationSelected,
            destinations: destinations,
            collapsed: isUltraWide && _sidebarCollapsed,
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
