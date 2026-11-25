import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import '../async_value.dart';
import '../models.dart';
import '../theme.dart';

/// Top status bar displaying control-plane reachability and version.
class CordonHealthBar extends StatelessWidget {
  const CordonHealthBar({super.key, required this.health});

  final AsyncValue<HealthResponse> health;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final scheme = Theme.of(context).colorScheme;
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
            decoration: BoxDecoration(color: dot, shape: BoxShape.circle),
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
}

/// Attribution footer displayed beneath every dashboard pane.
class CordonAttributionFooter extends StatelessWidget {
  const CordonAttributionFooter({super.key});

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
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
}

/// Tri-theme selector popup menu (Light, Dark, High-Contrast WCAG AAA).
class CordonThemeMenu extends StatelessWidget {
  const CordonThemeMenu({
    super.key,
    required this.themePreset,
    required this.onThemeChanged,
  });

  final CordonThemePreset themePreset;
  final ValueChanged<CordonThemePreset> onThemeChanged;

  Widget _entry(IconData icon, String label, bool selected) => Row(
        children: [
          Icon(selected ? Icons.check : icon, size: 18),
          const SizedBox(width: 8),
          Flexible(
            child: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
          ),
        ],
      );

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return PopupMenuButton<String>(
      key: const Key('display-menu'),
      tooltip: l10n.settingsLabel,
      icon: const Icon(Icons.palette),
      onSelected: (value) {
        switch (value) {
          case 'theme_light':
            onThemeChanged(CordonThemePreset.light);
          case 'theme_dark':
            onThemeChanged(CordonThemePreset.dark);
          case 'theme_high_contrast':
            onThemeChanged(CordonThemePreset.highContrast);
        }
      },
      itemBuilder: (context) => [
        PopupMenuItem(
          value: 'theme_light',
          child: _entry(
            Icons.light_mode,
            l10n.themeLight,
            themePreset == CordonThemePreset.light,
          ),
        ),
        PopupMenuItem(
          value: 'theme_dark',
          child: _entry(
            Icons.dark_mode,
            l10n.themeDark,
            themePreset == CordonThemePreset.dark,
          ),
        ),
        PopupMenuItem(
          value: 'theme_high_contrast',
          child: _entry(
            Icons.contrast,
            l10n.themeHighContrast,
            themePreset == CordonThemePreset.highContrast,
          ),
        ),
      ],
    );
  }
}

/// Expanded / desktop navigation sidebar with collapsible rail support (`GL-06`).
class CordonExpandedSidebar extends StatelessWidget {
  const CordonExpandedSidebar({
    super.key,
    required this.selectedIndex,
    required this.onDestinationSelected,
    required this.destinations,
    required this.collapsed,
  });

  final int selectedIndex;
  final ValueChanged<int> onDestinationSelected;
  final List<(IconData, String)> destinations;
  final bool collapsed;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    if (collapsed) {
      return NavigationRail(
        selectedIndex: selectedIndex,
        onDestinationSelected: onDestinationSelected,
        labelType: NavigationRailLabelType.selected,
        destinations: [
          for (final (icon, label) in destinations)
            NavigationRailDestination(icon: Icon(icon), label: Text(label)),
        ],
      );
    }

    return SizedBox(
      width: 260,
      child: NavigationDrawer(
        selectedIndex: selectedIndex,
        onDestinationSelected: onDestinationSelected,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(28, 16, 28, 8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  l10n.appTitle,
                  style: Theme.of(context)
                      .textTheme
                      .titleLarge
                      ?.copyWith(fontWeight: FontWeight.bold),
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
    );
  }
}
