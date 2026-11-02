import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

/// 5-Gate Rail pane: localized architectural explainer with an interactive
/// gate selector (content is product documentation, not API data).
class GatesPane extends StatefulWidget {
  const GatesPane({super.key});

  @override
  State<GatesPane> createState() => _GatesPaneState();
}

class _GatesPaneState extends State<GatesPane> {
  int _selectedGate = 0;

  static const int _gateCount = 5;

  String _gateTitle(AppLocalizations l10n, int index) => switch (index) {
        0 => l10n.gate1Title,
        1 => l10n.gate2Title,
        2 => l10n.gate3Title,
        3 => l10n.gate4Title,
        _ => l10n.gate5Title,
      };

  String _gateBody(AppLocalizations l10n, int index) => switch (index) {
        0 => l10n.gate1Body,
        1 => l10n.gate2Body,
        2 => l10n.gate3Body,
        3 => l10n.gate4Body,
        _ => l10n.gate5Body,
      };

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            l10n.gatesTitle,
            key: const Key('gates-title'),
            style: Theme.of(context).textTheme.headlineSmall,
          ),
        const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: List.generate(_gateCount, (index) {
                    return Semantics(
                      button: true,
                      selected: _selectedGate == index,
                      label: l10n.gateLabel(index + 1),
                      child: OutlinedButton(
                        key: Key('gate-button-$index'),
                        onPressed: () =>
                            setState(() => _selectedGate = index),
                        child: Text(l10n.gateLabel(index + 1)),
                      ),
                    );
                  }),
                ),
                const SizedBox(height: 12),
                Text(
                  _gateTitle(l10n, _selectedGate),
                  key: const Key('gate-detail-title'),
                  style: Theme.of(context).textTheme.titleMedium,
                ),
                const SizedBox(height: 8),
                Semantics(
                  liveRegion: true,
                  child: Text(
                    _gateBody(l10n, _selectedGate),
                    key: const Key('gate-detail-body'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
      ),
    );
  }
}
