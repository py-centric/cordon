import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import '../async_value.dart';
import '../models.dart';
import 'state_views.dart';

/// Renders the idle, loading, failure, or evaluated L7 `PolicyDecision` card.
class SimulatorResultCard extends StatelessWidget {
  const SimulatorResultCard({
    super.key,
    required this.decision,
    required this.lastMethod,
    required this.lastUrl,
    required this.baseUrl,
    required this.onRetry,
  });

  final AsyncValue<PolicyDecision>? decision;
  final String lastMethod;
  final String lastUrl;
  final String baseUrl;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final current = decision;
    final scheme = Theme.of(context).colorScheme;

    if (current == null) {
      return Card(
        key: const Key('sim-idle-prompt'),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Text(l10n.simIdlePrompt),
        ),
      );
    }

    if (current.isLoading) {
      return Card(
        key: const Key('sim-loading'),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(l10n.simRequestSummary(lastMethod, lastUrl)),
              const SizedBox(height: 12),
              const LinearProgressIndicator(),
            ],
          ),
        ),
      );
    }

    if (current.isFailure) {
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: ErrorStateView(
            message: describeApiError(current.error!, l10n, baseUrl),
            onRetry: onRetry,
          ),
        ),
      );
    }

    final result = current.data!;
    final (chipColor, chipLabelColor) = switch (result.verdict) {
      PolicyVerdict.allow => (scheme.tertiary, scheme.onTertiary),
      PolicyVerdict.block => (scheme.error, scheme.onError),
      PolicyVerdict.audit => (scheme.secondary, scheme.onSecondary),
    };

    return Card(
      key: const Key('sim-result-card'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              l10n.simRequestSummary(lastMethod, lastUrl),
              style: Theme.of(context).textTheme.labelMedium,
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Container(
                  key: const Key('verdict-chip'),
                  padding: const EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 6,
                  ),
                  decoration: BoxDecoration(
                    color: chipColor,
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Text(
                    result.verdict.wire,
                    style: TextStyle(
                      color: chipLabelColor,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    l10n.simVerdictLabel,
                    style: Theme.of(context).textTheme.labelLarge,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Semantics(
              liveRegion: true,
              child: Text(
                l10n.simVerdictSummary(
                  result.verdict.wire,
                  result.statusCode,
                  result.matchedRule,
                ),
                key: const Key('l7-verdict-text'),
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              l10n.simReasonLabel,
              style: Theme.of(context).textTheme.labelLarge,
            ),
            Text(result.reason),
            if (result.secretFingerprint != null) ...[
              const SizedBox(height: 4),
              Text(
                'SHA-256: ${result.secretFingerprint}',
                key: const Key('l7-secret-fingerprint'),
                style: Theme.of(context).textTheme.labelSmall,
              ),
            ],
            const SizedBox(height: 8),
            Text(
              l10n.simLatencyLabel(result.evaluationLatencyUs),
              key: const Key('l7-latency-text'),
              style: Theme.of(context).textTheme.labelSmall,
            ),
          ],
        ),
      ),
    );
  }
}
