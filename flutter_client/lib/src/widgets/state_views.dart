import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import '../cordon_api_client.dart';

/// Maps an API error to a localized, user-safe message.
///
/// Raw exception text and stack traces are never shown to the user.
String describeApiError(
  Object error,
  AppLocalizations l10n,
  String baseUrl,
) {
  if (error is CordonApiException) {
    switch (error.kind) {
      case CordonApiErrorKind.connection:
        return l10n.connectionErrorMessage(baseUrl);
      case CordonApiErrorKind.timeout:
        return l10n.timeoutErrorMessage;
      case CordonApiErrorKind.server:
        return l10n.serverErrorMessage(
          error.statusCode ?? 0,
          error.problem?.detail ?? error.message,
        );
      case CordonApiErrorKind.protocol:
        return l10n.unexpectedErrorMessage;
    }
  }
  return l10n.unexpectedErrorMessage;
}

/// Skeleton shimmer-style loader shown while a pane fetches data.
class LoadingSkeleton extends StatelessWidget {
  const LoadingSkeleton({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Semantics(
      container: true,
      label: AppLocalizations.of(context).loadingLabel,
      child: ListView(
        key: const Key('loading-indicator'),
        physics: const NeverScrollableScrollPhysics(),
        padding: const EdgeInsets.all(16),
        children: [
          Center(
            child: SizedBox(
              width: 24,
              height: 24,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: scheme.primary,
              ),
            ),
          ),
          const SizedBox(height: 16),
          for (var i = 0; i < 3; i++) ...[
            Container(
              height: 96,
              decoration: BoxDecoration(
                color: scheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(12),
              ),
            ),
            const SizedBox(height: 12),
          ],
        ],
      ),
    );
  }
}

/// Actionable error state: friendly message plus an in-place Retry action.
class ErrorStateView extends StatelessWidget {
  const ErrorStateView({
    super.key,
    required this.message,
    required this.onRetry,
  });

  final String message;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    final scheme = Theme.of(context).colorScheme;
    return Center(
      key: const Key('error-state-view'),
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 40, color: scheme.error),
            const SizedBox(height: 12),
            Text(
              l10n.errorTitle,
              style: Theme.of(context).textTheme.titleMedium,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(message, textAlign: TextAlign.center),
            const SizedBox(height: 16),
            Semantics(
              button: true,
              label: l10n.retryLabel,
              child: OutlinedButton.icon(
                key: const Key('retry-button'),
                onPressed: onRetry,
                icon: const Icon(Icons.refresh),
                label: Text(l10n.retryLabel),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Meaningful empty state: illustrative icon plus a clear message.
class EmptyStateView extends StatelessWidget {
  const EmptyStateView({
    super.key,
    required this.icon,
    required this.message,
  });

  final IconData icon;
  final String message;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 40, color: scheme.outline),
            const SizedBox(height: 12),
            Text(message, textAlign: TextAlign.center),
          ],
        ),
      ),
    );
  }
}
