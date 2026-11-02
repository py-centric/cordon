import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import '../async_value.dart';
import '../cordon_api_client.dart';
import '../models.dart';
import '../widgets/state_views.dart';

/// Audit Stream pane: consumes `GET /api/v1/events` and renders the telemetry
/// ring buffer with Loading / Error / Empty states and manual refresh.
///
/// [telemetryEpoch] is bumped by the dashboard after each successful policy
/// evaluation so the stream re-polls while the pane is alive.
class EventsPane extends StatefulWidget {
  const EventsPane({
    super.key,
    required this.client,
    required this.telemetryEpoch,
  });

  final CordonApiClient client;
  final int telemetryEpoch;

  @override
  State<EventsPane> createState() => _EventsPaneState();
}

class _EventsPaneState extends State<EventsPane> {
  AsyncValue<List<AuditEvent>> _events = const AsyncValue.loading();

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void didUpdateWidget(EventsPane oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.telemetryEpoch != widget.telemetryEpoch) {
      _load();
    }
  }

  Future<void> _load() async {
    setState(() => _events = const AsyncValue.loading());
    try {
      final events = await widget.client.fetchEvents(limit: 50);
      if (!mounted) return;
      setState(() => _events = AsyncValue.success(events));
    } catch (error) {
      if (!mounted) return;
      setState(() => _events = AsyncValue.failure(error));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  l10n.eventsTitle,
                  key: const Key('events-title'),
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
              ),
              IconButton(
                key: const Key('events-refresh'),
                tooltip: l10n.eventsRefresh,
                onPressed: _load,
                icon: const Icon(Icons.refresh),
              ),
            ],
          ),
        ),
        Expanded(child: _buildContent(l10n)),
      ],
    );
  }

  Widget _buildContent(AppLocalizations l10n) {
    if (_events.isLoading) return const LoadingSkeleton();

    if (_events.isFailure) {
      return ErrorStateView(
        message: describeApiError(_events.error!, l10n, widget.client.baseUrl),
        onRetry: _load,
      );
    }

    final events = _events.data ?? const <AuditEvent>[];
    if (events.isEmpty) {
      return EmptyStateView(
        key: const Key('events-empty'),
        icon: Icons.inbox_outlined,
        message: l10n.eventsEmpty,
      );
    }

    return ListView.builder(
      key: const Key('events-list'),
      padding: const EdgeInsets.all(16),
      itemCount: events.length,
      itemBuilder: (context, index) {
        final event = events[index];
        final scheme = Theme.of(context).colorScheme;
        final (chipColor, chipLabelColor) = switch (event.verdict) {
          PolicyVerdict.allow => (scheme.tertiary, scheme.onTertiary),
          PolicyVerdict.block => (scheme.error, scheme.onError),
          PolicyVerdict.audit => (scheme.secondary, scheme.onSecondary),
        };
        final details = event.details.entries
            .map((entry) => '${entry.key}: ${entry.value}')
            .join(' | ');

        return Semantics(
          container: true,
          label: l10n.eventCardLabel(event.subject),
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: chipColor,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Text(
                          event.verdict.wire,
                          style: TextStyle(
                            color: chipLabelColor,
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          event.timestamp,
                          style: Theme.of(context).textTheme.labelSmall,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    event.subject,
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                  const SizedBox(height: 4),
                  Text(
                    l10n.eventMeta(
                      event.plane.wire,
                      event.severity.wire,
                      event.verdict.wire,
                    ),
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  if (details.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Text(
                      details,
                      style: Theme.of(context).textTheme.labelSmall,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}
