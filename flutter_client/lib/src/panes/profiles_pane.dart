import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import '../async_value.dart';
import '../cordon_api_client.dart';
import '../models.dart';
import '../widgets/state_views.dart';

/// Profiles pane: consumes `GET /api/v1/profiles` and renders the sandbox
/// profile catalog with Loading / Error / Empty states.
class ProfilesPane extends StatefulWidget {
  const ProfilesPane({
    super.key,
    required this.client,
    required this.gridColumns,
    required this.activeProfileSlug,
    required this.onProfileSelected,
  });

  final CordonApiClient client;
  final int gridColumns;
  final String? activeProfileSlug;
  final ValueChanged<String> onProfileSelected;

  @override
  State<ProfilesPane> createState() => _ProfilesPaneState();
}

class _ProfilesPaneState extends State<ProfilesPane> {
  AsyncValue<List<CordonProfile>> _profiles = const AsyncValue.loading();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _profiles = const AsyncValue.loading());
    try {
      final profiles = await widget.client.fetchProfiles();
      if (!mounted) return;
      setState(() => _profiles = AsyncValue.success(profiles));
    } catch (error) {
      if (!mounted) return;
      setState(() => _profiles = AsyncValue.failure(error));
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
                  l10n.profilesTitle,
                  key: const Key('profiles-title'),
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
              ),
              IconButton(
                key: const Key('profiles-refresh'),
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
    if (_profiles.isLoading) return const LoadingSkeleton();

    if (_profiles.isFailure) {
      return ErrorStateView(
        message: describeApiError(_profiles.error!, l10n, widget.client.baseUrl),
        onRetry: _load,
      );
    }

    final profiles = _profiles.data ?? const <CordonProfile>[];
    if (profiles.isEmpty) {
      return EmptyStateView(
        icon: Icons.shield_outlined,
        message: l10n.profilesEmpty,
      );
    }

    return GridView.builder(
      key: const Key('profiles-grid'),
      padding: const EdgeInsets.all(16),
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: widget.gridColumns,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
        mainAxisExtent: 208,
      ),
      itemCount: profiles.length,
      itemBuilder: (context, index) {
        final profile = profiles[index];
        final isActive = profile.name == widget.activeProfileSlug;
        final scheme = Theme.of(context).colorScheme;
        return Semantics(
          container: true,
          label: l10n.profileCardLabel(profile.name),
          child: Card(
            shape: isActive
                ? RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                    side: BorderSide(color: scheme.primary, width: 2),
                  )
                : null,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    profile.name,
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                  const SizedBox(height: 4),
                  Expanded(
                    child: Text(
                      profile.description,
                      maxLines: 3,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Text(
                    l10n.profileMeta(
                      profile.filesystemMode,
                      profile.networkMode,
                      profile.protectGitDir.toString(),
                    ),
                    style: Theme.of(context).textTheme.labelSmall,
                  ),
                  const SizedBox(height: 4),
                  Semantics(
                    button: true,
                    label: l10n.profileUseInSimulatorSemantics(profile.name),
                    child: Align(
                      alignment: Alignment.centerRight,
                      child: OutlinedButton(
                        key: Key('simulate-${profile.name}'),
                        onPressed: () => widget.onProfileSelected(profile.name),
                        child: Text(l10n.profileUseInSimulator),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}
