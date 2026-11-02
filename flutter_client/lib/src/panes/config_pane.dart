import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import '../async_value.dart';
import '../cordon_api_client.dart';
import '../models.dart';
import '../widgets/state_views.dart';

/// Launch Plan Preview pane: consumes `POST /api/v1/compile-config` and
/// renders the deterministic 5-gate launch plan for a declarative config.
class ConfigPane extends StatefulWidget {
  const ConfigPane({super.key, required this.client});

  final CordonApiClient client;

  @override
  State<ConfigPane> createState() => _ConfigPaneState();
}

class _ConfigPaneState extends State<ConfigPane> {
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _contentController = TextEditingController();

  String _format = 'cordonfile';
  AsyncValue<SandboxLaunchPlan>? _plan;

  @override
  void dispose() {
    _contentController.dispose();
    super.dispose();
  }

  Future<void> _compile() async {
    if (!(_formKey.currentState?.validate() ?? false)) return;
    setState(() => _plan = const AsyncValue.loading());
    try {
      final plan = await widget.client.compileConfig(
        configContent: _contentController.text,
        format: _format,
      );
      if (!mounted) return;
      setState(() => _plan = AsyncValue.success(plan));
    } catch (error) {
      if (!mounted) return;
      setState(() => _plan = AsyncValue.failure(error));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context);
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            l10n.configTitle,
            key: const Key('config-title'),
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 12),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Form(
              key: _formKey,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  TextFormField(
                    key: const Key('config-content-field'),
                    controller: _contentController,
                    minLines: 6,
                    maxLines: 12,
                    style: const TextStyle(fontFamily: 'monospace'),
                    decoration: InputDecoration(
                      labelText: l10n.configContentLabel,
                      border: const OutlineInputBorder(),
                    ),
                    validator: (value) => value == null || value.trim().isEmpty
                        ? l10n.configContentRequired
                        : null,
                  ),
                  const SizedBox(height: 12),
                  _buildFormatRow(l10n),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
        _buildResultCard(l10n),
        ],
      ),
    );
  }

  /// Format selector + compile action: stacked on narrow (compact) widths,
  /// side-by-side when there is room.
  Widget _buildFormatRow(AppLocalizations l10n) {
    final formatField = DropdownButtonFormField<String>(
      key: const Key('config-format-dropdown'),
      initialValue: _format,
      isExpanded: true,
      decoration: InputDecoration(
        labelText: l10n.configFormatLabel,
        border: const OutlineInputBorder(),
      ),
      items: [
        DropdownMenuItem(value: 'cordonfile', child: Text(l10n.formatCordonfile)),
        DropdownMenuItem(value: 'toml', child: Text(l10n.formatToml)),
        DropdownMenuItem(value: 'json', child: Text(l10n.formatJson)),
      ],
      onChanged: (value) => setState(() => _format = value ?? 'cordonfile'),
    );

    final actionButton = Semantics(
      button: true,
      enabled: !(_plan?.isLoading ?? false),
      label: l10n.compileButton,
      child: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 48, minHeight: 48),
        child: FilledButton.icon(
          key: const Key('compile-button'),
          onPressed: (_plan?.isLoading ?? false) ? null : _compile,
          icon: (_plan?.isLoading ?? false)
              ? const SizedBox(
                  width: 20,
                  height: 20,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Icon(Icons.play_arrow),
          label: Text(l10n.compileButton),
        ),
      ),
    );

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              formatField,
              const SizedBox(height: 12),
              actionButton,
            ],
          );
        }
        return Row(
          children: [
            Expanded(child: formatField),
            const SizedBox(width: 12),
            actionButton,
          ],
        );
      },
    );
  }

  Widget _buildResultCard(AppLocalizations l10n) {
    final plan = _plan;
    if (plan == null) {
      return Card(
        key: const Key('config-idle-prompt'),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Text(l10n.configIdlePrompt),
        ),
      );
    }

    if (plan.isLoading) {
      return const Card(
        key: Key('config-loading'),
        child: Padding(
          padding: EdgeInsets.all(16),
          child: LinearProgressIndicator(),
        ),
      );
    }

    if (plan.isFailure) {
      return Card(
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: ErrorStateView(
            message: describeApiError(
              plan.error!,
              l10n,
              widget.client.baseUrl,
            ),
            onRetry: _compile,
          ),
        ),
      );
    }

    final result = plan.data!;
    return Card(
      key: const Key('plan-result-card'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '${l10n.planProfileLabel}: ${result.profileName}',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text('${l10n.planWorkspaceLabel}: ${result.canonicalWorkspace}'),
            const SizedBox(height: 8),
            Text(
              '${l10n.planGatesLabel}: ${result.gatesApplied.join(', ')}',
            ),
            const SizedBox(height: 8),
            Text(
              l10n.planCommandLabel,
              style: Theme.of(context).textTheme.labelLarge,
            ),
            SelectableText(
              result.fullArgv.join(' '),
              key: const Key('plan-command-text'),
              style: const TextStyle(fontFamily: 'monospace'),
            ),
          ],
        ),
      ),
    );
  }
}
