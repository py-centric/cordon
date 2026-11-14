import 'package:cordon_flutter_client/l10n/app_localizations.dart';
import 'package:flutter/material.dart';

import '../async_value.dart';
import '../cordon_api_client.dart';
import '../models.dart';
import '../widgets/simulator_result_card.dart';

/// One-click attack presets mirroring the web control plane dashboard.
/// Each preset only pre-fills the form; the verdict itself always comes from
/// the live `POST /api/v1/evaluate-l7` policy engine.
enum SimulatorPreset { allowLlm, blockDoh, blockPyPiPost, blockSecret }

class _PresetForm {
  const _PresetForm(this.url, this.method, this.body);

  final String url;
  final String method;
  final String body;
}

const Map<SimulatorPreset, _PresetForm> _presetForms = {
  SimulatorPreset.allowLlm: _PresetForm(
    'https://api.openai.com/v1/chat/completions',
    'POST',
    '',
  ),
  SimulatorPreset.blockDoh: _PresetForm(
    'https://1.1.1.1/dns-query',
    'GET',
    '',
  ),
  SimulatorPreset.blockPyPiPost: _PresetForm(
    'https://pypi.org/legacy/',
    'POST',
    'exfiltrated_archive_payload',
  ),
  SimulatorPreset.blockSecret: _PresetForm(
    'https://api.openai.com/v1/chat/completions',
    'POST',
    'Authorization: Bearer ghp_1234567890abcdefghijklmnopqrstuvwx',
  ),
};

/// L7 Policy Simulator pane: user-entered flow in, real `PolicyDecision` out.
class SimulatorPane extends StatefulWidget {
  const SimulatorPane({
    super.key,
    required this.client,
    required this.selectedProfileSlug,
    required this.onProfileChanged,
    required this.onEvaluationSucceeded,
  });

  final CordonApiClient client;
  final String? selectedProfileSlug;
  final ValueChanged<String> onProfileChanged;
  final VoidCallback onEvaluationSucceeded;

  @override
  State<SimulatorPane> createState() => _SimulatorPaneState();
}

class _SimulatorPaneState extends State<SimulatorPane> {
  static const List<String> _methods = [
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
  ];

  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final TextEditingController _urlController = TextEditingController();
  final TextEditingController _bodyController = TextEditingController();

  String _method = 'POST';
  AsyncValue<List<CordonProfile>> _profiles = const AsyncValue.loading();
  AsyncValue<PolicyDecision>? _decision;
  String _lastMethod = '';
  String _lastUrl = '';

  @override
  void initState() {
    super.initState();
    _loadProfiles();
  }

  @override
  void dispose() {
    _urlController.dispose();
    _bodyController.dispose();
    super.dispose();
  }

  Future<void> _loadProfiles() async {
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

  String? get _effectiveProfile {
    final profiles = _profiles.data ?? const <CordonProfile>[];
    final selected = widget.selectedProfileSlug;
    if (selected != null && profiles.any((p) => p.name == selected)) {
      return selected;
    }
    return profiles.isNotEmpty ? profiles.first.name : null;
  }

  void _applyPreset(SimulatorPreset preset) {
    final form = _presetForms[preset]!;
    setState(() {
      _urlController.text = form.url;
      _method = form.method;
      _bodyController.text = form.body;
    });
    _evaluate();
  }

  Future<void> _evaluate() async {
    if (!(_formKey.currentState?.validate() ?? false)) return;
    final profile = _effectiveProfile;
    if (profile == null) return;

    setState(() {
      _lastMethod = _method;
      _lastUrl = _urlController.text.trim();
      _decision = const AsyncValue.loading();
    });

    try {
      final decision = await widget.client.evaluateL7(
        profile: profile,
        url: _lastUrl,
        method: _lastMethod,
        body: _bodyController.text.trim(),
      );
      if (!mounted) return;
      setState(() => _decision = AsyncValue.success(decision));
      widget.onEvaluationSucceeded();
    } catch (error) {
      if (!mounted) return;
      setState(() => _decision = AsyncValue.failure(error));
    }
  }

  Widget _buildRequestFields(AppLocalizations l10n) {
    final urlField = TextFormField(
      key: const Key('sim-url-field'),
      controller: _urlController,
      decoration: InputDecoration(
        labelText: l10n.simUrlLabel,
        border: const OutlineInputBorder(),
      ),
      keyboardType: TextInputType.url,
      validator: (value) =>
          value == null || value.trim().isEmpty ? l10n.simUrlRequired : null,
    );
    final methodField = DropdownButtonFormField<String>(
      key: const Key('sim-method-dropdown'),
      initialValue: _method,
      isExpanded: true,
      decoration: InputDecoration(
        labelText: l10n.simMethodLabel,
        border: const OutlineInputBorder(),
      ),
      items: [
        for (final method in _methods)
          DropdownMenuItem(value: method, child: Text(method)),
      ],
      onChanged: (value) => setState(() => _method = value ?? 'GET'),
    );

    // Single column on narrow (compact) widths, two columns when there is
    // genuinely room: a tablet/desktop screen is adapted, never stretched.
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 520) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              urlField,
              const SizedBox(height: 12),
              methodField,
            ],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(flex: 2, child: urlField),
            const SizedBox(width: 12),
            Expanded(child: methodField),
          ],
        );
      },
    );
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
            l10n.simulatorTitle,
            key: const Key('simulator-title'),
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
                    _buildProfileField(l10n),
                    const SizedBox(height: 12),
                    _buildRequestFields(l10n),
                    const SizedBox(height: 12),
                  TextFormField(
                    key: const Key('sim-body-field'),
                    controller: _bodyController,
                    minLines: 2,
                    maxLines: 4,
                    decoration: InputDecoration(
                      labelText: l10n.simBodyLabel,
                      helperText: l10n.simBodyHint,
                      border: const OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: [
                      ElevatedButton(
                        key: const Key('preset-allow-llm'),
                        onPressed: () => _applyPreset(
                          SimulatorPreset.allowLlm,
                        ),
                        child: Text(l10n.presetAllowLlm),
                      ),
                      OutlinedButton(
                        key: const Key('preset-block-doh'),
                        onPressed: () => _applyPreset(
                          SimulatorPreset.blockDoh,
                        ),
                        child: Text(l10n.presetBlockDoh),
                      ),
                      OutlinedButton(
                        key: const Key('preset-block-pypi-post'),
                        onPressed: () => _applyPreset(
                          SimulatorPreset.blockPyPiPost,
                        ),
                        child: Text(l10n.presetBlockPyPiPost),
                      ),
                      OutlinedButton(
                        key: const Key('preset-block-secret'),
                        onPressed: () => _applyPreset(
                          SimulatorPreset.blockSecret,
                        ),
                        child: Text(l10n.presetBlockSecret),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Semantics(
                    button: true,
                    enabled: !(_decision?.isLoading ?? false),
                    label: l10n.evaluateFlowButton,
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(
                        minWidth: 48,
                        minHeight: 48,
                      ),
                      child: FilledButton.icon(
                        key: const Key('evaluate-button'),
                        onPressed:
                            (_decision?.isLoading ?? false) ? null : _evaluate,
                        icon: (_decision?.isLoading ?? false)
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                ),
                              )
                            : const Icon(Icons.policy),
                        label: Text(l10n.evaluateFlowButton),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
        const SizedBox(height: 16),
        SimulatorResultCard(
          decision: _decision,
          lastMethod: _lastMethod,
          lastUrl: _lastUrl,
          baseUrl: widget.client.baseUrl,
          onRetry: _evaluate,
        ),
        ],
      ),
    );
  }

  Widget _buildProfileField(AppLocalizations l10n) {
    if (_profiles.isFailure) {
      return Row(
        children: [
          Expanded(
            child: Text(l10n.simProfileLabel),
          ),
          TextButton(
            key: const Key('sim-profile-retry'),
            onPressed: _loadProfiles,
            child: Text(l10n.retryLabel),
          ),
        ],
      );
    }

    final profiles = _profiles.data ?? const <CordonProfile>[];
    if (profiles.isEmpty) {
      return Text(l10n.simProfileEmpty);
    }

    return DropdownButtonFormField<String>(
      key: const Key('sim-profile-dropdown'),
      initialValue: _effectiveProfile,
      isExpanded: true,
      decoration: InputDecoration(
        labelText: l10n.simProfileLabel,
        border: const OutlineInputBorder(),
      ),
      items: [
        for (final profile in profiles)
          DropdownMenuItem(
            value: profile.name,
            child: Text(profile.name),
          ),
      ],
      onChanged: (value) {
        if (value != null) widget.onProfileChanged(value);
      },
    );
  }
}
