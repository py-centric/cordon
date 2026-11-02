/// Static client configuration for the Cordon control plane companion.
///
/// Values are compile-time constants overridable via `--dart-define` so
/// proprietary deployments can point at a remote control plane or supply an
/// API token without ever committing secrets to source control.
abstract final class AppConfig {
  /// Base URL of the axum control plane (default bind: `127.0.0.1:8095`).
  static const String apiBaseUrl = String.fromEnvironment(
    'CORDON_API_BASE_URL',
    defaultValue: 'http://127.0.0.1:8095',
  );

  /// Optional bearer token sent as `Authorization: Bearer <token>`.
  /// Empty (the default) sends no `Authorization` header at all.
  static const String apiToken = String.fromEnvironment(
    'CORDON_API_TOKEN',
    defaultValue: '',
  );

  /// Bounded per-request timeout for every control plane call.
  static const Duration requestTimeout = Duration(seconds: 10);
}
