import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'app_config.dart';
import 'models.dart';

/// Failure class for an API call: connection failure, timeout, RFC 7807
/// problem details payload, or an unexpected (non-JSON) response body.
enum CordonApiErrorKind {
  /// TCP/TLS connection could not be established (server down, wrong port).
  connection,

  /// The request exceeded the configured timeout.
  timeout,

  /// The server answered with an RFC 7807 `application/problem+json` payload.
  server,

  /// The server answered with an unexpected or unparseable payload.
  protocol,
}

/// RFC 7807 `application/problem+json` payload (`src/error.rs`).
class ProblemDetails {
  const ProblemDetails({
    required this.type,
    required this.title,
    required this.status,
    required this.detail,
    required this.instance,
    required this.traceId,
  });

  final String type;
  final String title;
  final int status;
  final String detail;
  final String instance;
  final String traceId;

  factory ProblemDetails.fromJson(Map<String, dynamic> json) => ProblemDetails(
        type: json['type'] is String ? json['type'] as String : '',
        title: json['title'] is String ? json['title'] as String : '',
        status: json['status'] is num ? (json['status'] as num).toInt() : 0,
        detail: json['detail'] is String ? json['detail'] as String : '',
        instance: json['instance'] is String ? json['instance'] as String : '',
        traceId: json['trace_id'] is String ? json['trace_id'] as String : '',
      );
}

/// Typed exception raised by [CordonApiClient].
class CordonApiException implements Exception {
  CordonApiException(
    this.message, {
    required this.kind,
    this.statusCode,
    this.problem,
  });

  /// Human-readable fallback description (English; UI localizes by [kind]).
  final String message;
  final CordonApiErrorKind kind;
  final int? statusCode;
  final ProblemDetails? problem;

  @override
  String toString() => 'CordonApiException(${kind.name}): $message';
}

/// HTTP client for the Cordon axum control plane (default `127.0.0.1:8095`).
///
/// Every request carries a bounded timeout and, when configured, an optional
/// `Authorization: Bearer <token>` header (empty token = no header, so the
/// client works with and without API auth).
class CordonApiClient {
  CordonApiClient({
    http.Client? client,
    String? baseUrl,
    String? apiToken,
    this.timeout = AppConfig.requestTimeout,
  })  : _client = client ?? http.Client(),
        baseUrl = (baseUrl ?? AppConfig.apiBaseUrl).replaceAll(RegExp(r'/+$'), ''),
        apiToken = apiToken ?? AppConfig.apiToken;

  final http.Client _client;

  /// Control plane base URL without trailing slash.
  final String baseUrl;

  /// Optional bearer token; empty disables the `Authorization` header.
  final String apiToken;

  /// Per-request timeout applied to every call.
  final Duration timeout;

  /// Releases the underlying HTTP client (only when owned by this instance).
  void dispose() => _client.close();

  Map<String, String> _headers({bool jsonBody = false}) => {
        'Accept': 'application/json',
        if (jsonBody) 'Content-Type': 'application/json',
        if (apiToken.isNotEmpty) 'Authorization': 'Bearer $apiToken',
      };

  /// `GET /healthz` -> [HealthResponse].
  Future<HealthResponse> fetchHealth() async {
    final json = await _getJson('/healthz');
    return HealthResponse.fromJson(json);
  }

  /// `GET /api/v1/profiles` -> `ProfilesResponse.profiles`.
  Future<List<CordonProfile>> fetchProfiles() async {
    final json = await _getJson('/api/v1/profiles');
    final raw = json['profiles'];
    if (raw is List) {
      return raw
          .whereType<Map<String, dynamic>>()
          .map(CordonProfile.fromJson)
          .toList(growable: false);
    }
    return const [];
  }

  /// Resolves a single profile by name.
  ///
  /// NOTE: the v1.0.0 router serves no `GET /api/v1/profiles/{name}` route
  /// (see docs/FLUTTER_UI_UX_SIGNOFF.md, API findings), so the catalog is
  /// fetched and filtered client-side. Throws [CordonApiException] with
  /// `statusCode: 404` when the profile is unknown.
  Future<CordonProfile> fetchProfile(String name) async {
    final profiles = await fetchProfiles();
    for (final profile in profiles) {
      if (profile.name == name) return profile;
    }
    throw CordonApiException(
      'Unknown profile "$name"',
      kind: CordonApiErrorKind.server,
      statusCode: 404,
    );
  }

  /// `POST /api/v1/evaluate-l7` -> [PolicyDecision].
  Future<PolicyDecision> evaluateL7({
    required String profile,
    required String url,
    String method = 'GET',
    String? body,
  }) async {
    final json = await _postJson('/api/v1/evaluate-l7', {
      'profile': profile,
      'url': url,
      'method': method,
      if (body != null && body.isNotEmpty) 'body': body,
    });
    return PolicyDecision.fromJson(json);
  }

  /// `POST /api/v1/compile-config` -> [SandboxLaunchPlan].
  Future<SandboxLaunchPlan> compileConfig({
    required String configContent,
    String format = 'cordonfile',
    String? workspaceOverride,
    List<String> commandOverride = const [],
  }) async {
    final json = await _postJson('/api/v1/compile-config', {
      'config_content': configContent,
      'format': format,
      if (workspaceOverride != null && workspaceOverride.isNotEmpty)
        'workspace_override': workspaceOverride,
      'command_override': commandOverride,
    });
    return SandboxLaunchPlan.fromJson(json);
  }

  /// `GET /api/v1/events?limit=N` -> `EventsResponse.events`.
  Future<List<AuditEvent>> fetchEvents({int limit = 50}) async {
    final json = await _getJson('/api/v1/events?limit=$limit');
    final raw = json['events'];
    if (raw is List) {
      return raw
          .whereType<Map<String, dynamic>>()
          .map(AuditEvent.fromJson)
          .toList(growable: false);
    }
    return const [];
  }

  Future<Map<String, dynamic>> _getJson(String path) =>
      _send(() => _client.get(Uri.parse('$baseUrl$path'), headers: _headers()));

  Future<Map<String, dynamic>> _postJson(
    String path,
    Map<String, dynamic> payload,
  ) =>
      _send(
        () => _client.post(
          Uri.parse('$baseUrl$path'),
          headers: _headers(jsonBody: true),
          body: jsonEncode(payload),
        ),
      );

  Future<Map<String, dynamic>> _send(
    Future<http.Response> Function() operation,
  ) async {
    http.Response response;
    try {
      response = await operation().timeout(timeout);
    } on TimeoutException {
      throw CordonApiException(
        'Request to $baseUrl timed out after ${timeout.inMilliseconds} ms',
        kind: CordonApiErrorKind.timeout,
      );
    } on http.ClientException catch (error) {
      throw CordonApiException(
        'Cannot reach control plane at $baseUrl: ${error.message}',
        kind: CordonApiErrorKind.connection,
      );
    }

    return _decode(response);
  }

  Map<String, dynamic> _decode(http.Response response) {
    final raw = response.body.trim();
    Map<String, dynamic>? json;
    if (raw.isNotEmpty) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) json = decoded;
      } on FormatException {
        json = null;
      }
    }

    if (response.statusCode >= 400) {
      final problem =
          json == null ? null : ProblemDetails.fromJson(json);
      throw CordonApiException(
        problem?.detail ?? 'HTTP ${response.statusCode}',
        kind: CordonApiErrorKind.server,
        statusCode: response.statusCode,
        problem: problem,
      );
    }

    if (json == null) {
      throw CordonApiException(
        'Unparseable response body (HTTP ${response.statusCode})',
        kind: CordonApiErrorKind.protocol,
        statusCode: response.statusCode,
      );
    }
    return json;
  }
}
