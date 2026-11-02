import 'dart:convert';

import 'package:cordon_flutter_client/src/cordon_api_client.dart';
import 'package:cordon_flutter_client/src/models.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

void main() {
  const base = 'http://cordon.test';
  const jsonHeaders = {'content-type': 'application/json'};
  const problemHeaders = {'content-type': 'application/problem+json'};

  final profileFixture = <String, dynamic>{
    'name': 'ai-agent',
    'kind': 'ai-agent',
    'description': 'Local AI CLI coding agents.',
    'filesystem_mode': 'workspace_rw',
    'network_mode': 'inspected',
    'netns_name': 'agent-net',
    'subnet_cidr': '10.200.1.0/24',
    'mitm_port': 8080,
    'allowed_domains': ['api.openai.com'],
    'post_allowed_hosts': ['api.openai.com'],
    'denied_domains': ['pastebin.com'],
    'protect_git_dir': true,
    'block_doh': true,
    'inspect_body_secrets': true,
    'unshare_pid': true,
    'unshare_ipc': true,
  };

  final decisionFixture = <String, dynamic>{
    'verdict': 'BLOCK',
    'status_code': 403,
    'reason': 'Blocked mutating HTTP method POST to read-only host (FR-5.4).',
    'matched_rule': 'UNAUTHORIZED_MUTATING_METHOD',
    'url': 'https://pypi.org/legacy/',
    'method': 'POST',
    'evaluation_latency_us': 42,
  };

  final eventFixture = <String, dynamic>{
    'event_id': 'evt-1',
    'timestamp': '2026-10-31T10:00:00Z',
    'plane': 'mitmproxy',
    'severity': 'WARNING',
    'verdict': 'BLOCK',
    'profile': 'ai-agent',
    'subject': 'Blocked mutating HTTP method POST (FR-5.4).',
    'details': {'url': 'https://pypi.org/legacy/', 'rule': 'UNAUTHORIZED_MUTATING_METHOD'},
  };

  final planFixture = <String, dynamic>{
    'profile_name': 'ai-agent',
    'workload_kind': 'ai-agent',
    'canonical_workspace': '/home/v/work',
    'bwrap_argv': ['bwrap', '--ro-bind', '/', '/'],
    'netns_exec_argv': ['ip', 'netns', 'exec', 'agent-net'],
    'full_argv': ['ip', 'netns', 'exec', 'agent-net', 'bwrap'],
    'masked_binaries': ['/usr/bin/docker'],
    'env_overrides': {'OPENCODE_SANDBOX': 'cordon'},
    'gates_applied': ['bwrap', 'apparmor', 'netns', 'mitmproxy', 'tshark'],
    'network_mode': 'inspected',
    'filesystem_mode': 'workspace_rw',
  };

  final problemFixture = <String, dynamic>{
    'type': 'https://pycentric.co.za/errors/400',
    'title': 'Bad Request',
    'status': 400,
    'detail': 'Validation error: Invalid profile name',
    'instance': '/api/v1/evaluate-l7',
    'trace_id': 'trace-123',
  };

  group('CordonApiClient', () {
    test('fetchProfiles parses the profiles catalog', () async {
      final client = CordonApiClient(
        client: MockClient((request) async => http.Response(
              jsonEncode({'profiles': [profileFixture]}),
              200,
              headers: jsonHeaders,
            )),
        baseUrl: base,
      );

      final profiles = await client.fetchProfiles();
      expect(profiles, hasLength(1));
      expect(profiles.first.name, 'ai-agent');
      expect(profiles.first.filesystemMode, 'workspace_rw');
      expect(profiles.first.networkMode, 'inspected');
      expect(profiles.first.protectGitDir, isTrue);
      expect(profiles.first.allowedDomains, ['api.openai.com']);
    });

    test('evaluateL7 posts the exact v1 request shape and parses the decision',
        () async {
      http.Request? captured;
      final client = CordonApiClient(
        client: MockClient((request) async {
          captured = request;
          return http.Response(
            jsonEncode(decisionFixture),
            200,
            headers: jsonHeaders,
          );
        }),
        baseUrl: base,
      );

      final decision = await client.evaluateL7(
        profile: 'package-build',
        url: 'https://pypi.org/legacy/',
        method: 'POST',
        body: 'payload',
      );

      expect(captured!.method, 'POST');
      expect(captured!.url.path, '/api/v1/evaluate-l7');
      final body = jsonDecode(captured!.body) as Map<String, dynamic>;
      expect(body, {
        'profile': 'package-build',
        'url': 'https://pypi.org/legacy/',
        'method': 'POST',
        'body': 'payload',
      });
      expect(decision.verdict, PolicyVerdict.block);
      expect(decision.statusCode, 403);
      expect(decision.matchedRule, 'UNAUTHORIZED_MUTATING_METHOD');
      expect(decision.evaluationLatencyUs, 42);
    });

    test('sends Authorization bearer header only when a token is configured',
        () async {
      http.Request? withToken;
      http.Request? withoutToken;

      final authenticated = CordonApiClient(
        client: MockClient((request) async {
          withToken = request;
          return http.Response(
              jsonEncode({'profiles': []}), 200, headers: jsonHeaders);
        }),
        baseUrl: base,
        apiToken: 'secret-token',
      );
      await authenticated.fetchProfiles();

      final anonymous = CordonApiClient(
        client: MockClient((request) async {
          withoutToken = request;
          return http.Response(
              jsonEncode({'profiles': []}), 200, headers: jsonHeaders);
        }),
        baseUrl: base,
        apiToken: '',
      );
      await anonymous.fetchProfiles();

      expect(withToken!.headers['Authorization'], 'Bearer secret-token');
      expect(withoutToken!.headers.containsKey('Authorization'), isFalse);
    });

    test('maps RFC 7807 problem+json to CordonApiException', () async {
      final client = CordonApiClient(
        client: MockClient((request) async => http.Response(
              jsonEncode(problemFixture),
              400,
              headers: problemHeaders,
            )),
        baseUrl: base,
      );

      try {
        await client.evaluateL7(profile: 'ai-agent', url: 'https://x.test');
        fail('expected CordonApiException');
      } on CordonApiException catch (error) {
        expect(error.kind, CordonApiErrorKind.server);
        expect(error.statusCode, 400);
        expect(error.problem?.title, 'Bad Request');
        expect(error.problem?.detail, 'Validation error: Invalid profile name');
        expect(error.problem?.traceId, 'trace-123');
      }
    });

    test('maps connection failures to CordonApiErrorKind.connection', () async {
      final client = CordonApiClient(
        client: MockClient((request) async {
          throw http.ClientException('Connection refused');
        }),
        baseUrl: base,
      );

      expect(
        () => client.fetchHealth(),
        throwsA(isA<CordonApiException>().having(
          (error) => error.kind,
          'kind',
          CordonApiErrorKind.connection,
        )),
      );
    });

    test('maps slow responses to CordonApiErrorKind.timeout', () async {
      final client = CordonApiClient(
        client: MockClient((request) async {
          await Future<void>.delayed(const Duration(milliseconds: 250));
          return http.Response('{}', 200, headers: jsonHeaders);
        }),
        baseUrl: base,
        timeout: const Duration(milliseconds: 40),
      );

      expect(
        () => client.fetchEvents(),
        throwsA(isA<CordonApiException>().having(
          (error) => error.kind,
          'kind',
          CordonApiErrorKind.timeout,
        )),
      );
    });

    test('fetchProfile resolves by name and 404s on unknown slugs', () async {
      final client = CordonApiClient(
        client: MockClient((request) async => http.Response(
              jsonEncode({'profiles': [profileFixture]}),
              200,
              headers: jsonHeaders,
            )),
        baseUrl: base,
      );

      final profile = await client.fetchProfile('ai-agent');
      expect(profile.name, 'ai-agent');

      expect(
        () => client.fetchProfile('nope'),
        throwsA(isA<CordonApiException>()
            .having((error) => error.statusCode, 'statusCode', 404)),
      );
    });

    test('fetchHealth, fetchEvents and compileConfig parse typed models',
        () async {
      final client = CordonApiClient(
        client: MockClient((request) async {
          if (request.url.path == '/healthz') {
            return http.Response(
              jsonEncode({
                'status': 'ok',
                'service': 'pycentric-cordon',
                'version': '1.0.0',
                'governing_adr': 'ADR-L0-SEC-02',
                'profiles_count': 6,
                'buffered_events': 12,
              }),
              200,
              headers: jsonHeaders,
            );
          }
          if (request.url.path == '/api/v1/events') {
            expect(request.url.queryParameters['limit'], '10');
            return http.Response(
              jsonEncode({
                'events': [eventFixture]
              }),
              200,
              headers: jsonHeaders,
            );
          }
          return http.Response(jsonEncode(planFixture), 200,
              headers: jsonHeaders);
        }),
        baseUrl: base,
      );

      final health = await client.fetchHealth();
      expect(health.service, 'pycentric-cordon');
      expect(health.profilesCount, 6);
      expect(health.bufferedEvents, 12);

      final events = await client.fetchEvents(limit: 10);
      expect(events.single.verdict, PolicyVerdict.block);
      expect(events.single.plane, EnforcementPlane.mitmproxy);
      expect(events.single.severity, EventSeverity.warning);
      expect(events.single.details['rule'], 'UNAUTHORIZED_MUTATING_METHOD');

      final plan = await client.compileConfig(
        configContent: 'FROM ai-agent',
        format: 'toml',
      );
      expect(plan.profileName, 'ai-agent');
      expect(plan.gatesApplied, hasLength(5));
      expect(plan.fullArgv, contains('bwrap'));
      expect(plan.envOverrides['OPENCODE_SANDBOX'], 'cordon');
    });

    test('omits empty body field and normalizes trailing slash on base URL',
        () async {
      http.Request? captured;
      final client = CordonApiClient(
        client: MockClient((request) async {
          captured = request;
          return http.Response(
            jsonEncode(decisionFixture),
            200,
            headers: jsonHeaders,
          );
        }),
        baseUrl: 'http://cordon.test/',
      );

      await client.evaluateL7(
        profile: 'ai-agent',
        url: 'https://api.openai.com/v1/chat/completions',
        method: 'POST',
        body: '',
      );

      final body = jsonDecode(captured!.body) as Map<String, dynamic>;
      expect(body.containsKey('body'), isFalse);
      expect(captured!.url.toString(), 'http://cordon.test/api/v1/evaluate-l7');
    });

    test('unparseable success bodies raise CordonApiErrorKind.protocol',
        () async {
      final client = CordonApiClient(
        client: MockClient((request) async => http.Response('<html/>', 200)),
        baseUrl: base,
      );

      expect(
        () => client.fetchProfiles(),
        throwsA(isA<CordonApiException>().having(
          (error) => error.kind,
          'kind',
          CordonApiErrorKind.protocol,
        )),
      );
    });
  });

  group('Models', () {
    test('tolerate unknown enum wire values and missing fields', () async {
      final decision = PolicyDecision.fromJson(const {});
      expect(decision.verdict, PolicyVerdict.audit);
      expect(decision.statusCode, 0);

      final event = AuditEvent.fromJson(const {
        'verdict': 'ALLOW',
        'severity': 'CRITICAL',
        'plane': 'tshark',
        'subject': 'ok',
      });
      expect(event.verdict, PolicyVerdict.allow);
      expect(event.severity, EventSeverity.critical);
      expect(event.plane, EnforcementPlane.tshark);
      expect(event.details, isEmpty);
    });
  });
}
