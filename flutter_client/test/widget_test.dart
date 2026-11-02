import 'dart:async';
import 'dart:convert';

import 'package:cordon_flutter_client/main.dart';
import 'package:cordon_flutter_client/src/cordon_api_client.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const _jsonHeaders = {'content-type': 'application/json'};
const _problemHeaders = {'content-type': 'application/problem+json'};

final _healthBody = jsonEncode({
  'status': 'ok',
  'service': 'pycentric-cordon',
  'version': '1.0.0',
  'governing_adr': 'ADR-L0-SEC-02',
  'profiles_count': 2,
  'buffered_events': 3,
});

final _profileAiAgent = <String, dynamic>{
  'name': 'ai-agent',
  'kind': 'ai-agent',
  'description':
      'Local AI CLI coding agents with RW workspace, RO .git guard, and L3-L7 inspection.',
  'filesystem_mode': 'workspace_rw',
  'network_mode': 'inspected',
  'protect_git_dir': true,
};

final _profileUntrusted = <String, dynamic>{
  'name': 'untrusted-code',
  'kind': 'untrusted-code',
  'description': 'Arbitrary untrusted scripts with RO workspace and zero network.',
  'filesystem_mode': 'workspace_ro',
  'network_mode': 'none',
  'protect_git_dir': true,
};

String _profilesBody() => jsonEncode({
      'profiles': [_profileAiAgent, _profileUntrusted],
    });

String _emptyProfilesBody() => jsonEncode({'profiles': <Object>[]});

String _problemBody() => jsonEncode({
      'type': 'https://pycentric.co.za/errors/500',
      'title': 'Internal Server Error',
      'status': 500,
      'detail': 'Internal Server Error',
      'instance': '/api/v1/profiles',
      'trace_id': 'trace-xyz',
    });

String _decisionBody({
  String verdict = 'BLOCK',
  int status = 403,
  String rule = 'UNAUTHORIZED_MUTATING_METHOD',
  String url = 'https://pypi.org/legacy/',
  String method = 'POST',
}) =>
    jsonEncode({
      'verdict': verdict,
      'status_code': status,
      'reason': 'Blocked mutating HTTP method $method to read-only host (FR-5.4).',
      'matched_rule': rule,
      'url': url,
      'method': method,
      'evaluation_latency_us': 42,
    });

String _eventsBody() => jsonEncode({
      'events': [
        {
          'event_id': 'evt-1',
          'timestamp': '2026-10-31T10:00:00Z',
          'plane': 'mitmproxy',
          'severity': 'WARNING',
          'verdict': 'BLOCK',
          'profile': 'ai-agent',
          'subject': 'Blocked mutating HTTP method POST to read-only host (FR-5.4).',
          'details': {
            'url': 'https://pypi.org/legacy/',
            'rule': 'UNAUTHORIZED_MUTATING_METHOD',
          },
        },
      ],
    });

String _emptyEventsBody() => jsonEncode({'events': <Object>[]});

String _planBody() => jsonEncode({
      'profile_name': 'ai-agent',
      'workload_kind': 'ai-agent',
      'canonical_workspace': '/home/v/work',
      'bwrap_argv': ['bwrap', '--ro-bind', '/', '/'],
      'netns_exec_argv': ['ip', 'netns', 'exec', 'agent-net'],
      'full_argv': ['ip', 'netns', 'exec', 'agent-net', 'bwrap', '--ro-bind', '/', '/'],
      'masked_binaries': ['/usr/bin/docker'],
      'env_overrides': {'OPENCODE_SANDBOX': 'cordon'},
      'gates_applied': ['bwrap', 'apparmor', 'netns', 'mitmproxy', 'tshark'],
      'network_mode': 'inspected',
      'filesystem_mode': 'workspace_rw',
    });

/// Scriptable fake of the Cordon control plane for widget tests.
class FakeCordon {
  FakeCordon();

  int healthCalls = 0;
  int profilesCalls = 0;
  int eventsCalls = 0;
  int evaluateCalls = 0;
  int compileCalls = 0;

  http.Request? lastEvaluate;
  http.Request? lastCompile;

  FutureOr<http.Response> Function()? profilesHandler;
  FutureOr<http.Response> Function()? eventsHandler;
  FutureOr<http.Response> Function(http.Request request)? evaluateHandler;
  FutureOr<http.Response> Function(http.Request request)? compileHandler;

  Future<http.Response> handle(http.Request request) async {
    final path = request.url.path;
    if (path == '/healthz') {
      healthCalls++;
      return http.Response(_healthBody, 200, headers: _jsonHeaders);
    }
    if (path == '/api/v1/profiles') {
      profilesCalls++;
      return profilesHandler?.call() ??
          http.Response(_profilesBody(), 200, headers: _jsonHeaders);
    }
    if (path == '/api/v1/events') {
      eventsCalls++;
      return eventsHandler?.call() ??
          http.Response(_eventsBody(), 200, headers: _jsonHeaders);
    }
    if (path == '/api/v1/evaluate-l7') {
      evaluateCalls++;
      lastEvaluate = request;
      return evaluateHandler?.call(request) ??
          http.Response(_decisionBody(), 200, headers: _jsonHeaders);
    }
    if (path == '/api/v1/compile-config') {
      compileCalls++;
      lastCompile = request;
      return compileHandler?.call(request) ??
          http.Response(_planBody(), 200, headers: _jsonHeaders);
    }
    return http.Response(_problemBody(), 404, headers: _problemHeaders);
  }

  CordonApiClient buildClient() => CordonApiClient(
        client: MockClient(handle),
        baseUrl: 'http://cordon.test',
      );
}

Future<void> _pumpApp(
  WidgetTester tester,
  FakeCordon fake, {
  Size size = const Size(1280, 900),
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(CordonCompanionApp(apiClient: fake.buildClient()));
}

Finder _navTap(Finder container, IconData icon) =>
    find.descendant(of: container, matching: find.byIcon(icon));

void main() {
  testWidgets(
    'Compact viewport uses bottom NavigationBar and routes each tab to a distinct pane',
    (WidgetTester tester) async {
      final fake = FakeCordon();
      await _pumpApp(tester, fake, size: const Size(400, 800));
      await tester.pumpAndSettle();

      expect(find.byType(NavigationBar), findsOneWidget);
      expect(find.byType(NavigationRail), findsNothing);
      expect(find.byType(NavigationDrawer), findsNothing);
      expect(find.byKey(const Key('health-indicator')), findsOneWidget);
      expect(find.byKey(const Key('pycentric-attribution-footer')), findsOneWidget);
      expect(find.byKey(const Key('profiles-title')), findsOneWidget);
      expect(find.text('Control plane online (v1.0.0)'), findsOneWidget);

      // Navigation must route _selectedIndex to genuinely different panes.
      await tester.tap(_navTap(find.byType(NavigationBar), Icons.layers));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('gates-title')), findsOneWidget);
      expect(find.byKey(const Key('gate-button-0')), findsOneWidget);
      expect(find.byKey(const Key('profiles-title')), findsNothing);

      await tester.tap(_navTap(find.byType(NavigationBar), Icons.network_check));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('simulator-title')), findsOneWidget);
      expect(find.byKey(const Key('sim-idle-prompt')), findsOneWidget);

      await tester.tap(_navTap(find.byType(NavigationBar), Icons.description));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('config-title')), findsOneWidget);

      await tester.tap(_navTap(find.byType(NavigationBar), Icons.receipt_long));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('events-title')), findsOneWidget);
      expect(find.byKey(const Key('events-list')), findsOneWidget);
    },
  );

  testWidgets(
    'Medium viewport (600-840dp) switches to NavigationRail with 2-column grid',
    (WidgetTester tester) async {
      final fake = FakeCordon();
      await _pumpApp(tester, fake, size: const Size(700, 900));
      await tester.pumpAndSettle();

      expect(find.byType(NavigationRail), findsOneWidget);
      expect(find.byType(NavigationBar), findsNothing);
      expect(find.byType(NavigationDrawer), findsNothing);

      final rail = tester.widget<NavigationRail>(find.byType(NavigationRail));
      expect(rail.extended, isFalse);

      final grid = tester.widget<GridView>(find.byKey(const Key('profiles-grid')));
      final delegate = grid.gridDelegate as SliverGridDelegateWithFixedCrossAxisCount;
      expect(delegate.crossAxisCount, 2);
    },
  );

  testWidgets(
    'Expanded viewport (> 840dp) switches to permanent NavigationDrawer with 3-column grid',
    (WidgetTester tester) async {
      final fake = FakeCordon();
      await _pumpApp(tester, fake, size: const Size(1280, 900));
      await tester.pumpAndSettle();

      expect(find.byType(NavigationDrawer), findsOneWidget);
      expect(find.byType(NavigationRail), findsNothing);
      expect(find.byType(NavigationBar), findsNothing);
      expect(find.text('5-Gate Kernel Sandbox & L3-L7 Network Inspection'),
          findsOneWidget);

      final grid = tester.widget<GridView>(find.byKey(const Key('profiles-grid')));
      final delegate = grid.gridDelegate as SliverGridDelegateWithFixedCrossAxisCount;
      expect(delegate.crossAxisCount, 3);

      // Sidebar routing works the same as the rail/bar.
      await tester.tap(_navTap(find.byType(NavigationDrawer), Icons.receipt_long));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('events-title')), findsOneWidget);
    },
  );

  testWidgets(
    'Theme menu changes ThemeData colors across Light, Dark and High Contrast',
    (WidgetTester tester) async {
      final fake = FakeCordon();
      await _pumpApp(tester, fake, size: const Size(1024, 800));
      await tester.pumpAndSettle();

      Future<ThemeData> themeAfter(String label) async {
        await tester.tap(find.byKey(const Key('display-menu')));
        await tester.pumpAndSettle();
        await tester.tap(find.text(label));
        await tester.pumpAndSettle();
        final app = tester.widget<MaterialApp>(find.byType(MaterialApp));
        return app.theme!;
      }

      final light = await themeAfter('Light');
      final dark = await themeAfter('Dark');
      final highContrast = await themeAfter('High Contrast (7:1)');

      // Brightness flips with the toggle.
      expect(light.brightness, Brightness.light);
      expect(dark.brightness, Brightness.dark);
      expect(highContrast.brightness, Brightness.dark);

      // High Contrast is a real 7:1 palette, not a label swap.
      expect(highContrast.scaffoldBackgroundColor, Colors.black);
      expect(highContrast.colorScheme.primary, const Color(0xFFFFFF00));
      expect(highContrast.colorScheme.onSurface, Colors.white);

      // All three presets render genuinely different surfaces.
      expect(
        {
          light.scaffoldBackgroundColor,
          dark.scaffoldBackgroundColor,
          highContrast.scaffoldBackgroundColor,
        },
        hasLength(3),
      );
      expect(light.colorScheme.primary, isNot(dark.colorScheme.primary));

      // Live BuildContext theme agrees with the MaterialApp theme.
      final live = Theme.of(tester.element(find.byKey(const Key('health-indicator'))));
      expect(live.scaffoldBackgroundColor, Colors.black);

      // Constitutional 48x48dp minimum touch targets are theme-enforced.
      expect(
        highContrast.elevatedButtonTheme.style?.minimumSize
            ?.resolve(const <WidgetState>{}),
        const Size(48, 48),
      );
      expect(
        light.outlinedButtonTheme.style?.minimumSize
            ?.resolve(const <WidgetState>{}),
        const Size(48, 48),
      );
    },
  );

  testWidgets(
    'Locale toggle cycles en -> af -> zu and relocalizes visible strings',
    (WidgetTester tester) async {
      final fake = FakeCordon();
      await _pumpApp(tester, fake, size: const Size(1024, 800));
      await tester.pumpAndSettle();

      expect(
        find.descendant(
          of: find.byType(AppBar),
          matching: find.text('Cordon Control Plane'),
        ),
        findsOneWidget,
      );
      expect(find.text('EN'), findsOneWidget);

      await tester.tap(find.byKey(const Key('locale-toggle')));
      await tester.pumpAndSettle();
      expect(
        find.descendant(
          of: find.byType(AppBar),
          matching: find.text('Cordon Beheerplatform'),
        ),
        findsOneWidget,
      );
      expect(find.text('Profiele'), findsOneWidget);
      expect(find.text('AF'), findsOneWidget);

      await tester.tap(find.byKey(const Key('locale-toggle')));
      await tester.pumpAndSettle();
      expect(
        find.descendant(
          of: find.byType(AppBar),
          matching: find.text('Isistimu Yokulawula ye-Cordon'),
        ),
        findsOneWidget,
      );
      expect(find.text('Ama-Profile'), findsOneWidget);
      expect(find.text('ZU'), findsOneWidget);

      await tester.tap(find.byKey(const Key('locale-toggle')));
      await tester.pumpAndSettle();
      expect(
        find.descendant(
          of: find.byType(AppBar),
          matching: find.text('Cordon Control Plane'),
        ),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'Profiles pane shows Loading skeleton, then API-sourced data',
    (WidgetTester tester) async {
      final gate = Completer<http.Response>();
      final fake = FakeCordon()..profilesHandler = () => gate.future;

      await _pumpApp(tester, fake, size: const Size(800, 900));
      await tester.pump();

      // Loading state before the response resolves.
      expect(find.byKey(const Key('loading-indicator')), findsOneWidget);

      gate.complete(http.Response(_profilesBody(), 200, headers: _jsonHeaders));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('profiles-grid')), findsOneWidget);
      expect(find.text('ai-agent'), findsOneWidget);
      expect(find.text('untrusted-code'), findsOneWidget);
      expect(
        find.text('FS: workspace_rw | NET: inspected | .git RO: true'),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'Profiles pane shows an actionable error state and Retry recovers',
    (WidgetTester tester) async {
      var failing = true;
      final fake = FakeCordon()
        ..profilesHandler = () {
          if (failing) {
            failing = false;
            return http.Response(_problemBody(), 500, headers: _problemHeaders);
          }
          return http.Response(_profilesBody(), 200, headers: _jsonHeaders);
        };

      await _pumpApp(tester, fake, size: const Size(800, 900));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('error-state-view')), findsOneWidget);
      expect(find.byKey(const Key('retry-button')), findsOneWidget);
      expect(find.textContaining('HTTP 500'), findsOneWidget);

      await tester.tap(find.byKey(const Key('retry-button')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('profiles-grid')), findsOneWidget);
      expect(find.text('ai-agent'), findsOneWidget);
    },
  );

  testWidgets(
    'Profiles pane shows a meaningful empty state on an empty catalog',
    (WidgetTester tester) async {
      final fake = FakeCordon()
        ..profilesHandler = () =>
            http.Response(_emptyProfilesBody(), 200, headers: _jsonHeaders);

      await _pumpApp(tester, fake, size: const Size(800, 900));
      await tester.pumpAndSettle();

      expect(
        find.text('No sandbox profiles are registered on this control plane.'),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'Evaluate flow posts to /api/v1/evaluate-l7 and renders the real verdict',
    (WidgetTester tester) async {
      final fake = FakeCordon()
        ..evaluateHandler = (request) {
          final body = jsonDecode(request.body) as Map<String, dynamic>;
          return http.Response(
            _decisionBody(url: body['url'] as String, method: body['method'] as String),
            200,
            headers: _jsonHeaders,
          );
        };

      await _pumpApp(tester, fake, size: const Size(1280, 900));
      await tester.pumpAndSettle();

      await tester.tap(_navTap(find.byType(NavigationDrawer), Icons.network_check));
      await tester.pumpAndSettle();

      await tester.enterText(
        find.byKey(const Key('sim-url-field')),
        'https://pypi.org/legacy/',
      );
      await tester.tap(find.byKey(const Key('evaluate-button')));
      await tester.pumpAndSettle();

      // Real PolicyDecision rendered from the API response.
      expect(
        find.text('BLOCK (403) | Rule: UNAUTHORIZED_MUTATING_METHOD'),
        findsOneWidget,
      );
      expect(find.byKey(const Key('l7-verdict-text')), findsOneWidget);
      expect(find.text('Evaluation latency: 42 us'), findsOneWidget);
      expect(find.textContaining('FR-5.4'), findsOneWidget);

      // Request matched the documented v1 wire shape (no canned verdicts).
      expect(fake.evaluateCalls, 1);
      final sent = jsonDecode(fake.lastEvaluate!.body) as Map<String, dynamic>;
      expect(sent['profile'], 'ai-agent');
      expect(sent['url'], 'https://pypi.org/legacy/');
      expect(sent['method'], 'POST');
      expect(fake.lastEvaluate!.headers.containsKey('Authorization'), isFalse);

      // Telemetry epoch bump: the Audit Stream pane re-polls events.
      await tester.tap(_navTap(find.byType(NavigationDrawer), Icons.receipt_long));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('events-list')), findsOneWidget);
      expect(find.textContaining('Blocked mutating HTTP method'), findsOneWidget);
    },
  );

  testWidgets(
    'Preset buttons pre-fill the form and drive a live policy evaluation',
    (WidgetTester tester) async {
      final fake = FakeCordon();

      await _pumpApp(tester, fake, size: const Size(1280, 900));
      await tester.pumpAndSettle();

      await tester.tap(_navTap(find.byType(NavigationDrawer), Icons.network_check));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('preset-block-pypi-post')));
      await tester.pumpAndSettle();

      // The preset filled the form and the verdict came from the API call.
      expect(fake.evaluateCalls, 1);
      final sent = jsonDecode(fake.lastEvaluate!.body) as Map<String, dynamic>;
      expect(sent['url'], 'https://pypi.org/legacy/');
      expect(sent['method'], 'POST');
      expect(sent['body'], 'exfiltrated_archive_payload');
      expect(
        find.text('BLOCK (403) | Rule: UNAUTHORIZED_MUTATING_METHOD'),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'Simulator validates the URL field client-side before any request',
    (WidgetTester tester) async {
      final fake = FakeCordon();

      await _pumpApp(tester, fake, size: const Size(1280, 900));
      await tester.pumpAndSettle();

      await tester.tap(_navTap(find.byType(NavigationDrawer), Icons.network_check));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('evaluate-button')));
      await tester.pumpAndSettle();

      expect(find.text('Target URL is required'), findsOneWidget);
      expect(fake.evaluateCalls, 0);
    },
  );

  testWidgets(
    'Audit Stream pane shows empty state and error state with Retry',
    (WidgetTester tester) async {
      final fake = FakeCordon()
        ..eventsHandler = () =>
            http.Response(_emptyEventsBody(), 200, headers: _jsonHeaders);

      await _pumpApp(tester, fake, size: const Size(1280, 900));
      await tester.pumpAndSettle();
      await tester.tap(_navTap(find.byType(NavigationDrawer), Icons.receipt_long));
      await tester.pumpAndSettle();

      expect(
        find.text(
          'No audit events recorded yet. Evaluate an L7 flow to generate telemetry.',
        ),
        findsOneWidget,
      );

      fake.eventsHandler = () =>
          http.Response(_problemBody(), 503, headers: _problemHeaders);
      await tester.tap(find.byKey(const Key('events-refresh')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('error-state-view')), findsOneWidget);
      await tester.tap(find.byKey(const Key('retry-button')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('error-state-view')), findsOneWidget);
    },
  );

  testWidgets(
    'Config pane compiles a Cordonfile through the API and renders the plan',
    (WidgetTester tester) async {
      final fake = FakeCordon();

      await _pumpApp(tester, fake, size: const Size(1280, 900));
      await tester.pumpAndSettle();

      await tester.tap(_navTap(find.byType(NavigationDrawer), Icons.description));
      await tester.pumpAndSettle();

      await tester.enterText(
        find.byKey(const Key('config-content-field')),
        'FROM ai-agent\nWORKDIR .\nCMD ["opencode"]',
      );
      await tester.tap(find.byKey(const Key('compile-button')));
      await tester.pumpAndSettle();

      expect(find.text('Profile: ai-agent'), findsOneWidget);
      expect(find.text('Workspace: /home/v/work'), findsOneWidget);
      expect(
        find.text('Gates Applied: bwrap, apparmor, netns, mitmproxy, tshark'),
        findsOneWidget,
      );
      expect(
        find.text('ip netns exec agent-net bwrap --ro-bind / /'),
        findsOneWidget,
      );

      final sent = jsonDecode(fake.lastCompile!.body) as Map<String, dynamic>;
      expect(sent['format'], 'cordonfile');
      expect(sent['config_content'], contains('FROM ai-agent'));
    },
  );
}
