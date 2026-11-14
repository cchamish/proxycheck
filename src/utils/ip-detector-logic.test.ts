import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveCommitMetadata } from '../../vite.config';
import {
  REQUIRED_USER_RIGHTS,
  REQUIRED_USER_RIGHTS_SUMMARY,
  isValidIpAddress,
  canonicalizeIpAddress,
  extractCanonicalIpFromSearch,
  buildOAuthLoginUrl,
  buildPageUrlWithIp,
  updateIpHistory,
  filterComparisonResults,
  simplifySecurityFlags,
  createDetectionCoordinator,
  resolveRepoBaseUrl,
  formatUtcCommitTimestamp,
  formatCommitVersionLabel,
  buildDiagnosticMetrics,
  formatDiagnosticSummary,
  measureInitialLoadDurationSeconds,
  measureElapsedSeconds,
  type DetectionCoordinatorState,
  type ProviderRawResult,
} from './ip-detector-logic';

function makeProviderResult(provider: ProviderRawResult['provider']): ProviderRawResult {
  return {
    provider,
    status: 'OK',
    statusCode: 200,
    asn: '-',
    isp: '-',
    organisation: '-',
    location: '-',
    usageType: '-',
    securityFlags: [],
    threatScore: null,
    rawJson: {},
  };
}

test('IP validation accepts valid IPv4 and IPv6', () => {
  assert.equal(isValidIpAddress('1.1.1.1'), true);
  assert.equal(isValidIpAddress('8.8.8.8'), true);
  assert.equal(isValidIpAddress('192.168.1.1'), true);
  assert.equal(isValidIpAddress('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), true);
  assert.equal(isValidIpAddress('2606:4700:4700::1111'), true);

  assert.equal(isValidIpAddress(''), false);
  assert.equal(isValidIpAddress('999.999.999.999'), false);
  assert.equal(isValidIpAddress('hello.world'), false);
  assert.equal(isValidIpAddress('1.2.3'), false);
});

test('LocalStorage history keeps last 5 unique queried IPs', () => {
  let history: string[] = [];
  history = updateIpHistory(history, '1.1.1.1');
  history = updateIpHistory(history, '8.8.8.8');
  history = updateIpHistory(history, '9.9.9.9');
  history = updateIpHistory(history, '1.0.0.1');
  history = updateIpHistory(history, '8.8.4.4');
  assert.deepEqual(history, ['8.8.4.4', '1.0.0.1', '9.9.9.9', '8.8.8.8', '1.1.1.1']);

  history = updateIpHistory(history, '208.67.222.222');
  assert.equal(history.length, 5);
  assert.equal(history[0], '208.67.222.222');
  assert.equal(history.includes('1.1.1.1'), false);

  history = updateIpHistory(history, '9.9.9.9');
  assert.equal(history.length, 5);
  assert.equal(history[0], '9.9.9.9');
});

test('Security flags visual simplification: safe providers show strictly one "No Flags" pill', () => {
  assert.deepEqual(simplifySecurityFlags([]), [{ label: 'No Flags', isHighRisk: false }]);
  assert.deepEqual(
    simplifySecurityFlags([{ label: 'Clean Connection', isHighRisk: false }]),
    [{ label: 'No Flags', isHighRisk: false }]
  );
  assert.deepEqual(
    simplifySecurityFlags([{ label: 'Direct Connection', isHighRisk: false }, { label: 'Clean History', isHighRisk: false }]),
    [{ label: 'No Flags', isHighRisk: false }]
  );

  const threats = [
    { label: 'Proxy', isHighRisk: true },
    { label: 'VPN', isHighRisk: true },
    { label: 'Direct Connection', isHighRisk: false },
  ];
  const simplified = simplifySecurityFlags(threats);
  assert.equal(simplified.length, 2);
  assert.equal(simplified[0].label, 'Proxy');
  assert.equal(simplified[1].label, 'VPN');
});

test('IPv6 variant canonicalization normalizes uncompressed and uppercase addresses to standard compressed format', () => {
  assert.equal(canonicalizeIpAddress('2001:0db8:0:0::0001'), '2001:db8::1');
  assert.equal(canonicalizeIpAddress('2001:DB8:0000:0000:0000:0000:0000:0001'), '2001:db8::1');
  assert.equal(canonicalizeIpAddress('  2001:db8::1  '), '2001:db8::1');
  assert.equal(canonicalizeIpAddress('2606:4700:4700:0000:0000:0000:0000:1111'), '2606:4700:4700::1111');
  assert.equal(canonicalizeIpAddress('8.8.8.8'), '8.8.8.8');
  assert.equal(canonicalizeIpAddress('invalid-ip'), null);

  let history: string[] = [];
  history = updateIpHistory(history, '2001:0db8:0:0::0001');
  history = updateIpHistory(history, '2001:DB8::1');
  assert.deepEqual(history, ['2001:db8::1']);
});

test('Rapid consecutive history queries discard stale earlier responses and preserve latest state', async () => {
  let resolveSlowFirst!: (value: any) => void;
  let resolveFastSecond!: (value: any) => void;

  const firstPromise = new Promise((resolve) => {
    resolveSlowFirst = resolve;
  });
  const secondPromise = new Promise((resolve) => {
    resolveFastSecond = resolve;
  });

  const fakeFetch = (url: string) => {
    if (url.includes('1.1.1.1')) {
      return firstPromise as any;
    }
    return secondPromise as any;
  };

  const coordinator = createDetectionCoordinator(fakeFetch);

  const taskOne = coordinator.executeDetection('1.1.1.1');
  const taskTwo = coordinator.executeDetection('8.8.8.8');

  assert.equal(coordinator.state.isLoading, true);

  resolveFastSecond({
    ok: true,
    status: 200,
    json: async () => ({
      ip: '8.8.8.8',
      comprehensiveScore: 10,
      durationSeconds: 0.12,
      memoryMb: 44,
      isCached: true,
      results: [],
    }),
  });
  await taskTwo;

  assert.equal(coordinator.state.isLoading, false);
  assert.equal(coordinator.state.detectionData?.ip, '8.8.8.8');

  resolveSlowFirst({
    ok: true,
    status: 200,
    json: async () => ({
      ip: '1.1.1.1',
      comprehensiveScore: 85,
      durationSeconds: 0.95,
      memoryMb: 48,
      isCached: false,
      results: [],
    }),
  });
  await taskOne;

  assert.equal(coordinator.state.detectionData?.ip, '8.8.8.8');
  assert.equal(coordinator.state.detectionData?.comprehensiveScore, 10);
  assert.equal(coordinator.state.isLoading, false);
  assert.deepEqual(coordinator.state.ipHistory, ['8.8.8.8']);
});

test('HTTP 401 response during detection resets user session state and surfaces re-login guidance', async () => {
  const fakeFetch = async () => ({
    ok: false,
    status: 401,
    json: async () => ({ error: 'Authentication required. Please log in with Wikimedia.' }),
  });

  const coordinator = createDetectionCoordinator(fakeFetch, {
    isLoggedIn: true,
    username: 'AdminUser',
    role: 'Temporary Account Access (local: checkuser-temporary-account)',
    hasAccess: true,
  });
  coordinator.state.detectionData = { ip: '1.1.1.1', comprehensiveScore: 20, results: [] };

  await coordinator.executeDetection('8.8.8.8');

  assert.equal(coordinator.state.user.isLoggedIn, false);
  assert.equal(coordinator.state.user.hasAccess, false);
  assert.equal(coordinator.state.detectionData, null);
  assert.equal(coordinator.state.isLoading, false);
  assert.match(coordinator.state.sessionExpiredMessage, /session has expired/i);
  assert.match(coordinator.state.validationError, /session has expired/i);
});

test('filterComparisonResults excludes GetIPIntel and Tor Onionoo rows from comparison results', () => {
  const filtered = filterComparisonResults([
    makeProviderResult('Proxycheck'),
    makeProviderResult('GetIPIntel'),
    makeProviderResult('Tor Onionoo'),
    makeProviderResult('StopForumSpam'),
    makeProviderResult('DShield'),
  ]);
  assert.deepEqual(filtered.map((row) => row.provider), ['Proxycheck', 'StopForumSpam', 'DShield']);
  assert.deepEqual(filterComparisonResults(undefined), []);
});

test('Detection coordinator preserves null memory diagnostics and invokes history callback on shared state', async () => {
  const persistedSnapshots: string[][] = [];
  const externalState: DetectionCoordinatorState = {
    isLoading: false,
    validationError: '',
    sessionExpiredMessage: '',
    detectionData: null,
    diagnostic: null,
    user: {
      isLoggedIn: true,
      username: 'SysopUser',
      role: 'Temporary Account Access (local: checkuser-temporary-account)',
      hasAccess: true,
    },
    ipHistory: ['1.1.1.1'],
  };

  const coordinator = createDetectionCoordinator(
    async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        ip: '8.8.8.8',
        comprehensiveScore: 0,
        durationSeconds: 0.25,
        memoryMb: null,
        isCached: false,
        results: [],
      }),
    }),
    externalState.user,
    {
      state: externalState,
      onHistoryUpdated: (history) => persistedSnapshots.push([...history]),
    }
  );

  await coordinator.executeDetection('8.8.8.8');

  assert.equal(externalState.diagnostic?.memory, null);
  assert.equal(externalState.diagnostic?.duration, 0.25);
  assert.deepEqual(externalState.ipHistory, ['8.8.8.8', '1.1.1.1']);
  assert.deepEqual(persistedSnapshots, [['8.8.8.8', '1.1.1.1']]);
});

test('resolveRepoBaseUrl normalizes empty values, repository slugs, and full URLs', () => {
  assert.equal(resolveRepoBaseUrl(undefined), '');
  assert.equal(resolveRepoBaseUrl(null), '');
  assert.equal(resolveRepoBaseUrl('   '), '');
  assert.equal(resolveRepoBaseUrl('wikimedia/proxycheck'), 'https://github.com/wikimedia/proxycheck');
  assert.equal(resolveRepoBaseUrl('https://github.com/wikimedia/proxycheck/'), 'https://github.com/wikimedia/proxycheck');
});

test('formatDiagnosticSummary renders full unit labels and handles absent or invalid values', () => {
  assert.equal(
    formatDiagnosticSummary({ duration: 5.331, memory: 71.4, isCached: false }),
    'Executed in 5.331 seconds \u00b7 Taken 71.40 megabytes'
  );
  assert.equal(
    formatDiagnosticSummary({ duration: 0.012, memory: null, isCached: false }),
    'Executed in 0.012 seconds'
  );
  assert.equal(
    formatDiagnosticSummary({ duration: Number.NaN, memory: undefined as unknown as null, isCached: false }),
    'Executed in 0.000 seconds'
  );
  assert.equal(formatDiagnosticSummary(null), 'Executed in 0.000 seconds');
});

test('buildDiagnosticMetrics preserves zero durations, rounds memory to two decimals, and falls back on missing fields', () => {
  assert.deepEqual(
    buildDiagnosticMetrics({ durationSeconds: 0, memoryMb: 71.456, isCached: true }, 0.45),
    { duration: 0, memory: 71.46, isCached: true }
  );
  assert.deepEqual(
    buildDiagnosticMetrics({ durationSeconds: undefined, memoryMb: null, isCached: false }, 0.25),
    { duration: 0.25, memory: null, isCached: false }
  );
  assert.deepEqual(
    buildDiagnosticMetrics({ durationSeconds: -1, memoryMb: Number.NaN }, -0.5),
    { duration: 0, memory: null, isCached: false }
  );
  assert.deepEqual(buildDiagnosticMetrics(null, 0.123), {
    duration: 0.123,
    memory: null,
    isCached: false,
  });
});

test('Initial load and elapsed timing helpers return non-negative finite seconds', () => {
  const initialSeconds = measureInitialLoadDurationSeconds();
  assert.equal(typeof initialSeconds, 'number');
  assert.equal(Number.isFinite(initialSeconds) && initialSeconds >= 0, true);

  assert.equal(measureElapsedSeconds(Number.NaN), 0);
  const start = performance.now();
  const elapsed = measureElapsedSeconds(start);
  assert.equal(Number.isFinite(elapsed) && elapsed >= 0, true);
});

test('formatUtcCommitTimestamp formats dates in UTC with English month abbreviations', () => {
  const sampleDate = new Date('2026-11-14T12:34:56Z');
  assert.equal(formatUtcCommitTimestamp(sampleDate), '12:34 14 Nov 2026');

  const paddedDate = new Date('2026-01-05T04:07:09Z');
  assert.equal(formatUtcCommitTimestamp(paddedDate), '04:07 05 Jan 2026');

  const invalidFallback = formatUtcCommitTimestamp(new Date(Number.NaN));
  assert.match(invalidFallback, /^\d{2}:\d{2} \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}$/);
});

test('formatCommitVersionLabel formats commit hash and timestamp inside parentheses', () => {
  assert.equal(
    formatCommitVersionLabel('3236900', '12:34 14 Nov 2026'),
    '(r.3236900 @ 12:34 14 Nov 2026)'
  );
  assert.equal(formatCommitVersionLabel('3236900', ''), '(r.3236900)');
  assert.equal(formatCommitVersionLabel('', '12:34 14 Nov 2026'), '(r.dev @ 12:34 14 Nov 2026)');
  assert.equal(formatCommitVersionLabel(null, null), '(r.dev)');
});

test('resolveCommitMetadata reads Git metadata, honours env overrides, and falls back without .git', () => {
  const timestampPattern = /^\d{2}:\d{2} \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}$/;

  const fromRepo = resolveCommitMetadata({}, process.cwd());
  assert.notEqual(fromRepo.commitHash, '');
  assert.notEqual(fromRepo.commitHash, 'dev');
  assert.match(fromRepo.commitTimestamp, timestampPattern);

  const fromEnv = resolveCommitMetadata(
    {
      VITE_COMMIT_HASH: 'a046aca',
      VITE_COMMIT_TIMESTAMP: '12:34 14 Nov 2026',
    },
    process.cwd()
  );
  assert.deepEqual(fromEnv, {
    commitHash: 'a046aca',
    commitTimestamp: '12:34 14 Nov 2026',
  });

  const nonGitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxycheck-no-git-'));
  try {
    const fallback = resolveCommitMetadata({}, nonGitDir);
    assert.equal(fallback.commitHash, 'dev');
    assert.match(fallback.commitTimestamp, timestampPattern);

    const sourceVersionFallback = resolveCommitMetadata(
      { SOURCE_VERSION: '3236900abcdef1234567890' },
      nonGitDir
    );
    assert.equal(sourceVersionFallback.commitHash, '3236900');
    assert.match(sourceVersionFallback.commitTimestamp, timestampPattern);
  } finally {
    fs.rmSync(nonGitDir, { recursive: true, force: true });
  }
});

test('Login page displays required temporary-account rights notice beneath login button', () => {
  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  assert.match(
    appVue,
    /class="login-btn"[\s\S]*?REQUIRED_USER_RIGHTS\[0\][\s\S]*?REQUIRED_USER_RIGHTS\[1\]/,
  );
  assert.match(appVue, /class="login-groups-note"[\s\S]*?right on any Wikimedia project/);
  assert.match(appVue, /class="unauthorised-message"[\s\S]*?REQUIRED_USER_RIGHTS/);
  assert.doesNotMatch(appVue, /This tool is designed for the following user groups:/);
  assert.deepEqual([...REQUIRED_USER_RIGHTS], [
    'checkuser-temporary-account',
    'checkuser-temporary-account-no-preference',
  ]);
  assert.match(REQUIRED_USER_RIGHTS_SUMMARY, /checkuser-temporary-account/);
  assert.match(REQUIRED_USER_RIGHTS_SUMMARY, /checkuser-temporary-account-no-preference/);
});

test('extractCanonicalIpFromSearch parses and canonicalizes valid ip query values', () => {
  assert.equal(extractCanonicalIpFromSearch('?ip=%208.8.8.8%20'), '8.8.8.8');
  assert.equal(
    extractCanonicalIpFromSearch('?foo=bar&ip=2001:0DB8:0000:0000:0000:0000:0000:0001'),
    '2001:db8::1',
  );
  assert.equal(extractCanonicalIpFromSearch('?ip=008.008.008.008'), null);
  assert.equal(extractCanonicalIpFromSearch('?foo=bar'), null);
  assert.equal(extractCanonicalIpFromSearch('?ip=not-an-ip'), null);
  assert.equal(extractCanonicalIpFromSearch('?ip=https://evil.example/path'), null);
  assert.equal(extractCanonicalIpFromSearch(null), null);
});

test('buildOAuthLoginUrl preserves canonical ip from search or fallback and drops invalid values', () => {
  assert.equal(
    buildOAuthLoginUrl('?ip=2001:0DB8::01', '8.8.8.8'),
    '/api/v1/auth/login/?ip=2001%3Adb8%3A%3A1',
  );
  assert.equal(
    buildOAuthLoginUrl('?foo=1', ' 8.8.8.8 '),
    '/api/v1/auth/login/?ip=8.8.8.8',
  );
  assert.equal(
    buildOAuthLoginUrl('?ip=invalid-ip', '1.1.1.1'),
    '/api/v1/auth/login/?ip=1.1.1.1',
  );
  assert.equal(buildOAuthLoginUrl('?ip=invalid-ip', 'also-invalid'), '/api/v1/auth/login/');
  assert.equal(buildOAuthLoginUrl('', null), '/api/v1/auth/login/');
});

test('buildPageUrlWithIp sets or removes canonical ip while preserving unrelated query params', () => {
  assert.equal(
    buildPageUrlWithIp('/', '?tab=summary&ip=8.8.8.8', '2001:0db8::01'),
    '/?tab=summary&ip=2001%3Adb8%3A%3A1',
  );
  assert.equal(buildPageUrlWithIp('/', '?tab=summary&ip=8.8.8.8', null), '/?tab=summary');
  assert.equal(buildPageUrlWithIp('/', '?ip=8.8.8.8', null), '/');
  assert.equal(buildPageUrlWithIp('https://evil.example/steal', '?a=1', '8.8.8.8'), '/?a=1&ip=8.8.8.8');
});

test('Detection coordinator fires onDetectionSuccess only for non-stale HTTP 200 completions', async () => {
  const succeeded: Array<{ ip: string; score: number }> = [];
  let resolveSlowFirst: (value: any) => void = () => {};
  let resolveFastSecond: (value: any) => void = () => {};

  const slowPromise = new Promise((resolve) => {
    resolveSlowFirst = resolve;
  });
  const fastPromise = new Promise((resolve) => {
    resolveFastSecond = resolve;
  });

  const coordinator = createDetectionCoordinator(
    (url) => (url.includes('1.1.1.1') ? (slowPromise as any) : (fastPromise as any)),
    undefined,
    {
      onDetectionSuccess: (canonicalIp, data) => {
        succeeded.push({ ip: canonicalIp, score: data.comprehensiveScore });
      },
    },
  );

  // Validation error does not trigger onDetectionSuccess
  await coordinator.executeDetection('not-an-ip');
  assert.deepEqual(succeeded, []);

  // Out-of-order responses only invoke onDetectionSuccess for the latest request
  const firstTask = coordinator.executeDetection('1.1.1.1');
  const secondTask = coordinator.executeDetection('2001:0db8::01');

  resolveFastSecond({
    ok: true,
    status: 200,
    json: async () => ({
      ip: '2001:0db8:0000:0000:0000:0000:0000:0001',
      comprehensiveScore: 25,
      results: [],
    }),
  });
  await secondTask;

  resolveSlowFirst({
    ok: true,
    status: 200,
    json: async () => ({
      ip: '1.1.1.1',
      comprehensiveScore: 80,
      results: [],
    }),
  });
  await firstTask;

  assert.deepEqual(succeeded, [{ ip: '2001:db8::1', score: 25 }]);
});

test('Detection coordinator skips onDetectionSuccess when HTTP 401 expires session', async () => {
  let called = false;
  const coordinator = createDetectionCoordinator(
    async () => ({
      ok: false,
      status: 401,
      json: async () => ({ error: 'Authentication required.' }),
    }),
    {
      isLoggedIn: true,
      username: 'AdminUser',
      role: 'Temporary Account Access (global: checkuser-temporary-account)',
      hasAccess: true,
    },
    {
      onDetectionSuccess: () => {
        called = true;
      },
    },
  );

  await coordinator.executeDetection('8.8.8.8');
  assert.equal(called, false);
});
