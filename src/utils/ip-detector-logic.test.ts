import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { resolveCommitMetadata } from '../../vite.config';
import {
  REQUIRED_USER_RIGHTS,
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
  normalizeUtcCommitTimestamp,
  formatUtcCommitTimestamp,
  formatCommitVersionLabel,
  formatRelativeUpdatedLabel,
  resolveProviderUpdatedLabel,
  buildDiagnosticMetrics,
  formatDiagnosticSummary,
  measureInitialLoadDurationSeconds,
  measureElapsedSeconds,
  isAuthorisedAdminUser,
  computeQuotaUsagePercent,
  getQuotaProgressTone,
  formatUpstreamQuotaLabel,
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
      prediction_score: 10,
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
      prediction_score: 85,
      durationSeconds: 0.95,
      memoryMb: 48,
      isCached: false,
      results: [],
    }),
  });
  await taskOne;

  assert.equal(coordinator.state.detectionData?.ip, '8.8.8.8');
  assert.equal(coordinator.state.detectionData?.prediction_score, 10);
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
  coordinator.state.detectionData = { ip: '1.1.1.1', prediction_score: 20, results: [] };

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
        prediction_score: 0,
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

test('formatDiagnosticSummary renders execution duration and worker RSS labels', () => {
  assert.equal(
    formatDiagnosticSummary({ duration: 5.331, memory: 71.4, isCached: false }),
    'Executed in 5.331 seconds \u00b7 Worker RSS 71.40 MB'
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

test('normalizeUtcCommitTimestamp appends a single UTC suffix when missing', () => {
  assert.equal(normalizeUtcCommitTimestamp('12:34 14 Nov 2026'), '12:34 14 Nov 2026 (UTC)');
  assert.equal(normalizeUtcCommitTimestamp('12:34 14 Nov 2026 (UTC)'), '12:34 14 Nov 2026 (UTC)');
  assert.equal(normalizeUtcCommitTimestamp('12:34 14 Nov 2026(utc)'), '12:34 14 Nov 2026 (UTC)');
  assert.equal(normalizeUtcCommitTimestamp('12:34 14 Nov 2026 UTC'), '12:34 14 Nov 2026 (UTC)');
  assert.equal(normalizeUtcCommitTimestamp(''), '');
  assert.equal(normalizeUtcCommitTimestamp(null), '');
});

test('formatUtcCommitTimestamp formats dates in UTC with English month abbreviations', () => {
  const sampleDate = new Date('2026-11-14T12:34:56Z');
  assert.equal(formatUtcCommitTimestamp(sampleDate), '12:34 14 Nov 2026 (UTC)');

  const offsetDate = new Date('2026-11-14T17:12:13+08:00');
  assert.equal(formatUtcCommitTimestamp(offsetDate), '09:12 14 Nov 2026 (UTC)');

  const paddedDate = new Date('2026-01-05T04:07:09Z');
  assert.equal(formatUtcCommitTimestamp(paddedDate), '04:07 05 Jan 2026 (UTC)');

  const invalidFallback = formatUtcCommitTimestamp(new Date(Number.NaN));
  assert.match(invalidFallback, /^\d{2}:\d{2} \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \(UTC\)$/);
});

test('formatCommitVersionLabel formats commit hash and UTC timestamp inside parentheses', () => {
  assert.equal(
    formatCommitVersionLabel('3236900', '12:34 14 Nov 2026'),
    '(r.3236900 @ 12:34 14 Nov 2026 (UTC))'
  );
  assert.equal(
    formatCommitVersionLabel('3236900', '12:34 14 Nov 2026 (UTC)'),
    '(r.3236900 @ 12:34 14 Nov 2026 (UTC))'
  );
  assert.equal(formatCommitVersionLabel('3236900', ''), '(r.3236900)');
  assert.equal(formatCommitVersionLabel('', '12:34 14 Nov 2026'), '(r.dev @ 12:34 14 Nov 2026 (UTC))');
  assert.equal(formatCommitVersionLabel(null, null), '(r.dev)');
});

test('resolveCommitMetadata reads Git metadata in UTC, honours env overrides, and falls back without .git', () => {
  const timestampPattern = /^\d{2}:\d{2} \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \(UTC\)$/;

  const fromRepo = resolveCommitMetadata({}, process.cwd());
  assert.notEqual(fromRepo.commitHash, '');
  assert.notEqual(fromRepo.commitHash, 'dev');
  assert.match(fromRepo.commitTimestamp, timestampPattern);

  const fromEnvWithoutSuffix = resolveCommitMetadata(
    {
      VITE_COMMIT_HASH: 'a046aca',
      VITE_COMMIT_TIMESTAMP: '12:34 14 Nov 2026',
    },
    process.cwd()
  );
  assert.deepEqual(fromEnvWithoutSuffix, {
    commitHash: 'a046aca',
    commitTimestamp: '12:34 14 Nov 2026 (UTC)',
  });

  const fromEnvWithSuffix = resolveCommitMetadata(
    {
      VITE_COMMIT_HASH: 'a046aca',
      VITE_COMMIT_TIMESTAMP: '12:34 14 Nov 2026 (UTC)',
    },
    process.cwd()
  );
  assert.deepEqual(fromEnvWithSuffix, {
    commitHash: 'a046aca',
    commitTimestamp: '12:34 14 Nov 2026 (UTC)',
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
        succeeded.push({ ip: canonicalIp, score: data.prediction_score });
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
      prediction_score: 25,
      results: [],
    }),
  });
  await secondTask;

  resolveSlowFirst({
    ok: true,
    status: 200,
    json: async () => ({
      ip: '1.1.1.1',
      prediction_score: 80,
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

test('Comparison table renders simplified LOCATION header without coordinates suffix', () => {
  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  assert.match(appVue, /<th scope="col">LOCATION<\/th>/);
  assert.doesNotMatch(appVue, /LOCATION\s*(?:&amp;|&)\s*COORDINATES/i);
});

test('formatRelativeUpdatedLabel formats d/h/m relative age, omits zero units, and handles sub-minute timestamps', () => {
  const nowMs = Date.parse('2026-11-14T12:00:00Z');
  const minuteMs = 60_000;
  const hourMs = 60 * minuteMs;
  const dayMs = 24 * hourMs;

  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - 5_000), nowMs), 'Updated just now');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - 59_000), nowMs), 'Updated just now');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs + 5_000), nowMs), 'Updated just now');

  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - 1 * minuteMs), nowMs), 'Updated 1m ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - 59 * minuteMs), nowMs), 'Updated 59m ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - 1 * hourMs), nowMs), 'Updated 1h ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - (1 * hourMs + 35 * minuteMs)), nowMs), 'Updated 1h35m ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - 1 * dayMs), nowMs), 'Updated 1d ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - (1 * dayMs + 5 * minuteMs)), nowMs), 'Updated 1d5m ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - (2 * dayMs + 3 * hourMs)), nowMs), 'Updated 2d3h ago');
  assert.equal(
    formatRelativeUpdatedLabel(new Date(nowMs - (2 * dayMs + 3 * hourMs + 45 * minuteMs)), nowMs),
    'Updated 2d3h45m ago'
  );

  assert.equal(formatRelativeUpdatedLabel('2026-11-14T10:15:00+00:00', nowMs), 'Updated 1h45m ago');
  assert.equal(formatRelativeUpdatedLabel('', nowMs), null);
  assert.equal(formatRelativeUpdatedLabel(null, nowMs), null);
  assert.equal(formatRelativeUpdatedLabel('invalid-timestamp', nowMs), null);
});

test('resolveProviderUpdatedLabel handles per-row and top-level cache state and App.vue places it above provider label', () => {
  const nowMs = Date.parse('2026-11-14T12:00:00Z');
  const cachedRow = {
    ...makeProviderResult('IPRegistry'),
    isCached: true,
    cachedAt: '2026-11-14T11:30:00Z',
  };
  const freshRow = makeProviderResult('AbuseIPDB');

  assert.equal(
    resolveProviderUpdatedLabel(cachedRow, { isCached: false, cacheMeta: { status: 'partial', isPartial: true, hitCount: 1, missCount: 1, cooldownCount: 0, totalSources: 2, cachedAt: '2026-11-14T08:00:00Z' } }, nowMs),
    'Updated 30m ago'
  );
  assert.equal(
    resolveProviderUpdatedLabel(freshRow, { isCached: false, cacheMeta: { status: 'partial', isPartial: true, hitCount: 1, missCount: 1, cooldownCount: 0, totalSources: 2, cachedAt: '2026-11-14T08:00:00Z' } }, nowMs),
    null
  );
  assert.equal(
    resolveProviderUpdatedLabel(freshRow, { isCached: true, cacheMeta: { status: 'hit', isPartial: false, hitCount: 1, missCount: 0, cooldownCount: 0, totalSources: 1, cachedAt: '2026-11-14T08:00:00Z' } }, nowMs),
    'Updated 4h ago'
  );
  assert.equal(resolveProviderUpdatedLabel({ ...makeProviderResult('MaxMind'), isCached: false, cachedAt: '2026-11-14T10:00:00Z' }, { isCached: true }, nowMs), null);

  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  assert.match(
    appVue,
    /<div class="provider-cell">\s*<span[\s\S]*?class="provider-updated-time"[\s\S]*?>\s*\{\{\s*getProviderUpdatedLabel\(row\)\s*\}\}\s*<\/span>\s*<span class="provider-name">/
  );

  const codexCss = fs.readFileSync(path.resolve(process.cwd(), 'src/codex.css'), 'utf8');
  assert.match(codexCss, /\.provider-updated-time\s*\{[\s\S]*?font-size:\s*12px;[\s\S]*?color:\s*var\(--cdx-color-muted\);/);
});

test('Executive overview aligns Prediction gauge with IP details and renders six comparison columns', () => {
  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  const codexCss = fs.readFileSync(path.resolve(process.cwd(), 'src/codex.css'), 'utf8');

  assert.match(
    appVue,
    /<div class="overview-body">\s*<div class="score-gauge-container prediction-gauge-container">[\s\S]*?<span class="gauge-title">Prediction<\/span>[\s\S]*?<\/div>\s*<div class="basic-info-container">/
  );
  assert.match(
    appVue,
    /<thead>\s*<tr>\s*<th scope="col">PROVIDER<\/th>\s*<th scope="col"[^>]*>ASN<\/th>\s*<th scope="col">ISP \/ ORGANISATION<\/th>\s*<th scope="col">LOCATION<\/th>\s*<th scope="col">USAGE TYPE<\/th>\s*<th scope="col">SECURITY FLAGS<\/th>\s*<\/tr>\s*<\/thead>/
  );

  assert.match(codexCss, /\.executive-overview-card\s*\{[\s\S]*?align-items:\s*stretch;/);
  assert.match(codexCss, /\.executive-overview-card\s+\.cdx-card__text\s*\{[\s\S]*?width:\s*100%;/);
  assert.match(codexCss, /\.overview-body\s*\{[\s\S]*?grid-template-columns:\s*auto\s+1fr;[\s\S]*?width:\s*100%;/);
  assert.match(codexCss, /\.prediction-gauge-container\s*\{[\s\S]*?justify-self:\s*center;/);
});

test('isAuthorisedAdminUser honours only backend allowlist verification flag', () => {
  assert.equal(isAuthorisedAdminUser(null), false);
  assert.equal(isAuthorisedAdminUser({ isLoggedIn: false, hasAccess: true, isAdmin: true }), false);
  assert.equal(
    isAuthorisedAdminUser({
      isLoggedIn: true,
      hasAccess: false,
      isAdmin: true,
      role: 'Allowlisted Wikimedia User',
      localGroups: ['sysop'],
    }),
    false
  );
  assert.equal(
    isAuthorisedAdminUser({
      isLoggedIn: true,
      hasAccess: true,
      isAdmin: false,
      role: 'Local Administrator (sysop)',
      localGroups: ['sysop'],
      globalGroups: ['steward'],
    }),
    false
  );
  assert.equal(
    isAuthorisedAdminUser({
      isLoggedIn: true,
      hasAccess: true,
      role: 'Local Administrator (sysop)',
      localGroups: ['sysop'],
      globalGroups: [],
    }),
    false
  );
  assert.equal(
    isAuthorisedAdminUser({
      isLoggedIn: true,
      hasAccess: true,
      role: 'Steward',
      localGroups: [],
      globalGroups: ['steward'],
    }),
    false
  );
  assert.equal(
    isAuthorisedAdminUser({
      isLoggedIn: true,
      hasAccess: true,
      role: 'Temporary Account Access (local: checkuser-temporary-account)',
      localGroups: ['checkuser-temporary-account'],
      globalGroups: [],
    }),
    false
  );
  assert.equal(
    isAuthorisedAdminUser({
      isLoggedIn: true,
      hasAccess: true,
      isAdmin: true,
      role: 'Allowlisted Wikimedia User',
    }),
    true
  );
});

test('Quota percentage, tone thresholds, and upstream quota label formatters handle edge cases', () => {
  assert.equal(computeQuotaUsagePercent(5, 0), 0);
  assert.equal(computeQuotaUsagePercent(0, 100), 0);
  assert.equal(computeQuotaUsagePercent(45, 100), 45);
  assert.equal(computeQuotaUsagePercent(250, 100), 100);
  assert.equal(computeQuotaUsagePercent(-3, 100), 0);

  assert.equal(getQuotaProgressTone(5, 0), 'normal');
  assert.equal(getQuotaProgressTone(79, 100), 'normal');
  assert.equal(getQuotaProgressTone(80, 100), 'warning');
  assert.equal(getQuotaProgressTone(99, 100), 'warning');
  assert.equal(getQuotaProgressTone(100, 100), 'danger');

  assert.equal(
    formatUpstreamQuotaLabel({ upstreamRemaining: 982, upstreamLimit: 1000, upstreamUsed: null }),
    '982 / 1,000 left'
  );
  assert.equal(
    formatUpstreamQuotaLabel({ upstreamRemaining: 4950, upstreamLimit: null, upstreamUsed: null }),
    '4,950 left'
  );
  assert.equal(
    formatUpstreamQuotaLabel({ upstreamRemaining: null, upstreamLimit: null, upstreamUsed: 142 }),
    '142 used'
  );
  assert.equal(
    formatUpstreamQuotaLabel({ upstreamRemaining: null, upstreamLimit: null, upstreamUsed: null }),
    '-'
  );
});

test('App.vue gates the Status dashboard modal to authorised administrators', () => {
  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  const dashboardModalVue = fs.readFileSync(
    path.resolve(process.cwd(), 'src/components/ProviderDashboardModal.vue'),
    'utf8'
  );

  assert.match(appVue, /v-if="isAdminUser"[\s\S]*?>\s*Status\s*<\/cdx-button>/);
  assert.match(appVue, /<provider-dashboard-modal/);
  assert.match(dashboardModalVue, /\/api\/v1\/admin\/provider-dashboard|Refresh/);
  assert.match(dashboardModalVue, /Total Requests Today/);
  assert.match(dashboardModalVue, /Full Cache Hit Rate/);
  assert.match(dashboardModalVue, /Proactive Quota Blocks Today/);
  assert.match(dashboardModalVue, /Active Reactive Cooldowns/);
  assert.match(dashboardModalVue, /OK \/ CACHE HIT \/ 429 \/ QUOTA BLOCKED/);
});

function collectMockDomText(node: any): string {
  if (!node) {
    return '';
  }
  if (typeof node === 'string') {
    return node;
  }
  if (node._node) {
    return collectMockDomText(node._node);
  }
  if (typeof node.nodeType === 'number' && typeof node.textContent === 'string') {
    return node.textContent;
  }
  const parts: string[] = [];
  if (typeof node.textValue === 'string' && node.textValue) {
    parts.push(node.textValue);
  }
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      const childText = collectMockDomText(child);
      if (childText) {
        parts.push(childText);
      }
    }
  }
  return parts.join(' ');
}

test('Offline Databases Status panel stays inside admin-gated modal and is excluded from public main page', () => {
  const appPath = path.resolve(import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname), '../App.vue');
  const modalPath = path.resolve(
    import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname),
    '../components/ProviderDashboardModal.vue'
  );
  const appSource = fs.readFileSync(appPath, 'utf8');
  const modalSource = fs.readFileSync(modalPath, 'utf8');

  assert.doesNotMatch(appSource, /offline-dbs-panel/);
  assert.doesNotMatch(appSource, /\/api\/v1\/status\//);
  assert.match(appSource, /formatOfflineDbTimestamp/);
  assert.match(appSource, /Offline DB Missing/);
  assert.match(modalSource, /Offline Databases Status/);
  assert.match(modalSource, /db_missing/);
});

test('Userscript distinguishes light mode [LIGHT], commercial clean votes, quota guard [QUOTA], cooldown, and StopForumSpam hits', async () => {
  const vm = await import('node:vm');
  const gadgetPath = path.resolve(
    import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname),
    '../../scripts/user-gadget.js'
  );
  const scriptSource = fs.readFileSync(gadgetPath, 'utf8');

  const testPayloads: Record<string, any> = {
    '198.51.100.1': {
      ip: '198.51.100.1',
      queryMode: 'light',
      isPartialMode: true,
      prediction_score: 0,
      getipintel_chance: null,
      arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
      arbitrationTier: 'neutral',
      isTor: false,
      is_broadcast_ip: false,
      results: [
        {
          provider: 'MaxMind',
          status: '200 OK',
          statusCode: 200,
          offlineDbUpdatedAt: '2026-11-16T04:00:00+00:00',
          securityFlags: [{ label: 'No Flags', isHighRisk: false }],
        },
        {
          provider: 'StopForumSpam',
          status: '200 OK',
          statusCode: 200,
          appears: false,
          blacklisted: false,
          offlineDbUpdatedAt: '2026-11-16T05:00:00+00:00',
          securityFlags: [{ label: 'No Flags', isHighRisk: false }],
        },
        {
          provider: 'GetIPIntel',
          status: 'Deferred (Light Mode)',
          statusCode: null,
          isDeferred: true,
          securityFlags: [{ label: 'Deferred (Light Mode)', isHighRisk: false }],
        },
      ],
    },
    '198.51.100.2': {
      ip: '198.51.100.2',
      queryMode: 'full',
      isPartialMode: false,
      prediction_score: 0,
      getipintel_chance: null,
      arbitrationVerdict: 'Clean Residential / Direct (0/7 Sources)',
      arbitrationTier: 'success',
      isTor: false,
      is_broadcast_ip: false,
      results: [
        {
          provider: 'GetIPIntel',
          status: 'Local Quota Guard (15/15 req/min)',
          statusCode: 429,
          isCooldown: true,
          isQuotaGuarded: true,
          securityFlags: [{ label: 'Local Quota Guard', isHighRisk: false }],
        },
      ],
    },
    '198.51.100.3': {
      ip: '198.51.100.3',
      queryMode: 'light',
      isPartialMode: true,
      prediction_score: 0,
      getipintel_chance: null,
      arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
      arbitrationTier: 'neutral',
      isTor: false,
      is_broadcast_ip: false,
      results: [
        {
          provider: 'StopForumSpam',
          status: '200 OK',
          statusCode: 200,
          appears: true,
          blacklisted: true,
          toxicCidr: '198.51.100.0/24',
          offlineDbUpdatedAt: '2026-11-16T05:00:00+00:00',
          securityFlags: [{ label: 'Blacklisted Toxic CIDR (198.51.100.0/24)', isHighRisk: true }],
        },
        {
          provider: 'GetIPIntel',
          status: 'Deferred (Light Mode)',
          statusCode: null,
          isDeferred: true,
          securityFlags: [{ label: 'Deferred (Light Mode)', isHighRisk: false }],
        },
      ],
    },
    '198.51.100.4': {
      ip: '198.51.100.4',
      queryMode: 'light',
      isPartialMode: true,
      prediction_score: 0,
      getipintel_chance: null,
      arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
      arbitrationTier: 'neutral',
      isTor: false,
      is_broadcast_ip: false,
      results: [
        {
          provider: 'StopForumSpam',
          status: '200 OK',
          statusCode: 200,
          appears: true,
          blacklisted: false,
          frequency: 9,
          securityFlags: [{ label: 'Forum Spam (9x)', isHighRisk: true }],
        },
        {
          provider: 'GetIPIntel',
          status: 'Deferred (Light Mode)',
          statusCode: null,
          isDeferred: true,
          securityFlags: [{ label: 'Deferred (Light Mode)', isHighRisk: false }],
        },
      ],
    },
    '198.51.100.5': {
      ip: '198.51.100.5',
      queryMode: 'full',
      isPartialMode: false,
      prediction_score: 0,
      getipintel_chance: null,
      arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
      arbitrationTier: 'neutral',
      isTor: false,
      is_broadcast_ip: false,
      results: [
        {
          provider: 'GetIPIntel',
          status: 'No API Key',
          statusCode: null,
          securityFlags: [{ label: 'No Flags', isHighRisk: false }],
        },
      ],
    },
    '198.51.100.6': {
      ip: '198.51.100.6',
      queryMode: 'full',
      isPartialMode: false,
      prediction_score: 0,
      getipintel_chance: null,
      arbitrationVerdict: 'Clean Residential / Direct (0/2 Sources)',
      arbitrationTier: 'success',
      isTor: false,
      is_broadcast_ip: false,
      results: [
        {
          provider: 'GetIPIntel',
          status: 'Local Quota Guard (15/15 req/min)',
          statusCode: 429,
          isCooldown: true,
          isQuotaGuard: true,
          securityFlags: [{ label: 'Local Quota Guard', isHighRisk: false }],
        },
        {
          provider: 'AbuseIPDB',
          status: '200 OK',
          statusCode: 200,
          usageType: 'isp',
          securityFlags: [{ label: 'No Flags', isHighRisk: false }],
        },
        {
          provider: 'Proxycheck',
          status: '200 OK',
          statusCode: 200,
          usageType: 'residential',
          securityFlags: [{ label: 'No Flags', isHighRisk: false }],
        },
      ],
    },
  };

  const makeMockBadge = () => ({
    tagName: 'A',
    style: {} as Record<string, string>,
    className: '',
    href: '',
    textContent: '',
    title: '',
    dataset: {} as Record<string, string>,
    classList: { contains: () => true },
    addEventListener: () => {},
  });

  const makeMockAnchor = (ip: string) => {
    const inserted: any[] = [];
    const anchor: any = {
      tagName: 'A',
      nodeType: 1,
      textContent: ip,
      dataset: {} as Record<string, string>,
      style: {} as Record<string, string>,
      className: 'ext-checkuser-tempaccount-reveal-ip-anchor',
      parentNode: {
        insertBefore: (node: any) => {
          inserted.push(node);
          anchor.nextElementSibling = node;
        },
      },
      nextSibling: null,
      nextElementSibling: null,
      matches: (sel: string) => sel === 'a.ext-checkuser-tempaccount-reveal-ip-anchor',
      closest: () => null,
      inserted,
    };
    return anchor;
  };

  const anchors = Object.keys(testPayloads).map(makeMockAnchor);
  const createdBadges: any[] = [];
  const storageMap = new Map<string, string>([
    ['proxycheck-ip-policy-consent', '1'],
    ['proxycheck-gadget-token', 'valid-token'],
    ['proxycheck-gadget-token-user', 'TestSysop'],
    ['proxycheck-gadget-token-exp', String(Date.now() + 600_000)],
  ]);

  let readyCallback: (() => void) | null = null;
  const mwObj = {
    config: {
      get: (key: string) => {
        if (key === 'wgUserName') return 'TestSysop';
        if (key === 'wgUserIsTemp') return false;
        if (key === 'wgServerName') return 'meta.wikimedia.org';
        if (key === 'wgCanonicalSpecialPageName') return 'Recentchanges';
        if (key === 'wgNamespaceNumber') return -1;
        if (key === 'wgAction') return 'view';
        if (key === 'wgTitle') return 'RecentChanges';
        return null;
      },
    },
    storage: {
      get: (k: string) => storageMap.get(k) ?? null,
      set: (k: string, v: string) => storageMap.set(k, String(v)),
      remove: (k: string) => storageMap.delete(k),
    },
    hook: () => ({ add: () => {} }),
    Api: function () {
      return { get: () => Promise.resolve({ centralauthtoken: { centralauthtoken: 'fresh-cat-token' } }) };
    },
    loader: { using: () => Promise.resolve() },
    html: { escape: (s: string) => s },
  };
  const jQueryStub: any = (arg: any) => {
    if (typeof arg === 'function') {
      readyCallback = arg;
      return { length: 0 };
    }
    return {
      ready: (cb: () => void) => cb(),
      find: () => ({ length: 0 }),
      length: 0,
    };
  };
  const sandbox: Record<string, any> = {
    mw: mwObj,
    mediaWiki: mwObj,
    $: jQueryStub,
    jQuery: jQueryStub,
    window: {
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      setInterval: globalThis.setInterval.bind(globalThis),
      clearInterval: globalThis.clearInterval.bind(globalThis),
      localStorage: {
        getItem: (k: string) => storageMap.get(k) ?? null,
        setItem: (k: string, v: string) => storageMap.set(k, String(v)),
        removeItem: (k: string) => storageMap.delete(k),
      },
    },
    localStorage: {
      getItem: (k: string) => storageMap.get(k) ?? null,
      setItem: (k: string, v: string) => storageMap.set(k, String(v)),
      removeItem: (k: string) => storageMap.delete(k),
    },
    document: {
      documentElement: { classList: { contains: () => false } },
      head: { appendChild: () => {} },
      body: {
        nodeType: 1,
        matches: () => false,
        closest: () => null,
        classList: { contains: () => false },
        querySelectorAll: (sel: string) =>
          sel.indexOf('ext-checkuser-tempaccount-reveal-ip-anchor') !== -1 ? anchors : [],
      },
      getElementById: () => null,
      createElement: (tag: string) => {
        if (tag === 'a') {
          const badge = makeMockBadge();
          createdBadges.push(badge);
          return badge;
        }
        return { tagName: tag.toUpperCase(), style: {}, id: '', textContent: '', appendChild: () => {} };
      },
      createTextNode: (text: string) => ({ nodeType: 3, textContent: text }),
    },
    MutationObserver: function () {
      return { observe: () => {}, disconnect: () => {} };
    },
    fetch: async () => ({
      ok: true,
      status: 200,
      json: async () => ({ results: testPayloads, count: Object.keys(testPayloads).length, queryMode: 'light' }),
    }),
    console,
    Promise,
    Map,
    Set,
    Object,
    Array,
    String,
    Number,
    Boolean,
    Date,
    Math,
    JSON,
    encodeURIComponent,
    isNaN,
    RegExp,
  };
  sandbox.window.localStorage = sandbox.localStorage;

  vm.runInNewContext(scriptSource, sandbox);
  assert.ok(readyCallback, 'expected gadget ready handler');
  (readyCallback as () => void)();
  await new Promise((resolve) => setTimeout(resolve, 120));

  const badgeByIp = Object.fromEntries(anchors.map((a) => [a.textContent, a.inserted[0]]));
  assert.equal(badgeByIp['198.51.100.1'].textContent, '[LIGHT]');
  assert.match(badgeByIp['198.51.100.1'].className, /proxycheck-badge-lite/);
  assert.match(
    badgeByIp['198.51.100.1'].title,
    /Light screening passed \(no local\/free-tier flags\)\. Click to run full commercial check\./
  );
  assert.match(badgeByIp['198.51.100.1'].title, /MaxMind 2026-11-16 04:00 UTC/);

  assert.equal(badgeByIp['198.51.100.2'].textContent, '[QUOTA]');
  assert.match(badgeByIp['198.51.100.2'].className, /proxycheck-badge-quota/);
  assert.match(badgeByIp['198.51.100.2'].title, /Quota Guard Active/);

  assert.equal(badgeByIp['198.51.100.3'].textContent, '[BLACKLIST]');
  assert.match(badgeByIp['198.51.100.3'].className, /proxycheck-tier-high/);

  assert.equal(badgeByIp['198.51.100.4'].textContent, '[SPAM]');
  assert.match(badgeByIp['198.51.100.4'].className, /proxycheck-tier-medium/);

  assert.equal(badgeByIp['198.51.100.5'].textContent, '[N/A]');

  assert.equal(badgeByIp['198.51.100.6'].textContent, '[OK 0/2]');
  assert.match(badgeByIp['198.51.100.6'].className, /proxycheck-tier-low/);
  assert.doesNotMatch(badgeByIp['198.51.100.6'].className, /proxycheck-badge-quota/);
});

function createGadgetVmHarness(options: {
  pageName?: string;
  specialPage?: string | false;
  relevantUserName?: string;
  initialVisibilityState?: string;
  initialStorageEntries?: Array<[string, string]>;
  anchors?: any[];
  fetchImpl: (url: string, init?: any) => Promise<any>;
}) {
  const gadgetPath = path.resolve(
    import.meta.dirname ?? path.dirname(new URL(import.meta.url).pathname),
    '../../scripts/user-gadget.js'
  );
  const scriptSource = fs.readFileSync(gadgetPath, 'utf8');

  const storageMap = new Map<string, string>([
    ['proxycheck-ip-policy-consent', '1'],
    ['proxycheck-gadget-token', 'valid-token'],
    ['proxycheck-gadget-token-user', 'TestSysop'],
    ['proxycheck-gadget-token-exp', String(Date.now() + 600_000)],
    ...(options.initialStorageEntries ?? []),
  ]);

  let currentNowMs = Date.now();
  const FakeDate: any = function (this: any, ...args: any[]) {
    if (args.length === 0) {
      return new Date(currentNowMs);
    }
    return new (Date as any)(...args);
  };
  FakeDate.now = () => currentNowMs;
  FakeDate.parse = Date.parse;
  FakeDate.UTC = Date.UTC;

  const docListeners: Record<string, Array<(ev?: any) => void>> = {};
  const elementsById = new Map<string, any>();
  const openedAlerts: Array<{ title: string; messageWrapper: any; resolveDialog: () => void }> = [];
  const createdBadges: any[] = [];
  const anchors = options.anchors ?? [];

  function wrapMockJQueryNode(node: any): any {
    const wrapper: any = {
      _node: node,
      length: 1,
      0: node,
      append: (...args: any[]) => {
        for (const item of args) {
          if (item === null || item === undefined) {
            continue;
          }
          if (item._node) {
            item._node.parent = node;
            item._node.parentNode = node;
            node.children.push(item._node);
          } else if (typeof item === 'object' && typeof item.nodeType === 'number') {
            node.children.push({
              tag: '#text',
              props: {},
              textValue: String(item.textContent || ''),
              children: [],
              parent: node,
              parentNode: node,
            });
          } else {
            node.children.push({
              tag: '#text',
              props: {},
              textValue: String(item),
              children: [],
              parent: node,
              parentNode: node,
            });
          }
        }
        return wrapper;
      },
      appendTo: (target: any) => {
        if (target && typeof target.append === 'function') {
          target.append(wrapper);
        }
        return wrapper;
      },
      before: (item: any) => {
        if (item && item._node && item._node.props && item._node.props.id) {
          elementsById.set(item._node.props.id, item._node);
        }
        return wrapper;
      },
      prepend: (item: any) => wrapper.append(item),
      after: (item: any) => wrapper.append(item),
      empty: () => {
        node.children = [];
        node.textValue = '';
        return wrapper;
      },
      remove: () => {
        if (node.props && node.props.id && elementsById.get(node.props.id) === node) {
          elementsById.delete(node.props.id);
        }
        if (node.parent) {
          node.parent.children = node.parent.children.filter((c: any) => c !== node);
          node.parent = null;
          node.parentNode = null;
        }
        return wrapper;
      },
      text: (val?: string) => {
        if (val === undefined) {
          return collectMockDomText(node);
        }
        node.children = [];
        node.textValue = String(val);
        return wrapper;
      },
      html: (val?: string) => {
        if (val === undefined) {
          return collectMockDomText(node);
        }
        node.children = [];
        node.textValue = String(val);
        return wrapper;
      },
      attr: (key: string, val?: any) => {
        if (val === undefined) {
          return node.props[key];
        }
        node.props[key] = val;
        return wrapper;
      },
      prop: (key: string, val?: any) => {
        if (val === undefined) {
          return node.props[key];
        }
        node.props[key] = val;
        return wrapper;
      },
      css: () => wrapper,
      on: (eventName: string, handler: (ev: any) => void) => {
        node.listeners[eventName] = node.listeners[eventName] || [];
        node.listeners[eventName].push(handler);
        return wrapper;
      },
      find: () => ({ length: 0 }),
      first: () => wrapper,
      parent: () => ({ length: 1 }),
      closest: () => ({ length: 0 }),
      each: () => wrapper,
    };
    return wrapper;
  }

  function makeMockNode(tag: string, attrs?: Record<string, any>) {
    const classSet = new Set<string>(
      attrs && typeof attrs.class === 'string' ? attrs.class.split(/\s+/).filter(Boolean) : []
    );
    const node: any = {
      tag: tag.toLowerCase(),
      nodeType: 1,
      props: attrs ? { ...attrs } : {},
      textValue: attrs && attrs.text !== undefined ? String(attrs.text) : '',
      children: [],
      listeners: {} as Record<string, Array<(ev: any) => void>>,
      parent: null,
      parentNode: null,
      classList: {
        add: (cls: string) => classSet.add(cls),
        remove: (cls: string) => classSet.delete(cls),
        contains: (cls: string) => classSet.has(cls),
      },
    };
    if (attrs && attrs.id) {
      elementsById.set(attrs.id, node);
    }
    return node;
  }

  let readyCallback: (() => void) | null = null;
  const contribHeaderNode = makeMockNode('div', { class: 'mw-contributions-header' });
  const jQueryStub: any = (arg: any, attrs?: Record<string, any>) => {
    if (typeof arg === 'function') {
      readyCallback = arg;
      return { length: 0 };
    }
    if (arg && arg._node) {
      return arg;
    }
    if (typeof arg === 'string') {
      const tagMatch = arg.match(/^<([a-zA-Z0-9]+)>$/);
      if (tagMatch) {
        return wrapMockJQueryNode(makeMockNode(tagMatch[1], attrs));
      }
      if (arg === '#proxycheck-pageinfo') {
        const existing = elementsById.get('proxycheck-pageinfo');
        return existing ? wrapMockJQueryNode(existing) : { length: 0 };
      }
      if (arg.includes('mw-contributions-header')) {
        return wrapMockJQueryNode(contribHeaderNode);
      }
    }
    return {
      length: 0,
      first: () => ({ length: 0 }),
      find: () => ({ length: 0 }),
      each: () => ({ length: 0 }),
    };
  };

  const mwObj = {
    config: {
      get: (key: string) => {
        if (key === 'wgUserName') return 'TestSysop';
        if (key === 'wgUserIsTemp') return false;
        if (key === 'wgServerName') return 'meta.wikimedia.org';
        if (key === 'wgCanonicalSpecialPageName') return options.specialPage ?? 'Recentchanges';
        if (key === 'wgPageName') return options.pageName ?? 'Special:RecentChanges';
        if (key === 'wgRelevantUserName') return options.relevantUserName ?? null;
        if (key === 'wgTitle') return options.pageName ?? 'RecentChanges';
        return null;
      },
    },
    storage: {
      get: (k: string) => storageMap.get(k) ?? null,
      set: (k: string, v: string) => storageMap.set(k, String(v)),
      remove: (k: string) => storageMap.delete(k),
    },
    hook: () => ({ add: () => {} }),
    Api: function () {
      return { get: () => Promise.resolve({ centralauthtoken: { centralauthtoken: 'fresh-cat' } }) };
    },
    loader: { using: () => Promise.resolve() },
    html: { escape: (s: string) => s },
  };

  const documentObj: any = {
    visibilityState: options.initialVisibilityState ?? 'visible',
    documentElement: { classList: { contains: () => false } },
    head: { appendChild: () => {} },
    body: {
      nodeType: 1,
      matches: () => false,
      closest: () => null,
      contains: () => true,
      classList: { contains: () => false },
      querySelectorAll: (sel: string) =>
        sel.indexOf('ext-checkuser-tempaccount-reveal-ip-anchor') !== -1 ? anchors : [],
    },
    getElementById: (id: string) => elementsById.get(id) ?? null,
    addEventListener: (name: string, fn: (ev?: any) => void) => {
      docListeners[name] = docListeners[name] || [];
      docListeners[name].push(fn);
    },
    removeEventListener: (name: string, fn: (ev?: any) => void) => {
      docListeners[name] = (docListeners[name] || []).filter((item) => item !== fn);
    },
    createElement: (tag: string) => {
      const listeners: Record<string, Array<(ev: any) => void>> = {};
      const el = {
        tagName: tag.toUpperCase(),
        style: {},
        className: '',
        href: '',
        textContent: '',
        title: '',
        dataset: {},
        classList: { contains: (cls: string) => cls === 'proxycheck-ip-badge' },
        setAttribute: () => {},
        addEventListener: (eventName: string, handler: (ev: any) => void) => {
          listeners[eventName] = listeners[eventName] || [];
          listeners[eventName].push(handler);
        },
        _trigger: (eventName: string) => {
          for (const fn of listeners[eventName] || []) {
            fn({ preventDefault: () => {}, stopPropagation: () => {} });
          }
        },
      };
      if (tag === 'a') {
        createdBadges.push(el);
      }
      return el;
    },
    createTextNode: (text: string) => ({ nodeType: 3, textContent: text }),
  };

  const sandbox: Record<string, any> = {
    mw: mwObj,
    mediaWiki: mwObj,
    $: jQueryStub,
    jQuery: jQueryStub,
    OO: {
      ui: {
        alert: ($message: any, opts: { title: string }) =>
          new Promise<void>((resolve) => {
            openedAlerts.push({
              title: opts.title,
              messageWrapper: $message,
              resolveDialog: resolve,
            });
          }),
      },
    },
    window: {
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      setInterval: globalThis.setInterval.bind(globalThis),
      clearInterval: globalThis.clearInterval.bind(globalThis),
      localStorage: {
        getItem: (k: string) => storageMap.get(k) ?? null,
        setItem: (k: string, v: string) => storageMap.set(k, String(v)),
        removeItem: (k: string) => storageMap.delete(k),
      },
    },
    localStorage: null,
    document: documentObj,
    MutationObserver: function () {
      return { observe: () => {}, disconnect: () => {} };
    },
    fetch: options.fetchImpl,
    console,
    Promise,
    Map,
    Set,
    Object,
    Array,
    String,
    Number,
    Boolean,
    Date: FakeDate,
    Math,
    JSON,
    encodeURIComponent,
    isNaN,
    RegExp,
  };
  sandbox.localStorage = sandbox.window.localStorage;

  vm.runInNewContext(scriptSource, sandbox);
  return {
    runReady: () => {
      if (readyCallback) {
        readyCallback();
      }
    },
    setNow: (ms: number) => {
      currentNowMs = ms;
    },
    getNow: () => currentNowMs,
    setVisibility: (state: string) => {
      documentObj.visibilityState = state;
      const listeners = (docListeners.visibilitychange || []).slice();
      for (const fn of listeners) {
        fn();
      }
    },
    findNode: (predicate: (node: any) => boolean) => {
      function walk(node: any): any {
        if (!node) return null;
        if (predicate(node)) return node;
        for (const child of node.children || []) {
          const hit = walk(child);
          if (hit) return hit;
        }
        return null;
      }
      for (const alert of openedAlerts) {
        const hit = walk(alert.messageWrapper?._node);
        if (hit) return hit;
      }
      const bannerNode = elementsById.get('proxycheck-pageinfo');
      return bannerNode ? walk(bannerNode) : null;
    },
    openedAlerts,
    createdBadges,
    storageMap,
    elementsById,
  };
}

test('Userscript short-caches degraded quota results for 60s and exposes Retry Full Check in showInfoDialog', async () => {
  const fullUrls: string[] = [];
  let fullCallCount = 0;

  const anchor: any = {
    tagName: 'A',
    nodeType: 1,
    textContent: '198.51.100.10',
    dataset: {},
    style: {},
    nextSibling: null,
    nextElementSibling: null,
    matches: (sel: string) => sel === 'a.ext-checkuser-tempaccount-reveal-ip-anchor',
    closest: () => null,
    parentNode: {
      insertBefore: (badge: any) => {
        anchor.nextElementSibling = badge;
      },
    },
  };

  const lightPayload = {
    ip: '198.51.100.10',
    queryMode: 'light',
    isPartialMode: true,
    prediction_score: 0,
    getipintel_chance: null,
    arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
    arbitrationTier: 'neutral',
    isTor: false,
    is_broadcast_ip: false,
    results: [
      {
        provider: 'MaxMind',
        status: '200 OK',
        statusCode: 200,
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
      {
        provider: 'GetIPIntel',
        status: 'Deferred (Light Mode)',
        statusCode: null,
        isDeferred: true,
        securityFlags: [{ label: 'Deferred (Light Mode)', isHighRisk: false }],
      },
    ],
  };

  const degradedFullPayload = {
    ip: '198.51.100.10',
    queryMode: 'full',
    isPartialMode: false,
    prediction_score: 0,
    getipintel_chance: null,
    arbitrationVerdict: 'Clean Residential / Direct (0/1 Sources)',
    arbitrationTier: 'success',
    isTor: false,
    is_broadcast_ip: false,
    results: [
      {
        provider: 'GetIPIntel',
        status: 'Local Quota Guard (15/15 req/min)',
        statusCode: 429,
        isCooldown: true,
        isQuotaGuarded: true,
        securityFlags: [{ label: 'Local Quota Guard', isHighRisk: false }],
      },
      {
        provider: 'Proxycheck',
        status: '200 OK',
        statusCode: 200,
        usageType: 'residential',
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
    ],
  };

  const recoveredFullPayload = {
    ip: '198.51.100.10',
    queryMode: 'full',
    isPartialMode: false,
    prediction_score: 12.5,
    getipintel_chance: 12.5,
    arbitrationVerdict: 'Clean Residential / Direct (0/2 Sources)',
    arbitrationTier: 'success',
    isTor: false,
    is_broadcast_ip: false,
    results: [
      {
        provider: 'GetIPIntel',
        status: '200 OK',
        statusCode: 200,
        chance: 12.5,
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
      {
        provider: 'Proxycheck',
        status: '200 OK',
        statusCode: 200,
        usageType: 'residential',
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
    ],
  };

  const harness = createGadgetVmHarness({
    anchors: [anchor],
    fetchImpl: async (url: string) => {
      if (url.includes('/api/v1/detect/batch')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ results: { '198.51.100.10': lightPayload }, count: 1, queryMode: 'light' }),
        };
      }
      fullUrls.push(url);
      fullCallCount += 1;
      const payload = fullCallCount === 1 ? degradedFullPayload : recoveredFullPayload;
      return { ok: true, status: 200, json: async () => payload };
    },
  });
  harness.runReady();
  await new Promise((resolve) => setTimeout(resolve, 90));

  const badge = anchor.nextElementSibling;
  assert.equal(badge.textContent, '[LIGHT]');

  // Click badge to trigger first full lookup, which returns quota-guarded GetIPIntel
  badge._trigger('click');
  await new Promise((resolve) => setTimeout(resolve, 40));

  assert.equal(fullUrls.length, 1);
  assert.equal(badge.textContent, '[OK 0/1]');
  const persistedRaw = harness.storageMap.get('proxycheck-ip-result-cache-v1');
  assert.ok(persistedRaw);
  const persistedParsed = JSON.parse(persistedRaw);
  assert.equal(persistedParsed.entries['198.51.100.10'].ttlMs, 60000);

  const retryBtn = harness.findNode(
    (node: any) => node.tag === 'button' && node.props?.class === 'proxycheck-retry-full-btn'
  );
  assert.ok(retryBtn, 'Expected Retry Full Check button when GetIPIntel is quota-guarded');

  // Clicking Retry Full Check clears the 60s cache and fetches fresh full intelligence
  for (const fn of retryBtn.listeners.click || []) {
    fn({ preventDefault: () => {}, stopPropagation: () => {} });
  }
  await new Promise((resolve) => setTimeout(resolve, 40));

  assert.equal(fullUrls.length, 2);
  assert.equal(badge.textContent, '[12.5%]');
  const postRecoveryBtn = harness.findNode(
    (node: any) => node.tag === 'button' && node.props?.class === 'proxycheck-retry-full-btn'
  );
  assert.equal(postRecoveryBtn, null);
  const recoveredStore = JSON.parse(harness.storageMap.get('proxycheck-ip-result-cache-v1') || '{}');
  assert.equal(recoveredStore.entries['198.51.100.10'].ttlMs, 30 * 60 * 1000);
  harness.openedAlerts[0].resolveDialog();

  // Verify a degraded entry stored 65s ago is rejected on read while a fresh one (< 60s) is honoured
  const nowMs = harness.getNow();
  harness.storageMap.set(
    'proxycheck-ip-result-cache-v1',
    JSON.stringify({
      entries: {
        '198.51.100.99': {
          ts: nowMs - 65_000,
          ttlMs: 60_000,
          data: { ...degradedFullPayload, ip: '198.51.100.99' },
        },
      },
    })
  );
  const anchor2: any = {
    tagName: 'A',
    nodeType: 1,
    textContent: '198.51.100.99',
    dataset: {},
    style: {},
    nextSibling: null,
    nextElementSibling: null,
    matches: (sel: string) => sel === 'a.ext-checkuser-tempaccount-reveal-ip-anchor',
    closest: () => null,
    parentNode: {
      insertBefore: (b: any) => {
        anchor2.nextElementSibling = b;
      },
    },
  };
  let secondBatchCount = 0;
  const expiredHarness = createGadgetVmHarness({
    anchors: [anchor2],
    initialStorageEntries: [['proxycheck-ip-result-cache-v1', harness.storageMap.get('proxycheck-ip-result-cache-v1')!]],
    fetchImpl: async () => {
      secondBatchCount += 1;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          results: { '198.51.100.99': { ...lightPayload, ip: '198.51.100.99' } },
          count: 1,
          queryMode: 'light',
        }),
      };
    },
  });
  expiredHarness.runReady();
  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(secondBatchCount, 1);
  assert.equal(anchor2.nextElementSibling.textContent, '[LIGHT]');
});

test('Userscript defers Special:Contributions full lookups in hidden tabs until visible plus delay', async () => {
  const hiddenRequests: string[] = [];
  const fullPayload = {
    ip: '198.51.100.77',
    queryMode: 'full',
    isPartialMode: false,
    prediction_score: 0,
    getipintel_chance: 0,
    arbitrationVerdict: 'Clean Residential / Direct (0/1 Sources)',
    arbitrationTier: 'success',
    isTor: false,
    is_broadcast_ip: false,
    results: [
      {
        provider: 'GetIPIntel',
        status: '200 OK',
        statusCode: 200,
        chance: 0,
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
    ],
  };

  // Hidden background tab without cache must fire zero requests until activated
  const hiddenHarness = createGadgetVmHarness({
    specialPage: 'Contributions',
    pageName: 'Special:Contributions/198.51.100.77',
    relevantUserName: '198.51.100.77',
    initialVisibilityState: 'hidden',
    fetchImpl: async (url: string) => {
      hiddenRequests.push(url);
      return { ok: true, status: 200, json: async () => fullPayload };
    },
  });
  hiddenHarness.runReady();
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(hiddenRequests.length, 0);

  // Switching tab to visible resolves mount target (400ms fallback) and fires mode=full after the short delay
  hiddenHarness.setVisibility('visible');
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(hiddenRequests.length, 0);
  await new Promise((resolve) => setTimeout(resolve, 900));
  assert.equal(hiddenRequests.length, 1);
  assert.match(hiddenRequests[0], /mode=full/);

  // Cached light result in a hidden tab renders banner immediately with zero requests until visible
  const cachedLightRequests: string[] = [];
  const cachedLightPayload = {
    ip: '198.51.100.88',
    queryMode: 'light',
    isPartialMode: true,
    prediction_score: 0,
    getipintel_chance: null,
    arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
    arbitrationTier: 'neutral',
    isTor: false,
    is_broadcast_ip: false,
    recommendedCidr: '198.51.100.0/24',
    results: [
      {
        provider: 'MaxMind',
        status: '200 OK',
        statusCode: 200,
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
    ],
  };
  const cachedLightHarness = createGadgetVmHarness({
    specialPage: 'IPContributions',
    pageName: 'Special:IPContributions/198.51.100.88',
    relevantUserName: '198.51.100.88',
    initialVisibilityState: 'hidden',
    initialStorageEntries: [
      [
        'proxycheck-ip-result-cache-v1',
        JSON.stringify({
          entries: {
            '198.51.100.88': {
              ts: Date.now(),
              ttlMs: 30 * 60 * 1000,
              data: cachedLightPayload,
            },
          },
        }),
      ],
    ],
    fetchImpl: async (url: string) => {
      cachedLightRequests.push(url);
      return { ok: true, status: 200, json: async () => ({ ...fullPayload, ip: '198.51.100.88' }) };
    },
  });
  cachedLightHarness.runReady();
  await new Promise((resolve) => setTimeout(resolve, 550));
  assert.equal(cachedLightRequests.length, 0);
  assert.ok(cachedLightHarness.elementsById.get('proxycheck-pageinfo'));

  cachedLightHarness.setVisibility('visible');
  await new Promise((resolve) => setTimeout(resolve, 650));
  assert.equal(cachedLightRequests.length, 1);
  assert.match(cachedLightRequests[0], /mode=full/);
});




