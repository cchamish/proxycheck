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
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - (1 * hourMs + 35 * minuteMs)), nowMs), 'Updated 1h 35m ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - 1 * dayMs), nowMs), 'Updated 1d ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - (1 * dayMs + 5 * minuteMs)), nowMs), 'Updated 1d 5m ago');
  assert.equal(formatRelativeUpdatedLabel(new Date(nowMs - (2 * dayMs + 3 * hourMs)), nowMs), 'Updated 2d 3h ago');
  assert.equal(
    formatRelativeUpdatedLabel(new Date(nowMs - (2 * dayMs + 3 * hourMs + 45 * minuteMs)), nowMs),
    'Updated 2d 3h 45m ago'
  );

  assert.equal(formatRelativeUpdatedLabel('2026-11-14T10:15:00+00:00', nowMs), 'Updated 1h 45m ago');
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

test('App.vue gates the API Quota & Health dashboard modal to authorised administrators', () => {
  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  const dashboardModalVue = fs.readFileSync(
    path.resolve(process.cwd(), 'src/components/ProviderDashboardModal.vue'),
    'utf8'
  );

  assert.match(appVue, /v-if="isAdminUser"[\s\S]*?API Quota &(?:amp;)? Health/);
  assert.match(appVue, /<provider-dashboard-modal/);
  assert.match(dashboardModalVue, /\/api\/v1\/admin\/provider-dashboard|Refresh/);
  assert.match(dashboardModalVue, /Total Requests Today/);
  assert.match(dashboardModalVue, /Full Cache Hit Rate/);
  assert.match(dashboardModalVue, /Proactive Quota Blocks Today/);
  assert.match(dashboardModalVue, /Active Reactive Cooldowns/);
  assert.match(dashboardModalVue, /OK \/ CACHE HIT \/ 429 \/ QUOTA BLOCKED/);
});

async function createUserscriptTestHarness(
  fetchImpl: (url: string, init?: any) => Promise<any>,
  anchorCount: number,
  options?: {
    initialStorageEntries?: Array<[string, string]>;
    storageDisabled?: boolean;
  }
) {
  const userscriptPath = path.resolve(process.cwd(), '../js/hydrogen-meta-userscript.js');
  if (!fs.existsSync(userscriptPath)) {
    return null;
  }
  const vm = await import('node:vm');
  const scriptSource = fs.readFileSync(userscriptPath, 'utf8');
  const anchors: any[] = [];
  const insertedBadges: any[] = [];

  for (let i = 1; i <= anchorCount; i += 1) {
    const anchor: any = {
      nodeType: 1,
      textContent: `198.51.100.${i}`,
      dataset: {},
      style: {},
      nextSibling: null,
      nextElementSibling: null,
      classList: { contains: () => false },
      matches: (sel: string) => sel === 'a.ext-checkuser-tempaccount-reveal-ip-anchor',
      closest: () => null,
    };
    anchor.parentNode = {
      insertBefore: (badge: any) => {
        insertedBadges.push({ ip: anchor.textContent, badge });
        anchor.nextElementSibling = badge;
      },
    };
    anchors.push(anchor);
  }

  let readyCallback: (() => void) | null = null;
  let observerDisconnected = false;
  const storageMap = new Map<string, string>(
    options?.initialStorageEntries ?? [
      ['proxycheck-ip-policy-consent', '1'],
      ['proxycheck-gadget-token', 'initial-signed-token'],
      ['proxycheck-gadget-token-user', 'AdminTester'],
    ]
  );

  const mwStub = {
    config: {
      get: (key: string) => {
        if (key === 'wgUserName') return 'AdminTester';
        if (key === 'wgUserIsTemp') return false;
        if (key === 'wgServerName') return 'meta.wikimedia.org';
        if (key === 'wgCanonicalSpecialPageName') return false;
        return null;
      },
    },
    storage: options?.storageDisabled
      ? {
          get: (k: string) => (k === 'proxycheck-ip-policy-consent' ? '1' : false),
          set: () => false,
          remove: () => false,
        }
      : {
          get: (k: string) => storageMap.get(k) ?? null,
          set: (k: string, v: string) => storageMap.set(k, v),
          remove: (k: string) => storageMap.delete(k),
        },
    loader: {
      using: () => Promise.resolve(),
    },
    Api: function () {
      return {
        get: () =>
          Promise.resolve({
            centralauthtoken: { centralauthtoken: 'fresh-cat-token' },
          }),
      };
    },
    html: {
      escape: (s: string) => s,
    },
  };

  const jQueryStub: any = (arg: any) => {
    if (typeof arg === 'function') {
      readyCallback = arg;
    }
    return { length: 0 };
  };

  const documentStub = {
    body: {
      nodeType: 1,
      matches: () => false,
      closest: () => null,
      querySelectorAll: (sel: string) =>
        sel === 'a.ext-checkuser-tempaccount-reveal-ip-anchor' ? anchors : [],
    },
    getElementById: () => null,
    createElement: (tag: string) => ({
      tagName: tag.toUpperCase(),
      style: {},
      classList: { contains: (cls: string) => cls === 'proxycheck-ip-badge' },
      addEventListener: () => {},
    }),
    createTextNode: (text: string) => ({ nodeType: 3, textContent: text }),
  };

  const windowStub: any = {
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
  };

  const context = vm.createContext({
    mediaWiki: mwStub,
    jQuery: jQueryStub,
    window: windowStub,
    document: documentStub,
    MutationObserver: function () {
      return {
        observe: () => {},
        disconnect: () => {
          observerDisconnected = true;
        },
      };
    },
    fetch: fetchImpl,
    console,
    Promise,
    Map,
    Set,
    Object,
    Array,
    String,
    Number,
    Boolean,
    JSON,
    encodeURIComponent,
    isNaN,
  });

  vm.runInContext(scriptSource, context);
  if (readyCallback) {
    (readyCallback as () => void)();
  }

  return {
    anchors,
    insertedBadges,
    storageMap,
    isObserverDisconnected: () => observerDisconnected,
  };
}

test('Userscript micro-batcher coalesces 20 IP anchors into one batch POST and falls back on 404 or 405', async () => {
  const userscriptPath = path.resolve(process.cwd(), '../js/hydrogen-meta-userscript.js');
  if (!fs.existsSync(userscriptPath)) {
    return;
  }

  // Verify 20 simultaneous IP anchors coalesce into a single batch POST request
  const batchCalls: Array<{ url: string; method: string; body: any; auth: string }> = [];
  const harness20 = (await createUserscriptTestHarness(async (url, init) => {
    const parsedBody = init?.body ? JSON.parse(init.body) : null;
    batchCalls.push({
      url,
      method: init?.method || 'GET',
      body: parsedBody,
      auth: init?.headers?.Authorization || '',
    });
    const results: Record<string, any> = {};
    for (const ip of parsedBody.ips) {
      results[ip] = {
        ip,
        isNonPublic: false,
        prediction_score: 75,
        getipintel_chance: 0.75,
        is_broadcast_ip: false,
        isTor: false,
        isMajorityProxyVpn: true,
        arbitrationVerdict: 'Confirmed Proxy / VPN (5/8 Sources)',
        arbitrationTier: 'destructive',
        recommendedCidr: `${ip}/24`,
        mmdbCidr: `${ip}/24`,
        results: [],
      };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        results,
        count: parsedBody.ips.length,
      }),
    };
  }, 20))!;

  await new Promise((resolve) => setTimeout(resolve, 90));

  assert.equal(batchCalls.length, 1);
  assert.equal(batchCalls[0].url, 'https://proxycheck.toolforge.org/api/v1/detect/batch');
  assert.equal(batchCalls[0].method, 'POST');
  assert.equal(batchCalls[0].body.ips.length, 20);
  assert.equal(harness20.insertedBadges.length, 20);

  // Verify HTTP 401 on batch triggers one token refresh and retries the batch
  const retryCalls: string[] = [];
  let firstBatchAttempt = true;
  const harness401 = (await createUserscriptTestHarness(async (url, init) => {
    retryCalls.push(url);
    if (url.endsWith('/api/v1/auth/gadget-token')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ token: 'refreshed-signed-token', username: 'AdminTester', expires_in: 3600 }),
      };
    }
    if (firstBatchAttempt) {
      firstBatchAttempt = false;
      return { ok: false, status: 401, json: async () => ({ error: 'Expired' }) };
    }
    const parsedBody = JSON.parse(init.body);
    assert.equal(init.headers.Authorization, 'Bearer refreshed-signed-token');
    const results: Record<string, any> = {};
    for (const ip of parsedBody.ips) {
      results[ip] = {
        ip,
        isNonPublic: true,
        nonPublicCategory: 'documentation',
        nonPublicReason: 'Documentation Reserved Address',
        results: [],
      };
    }
    return { ok: true, status: 200, json: async () => ({ results, count: parsedBody.ips.length }) };
  }, 3))!;

  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.deepEqual(retryCalls, [
    'https://proxycheck.toolforge.org/api/v1/detect/batch',
    'https://proxycheck.toolforge.org/api/v1/auth/gadget-token',
    'https://proxycheck.toolforge.org/api/v1/detect/batch',
  ]);
  assert.equal(harness401.insertedBadges.length, 3);

  // Verify HTTP 404 on batch smoothly degrades all items in the batch to single-IP GET requests
  const fallbackCalls: string[] = [];
  const harness404 = (await createUserscriptTestHarness(async (url) => {
    fallbackCalls.push(url);
    if (url.endsWith('/api/v1/detect/batch')) {
      return { ok: false, status: 404, json: async () => ({ error: 'Not found' }) };
    }
    const ipParam = new URL(url).searchParams.get('ip') || '198.51.100.1';
    return {
      ok: true,
      status: 200,
      json: async () => ({
        ip: ipParam,
        isNonPublic: false,
        prediction_score: 10,
        getipintel_chance: 0.1,
        is_broadcast_ip: false,
        isTor: false,
        isMajorityProxyVpn: false,
        arbitrationVerdict: 'Clean Residential / Direct (0/8 Sources)',
        arbitrationTier: 'success',
        results: [],
      }),
    };
  }, 4))!;

  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.equal(fallbackCalls[0], 'https://proxycheck.toolforge.org/api/v1/detect/batch');
  assert.equal(fallbackCalls.filter((u) => u.includes('/api/v1/detect?ip=')).length, 4);
  assert.equal(harness404.insertedBadges.length, 4);
});

test('Userscript proactively refreshes expired stored tokens via TOKEN_EXPIRY_KEY and blocks on 403', async () => {
  const userscriptPath = path.resolve(process.cwd(), '../js/hydrogen-meta-userscript.js');
  if (!fs.existsSync(userscriptPath)) {
    return;
  }

  function makeNonPublicBatchResponse(ip: string) {
    return {
      ok: true,
      status: 200,
      json: async () => ({
        results: {
          [ip]: {
            ip,
            isNonPublic: true,
            nonPublicCategory: 'documentation',
            nonPublicReason: 'Documentation Reserved Address',
            results: [],
          },
        },
        count: 1,
      }),
    };
  }

  // Expired TOKEN_EXPIRY_KEY triggers a proactive token exchange before sending any detection request
  const expiredCalls: Array<{ url: string; auth: string }> = [];
  const beforeExchangeMs = Date.now();
  const expiredHarness = (await createUserscriptTestHarness(
    async (url, init) => {
      expiredCalls.push({ url, auth: init?.headers?.Authorization || '' });
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: 'proactively-refreshed-token', username: 'AdminTester', expires_in: 3600 }),
        };
      }
      return makeNonPublicBatchResponse('198.51.100.1');
    },
    1,
    {
      initialStorageEntries: [
        ['proxycheck-ip-policy-consent', '1'],
        ['proxycheck-gadget-token', 'stale-signed-token'],
        ['proxycheck-gadget-token-user', 'AdminTester'],
        ['proxycheck-gadget-token-exp', String(Date.now() - 1000)],
      ],
    }
  ))!;

  await new Promise((resolve) => setTimeout(resolve, 90));
  const afterExchangeMs = Date.now();

  assert.deepEqual(expiredCalls, [
    { url: 'https://proxycheck.toolforge.org/api/v1/auth/gadget-token', auth: '' },
    {
      url: 'https://proxycheck.toolforge.org/api/v1/detect/batch?compact=1',
      auth: 'Bearer proactively-refreshed-token',
    },
  ]);
  assert.equal(expiredHarness.storageMap.get('proxycheck-gadget-token'), 'proactively-refreshed-token');
  const storedExpiryMs = Number(expiredHarness.storageMap.get('proxycheck-gadget-token-exp'));
  assert.ok(
    storedExpiryMs >= beforeExchangeMs + 3540 * 1000 && storedExpiryMs <= afterExchangeMs + 3540 * 1000,
    `Expected stored expiry within 59-minute buffer window, got ${storedExpiryMs}`
  );

  // Corrupt TOKEN_EXPIRY_KEY also clears stored credentials and triggers proactive refresh
  const corruptCalls: string[] = [];
  await createUserscriptTestHarness(
    async (url) => {
      corruptCalls.push(url);
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: 'recovered-token', username: 'AdminTester', expires_in: 3600 }),
        };
      }
      return makeNonPublicBatchResponse('198.51.100.1');
    },
    1,
    {
      initialStorageEntries: [
        ['proxycheck-ip-policy-consent', '1'],
        ['proxycheck-gadget-token', 'corrupt-expiry-token'],
        ['proxycheck-gadget-token-user', 'AdminTester'],
        ['proxycheck-gadget-token-exp', 'not-a-timestamp'],
      ],
    }
  );

  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.deepEqual(corruptCalls, [
    'https://proxycheck.toolforge.org/api/v1/auth/gadget-token',
    'https://proxycheck.toolforge.org/api/v1/detect/batch?compact=1',
  ]);

  // Unexpired TOKEN_EXPIRY_KEY reuses the cached token without hitting the exchange endpoint
  const validCalls: Array<{ url: string; auth: string }> = [];
  await createUserscriptTestHarness(
    async (url, init) => {
      validCalls.push({ url, auth: init?.headers?.Authorization || '' });
      return makeNonPublicBatchResponse('198.51.100.1');
    },
    1,
    {
      initialStorageEntries: [
        ['proxycheck-ip-policy-consent', '1'],
        ['proxycheck-gadget-token', 'fresh-cached-token'],
        ['proxycheck-gadget-token-user', 'AdminTester'],
        ['proxycheck-gadget-token-exp', String(Date.now() + 120000)],
      ],
    }
  );

  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.deepEqual(validCalls, [
    {
      url: 'https://proxycheck.toolforge.org/api/v1/detect/batch?compact=1',
      auth: 'Bearer fresh-cached-token',
    },
  ]);

  // Disabled mw.storage returning false still exchanges a token and proceeds cleanly in memory
  const disabledStorageCalls: Array<{ url: string; auth: string }> = [];
  await createUserscriptTestHarness(
    async (url, init) => {
      disabledStorageCalls.push({ url, auth: init?.headers?.Authorization || '' });
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ token: 'memory-only-token', username: 'AdminTester', expires_in: 3600 }),
        };
      }
      return makeNonPublicBatchResponse('198.51.100.1');
    },
    1,
    { storageDisabled: true }
  );

  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.deepEqual(disabledStorageCalls, [
    { url: 'https://proxycheck.toolforge.org/api/v1/auth/gadget-token', auth: '' },
    {
      url: 'https://proxycheck.toolforge.org/api/v1/detect/batch?compact=1',
      auth: 'Bearer memory-only-token',
    },
  ]);

  // HTTP 403 clears token, user, and expiry keys and halts access without retrying token exchange
  const forbiddenCalls: string[] = [];
  const forbiddenHarness = (await createUserscriptTestHarness(
    async (url) => {
      forbiddenCalls.push(url);
      return {
        ok: false,
        status: 403,
        json: async () => ({ error: 'Access denied. Insufficient Wikimedia user rights.' }),
      };
    },
    1,
    {
      initialStorageEntries: [
        ['proxycheck-ip-policy-consent', '1'],
        ['proxycheck-gadget-token', 'revoked-token'],
        ['proxycheck-gadget-token-user', 'AdminTester'],
        ['proxycheck-gadget-token-exp', String(Date.now() + 120000)],
      ],
    }
  ))!;

  await new Promise((resolve) => setTimeout(resolve, 90));
  assert.deepEqual(forbiddenCalls, ['https://proxycheck.toolforge.org/api/v1/detect/batch?compact=1']);
  assert.equal(forbiddenHarness.storageMap.has('proxycheck-gadget-token'), false);
  assert.equal(forbiddenHarness.storageMap.has('proxycheck-gadget-token-user'), false);
  assert.equal(forbiddenHarness.storageMap.has('proxycheck-gadget-token-exp'), false);
  assert.equal(forbiddenHarness.isObserverDisconnected(), true);
});



