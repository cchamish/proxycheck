import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { resolveCommitMetadata } from '../../vite.config';
import {
  COMMERCIAL_ARBITRATION_PROVIDERS,
  PROVIDER_NAMES,
  REQUIRED_USER_RIGHTS,
  isValidIpAddress,
  canonicalizeIpAddress,
  extractCanonicalIpFromSearch,
  buildOAuthLoginUrl,
  buildPageUrlWithIp,
  buildSpecialBlockUrl,
  buildVerificationLinks,
  buildWikitextSummary,
  updateIpHistory,
  filterComparisonResults,
  simplifySecurityFlags,
  getProviderMetaItems,
  getStatusBadgeClass,
  getPredictionScoreTierClass,
  getArbitrationBadgeClass,
  getPtrBadgeClass,
  getSharedPrivacyEgressInfo,
  isCacheStale,
  isMobileOrCgnatDetection,
  extractOpenProxyPorts,
  extractShodanTags,
  shouldRecommendFreshRecheck,
  shouldUseSoftBlockDefaults,
  formatCacheAgeBadgeLabel,
  formatExactUtcTimestamp,
  resolveRefetchButtonState,
  resolveDashboardCacheTelemetry,
  formatChance,
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
  type CacheMeta,
  type DetectionCoordinatorState,
  type DetectionResponse,
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

  await coordinator.executeDetection('not-an-ip');
  assert.deepEqual(succeeded, []);

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
  const bypassedMeta: CacheMeta = {
    status: 'bypassed',
    isPartial: false,
    hitCount: 0,
    missCount: 0,
    cooldownCount: 0,
    totalSources: 0,
    cachedAt: null,
  };

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
  assert.equal(resolveProviderUpdatedLabel(freshRow, { isCached: false, cacheMeta: bypassedMeta }, nowMs), null);
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

test('Status, prediction, arbitration, PTR, and metadata helpers classify provider and response states', () => {
  assert.equal(PROVIDER_NAMES.length, 18);
  assert.deepEqual(PROVIDER_NAMES.slice(-3), ['IPsum / DROP', 'X4BNet VPN', 'Shodan InternetDB']);
  assert.equal(COMMERCIAL_ARBITRATION_PROVIDERS.length, 8);

  const statusCases: Array<[string | null | undefined, string]> = [
    [null, 'badge-neutral'],
    ['200 OK', 'badge-success'],
    ['No API Key', 'badge-neutral'],
    ['Database Missing', 'badge-neutral'],
    ['Offline DB Missing', 'badge-neutral'],
    ['Skipped (IPv6)', 'badge-neutral'],
    ['Deferred (Light Mode)', 'badge-neutral'],
    ['429 Rate Limited', 'badge-warning'],
    ['429 Cooldown (120s)', 'badge-warning'],
    ['Local Quota Guard (15/15 req/min)', 'badge-warning'],
    ['502 Error', 'badge-destructive'],
  ];
  for (const [status, expectedBadge] of statusCases) {
    assert.equal(getStatusBadgeClass(status), expectedBadge, `Unexpected badge for ${String(status)}`);
  }

  assert.equal(getPredictionScoreTierClass(null), 'score-tier-low');
  assert.equal(getPredictionScoreTierClass({ predictionTier: 'destructive', prediction_score: 5 }), 'score-tier-high');
  assert.equal(getPredictionScoreTierClass({ predictionTier: 'warning', prediction_score: 5 }), 'score-tier-moderate');
  assert.equal(getPredictionScoreTierClass({ predictionTier: 'success', prediction_score: 95 }), 'score-tier-low');
  assert.equal(getPredictionScoreTierClass({ prediction_score: 75 }), 'score-tier-high');
  assert.equal(getPredictionScoreTierClass({ prediction_score: 40 }), 'score-tier-moderate');
  assert.equal(getPredictionScoreTierClass({ prediction_score: 10 }), 'score-tier-low');

  assert.equal(getArbitrationBadgeClass(null), 'badge-neutral');
  assert.equal(getArbitrationBadgeClass({ arbitrationTier: 'destructive' }), 'badge-destructive');
  assert.equal(getArbitrationBadgeClass({ isMajorityProxyVpn: true }), 'badge-destructive');
  assert.equal(getArbitrationBadgeClass({ arbitrationVerdict: 'Disputed (2/6 Sources)' }), 'badge-warning');
  assert.equal(getArbitrationBadgeClass({ arbitrationTier: 'neutral' }), 'badge-neutral');
  assert.equal(getArbitrationBadgeClass({ arbitrationTier: 'success' }), 'badge-success');

  assert.equal(getPtrBadgeClass(null), 'badge-neutral');
  assert.equal(getPtrBadgeClass({ ptrCategory: 'hosting_or_gateway' }), 'badge-destructive');
  assert.equal(getPtrBadgeClass({ ptrCategory: 'unclassified', ptrIsHighRisk: true }), 'badge-destructive');
  assert.equal(getPtrBadgeClass({ ptrCategory: 'mobile_or_cgnat' }), 'badge-warning');
  assert.equal(getPtrBadgeClass({ ptrCategory: 'dynamic_residential' }), 'badge-success');
  assert.equal(getPtrBadgeClass({ ptrCategory: 'unclassified' }), 'badge-neutral');

  assert.equal(formatChance(12.34567), 12.346);
  assert.equal(formatChance('invalid'), 0);

  const nowMs = Date.parse('2026-11-16T06:00:00Z');
  assert.deepEqual(
    getProviderMetaItems(
      {
        provider: 'StopForumSpam',
        port: 1080,
        frequency: 12,
        confidence: 95,
        carrier: 'T-Mobile',
        mobileBrand: 'Metro',
        cloudProvider: 'Amazon AWS',
        totalReports: 7,
        numDistinctUsers: 4,
        lastSeen: '2026-11-15',
        offlineDbUpdatedAt: '2026-11-16T05:00:00Z',
      },
      nowMs
    ),
    [
      'Port: 1080',
      'Frequency: 12',
      'Confidence: 95%',
      'Carrier: T-Mobile',
      'Mobile brand: Metro',
      'Cloud: Amazon AWS',
      'Reports: 7',
      'Distinct users: 4',
      'Last seen: 2026-11-15',
      'Offline DB: 2026-11-16 05:00 UTC (1h ago)',
    ]
  );
  assert.deepEqual(
    getProviderMetaItems({
      provider: 'DShield',
      attacks: 20,
      count: 3,
      threatfeeds: ['scanner', 'ssh'],
    }),
    ['Attacks: 20', 'Targets: 3', 'Feeds: scanner, ssh']
  );
});

test('Provider metadata helpers format Shodan ports and tags, IPsum and DROP hits, and X4BNet categories', () => {
  const metaCases: Array<{ label: string; row: Parameters<typeof getProviderMetaItems>[0]; expected: string[] }> = [
    {
      label: 'shodan proxy ports tags and hostnames',
      row: { provider: 'Shodan InternetDB', ports: [80, 443, 1080, 3128], openProxyPorts: [1080, 3128], tags: ['proxy', 'compromised'], hostnames: ['gw1.example.net', 'gw2.example.net'] },
      expected: ['Proxy ports: 1080, 3128', 'Tags: proxy, compromised', 'Hostnames: gw1.example.net, gw2.example.net'],
    },
    {
      label: 'shodan general open ports without proxy ports',
      row: { provider: 'Shodan InternetDB', ports: [22, 80, 443], openProxyPorts: [], tags: ['vpn'] },
      expected: ['Open ports: 22, 80, 443', 'Tags: vpn'],
    },
    {
      label: 'ipsum score and spamhaus drop prefix',
      row: { provider: 'IPsum / DROP', ipsumScore: 4, inSpamhausDrop: true, dropSblId: 'SBL123456', dropCidr: '198.51.100.0/24' },
      expected: ['IPsum lists: 4', 'Spamhaus DROP: SBL123456 · 198.51.100.0/24'],
    },
    {
      label: 'x4bnet vpn category and prefix',
      row: { provider: 'X4BNet VPN', category: 'vpn', matchedCidr: '203.0.113.0/24', sources: ['x4bnet_vpn'] },
      expected: ['Category: VPN', 'Prefix: 203.0.113.0/24', 'Sources: x4bnet_vpn'],
    },
    {
      label: 'x4bnet datacenter category and historical fallback',
      row: { provider: 'X4BNet VPN', category: 'datacenter', isHistoricalFallback: true },
      expected: ['Category: Datacentre', 'Historical L2 fallback'],
    },
  ];
  for (const { label, row, expected } of metaCases) {
    assert.deepEqual(getProviderMetaItems(row), expected, label);
  }
});

function buildCachedDetectionPayload(
  ip: string,
  overrides: Partial<DetectionResponse> = {},
  metaOverrides: Partial<CacheMeta> = {}
): DetectionResponse {
  const baseMeta: CacheMeta = {
    status: 'hit',
    layer: 'L2',
    isPartial: false,
    hitCount: 8,
    missCount: 0,
    cooldownCount: 0,
    totalSources: 8,
    cachedAt: '2026-10-01T12:00:00Z',
    fetchedAt: '2026-10-01T12:00:00Z',
    ageSeconds: 45 * 86_400,
    staleThresholdSeconds: 7_776_000,
    isStale: false,
    shouldAutoRefresh: false,
    refreshInProgress: false,
    degradedRefreshFallback: false,
    recommendFreshRecheck: false,
    ...metaOverrides,
  };
  return {
    ip,
    fetchedAt: baseMeta.fetchedAt,
    isCached: true,
    cacheMeta: baseMeta,
    is_broadcast_ip: false,
    prediction_score: 12,
    getipintel_chance: 12,
    arbitrationVerdict: 'Clean Residential / Direct (0/6 Sources)',
    arbitrationTier: 'success',
    isMajorityProxyVpn: false,
    primaryCountry: 'United Kingdom',
    primaryCoordinates: '51.5, -0.1',
    primaryAsn: 'AS2856',
    recommendedCidr: `${ip}/24`,
    results: [
      { ...makeProviderResult('Cloudflare Radar'), status: '200 OK', asn: 'AS2856', isp: 'British Telecommunications PLC', organisation: 'British Telecommunications PLC' },
    ],
    ...overrides,
  };
}

test('Cache age badge, exact UTC tooltip, staleness, and unified refetch button helpers handle all states', () => {
  const nowMs = Date.parse('2026-11-15T12:00:00Z');
  assert.equal(formatExactUtcTimestamp('2026-10-01T12:00:00.123456+00:00'), '2026-10-01 12:00:00 UTC');
  assert.equal(formatExactUtcTimestamp('invalid'), null);
  assert.equal(formatExactUtcTimestamp(null), null);

  const within90d = buildCachedDetectionPayload('203.0.113.10');
  assert.equal(isCacheStale(within90d), false);
  assert.equal(formatCacheAgeBadgeLabel(within90d, nowMs), 'Cached 45d ago');

  const staleOver90d = buildCachedDetectionPayload(
    '203.0.113.11',
    {},
    { status: 'stale', fetchedAt: '2026-07-01T12:00:00Z', cachedAt: '2026-07-01T12:00:00Z', ageSeconds: 137 * 86_400, isStale: true, shouldAutoRefresh: true }
  );
  assert.equal(isCacheStale(staleOver90d), true);
  assert.equal(formatCacheAgeBadgeLabel(staleOver90d, nowMs), 'Cached 137d ago');

  const refreshedPayload = buildCachedDetectionPayload(
    '203.0.113.11',
    { isCached: false, fetchedAt: '2026-11-15T11:59:55Z' },
    { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, fetchedAt: '2026-11-15T11:59:55Z' }
  );
  assert.equal(formatCacheAgeBadgeLabel(refreshedPayload, nowMs, '2026-11-15T11:59:55Z'), 'Just updated');
  assert.equal(formatCacheAgeBadgeLabel({ ...within90d, isNonPublic: true }, nowMs), null);

  assert.deepEqual(resolveRefetchButtonState({ data: within90d, isRefreshing: false, isLoading: false }), {
    visible: true, label: 'Refetch', disabled: false, isBusy: false,
  });
  assert.deepEqual(resolveRefetchButtonState({ data: within90d, isRefreshing: true, isLoading: false }), {
    visible: true, label: 'Updating...', disabled: true, isBusy: true,
  });
  assert.deepEqual(
    resolveRefetchButtonState({ data: buildCachedDetectionPayload('203.0.113.12', {}, { refreshInProgress: true }) }),
    { visible: true, label: 'Updating...', disabled: true, isBusy: true }
  );
});

test('Coordinator 90-day SWR state machine handles manual refetch, auto-SWR first paint, and concurrent lock notice', async () => {
  const requests: Array<{ url: string; method: string; body?: any }> = [];
  let resolveManualRefresh!: (val: any) => void;

  const coordinator = createDetectionCoordinator((url, init) => {
    const method = init?.method || 'GET';
    const body = typeof init?.body === 'string' ? JSON.parse(init.body) : undefined;
    requests.push({ url, method, body });
    if (url.includes('ip=203.0.113.20')) {
      return Promise.resolve({ ok: true, status: 200, json: async () => buildCachedDetectionPayload('203.0.113.20') });
    }
    if (url === '/api/v1/detect/refresh' && body?.ip === '203.0.113.20') {
      return new Promise((resolve) => { resolveManualRefresh = resolve; });
    }
    if (url.includes('ip=203.0.113.21')) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => buildCachedDetectionPayload('203.0.113.21', {}, { refreshInProgress: true, shouldAutoRefresh: false }),
      });
    }
    throw new Error(`Unexpected URL ${url}`);
  });

  await coordinator.executeDetection('203.0.113.20');
  assert.equal(requests.length, 1);
  assert.equal(coordinator.state.isRefreshing, false);
  assert.equal(coordinator.state.detectionData?.ip, '203.0.113.20');

  const firstClick = coordinator.refreshDetection();
  assert.equal(coordinator.state.isRefreshing, true);
  assert.equal(resolveRefetchButtonState({ data: coordinator.state.detectionData, isRefreshing: coordinator.state.isRefreshing }).label, 'Updating...');

  // Duplicate manual click while Updating... is active does not send a second POST
  const duplicateClick = coordinator.refreshDetection();
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[1], {
    url: '/api/v1/detect/refresh',
    method: 'POST',
    body: { ip: '203.0.113.20', mode: 'full', compact: false },
  });

  resolveManualRefresh({
    ok: true,
    status: 200,
    json: async () =>
      buildCachedDetectionPayload(
        '203.0.113.20',
        { isCached: false, fetchedAt: '2026-11-18T00:00:00Z', arbitrationVerdict: 'Confirmed Proxy / VPN (5/6 Sources)' },
        { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false, fetchedAt: '2026-11-18T00:00:00Z' }
      ),
  });
  await Promise.all([firstClick, duplicateClick]);

  assert.equal(coordinator.state.isRefreshing, false);
  assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Confirmed Proxy / VPN (5/6 Sources)');
  assert.equal(
    formatCacheAgeBadgeLabel(coordinator.state.detectionData, Date.parse('2026-11-18T00:00:10Z'), coordinator.state.lastRefreshedAt),
    'Just updated'
  );

  // Concurrent refreshInProgress from another user renders immediately without duplicate POST
  await coordinator.executeDetection('203.0.113.21');
  assert.equal(requests.length, 3);
  assert.equal(coordinator.state.isRefreshing, false);
  assert.equal(resolveRefetchButtonState({ data: coordinator.state.detectionData, isRefreshing: coordinator.state.isRefreshing }).label, 'Updating...');
});

test('Coordinator triggers non-blocking auto-SWR over 90 days and aborts stale refresh on IP switch', async () => {
  let resolveAutoRefreshA!: (val: any) => void;
  let capturedRefreshSignalA: AbortSignal | undefined;
  const calls: string[] = [];

  const coordinator = createDetectionCoordinator((url, init) => {
    calls.push(`${init?.method || 'GET'} ${url}`);
    if (url.includes('ip=198.51.100.1')) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () =>
          buildCachedDetectionPayload(
            '198.51.100.1',
            { arbitrationVerdict: 'Historical Cached Verdict' },
            { status: 'stale', ageSeconds: 120 * 86_400, isStale: true, shouldAutoRefresh: true, refreshInProgress: false }
          ),
      });
    }
    if (url === '/api/v1/detect/refresh') {
      capturedRefreshSignalA = init?.signal ?? undefined;
      return new Promise((resolve) => { resolveAutoRefreshA = resolve; });
    }
    if (url.includes('ip=198.51.100.2')) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => buildCachedDetectionPayload('198.51.100.2', { arbitrationVerdict: 'Second IP Clean Verdict' }),
      });
    }
    throw new Error(`Unexpected request: ${url}`);
  });

  await coordinator.executeDetection('198.51.100.1');
  assert.equal(coordinator.state.isLoading, false);
  assert.equal(coordinator.state.detectionData?.ip, '198.51.100.1');
  assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Historical Cached Verdict');
  assert.equal(coordinator.state.isRefreshing, true);
  assert.deepEqual(calls, ['GET /api/v1/detect?ip=198.51.100.1', 'POST /api/v1/detect/refresh']);
  assert.equal(capturedRefreshSignalA?.aborted, false);

  const secondQuery = coordinator.executeDetection('198.51.100.2');
  assert.equal(capturedRefreshSignalA?.aborted, true);
  await secondQuery;

  resolveAutoRefreshA({
    ok: true,
    status: 200,
    json: async () => buildCachedDetectionPayload('198.51.100.1', { arbitrationVerdict: 'Stale Refresh Overwrite Attempt' }),
  });
  await coordinator.waitForActiveRefresh();

  assert.equal(coordinator.state.detectionData?.ip, '198.51.100.2');
  assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Second IP Clean Verdict');
  assert.equal(coordinator.state.isRefreshing, false);
});

test('Coordinator preserves valid historical data on degradedRefreshFallback and HTTP 429 responses', async () => {
  const failureCases: Array<{ label: string; refreshResponse: { ok: boolean; status: number; json: () => Promise<any> }; expectedWarningPattern: RegExp }> = [
    {
      label: 'degradedRefreshFallback response',
      refreshResponse: {
        ok: true,
        status: 200,
        json: async () => ({
          ip: '203.0.113.55',
          isCached: true,
          cacheMeta: { status: 'stale', isStale: true, shouldAutoRefresh: false, refreshInProgress: false, degradedRefreshFallback: true },
        }),
      },
      expectedWarningPattern: /temporarily constrained[\s\S]*historical intelligence is preserved/i,
    },
    {
      label: 'HTTP 429 rate limited response',
      refreshResponse: { ok: false, status: 429, json: async () => ({ error: 'rate_limited', retryAfterSeconds: 42 }) },
      expectedWarningPattern: /rate limit is temporarily constrained[\s\S]*42s/i,
    },
  ];

  for (const { label, refreshResponse, expectedWarningPattern } of failureCases) {
    const coordinator = createDetectionCoordinator(async (url) => {
      if (url.startsWith('/api/v1/detect?')) {
        return {
          ok: true,
          status: 200,
          json: async () =>
            buildCachedDetectionPayload('203.0.113.55', { arbitrationVerdict: 'Preserved Historical Verdict (4/6 Sources)' }, { status: 'stale', isStale: true, shouldAutoRefresh: true }),
        };
      }
      return refreshResponse;
    });

    await coordinator.executeDetection('203.0.113.55');
    await coordinator.waitForActiveRefresh();

    assert.equal(coordinator.state.isRefreshing, false, label);
    assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Preserved Historical Verdict (4/6 Sources)', label);
    assert.equal(coordinator.state.detectionData?.results?.length, 1, label);
    assert.equal(coordinator.state.detectionData?.cacheMeta?.shouldAutoRefresh, false, label);
    assert.match(coordinator.state.refreshWarningMessage || '', expectedWarningPattern, label);
  }
});

test('Special:Block soft-block parameters, verification deep links, threat helpers, and desensitised Wikitext summary', () => {
  assert.equal(getSharedPrivacyEgressInfo('icloud_private_relay')?.label, 'Apple iCloud Private Relay');
  assert.equal(getSharedPrivacyEgressInfo('cloudflare_warp')?.label, 'Cloudflare WARP');
  assert.equal(getSharedPrivacyEgressInfo(null), null);
  assert.equal(isMobileOrCgnatDetection({ isMobileOrCgnat: true }), true);
  assert.equal(isMobileOrCgnatDetection({ ptrCategory: 'mobile_or_cgnat' }), true);
  assert.equal(isMobileOrCgnatDetection({ ptrCategory: 'dynamic_residential' }), false);

  const shodanPayload = buildCachedDetectionPayload(
    '198.51.100.77',
    {
      suspectedResidentialProxy: true,
      results: [
        { ...makeProviderResult('Shodan InternetDB'), status: '200 OK', openProxyPorts: [1080, 8080], tags: ['proxy', 'compromised'] },
        { ...makeProviderResult('AbuseIPDB'), status: '200 OK', isp: 'Example Residential ISP', riskScore: 93, totalReports: 41, rawJson: { abuseConfidenceScore: 93 } },
      ],
    },
    { ageSeconds: 10 * 86_400, recommendFreshRecheck: true }
  );

  assert.deepEqual(extractOpenProxyPorts(shodanPayload), [1080, 8080]);
  assert.deepEqual(extractShodanTags(shodanPayload), ['proxy', 'compromised']);
  assert.equal(shouldRecommendFreshRecheck(shodanPayload), true);
  assert.equal(
    shouldRecommendFreshRecheck({
      suspectedResidentialProxy: true,
      cacheMeta: { status: 'hit', isPartial: false, hitCount: 1, missCount: 0, cooldownCount: 0, totalSources: 1, cachedAt: null, ageSeconds: 3600 },
    }),
    false
  );

  const standardLinks = buildVerificationLinks(shodanPayload);
  assert.ok(standardLinks);
  assert.equal(standardLinks.globalContributionsUrl, 'https://meta.wikimedia.org/wiki/Special:GlobalContributions/198.51.100.77');
  assert.equal(standardLinks.rangeblockFinderUrl, 'https://rangeblockfinder.toolforge.org/?ip=198.51.100.77');
  assert.equal(standardLinks.whoisGatewayUrl, 'https://whois.toolforge.org/gateway.py?lookup=true&ip=198.51.100.77');
  assert.equal(standardLinks.specialBlockUrl, 'https://meta.wikimedia.org/wiki/Special:Block/198.51.100.77/24');
  assert.equal(standardLinks.isSoftBlockRecommended, false);

  const softBlockCases: Array<{ label: string; data: Partial<DetectionResponse>; expectedTarget: string }> = [
    { label: 'iCloud Private Relay IPv6', data: { ip: '2a09:bac2:1234::1', recommendedCidr: '2a09:bac2:1234::/64', sharedPrivacyEgress: 'icloud_private_relay' }, expectedTarget: '2a09:bac2:1234::/64' },
    { label: 'Mobile CGNAT IPv4', data: { ip: '100.64.12.34', recommendedCidr: '100.64.12.34/32', isMobileOrCgnat: true }, expectedTarget: '100.64.12.34/32' },
    { label: 'PTR mobile_or_cgnat fallback', data: { ip: '203.0.113.99', recommendedCidr: '203.0.113.99/32', ptrCategory: 'mobile_or_cgnat' }, expectedTarget: '203.0.113.99/32' },
  ];
  for (const { label, data, expectedTarget } of softBlockCases) {
    assert.equal(shouldUseSoftBlockDefaults(data), true, label);
    assert.equal(buildSpecialBlockUrl(data), `https://meta.wikimedia.org/wiki/Special:Block/${expectedTarget}?wpHardBlock=0&wpDisableUTEdit=0`, label);
  }

  const ipv6EscalationPayload = buildCachedDetectionPayload(
    '2001:0db8:abcd:0012::0001',
    {
      primaryAsn: 'AS6805',
      recommendedCidr: '2001:db8:abcd:12::/64',
      escalationCidr: '2001:db8:abcd::/56',
      arbitrationVerdict: 'Suspected Residential Proxy / Compromised Host',
      suspectedResidentialProxy: true,
      prediction_score: 98.765,
      getipintel_chance: 98.765,
      fetchedAt: '2026-07-15T09:12:30Z',
      results: [
        { ...makeProviderResult('Cloudflare Radar'), status: '200 OK', asn: 'AS6805', isp: 'Telefonica Germany' },
        { ...makeProviderResult('Shodan InternetDB'), status: '200 OK', openProxyPorts: [1080, 3128] },
        { ...makeProviderResult('AbuseIPDB'), status: '200 OK', riskScore: 95, totalReports: 88, rawJson: { abuseConfidenceScore: 95 } },
      ],
    },
    { fetchedAt: '2026-07-15T09:12:30Z' }
  );

  const wikitext = buildWikitextSummary(ipv6EscalationPayload);
  assert.match(wikitext, /2001:db8:abcd:12::1/);
  assert.match(wikitext, /2001:db8:abcd:12::\/64/);
  assert.match(wikitext, /escalation: <code>2001:db8:abcd::\/56<\/code>/);
  assert.match(wikitext, /AS6805/);
  assert.match(wikitext, /Telefonica Germany/);
  assert.match(wikitext, /Suspected Residential Proxy \/ Compromised Host/);
  assert.match(wikitext, /Open proxy ports: 1080, 3128/);
  assert.match(wikitext, /fetched 2026-07-15 UTC/);
  assert.doesNotMatch(wikitext, /98\.765|abuseConfidenceScore|totalReports|88|95%|GetIPIntel|AbuseIPDB/);
});

test('Dashboard cache telemetry resolver and Vue templates expose dual-layer SWR metrics', () => {
  const expectedTelemetry = {
    l1Hit: 120, l2HitFresh: 45, l2HitStaleSwr: 12, upstreamMiss: 23,
    refreshOk: 9, refreshRateLimited: 2, dualLayerHitRatePercent: 88.5, l2EstimatedRows: 15_420,
  };
  assert.deepEqual(resolveDashboardCacheTelemetry({ cacheTelemetry: expectedTelemetry }), expectedTelemetry);

  const fallbackFromGlobal = resolveDashboardCacheTelemetry({
    global: {
      totalRequestsToday: 10, authSession: 8, authGadget: 2, cacheHit: 7, cachePartial: 0, cacheMiss: 3,
      fullCacheHitRatePercent: 70, l1Hit: 5, l2HitFresh: 2, l2HitStaleSwr: 0, upstreamMiss: 3,
      refreshOk: 1, refreshRateLimited: 0, dualLayerHitRatePercent: 70, l2EstimatedRows: null,
      totalQuotaBlocksToday: 0, activeCooldownCount: 0, activeQuotaGuardCount: 0,
    },
  });
  assert.equal(fallbackFromGlobal.l1Hit, 5);
  assert.equal(fallbackFromGlobal.l2HitFresh, 2);
  assert.equal(fallbackFromGlobal.l2EstimatedRows, null);

  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  const dashboardVue = fs.readFileSync(path.resolve(process.cwd(), 'src/components/ProviderDashboardModal.vue'), 'utf8');

  for (const requiredPattern of [/Copy Wikitext Summary/]) {
    assert.match(appVue, requiredPattern);
  }
  for (const requiredModalPattern of [/Dual-Layer Cache Hit Rate/, /ToolsDB L2 Hits/, /ToolsDB L2 Estimated Rows/, /429 Rate-Limited/]) {
    assert.match(dashboardVue, requiredModalPattern);
  }
});
