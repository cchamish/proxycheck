import test from 'node:test';
import assert from 'node:assert/strict';
import {
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
  createDetectionCoordinator,
  formatRelativeUpdatedLabel,
  resolveProviderUpdatedLabel,
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
