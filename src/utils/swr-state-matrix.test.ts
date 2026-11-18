import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

import {
  buildSpecialBlockUrl,
  buildWikitextSummary,
  createDetectionCoordinator,
  formatCacheAgeBadgeLabel,
  isCacheStale,
  resolveDashboardCacheTelemetry,
  resolveRefetchButtonState,
  shouldRecommendFreshRecheck,
  shouldUseSoftBlockDefaults,
  type CacheMeta,
  type DetectionResponse,
  type ProviderRawResult,
} from './ip-detector-logic.ts';

const REPO_ROOT = path.resolve(import.meta.dirname, '..', '..');
const GADGET_PATH = path.join(REPO_ROOT, 'scripts', 'user-gadget.js');
const GADGET_SOURCE = fs.readFileSync(GADGET_PATH, 'utf8');

const FIXED_NOW_ISO = '2026-11-18T12:00:00.000Z';
const FIXED_NOW_MS = Date.parse(FIXED_NOW_ISO);
const NINETY_DAYS_SECONDS = 90 * 86_400;

type AnyRecord = Record<string, unknown>;

interface RecordedSpaCall {
  url: string;
  method: string;
  signal: AbortSignal | null;
  bodyJson: unknown;
}

function makeProviderRow(
  provider: ProviderRawResult['provider'],
  overrides: Partial<ProviderRawResult> = {}
): ProviderRawResult {
  return {
    provider,
    status: '200 OK',
    statusCode: 200,
    asn: 'AS14061',
    isp: 'DigitalOcean, LLC',
    organisation: 'DigitalOcean, LLC',
    location: 'United States',
    usageType: 'hosting',
    securityFlags: [{ label: 'No Flags', isHighRisk: false }],
    rawJson: {},
    ...overrides,
  };
}

function makeDetectionPayload(
  ip: string,
  overrides: Partial<DetectionResponse> = {},
  metaOverrides: Partial<CacheMeta> = {}
): DetectionResponse {
  const ageSeconds = metaOverrides.ageSeconds ?? 0;
  const computedFetchedAt = new Date(FIXED_NOW_MS - ageSeconds * 1000).toISOString();
  const baseMeta: CacheMeta = {
    status: ageSeconds > NINETY_DAYS_SECONDS ? 'stale' : 'hit',
    layer: ageSeconds === 0 ? 'upstream' : 'L2',
    isPartial: false,
    hitCount: ageSeconds === 0 ? 0 : 12,
    missCount: ageSeconds === 0 ? 12 : 0,
    cooldownCount: 0,
    totalSources: 12,
    cachedAt: computedFetchedAt,
    fetchedAt: computedFetchedAt,
    ageSeconds,
    staleThresholdSeconds: NINETY_DAYS_SECONDS,
    isStale: ageSeconds > NINETY_DAYS_SECONDS,
    shouldAutoRefresh: ageSeconds > NINETY_DAYS_SECONDS,
    refreshInProgress: false,
    degradedRefreshFallback: false,
    recommendFreshRecheck: false,
    ...metaOverrides,
  };

  return {
    ip,
    fetchedAt: overrides.fetchedAt ?? baseMeta.fetchedAt ?? computedFetchedAt,
    queryMode: 'full',
    isPartialMode: false,
    isCached: overrides.isCached ?? ageSeconds > 0,
    cacheMeta: baseMeta,
    durationSeconds: 0.042,
    memoryMb: 64.5,
    is_broadcast_ip: false,
    prediction_score: 82.5,
    predictionTier: 'destructive',
    getipintel_chance: 82.5,
    arbitrationVerdict: 'Confirmed Proxy / VPN (4/5 Sources)',
    arbitrationTier: 'destructive',
    isMajorityProxyVpn: true,
    suspectedResidentialProxy: false,
    primaryCountry: 'US',
    primaryCoordinates: '37.7510, -97.8220',
    primaryAsn: 'AS14061',
    recommendedCidr: ip.includes(':') ? `${ip}/64` : `${ip}/24`,
    bgpPrefix: ip.includes(':') ? '2001:db8::/32' : '198.51.100.0/22',
    escalationCidr: null,
    isMobileOrCgnat: false,
    sharedPrivacyEgress: null,
    results: [
      makeProviderRow('Cloudflare Radar'),
      makeProviderRow('MaxMind'),
      makeProviderRow('Proxycheck', { securityFlags: [{ label: 'VPN', isHighRisk: true }] }),
    ],
    ...overrides,
  };
}

function deferredResponse<T>() {
  let resolveFn!: (value: T) => void;
  let rejectFn!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    resolveFn = resolve;
    rejectFn = reject;
  });
  return { promise, resolve: resolveFn, reject: rejectFn };
}

test('SPA state machine matrix covers cold, fresh <=90d manual refetch, >90d auto-SWR, and singleflight lock', async (t) => {
  const tierCases: Array<{
    name: string;
    ip: string;
    isCached: boolean;
    meta: Partial<CacheMeta>;
    expectInitialStale: boolean;
    expectInitialBadge: string;
    expectAutoSwr: boolean;
    expectInitialBusy: boolean;
  }> = [
    {
      name: 'cold_upstream_miss',
      ip: '198.51.100.1',
      isCached: false,
      meta: { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false },
      expectInitialStale: false,
      expectInitialBadge: 'Just updated',
      expectAutoSwr: false,
      expectInitialBusy: false,
    },
    {
      name: 'l1_fresh_45d_manual_refetch',
      ip: '198.51.100.2',
      isCached: true,
      meta: { status: 'hit', layer: 'L1', ageSeconds: 45 * 86_400, isStale: false, shouldAutoRefresh: false },
      expectInitialStale: false,
      expectInitialBadge: 'Cached 45d ago',
      expectAutoSwr: false,
      expectInitialBusy: false,
    },
    {
      name: 'l2_exact_90d_boundary_manual_refetch',
      ip: '198.51.100.3',
      isCached: true,
      meta: { status: 'hit', layer: 'L2', ageSeconds: NINETY_DAYS_SECONDS, isStale: false, shouldAutoRefresh: false },
      expectInitialStale: false,
      expectInitialBadge: 'Cached 90d ago',
      expectAutoSwr: false,
      expectInitialBusy: false,
    },
    {
      name: 'l2_stale_91d_triggers_auto_swr',
      ip: '198.51.100.4',
      isCached: true,
      meta: { status: 'stale', layer: 'L2', ageSeconds: 91 * 86_400, isStale: true, shouldAutoRefresh: true },
      expectInitialStale: true,
      expectInitialBadge: 'Cached 91d ago',
      expectAutoSwr: true,
      expectInitialBusy: true,
    },
    {
      name: 'l2_stale_135d_triggers_auto_swr',
      ip: '2001:db8:abcd::4',
      isCached: true,
      meta: { status: 'stale', layer: 'L2', ageSeconds: 135 * 86_400, isStale: true, shouldAutoRefresh: true },
      expectInitialStale: true,
      expectInitialBadge: 'Cached 135d ago',
      expectAutoSwr: true,
      expectInitialBusy: true,
    },
    {
      name: 'l2_stale_with_peer_refresh_in_progress',
      ip: '198.51.100.5',
      isCached: true,
      meta: {
        status: 'stale',
        layer: 'L2',
        ageSeconds: 120 * 86_400,
        isStale: true,
        shouldAutoRefresh: false,
        refreshInProgress: true,
      },
      expectInitialStale: true,
      expectInitialBadge: 'Cached 120d ago',
      expectAutoSwr: false,
      expectInitialBusy: true,
    },
  ];

  for (const tc of tierCases) {
    await t.test(tc.name, async () => {
      const calls: RecordedSpaCall[] = [];
      const pendingRefresh = deferredResponse<{ ok: boolean; status: number; json: () => Promise<unknown> }>();
      const initialPayload = makeDetectionPayload(
        tc.ip,
        {
          isCached: tc.isCached,
          arbitrationVerdict: 'Disputed Proxy / VPN (1/5 Sources)',
          arbitrationTier: 'warning',
          isMajorityProxyVpn: false,
        },
        tc.meta
      );

      const coordinator = createDetectionCoordinator(async (url, init) => {
        const bodyText = typeof init?.body === 'string' ? init.body : '';
        calls.push({
          url,
          method: String(init?.method ?? 'GET').toUpperCase(),
          signal: init?.signal ?? null,
          bodyJson: bodyText ? JSON.parse(bodyText) : null,
        });
        if (url === '/api/v1/detect/refresh') return pendingRefresh.promise;
        return { ok: true, status: 200, json: async () => initialPayload };
      });

      await coordinator.executeDetection(tc.ip);

      assert.equal(isCacheStale(coordinator.state.detectionData), tc.expectInitialStale);
      assert.equal(
        formatCacheAgeBadgeLabel(coordinator.state.detectionData, FIXED_NOW_MS, coordinator.state.lastRefreshedAt),
        tc.expectInitialBadge
      );

      const initialBtn = resolveRefetchButtonState({
        data: coordinator.state.detectionData,
        isRefreshing: coordinator.state.isRefreshing,
        isLoading: coordinator.state.isLoading,
      });
      assert.equal(initialBtn.visible, true);
      assert.equal(initialBtn.isBusy, tc.expectInitialBusy);
      assert.equal(initialBtn.label, tc.expectInitialBusy ? 'Updating...' : 'Refetch');
      assert.equal(initialBtn.disabled, tc.expectInitialBusy);
      assert.equal(calls.filter((c) => c.url === '/api/v1/detect/refresh').length, tc.expectAutoSwr ? 1 : 0);

      if (tc.meta.refreshInProgress) {
        await coordinator.refreshDetection();
        assert.equal(calls.filter((c) => c.url === '/api/v1/detect/refresh').length, 0);
        return;
      }

      let manualPromise: Promise<void> | null = null;
      if (!tc.expectAutoSwr) {
        manualPromise = coordinator.refreshDetection();
        const busyBtn = resolveRefetchButtonState({
          data: coordinator.state.detectionData,
          isRefreshing: coordinator.state.isRefreshing,
          isLoading: coordinator.state.isLoading,
        });
        assert.equal(coordinator.state.isRefreshing, true);
        assert.equal(busyBtn.label, 'Updating...');
        assert.equal(busyBtn.disabled, true);
        assert.equal(calls.filter((c) => c.url === '/api/v1/detect/refresh').length, 1);
      }

      const freshPayload = makeDetectionPayload(
        tc.ip,
        {
          isCached: false,
          fetchedAt: FIXED_NOW_ISO,
          arbitrationVerdict: 'Confirmed Proxy / VPN (5/5 Sources)',
          arbitrationTier: 'destructive',
          isMajorityProxyVpn: true,
        },
        { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false, fetchedAt: FIXED_NOW_ISO }
      );
      pendingRefresh.resolve({ ok: true, status: 200, json: async () => freshPayload });

      if (manualPromise) await manualPromise;
      else await coordinator.waitForActiveRefresh();

      assert.equal(coordinator.state.isRefreshing, false);
      assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Confirmed Proxy / VPN (5/5 Sources)');
      assert.equal(isCacheStale(coordinator.state.detectionData), false);
      assert.equal(
        formatCacheAgeBadgeLabel(coordinator.state.detectionData, FIXED_NOW_MS, coordinator.state.lastRefreshedAt),
        'Just updated'
      );
      assert.deepEqual(
        resolveRefetchButtonState({
          data: coordinator.state.detectionData,
          isRefreshing: coordinator.state.isRefreshing,
          isLoading: coordinator.state.isLoading,
        }),
        { visible: true, label: 'Refetch', disabled: false, isBusy: false }
      );
    });
  }
});

test('SPA AbortController cancellation matrix aborts in-flight manual and auto-SWR refreshes on IP switch', async (t) => {
  const abortScenarios: Array<{
    name: string;
    firstIp: string;
    firstAgeSeconds: number;
    firstAutoSwr: boolean;
    action: 'switch_ip' | 'cancel_pending';
    secondIp?: string;
  }> = [
    {
      name: 'ip_switch_aborts_manual_refetch',
      firstIp: '198.51.100.10',
      firstAgeSeconds: 30 * 86_400,
      firstAutoSwr: false,
      action: 'switch_ip',
      secondIp: '198.51.100.88',
    },
    {
      name: 'ip_switch_aborts_auto_swr_refresh',
      firstIp: '198.51.100.11',
      firstAgeSeconds: 110 * 86_400,
      firstAutoSwr: true,
      action: 'switch_ip',
      secondIp: '2001:db8:cafe::88',
    },
    {
      name: 'cancel_pending_aborts_auto_swr_refresh',
      firstIp: '198.51.100.12',
      firstAgeSeconds: 105 * 86_400,
      firstAutoSwr: true,
      action: 'cancel_pending',
    },
  ];

  for (const sc of abortScenarios) {
    await t.test(sc.name, async () => {
      const calls: RecordedSpaCall[] = [];
      const firstRefreshDeferred = deferredResponse<{ ok: boolean; status: number; json: () => Promise<unknown> }>();

      const coordinator = createDetectionCoordinator(async (url, init) => {
        const bodyText = typeof init?.body === 'string' ? init.body : '';
        calls.push({
          url,
          method: String(init?.method ?? 'GET').toUpperCase(),
          signal: init?.signal ?? null,
          bodyJson: bodyText ? JSON.parse(bodyText) : null,
        });
        if (url === '/api/v1/detect/refresh') return firstRefreshDeferred.promise;
        const queriedIp = new URL(url, 'https://proxycheck.toolforge.org').searchParams.get('ip') ?? sc.firstIp;
        if (queriedIp === sc.firstIp) {
          return {
            ok: true,
            status: 200,
            json: async () =>
              makeDetectionPayload(
                sc.firstIp,
                { arbitrationVerdict: 'First IP Cached Verdict' },
                { ageSeconds: sc.firstAgeSeconds, isStale: sc.firstAutoSwr, shouldAutoRefresh: sc.firstAutoSwr }
              ),
          };
        }
        return {
          ok: true,
          status: 200,
          json: async () =>
            makeDetectionPayload(
              queriedIp,
              { isCached: false, arbitrationVerdict: 'Second IP Authoritative Verdict' },
              { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false }
            ),
        };
      });

      await coordinator.executeDetection(sc.firstIp);
      const manualRefreshTask = sc.firstAutoSwr ? null : coordinator.refreshDetection();

      const refreshCall = calls.find((c) => c.url === '/api/v1/detect/refresh');
      assert.ok(refreshCall, 'Expected refresh request to be in flight');
      assert.equal(refreshCall.signal?.aborted, false);
      assert.equal(coordinator.state.isRefreshing, true);

      if (sc.action === 'switch_ip' && sc.secondIp) {
        await coordinator.executeDetection(sc.secondIp);
        assert.equal(refreshCall.signal?.aborted, true);
        assert.equal(coordinator.state.isRefreshing, false);
        assert.equal(coordinator.state.detectionData?.ip, sc.secondIp);
        assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Second IP Authoritative Verdict');
      } else {
        coordinator.cancelPending();
        assert.equal(refreshCall.signal?.aborted, true);
        assert.equal(coordinator.state.isRefreshing, false);
        assert.equal(coordinator.state.isLoading, false);
      }

      firstRefreshDeferred.resolve({
        ok: true,
        status: 200,
        json: async () =>
          makeDetectionPayload(
            sc.firstIp,
            { isCached: false, arbitrationVerdict: 'Late Stale Refresh Payload' },
            { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false }
          ),
      });
      if (manualRefreshTask) await manualRefreshTask;
      await coordinator.waitForActiveRefresh();

      if (sc.action === 'switch_ip' && sc.secondIp) {
        assert.equal(coordinator.state.detectionData?.ip, sc.secondIp);
        assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Second IP Authoritative Verdict');
      } else {
        assert.notEqual(coordinator.state.detectionData?.arbitrationVerdict, 'Late Stale Refresh Payload');
      }
    });
  }
});

test('SPA degraded refresh, HTTP 429, HTTP 503, and network failure matrix preserves historical data', async (t) => {
  const errorCases: Array<{
    name: string;
    responder: () => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>;
    expectedWarningSubstring: string;
    expectDegradedFlag: boolean;
  }> = [
    {
      name: 'degraded_fallback_with_preserved_rows',
      responder: async () => ({
        ok: true,
        status: 200,
        json: async () =>
          makeDetectionPayload(
            '198.51.100.70',
            { arbitrationVerdict: 'Preserved Historical Consensus (4/5 Sources)' },
            { ageSeconds: 95 * 86_400, isStale: true, shouldAutoRefresh: false, degradedRefreshFallback: true }
          ),
      }),
      expectedWarningSubstring: 'Upstream providers or quota limits are temporarily constrained',
      expectDegradedFlag: true,
    },
    {
      name: 'degraded_fallback_with_empty_rows_retains_prior_state',
      responder: async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.70',
          results: [],
          cacheMeta: {
            status: 'stale',
            layer: 'L2',
            ageSeconds: 95 * 86_400,
            isStale: true,
            shouldAutoRefresh: true,
            degradedRefreshFallback: true,
          },
        }),
      }),
      expectedWarningSubstring: 'Upstream providers or quota limits are temporarily constrained',
      expectDegradedFlag: true,
    },
    {
      name: 'http_429_rate_limited_with_retry_after',
      responder: async () => ({
        ok: false,
        status: 429,
        json: async () => ({ error: 'rate_limited', retryAfterSeconds: 35 }),
      }),
      expectedWarningSubstring: 'Please wait 35s before retrying.',
      expectDegradedFlag: false,
    },
    {
      name: 'http_503_upstream_unavailable',
      responder: async () => ({
        ok: false,
        status: 503,
        json: async () => ({ error: 'upstream_down' }),
      }),
      expectedWarningSubstring: 'Upstream providers are temporarily constrained; valid historical intelligence is preserved.',
      expectDegradedFlag: false,
    },
    {
      name: 'network_exception_during_refresh',
      responder: async () => {
        throw new Error('Socket hang up');
      },
      expectedWarningSubstring: 'Unable to complete upstream refresh at this time; valid historical intelligence is preserved.',
      expectDegradedFlag: false,
    },
  ];

  for (const ec of errorCases) {
    await t.test(ec.name, async () => {
      const coordinator = createDetectionCoordinator(async (url) => {
        if (url === '/api/v1/detect/refresh') return ec.responder();
        return {
          ok: true,
          status: 200,
          json: async () =>
            makeDetectionPayload(
              '198.51.100.70',
              { arbitrationVerdict: 'Preserved Historical Consensus (4/5 Sources)' },
              { ageSeconds: 95 * 86_400, isStale: true, shouldAutoRefresh: true }
            ),
        };
      });

      await coordinator.executeDetection('198.51.100.70');
      await coordinator.waitForActiveRefresh();

      assert.equal(coordinator.state.isRefreshing, false);
      assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Preserved Historical Consensus (4/5 Sources)');
      assert.ok((coordinator.state.detectionData?.results?.length ?? 0) >= 3);
      assert.equal(coordinator.state.detectionData?.cacheMeta?.shouldAutoRefresh, false);
      assert.equal(coordinator.state.detectionData?.cacheMeta?.refreshInProgress, false);
      assert.equal(Boolean(coordinator.state.detectionData?.cacheMeta?.degradedRefreshFallback), ec.expectDegradedFlag);
      assert.ok(coordinator.state.refreshWarningMessage?.includes(ec.expectedWarningSubstring));
      assert.deepEqual(
        resolveRefetchButtonState({
          data: coordinator.state.detectionData,
          isRefreshing: coordinator.state.isRefreshing,
          isLoading: coordinator.state.isLoading,
        }),
        { visible: true, label: 'Refetch', disabled: false, isBusy: false }
      );
    });
  }
});

test('SPA 7-day recheck boundary, soft-block URLs, desensitised Wikitext, and telemetry normalisation matrix', async (t) => {
  const recheckCases: Array<{
    name: string;
    suspectedResidentialProxy: boolean;
    ageSeconds: number;
    explicitFlag?: boolean;
    expected: boolean;
  }> = [
    { name: 'paradox_at_0s', suspectedResidentialProxy: true, ageSeconds: 0, expected: false },
    { name: 'paradox_exact_7d_boundary', suspectedResidentialProxy: true, ageSeconds: 7 * 86_400, expected: false },
    { name: 'paradox_over_7d_by_1s', suspectedResidentialProxy: true, ageSeconds: 7 * 86_400 + 1, expected: true },
    { name: 'explicit_backend_flag_overrides_age', suspectedResidentialProxy: false, ageSeconds: 60, explicitFlag: true, expected: true },
    { name: 'non_paradox_at_30d', suspectedResidentialProxy: false, ageSeconds: 30 * 86_400, expected: false },
  ];

  for (const rc of recheckCases) {
    await t.test(`recheck_${rc.name}`, () => {
      const payload = makeDetectionPayload(
        '198.51.100.30',
        { suspectedResidentialProxy: rc.suspectedResidentialProxy },
        { ageSeconds: rc.ageSeconds, recommendFreshRecheck: rc.explicitFlag ?? false }
      );
      assert.equal(shouldRecommendFreshRecheck(payload), rc.expected);
    });
  }

  const blockCases: Array<{
    name: string;
    ip: string;
    overrides: Partial<DetectionResponse>;
    expectSoft: boolean;
    expectedTarget: string;
  }> = [
    {
      name: 'apple_private_relay_soft_block',
      ip: '172.224.226.15',
      overrides: { sharedPrivacyEgress: 'icloud_private_relay', recommendedCidr: '172.224.226.15/32' },
      expectSoft: true,
      expectedTarget: '172.224.226.15/32',
    },
    {
      name: 'cloudflare_warp_soft_block',
      ip: '2a09:bac1::7',
      overrides: { sharedPrivacyEgress: 'cloudflare_warp', recommendedCidr: '2a09:bac1::/64' },
      expectSoft: true,
      expectedTarget: '2a09:bac1::/64',
    },
    {
      name: 'mobile_cgnat_flag_soft_block',
      ip: '172.56.21.9',
      overrides: { isMobileOrCgnat: true, recommendedCidr: '172.56.21.9/32' },
      expectSoft: true,
      expectedTarget: '172.56.21.9/32',
    },
    {
      name: 'ptr_mobile_cgnat_soft_block',
      ip: '100.64.12.8',
      overrides: { ptrCategory: 'mobile_or_cgnat', recommendedCidr: '100.64.12.8/32' },
      expectSoft: true,
      expectedTarget: '100.64.12.8/32',
    },
    {
      name: 'confirmed_vpn_hard_block_default',
      ip: '198.51.100.200',
      overrides: { sharedPrivacyEgress: null, isMobileOrCgnat: false, recommendedCidr: '198.51.100.0/24' },
      expectSoft: false,
      expectedTarget: '198.51.100.0/24',
    },
  ];

  for (const bc of blockCases) {
    await t.test(`block_${bc.name}`, () => {
      const payload = makeDetectionPayload(bc.ip, bc.overrides);
      assert.equal(shouldUseSoftBlockDefaults(payload), bc.expectSoft);
      const blockUrl = buildSpecialBlockUrl(payload, 'https://en.wikipedia.org')!;
      assert.ok(blockUrl.startsWith(`https://en.wikipedia.org/wiki/Special:Block/${bc.expectedTarget}`));
      assert.equal(blockUrl.includes('wpHardBlock=0&wpDisableUTEdit=0'), bc.expectSoft);
    });
  }

  await t.test('wikitext_summary_desensitisation_and_dashboard_telemetry', () => {
    const richPayload = makeDetectionPayload('2001:db8:abcd:1200::5', {
      fetchedAt: '2026-11-12T08:15:00Z',
      primaryAsn: 'AS7922',
      recommendedCidr: '2001:db8:abcd:1200::/64',
      escalationCidr: '2001:db8:abcd:1200::/56',
      isTor: true,
      torIsExit: true,
      torLabel: 'Tor Exit',
      suspectedResidentialProxy: true,
      openProxyPorts: [1080, 9050],
      results: [
        makeProviderRow('Cloudflare Radar', { isp: 'Comcast Cable Communications' }),
        makeProviderRow('GetIPIntel', { chance: 98.76 }),
        makeProviderRow('AbuseIPDB', { riskScore: 87 }),
        makeProviderRow('IPsum / DROP', { inSpamhausDrop: true, dropSblId: 'SBL44005' }),
      ],
    });
    const summary = buildWikitextSummary(richPayload);
    assert.ok(summary.includes('2001:db8:abcd:1200::5'));
    assert.ok(summary.includes('2001:db8:abcd:1200::/64'));
    assert.ok(summary.includes('escalation: <code>2001:db8:abcd:1200::/56</code>'));
    assert.ok(summary.includes('AS7922'));
    assert.ok(summary.includes('Comcast Cable Communications'));
    assert.ok(summary.includes('Tor Exit'));
    assert.ok(summary.includes('Open proxy ports: 1080, 9050'));
    assert.ok(summary.includes('Spamhaus DROP (SBL44005)'));
    assert.ok(summary.includes('2026-11-12 UTC'));
    assert.equal(summary.includes('GetIPIntel'), false);
    assert.equal(summary.includes('AbuseIPDB'), false);
    assert.equal(summary.includes('98.76'), false);
    assert.equal(summary.includes('87'), false);

    const telemetry = resolveDashboardCacheTelemetry({
      cacheTelemetry: {
        l1Hit: 120,
        l2HitFresh: 80,
        l2HitStaleSwr: 15,
        upstreamMiss: 10,
        refreshOk: 12,
        refreshRateLimited: 2,
        dualLayerHitRatePercent: 95.5,
        l2EstimatedRows: 4820.9,
      },
    });
    assert.equal(telemetry.l1Hit, 120);
    assert.equal(telemetry.l2HitFresh, 80);
    assert.equal(telemetry.l2HitStaleSwr, 15);
    assert.equal(telemetry.l2EstimatedRows, 4820);
  });
});

interface GadgetFetchCall { url: string; method: string; bodyJson: unknown; }
interface GadgetMockResponse { status?: number; body?: unknown; }
type GadgetFetchResponder = (call: GadgetFetchCall) => GadgetMockResponse | Promise<GadgetMockResponse>;
interface GadgetMutationRecord { target: GadgetNode; addedNodes: GadgetNode[]; }

function isGadgetNodeConnected(node: GadgetNode | null, root: GadgetNode): boolean {
  for (let cur = node; cur; cur = cur.parentNode) if (cur === root) return true;
  return false;
}

class GadgetNode {
  nodeType: number;
  nodeValue: string | null = null;
  parentNode: GadgetElement | null = null;
  childNodes: GadgetNode[] = [];
  ownerDoc: GadgetDocument;
  constructor(nodeType: number, ownerDoc: GadgetDocument) {
    this.nodeType = nodeType;
    this.ownerDoc = ownerDoc;
  }
  get nextSibling(): GadgetNode | null {
    if (!this.parentNode) return null;
    const idx = this.parentNode.childNodes.indexOf(this);
    return idx >= 0 && idx + 1 < this.parentNode.childNodes.length ? this.parentNode.childNodes[idx + 1] : null;
  }
  get nextElementSibling(): GadgetElement | null {
    for (let cur = this.nextSibling; cur; cur = cur.nextSibling) if (cur instanceof GadgetElement) return cur;
    return null;
  }
  get isConnected(): boolean { return isGadgetNodeConnected(this, this.ownerDoc.documentElement); }
  get textContent(): string { return this.nodeValue ?? ''; }
  set textContent(val: string) {
    this.nodeValue = String(val);
    this.ownerDoc.enqueueMutation({ target: this, addedNodes: [] });
  }
}

class GadgetTextNode extends GadgetNode {
  constructor(text: string, ownerDoc: GadgetDocument) {
    super(3, ownerDoc);
    this.nodeValue = String(text);
  }
}

function splitCssBranches(selector: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < selector.length; i++) {
    const ch = selector[i];
    if (ch === '(' || ch === '[') depth += 1;
    else if (ch === ')' || ch === ']') depth = Math.max(0, depth - 1);
    else if (ch === ',' && depth === 0) { parts.push(selector.slice(start, i).trim()); start = i + 1; }
  }
  parts.push(selector.slice(start).trim());
  return parts.filter(Boolean);
}

function splitCssDescendants(selector: string): string[] {
  const tokens: string[] = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < selector.length; i++) {
    const ch = selector[i];
    if (ch === '(' || ch === '[') { depth += 1; cur += ch; }
    else if (ch === ')' || ch === ']') { depth = Math.max(0, depth - 1); cur += ch; }
    else if (/\s/.test(ch) && depth === 0) { if (cur) tokens.push(cur); cur = ''; }
    else cur += ch;
  }
  if (cur) tokens.push(cur);
  return tokens;
}

function matchesCssCompound(el: GadgetElement, compound: string): boolean {
  let rem = compound.trim();
  if (!rem) return false;
  const negations: string[] = [];
  rem = rem.replace(/:not\(([^)]+)\)/g, (_m, inner: string) => { negations.push(inner.trim()); return ''; });
  if (negations.some((neg) => matchesCssSelectorList(el, neg))) return false;
  const attrs: Array<{ name: string; value: string | null }> = [];
  rem = rem.replace(/\[([^\]=]+)(?:="([^"]*)")?\]/g, (_m, rawName: string, rawVal?: string) => {
    attrs.push({ name: rawName.trim(), value: rawVal ?? null });
    return '';
  });
  for (const attr of attrs) {
    const actual = el.getAttribute(attr.name);
    if (attr.value === null ? actual === null : actual !== attr.value) return false;
  }
  const tagMatch = rem.match(/^[a-zA-Z][a-zA-Z0-9-]*/);
  if (tagMatch) {
    if (el.tagName !== tagMatch[0].toUpperCase()) return false;
    rem = rem.slice(tagMatch[0].length);
  }
  for (const idTok of rem.match(/#[a-zA-Z0-9_-]+/g) ?? []) if (el.id !== idTok.slice(1)) return false;
  rem = rem.replace(/#[a-zA-Z0-9_-]+/g, '');
  for (const clsTok of rem.match(/\.[a-zA-Z0-9_-]+/g) ?? []) if (!el.classList.contains(clsTok.slice(1))) return false;
  return rem.replace(/\.[a-zA-Z0-9_-]+/g, '').trim() === '';
}

function matchesCssChain(el: GadgetElement, segments: string[], idx: number): boolean {
  if (!matchesCssCompound(el, segments[idx])) return false;
  if (idx === 0) return true;
  for (let anc = el.parentNode; anc; anc = anc.parentNode) if (matchesCssChain(anc, segments, idx - 1)) return true;
  return false;
}

function matchesCssSelectorList(el: GadgetElement, selector: string): boolean {
  return splitCssBranches(selector).some((branch) => {
    const segs = splitCssDescendants(branch);
    return segs.length > 0 && matchesCssChain(el, segs, segs.length - 1);
  });
}

function findClosestGadgetAncestor(start: GadgetElement | null, selector: string): GadgetElement | null {
  for (let cur = start; cur; cur = cur.parentNode) if (cur.matches(selector)) return cur;
  return null;
}

function bubbleGadgetClick(target: GadgetElement, ev: AnyRecord, isStopped: () => boolean): void {
  for (let cur: GadgetElement | null = target; cur && !isStopped(); cur = cur.parentNode) {
    for (const handler of cur.getListeners('click')) handler.call(cur, ev);
  }
}

class GadgetElement extends GadgetNode {
  tagName: string;
  style: Record<string, string> = {};
  dataset: Record<string, string | undefined> = {};
  checked = false;
  disabled = false;
  value = '';
  href = '';
  title = '';
  target = '';
  rel = '';
  type = '';
  role = '';
  private attrs = new Map<string, string>();
  private listeners = new Map<string, Array<(ev: AnyRecord) => void>>();

  readonly classList = {
    add: (...names: string[]): void => {
      const cur = this.className ? this.className.split(/\s+/).filter(Boolean) : [];
      for (const n of names) if (n && !cur.includes(n)) cur.push(n);
      this.className = cur.join(' ');
    },
    remove: (...names: string[]): void => {
      const cur = this.className ? this.className.split(/\s+/).filter(Boolean) : [];
      this.className = cur.filter((c) => !names.includes(c)).join(' ');
    },
    contains: (name: string): boolean => (this.className ? this.className.split(/\s+/).filter(Boolean) : []).includes(name),
  };

  constructor(tagName: string, ownerDoc: GadgetDocument) { super(1, ownerDoc); this.tagName = tagName.toUpperCase(); }
  get id(): string { return this.attrs.get('id') ?? ''; }
  set id(val: string) { if (val) this.attrs.set('id', String(val)); else this.attrs.delete('id'); }
  get className(): string { return this.attrs.get('class') ?? ''; }
  set className(val: string) {
    const str = String(val ?? '').trim();
    if (str) this.attrs.set('class', str); else this.attrs.delete('class');
  }
  override get textContent(): string { return this.childNodes.map((c) => c.textContent).join(''); }
  override set textContent(val: string) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    const str = String(val ?? '');
    if (str !== '') {
      const tn = new GadgetTextNode(str, this.ownerDoc);
      tn.parentNode = this;
      this.childNodes.push(tn);
      this.ownerDoc.enqueueMutation({ target: this, addedNodes: [tn] });
    } else {
      this.ownerDoc.enqueueMutation({ target: this, addedNodes: [] });
    }
  }
  setAttribute(name: string, val: string): void {
    const str = String(val);
    this.attrs.set(name, str);
    if (name === 'href') this.href = str;
    else if (name === 'title') this.title = str;
    else if (name === 'target') this.target = str;
    else if (name === 'rel') this.rel = str;
    else if (name === 'type') this.type = str;
    else if (name === 'role') this.role = str;
    else if (name === 'style') {
      for (const pair of str.split(';')) {
        const colon = pair.indexOf(':');
        if (colon > 0) this.style[pair.slice(0, colon).trim()] = pair.slice(colon + 1).trim();
      }
    } else if (name.startsWith('data-')) {
      this.dataset[name.slice(5).replace(/-([a-z])/g, (_m, ch: string) => ch.toUpperCase())] = str;
    }
  }
  getAttribute(name: string): string | null {
    if (name === 'href' && this.href) return this.href;
    if (name === 'title' && this.title) return this.title;
    return this.attrs.get(name) ?? null;
  }
  removeAttribute(name: string): void { this.attrs.delete(name); }
  appendChild<T extends GadgetNode>(child: T): T { return this.insertBefore(child, null); }
  insertBefore<T extends GadgetNode>(newChild: T, refChild: GadgetNode | null): T {
    if (newChild.parentNode) newChild.parentNode.removeChild(newChild);
    newChild.parentNode = this;
    const idx = refChild === null ? -1 : this.childNodes.indexOf(refChild);
    if (idx === -1) this.childNodes.push(newChild); else this.childNodes.splice(idx, 0, newChild);
    this.ownerDoc.enqueueMutation({ target: this, addedNodes: [newChild] });
    return newChild;
  }
  removeChild<T extends GadgetNode>(child: T): T {
    const idx = this.childNodes.indexOf(child);
    if (idx !== -1) { this.childNodes.splice(idx, 1); child.parentNode = null; }
    return child;
  }
  contains(other: GadgetNode | null): boolean { return isGadgetNodeConnected(other, this); }
  matches(selector: string): boolean { return matchesCssSelectorList(this, selector); }
  closest(selector: string): GadgetElement | null { return findClosestGadgetAncestor(this, selector); }
  querySelectorAll(selector: string): GadgetElement[] {
    const found: GadgetElement[] = [];
    const visit = (node: GadgetElement): void => {
      for (const child of node.childNodes) {
        if (child instanceof GadgetElement) {
          if (child.matches(selector)) found.push(child);
          visit(child);
        }
      }
    };
    visit(this);
    return found;
  }
  querySelector(selector: string): GadgetElement | null { return this.querySelectorAll(selector)[0] ?? null; }
  getListeners(type: string): Array<(ev: AnyRecord) => void> { return (this.listeners.get(type) ?? []).slice(); }
  addEventListener(type: string, fn: (ev: AnyRecord) => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(fn);
    this.listeners.set(type, list);
  }
  removeEventListener(type: string, fn: (ev: AnyRecord) => void): void {
    const list = this.listeners.get(type);
    if (list) this.listeners.set(type, list.filter((item) => item !== fn));
  }
  click(): void {
    let stopped = false;
    const ev: AnyRecord = {
      type: 'click',
      target: this,
      defaultPrevented: false,
      preventDefault() { ev.defaultPrevented = true; },
      stopPropagation() { stopped = true; },
    };
    if (this.tagName === 'INPUT' && this.type === 'checkbox') this.checked = !this.checked;
    bubbleGadgetClick(this, ev, () => stopped);
  }
}

class GadgetDocument {
  documentElement: GadgetElement;
  head: GadgetElement;
  body: GadgetElement;
  visibilityState = 'visible';
  private observers: Array<(records: GadgetMutationRecord[]) => void> = [];
  private queuedMutations: GadgetMutationRecord[] = [];
  private flushScheduled = false;
  constructor() {
    this.documentElement = new GadgetElement('html', this);
    this.head = new GadgetElement('head', this);
    this.body = new GadgetElement('body', this);
    this.documentElement.childNodes.push(this.head, this.body);
    this.head.parentNode = this.documentElement;
    this.body.parentNode = this.documentElement;
  }
  createElement(tag: string): GadgetElement { return new GadgetElement(tag, this); }
  createTextNode(text: string): GadgetTextNode { return new GadgetTextNode(text, this); }
  getElementById(id: string): GadgetElement | null { return this.documentElement.querySelector(`#${id}`); }
  querySelectorAll(selector: string): GadgetElement[] { return this.documentElement.querySelectorAll(selector); }
  querySelector(selector: string): GadgetElement | null { return this.documentElement.querySelector(selector); }
  addEventListener(): void {}
  removeEventListener(): void {}
  registerObserver(cb: (records: GadgetMutationRecord[]) => void): () => void {
    if (!this.observers.includes(cb)) this.observers.push(cb);
    return () => { this.observers = this.observers.filter((item) => item !== cb); };
  }
  enqueueMutation(record: GadgetMutationRecord): void {
    if (this.observers.length === 0 || !record.target.isConnected) return;
    this.queuedMutations.push(record);
    if (!this.flushScheduled) {
      this.flushScheduled = true;
      queueMicrotask(() => {
        this.flushScheduled = false;
        const pending = this.queuedMutations.splice(0, this.queuedMutations.length);
        if (pending.length > 0) for (const cb of this.observers.slice()) cb(pending);
      });
    }
  }
}

function createGadgetJQuery(doc: GadgetDocument, readyCallbacks: Array<() => void>) {
  function toNodes(item: unknown): GadgetNode[] {
    if (item === null || item === undefined) return [];
    if (item instanceof GadgetNode) return [item];
    if (typeof item === 'string') return [doc.createTextNode(item)];
    if (typeof item === 'object' && 'length' in (item as AnyRecord)) {
      const col = item as Record<number, GadgetElement> & { length: number };
      const out: GadgetNode[] = [];
      for (let i = 0; i < col.length; i++) if (col[i]) out.push(col[i]);
      return out;
    }
    return [];
  }
  function wrap(elements: GadgetElement[]) {
    const col: Record<number, GadgetElement> = {};
    elements.forEach((el, idx) => { col[idx] = el; });
    const api: AnyRecord = Object.assign(col, {
      length: elements.length,
      append(...items: unknown[]) {
        const firstEl = elements[0];
        if (firstEl) for (const item of items) for (const node of toNodes(item)) firstEl.appendChild(node);
        return api;
      },
      appendTo(target: AnyRecord | GadgetElement) {
        const dest = target instanceof GadgetElement ? target : (target[0] as GadgetElement | undefined);
        if (dest) for (const el of elements) dest.appendChild(el);
        return api;
      },
      prepend(item: unknown) {
        const firstEl = elements[0];
        if (firstEl) { const ref = firstEl.childNodes[0] ?? null; for (const node of toNodes(item)) firstEl.insertBefore(node, ref); }
        return api;
      },
      before(item: unknown) {
        const firstEl = elements[0];
        if (firstEl?.parentNode) for (const node of toNodes(item)) firstEl.parentNode.insertBefore(node, firstEl);
        return api;
      },
      after(item: unknown) {
        const firstEl = elements[0];
        if (firstEl?.parentNode) { const ref = firstEl.nextSibling; for (const node of toNodes(item)) firstEl.parentNode.insertBefore(node, ref); }
        return api;
      },
      empty() {
        for (const el of elements) { for (const child of el.childNodes) child.parentNode = null; el.childNodes = []; }
        return api;
      },
      remove() { for (const el of elements) if (el.parentNode) el.parentNode.removeChild(el); return api; },
      text(val?: string) {
        if (val === undefined) return elements.map((el) => el.textContent).join('');
        for (const el of elements) el.textContent = String(val);
        return api;
      },
      attr(name: string, val?: string) {
        if (val === undefined) return elements[0]?.getAttribute(name) ?? undefined;
        for (const el of elements) el.setAttribute(name, String(val));
        return api;
      },
      prop(name: string, val?: unknown) {
        if (val === undefined) return elements[0] ? (elements[0] as unknown as AnyRecord)[name] : undefined;
        for (const el of elements) (el as unknown as AnyRecord)[name] = val;
        return api;
      },
      css(name: string, val: string) { for (const el of elements) el.style[name] = val; return api; },
      addClass(cls: string) { for (const el of elements) el.classList.add(...cls.split(/\s+/).filter(Boolean)); return api; },
      removeClass(cls: string) { for (const el of elements) el.classList.remove(...cls.split(/\s+/).filter(Boolean)); return api; },
      find(selector: string) {
        const matched: GadgetElement[] = [];
        for (const el of elements) for (const item of el.querySelectorAll(selector)) if (!matched.includes(item)) matched.push(item);
        return wrap(matched);
      },
      first: () => wrap(elements[0] ? [elements[0]] : []),
      parent: () => wrap(elements.map((el) => el.parentNode).filter((p): p is GadgetElement => p instanceof GadgetElement)),
      closest: (sel: string) => wrap(elements.map((el) => el.closest(sel)).filter((c): c is GadgetElement => c instanceof GadgetElement)),
      each(fn: (this: GadgetElement, idx: number, el: GadgetElement) => void) { elements.forEach((el, idx) => fn.call(el, idx, el)); return api; },
      on(eventName: string, handler: (ev: AnyRecord) => void) { for (const el of elements) el.addEventListener(eventName, handler); return api; },
    });
    return api;
  }
  return function $(arg: unknown, attrs?: AnyRecord) {
    if (typeof arg === 'function') { readyCallbacks.push(arg as () => void); return undefined; }
    if (arg instanceof GadgetElement) return wrap([arg]);
    if (typeof arg === 'string') {
      const tagMatch = arg.trim().match(/^<([a-zA-Z0-9-]+)\s*\/?>$/);
      if (tagMatch) {
        const el = doc.createElement(tagMatch[1]);
        if (attrs && typeof attrs === 'object') {
          for (const [k, v] of Object.entries(attrs)) {
            if (v === undefined || v === null) continue;
            if (k === 'text') el.textContent = String(v);
            else if (k === 'class') el.className = String(v);
            else if (k === 'checked' || k === 'disabled') (el as unknown as AnyRecord)[k] = Boolean(v);
            else el.setAttribute(k, String(v));
          }
        }
        return wrap([el]);
      }
      return wrap(doc.querySelectorAll(arg.trim()));
    }
    return wrap([]);
  };
}

function bootGadgetVm(options: {
  mwConfig?: Record<string, unknown>;
  onFetch: GadgetFetchResponder;
  setupDom: (doc: GadgetDocument) => void;
}) {
  const doc = new GadgetDocument();
  const mwStorageMap = new Map<string, string>([
    ['proxycheck-ip-policy-consent', '1'],
    ['proxycheck-gadget-token', 'signed-test-token'],
    ['proxycheck-gadget-token-user', 'AdminPatroller'],
    ['proxycheck-gadget-token-exp', String(FIXED_NOW_MS + 3_600_000)],
  ]);
  const localStorageMap = new Map<string, string>();
  const configValues: Record<string, unknown> = {
    wgUserName: 'AdminPatroller',
    wgUserIsTemp: false,
    wgServerName: 'en.wikipedia.org',
    wgArticlePath: '/wiki/$1',
    wgCanonicalSpecialPageName: 'Recentchanges',
    wgPageName: 'Special:RecentChanges',
    wgTitle: 'RecentChanges',
    wgRelevantUserName: null,
    ...options.mwConfig,
  };
  options.setupDom(doc);

  const fetchCalls: GadgetFetchCall[] = [];
  const openDialogs: Array<{ host: GadgetElement; close: () => void }> = [];
  const readyCallbacks: Array<() => void> = [];
  const activeTimers = new Map<number, { fn: () => void; delay: number; isInterval: boolean }>();
  let nextTimerId = 1;

  const MockDate = class extends Date { static override now(): number { return FIXED_NOW_MS; } };
  const makeStorage = (map: Map<string, string>) => ({
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => { map.set(k, String(v)); },
    removeItem: (k: string) => { map.delete(k); },
  });

  const mediaWiki = {
    config: { get: (key: string) => (key in configValues ? configValues[key] : null) },
    storage: {
      get: (key: string) => (mwStorageMap.has(key) ? mwStorageMap.get(key)! : null),
      set: (key: string, val: string) => { mwStorageMap.set(key, String(val)); return true; },
      remove: (key: string) => { mwStorageMap.delete(key); },
    },
    loader: { using: () => Promise.resolve() },
    util: {
      getUrl: (title: string) => `/wiki/${title}`,
      getParamValue: () => null,
      addCSS: () => {},
      isTemporaryUser: (name: string) => /^~\d{4}-/.test(name),
    },
    hook: () => ({ add: () => {}, fire: () => {} }),
    Api: class { get() { return Promise.resolve({ centralauthtoken: { centralauthtoken: 'mock-centralauth-token' } }); } },
  };

  const OO = {
    ui: {
      confirm: () => Promise.resolve(true),
      alert: ($message: Record<number, GadgetElement>) =>
        new Promise<void>((resolve) => {
          const host = doc.createElement('div');
          host.className = 'mock-ooui-dialog';
          if ($message && $message[0]) host.appendChild($message[0]);
          doc.body.appendChild(host);
          openDialogs.push({
            host,
            close: () => { if (host.parentNode) host.parentNode.removeChild(host); resolve(); },
          });
        }),
    },
  };

  class MockMutationObserver {
    private disconnectFn: (() => void) | null = null;
    private cb: (records: GadgetMutationRecord[]) => void;
    constructor(cb: (records: GadgetMutationRecord[]) => void) { this.cb = cb; }
    observe(): void { if (!this.disconnectFn) this.disconnectFn = doc.registerObserver(this.cb); }
    disconnect(): void { if (this.disconnectFn) { this.disconnectFn(); this.disconnectFn = null; } }
  }

  const windowObj: AnyRecord = {
    location: { search: '' },
    localStorage: makeStorage(localStorageMap),
    sessionStorage: makeStorage(new Map()),
    setTimeout: (fn: () => void, delay = 0) => { const id = nextTimerId++; activeTimers.set(id, { fn, delay, isInterval: false }); return id; },
    clearTimeout: (id: number) => activeTimers.delete(id),
    setInterval: (fn: () => void, delay = 0) => { const id = nextTimerId++; activeTimers.set(id, { fn, delay, isInterval: true }); return id; },
    clearInterval: (id: number) => activeTimers.delete(id),
  };

  const fetchMock = (url: string, init: AnyRecord = {}) => {
    const bodyText = typeof init.body === 'string' ? init.body : '';
    const call: GadgetFetchCall = {
      url: String(url),
      method: String(init.method ?? 'GET').toUpperCase(),
      bodyJson: bodyText ? JSON.parse(bodyText) : null,
    };
    fetchCalls.push(call);
    return Promise.resolve(options.onFetch(call)).then((spec) => {
      const status = spec.status ?? 200;
      const serialised = JSON.stringify(spec.body ?? {});
      return {
        status,
        ok: status >= 200 && status < 300,
        json: () => Promise.resolve(JSON.parse(serialised)),
        text: () => Promise.resolve(serialised),
      };
    });
  };

  const jQuery = createGadgetJQuery(doc, readyCallbacks);
  const sandbox = vm.createContext({
    window: windowObj, document: doc,
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    MutationObserver: MockMutationObserver, mediaWiki, jQuery, OO, fetch: fetchMock, Date: MockDate,
    console, Promise, Map, Set, WeakSet, URL, encodeURIComponent, decodeURIComponent,
    parseInt, isNaN, isFinite, Number, String, Boolean, Array, Object, Math, JSON,
  });

  vm.runInContext(GADGET_SOURCE, sandbox, { filename: 'scripts/user-gadget.js' });
  for (const cb of readyCallbacks) cb();

  async function flushAsync(rounds = 8): Promise<void> {
    for (let i = 0; i < rounds; i++) await new Promise<void>((resolve) => setImmediate(resolve));
  }

  async function runPendingTimers(maxDelayMs = 600): Promise<void> {
    await flushAsync();
    for (let pass = 0; pass < 6; pass++) {
      const dueIds: number[] = [];
      for (const [id, entry] of activeTimers) if (!entry.isInterval && entry.delay <= maxDelayMs) dueIds.push(id);
      if (dueIds.length === 0) break;
      for (const id of dueIds) {
        const entry = activeTimers.get(id);
        if (entry) { activeTimers.delete(id); entry.fn(); }
      }
      await flushAsync();
    }
  }

  return { doc, fetchCalls, openDialogs, flushAsync, runPendingTimers };
}

test('MediaWiki gadget inline badge and dialog state matrix covers <=90d boundary, >90d auto-SWR, and degraded fallback', async (t) => {
  const dialogCases: Array<{
    name: string;
    ip: string;
    ageSeconds: number;
    expectStaleBadge: boolean;
    expectAutoSwrOnOpen: boolean;
    refreshResponse: GadgetMockResponse;
    expectWarningAfterRefresh: boolean;
  }> = [
    {
      name: 'exact_90d_boundary_manual_refetch_to_fresh',
      ip: '198.51.100.61',
      ageSeconds: NINETY_DAYS_SECONDS,
      expectStaleBadge: false,
      expectAutoSwrOnOpen: false,
      refreshResponse: {
        status: 200,
        body: makeDetectionPayload(
          '198.51.100.61',
          { isCached: false, prediction_score: 15, getipintel_chance: 15, arbitrationVerdict: 'Clean Residential / Direct (0/5 Sources)' },
          { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false }
        ),
      },
      expectWarningAfterRefresh: false,
    },
    {
      name: 'over_90d_91d_auto_swr_to_fresh',
      ip: '198.51.100.62',
      ageSeconds: 91 * 86_400,
      expectStaleBadge: true,
      expectAutoSwrOnOpen: true,
      refreshResponse: {
        status: 200,
        body: makeDetectionPayload(
          '198.51.100.62',
          { isCached: false, prediction_score: 96, getipintel_chance: 96, arbitrationVerdict: 'Confirmed Proxy / VPN (5/5 Sources)' },
          { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false }
        ),
      },
      expectWarningAfterRefresh: false,
    },
    {
      name: 'over_90d_degraded_refresh_fallback_warning_in_dialog',
      ip: '198.51.100.63',
      ageSeconds: 100 * 86_400,
      expectStaleBadge: true,
      expectAutoSwrOnOpen: true,
      refreshResponse: {
        status: 200,
        body: makeDetectionPayload(
          '198.51.100.63',
          { arbitrationVerdict: 'Confirmed Proxy / VPN (4/5 Sources)' },
          { ageSeconds: 100 * 86_400, isStale: true, shouldAutoRefresh: false, degradedRefreshFallback: true }
        ),
      },
      expectWarningAfterRefresh: true,
    },
  ];

  for (const dc of dialogCases) {
    await t.test(dc.name, async () => {
      const refreshGate = deferredResponse<GadgetMockResponse>();
      const vmHarness = bootGadgetVm({
        setupDom(doc) {
          const content = doc.createElement('div');
          content.id = 'mw-content-text';
          const span = doc.createElement('span');
          span.className = 'ext-checkuser-tempaccount-reveal-ip';
          span.textContent = dc.ip;
          content.appendChild(span);
          doc.body.appendChild(content);
        },
        onFetch(call) {
          if (call.url.endsWith('/api/v1/detect/refresh')) return refreshGate.promise;
          const initial = makeDetectionPayload(
            dc.ip,
            { queryMode: 'full', isPartialMode: false },
            { ageSeconds: dc.ageSeconds, isStale: dc.expectStaleBadge, shouldAutoRefresh: dc.expectAutoSwrOnOpen }
          );
          if (call.url.includes('/api/v1/detect/batch')) {
            return { status: 200, body: { queryMode: 'light', inputMap: {}, results: { [dc.ip]: initial } } };
          }
          return { status: 200, body: initial };
        },
      });

      await vmHarness.runPendingTimers(100);
      const badge = vmHarness.doc.querySelector('.proxycheck-ip-badge')!;
      assert.equal(badge.classList.contains('proxycheck-badge-stale'), dc.expectStaleBadge);
      assert.equal(vmHarness.fetchCalls.some((c) => c.url.endsWith('/api/v1/detect/refresh')), false);

      badge.click();
      await vmHarness.flushAsync();

      const dialog = vmHarness.openDialogs[0].host;
      const refetchBtn = dialog.querySelector('.proxycheck-refetch-btn')!;
      if (dc.expectAutoSwrOnOpen) {
        assert.equal(refetchBtn.textContent, 'Updating...');
        assert.equal(refetchBtn.disabled, true);
      } else {
        assert.equal(refetchBtn.textContent, 'Refetch');
        assert.equal(refetchBtn.disabled, false);
        refetchBtn.click();
        await vmHarness.flushAsync();
        assert.equal(refetchBtn.textContent, 'Updating...');
        assert.equal(refetchBtn.disabled, true);
      }

      refreshGate.resolve(dc.refreshResponse);
      await vmHarness.flushAsync();

      assert.equal(refetchBtn.textContent, 'Refetch');
      assert.equal(refetchBtn.disabled, false);
      const warningEl = dialog.querySelector('.proxycheck-refresh-warning')!;
      if (dc.expectWarningAfterRefresh) {
        assert.equal(warningEl.style.display, 'block');
        assert.ok(warningEl.textContent.includes('Preserving cached intelligence'));
      } else {
        assert.ok(dialog.textContent.includes('Just updated'));
      }
    });
  }
});

test('MediaWiki gadget multi-IP temporary account contributions switcher isolates overlapping banner refreshes', async (t) => {
  function bootMultiIpContributionsVm(accountName: string, ipA: string, ipB: string, verdictA: string, verdictB: string) {
    const refreshQueue: Array<{ ip: string; resolve: (spec: GadgetMockResponse) => void }> = [];
    const vmHarness = bootGadgetVm({
      mwConfig: {
        wgCanonicalSpecialPageName: 'Contributions',
        wgPageName: `Special:Contributions/${accountName}`,
        wgTitle: `Contributions/${accountName}`,
        wgRelevantUserName: accountName,
      },
      setupDom(doc) {
        const content = doc.createElement('div');
        content.id = 'mw-content-text';
        for (const ip of [ipA, ipB]) {
          const span = doc.createElement('span');
          span.className = 'ext-checkuser-tempaccount-reveal-ip';
          span.textContent = ip;
          content.appendChild(span);
        }
        doc.body.appendChild(content);
      },
      onFetch(call) {
        if (call.url.endsWith('/api/v1/detect/refresh')) {
          const body = call.bodyJson as { ip: string };
          return new Promise<GadgetMockResponse>((resolve) => { refreshQueue.push({ ip: body.ip, resolve }); });
        }
        const payloadFor = (targetIp: string) =>
          makeDetectionPayload(
            targetIp,
            { arbitrationVerdict: targetIp === ipA ? verdictA : verdictB },
            { ageSeconds: 20 * 86_400, isStale: false, shouldAutoRefresh: false }
          );
        if (call.url.includes('/api/v1/detect/batch')) {
          return { status: 200, body: { queryMode: 'light', inputMap: {}, results: { [ipA]: payloadFor(ipA), [ipB]: payloadFor(ipB) } } };
        }
        return { status: 200, body: payloadFor(new URL(call.url).searchParams.get('ip') ?? ipA) };
      },
    });
    return { vmHarness, refreshQueue };
  }

  await t.test('stale_ip_a_refresh_completion_preserves_ip_b_inflight_guard_and_caches_ip_a_update', async () => {
    const ipA = '198.51.100.10';
    const ipB = '198.51.100.20';
    const { vmHarness, refreshQueue } = bootMultiIpContributionsVm(
      '~2026-99999-1', ipA, ipB, 'Initial IP A Cached Verdict', 'Initial IP B Cached Verdict'
    );
    await vmHarness.runPendingTimers(600);

    const banner = vmHarness.doc.getElementById('proxycheck-pageinfo')!;
    assert.ok(banner.textContent.includes(ipA));
    const firstBtn = banner.querySelector('.proxycheck-refetch-btn')!;
    firstBtn.click();
    await vmHarness.flushAsync();
    assert.equal(firstBtn.textContent, 'Updating...');
    assert.equal(refreshQueue.length, 1);
    assert.equal(refreshQueue[0].ip, ipA);

    banner.querySelectorAll('.proxycheck-ip-pill')[1].click();
    await vmHarness.flushAsync();
    assert.ok(banner.textContent.includes(ipB));

    const ipBBtn = banner.querySelector('.proxycheck-refetch-btn')!;
    ipBBtn.click();
    await vmHarness.flushAsync();
    assert.equal(ipBBtn.textContent, 'Updating...');
    assert.equal(ipBBtn.disabled, true);
    assert.equal(refreshQueue.length, 2);
    assert.equal(refreshQueue[1].ip, ipB);

    refreshQueue[0].resolve({
      status: 200,
      body: makeDetectionPayload(
        ipA,
        { isCached: false, arbitrationVerdict: 'Completed IP A Fresh Verdict' },
        { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false }
      ),
    });
    await vmHarness.flushAsync();

    assert.equal(ipBBtn.textContent, 'Updating...');
    assert.equal(ipBBtn.disabled, true);
    assert.equal(banner.textContent.includes('Completed IP A Fresh Verdict'), false);
    ipBBtn.click();
    await vmHarness.flushAsync();
    assert.equal(refreshQueue.length, 2, 'Earlier IP A completion must not clear active in-flight guard on IP B');

    refreshQueue[1].resolve({
      status: 200,
      body: makeDetectionPayload(
        ipB,
        { isCached: false, arbitrationVerdict: 'Authoritative IP B Fresh Verdict' },
        { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false }
      ),
    });
    await vmHarness.flushAsync();

    assert.ok(banner.textContent.includes('Authoritative IP B Fresh Verdict'));
    assert.ok(banner.textContent.includes('Just updated'));
    const settledBtn = banner.querySelector('.proxycheck-refetch-btn')!;
    assert.equal(settledBtn.textContent, 'Refetch');
    assert.equal(settledBtn.disabled, false);
  });

  await t.test('roundtrip_same_ip_coalesces_inflight_refresh_and_ignores_superseded_banner_epoch', async () => {
    const ipA = '198.51.100.31';
    const ipB = '198.51.100.32';
    const { vmHarness, refreshQueue } = bootMultiIpContributionsVm(
      '~2026-99999-2', ipA, ipB, 'Cached Epoch Zero IP A', 'Cached Epoch Zero IP B'
    );
    await vmHarness.runPendingTimers(600);

    const banner = vmHarness.doc.getElementById('proxycheck-pageinfo')!;
    banner.querySelector('.proxycheck-refetch-btn')!.click();
    await vmHarness.flushAsync();
    assert.equal(refreshQueue.length, 1);

    banner.querySelectorAll('.proxycheck-ip-pill')[1].click();
    await vmHarness.flushAsync();
    banner.querySelectorAll('.proxycheck-ip-pill')[0].click();
    await vmHarness.flushAsync();

    assert.equal(banner.querySelector('.proxycheck-refetch-btn')!.textContent, 'Refetch');
    assert.equal(banner.querySelector('.proxycheck-refetch-btn')!.disabled, false);

    refreshQueue[0].resolve({ status: 429, body: { error: 'rate_limited', retryAfterSeconds: 25 } });
    await vmHarness.flushAsync();

    assert.equal(
      banner.querySelector('.proxycheck-refresh-warning')!.style.display,
      'none',
      'Superseded banner epoch must not mutate newly rendered IP A banner when user did not re-trigger refresh'
    );
  });
});
