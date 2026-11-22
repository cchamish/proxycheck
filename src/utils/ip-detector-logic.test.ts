import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalizeIpAddress,
  createDetectionCoordinator,
  isAuthorisedAdminUser,
  isValidIpAddress,
  type DetectionCoordinatorState,
  type DetectionResponse,
} from './ip-detector-logic';

function makeDetectionPayload(ip: string): DetectionResponse {
  return {
    ip,
    isCached: false,
    isNonPublic: false,
    is_broadcast_ip: false,
    prediction_score: 0,
    getipintel_chance: 0,
    arbitrationVerdict: 'Clean',
    isMajorityProxyVpn: false,
    primaryCountry: 'United States',
    primaryAsn: 'AS15169',
    results: [
      {
        provider: 'MaxMind',
        status: '200 OK',
        statusCode: 200,
        asn: 'AS15169',
        isp: 'Google LLC',
        organisation: 'Google LLC',
        location: 'United States',
        usageType: 'isp',
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
        rawJson: {},
      },
    ],
  };
}

test('validates and canonicalises IPv4 and IPv6 addresses consistently', () => {
  const validCases: Array<{ raw: string; canonical: string }> = [
    { raw: '8.8.8.8', canonical: '8.8.8.8' },
    { raw: ' 192.0.2.1 ', canonical: '192.0.2.1' },
    { raw: '2001:0db8:0000:0000:0000:0000:0000:0001', canonical: '2001:db8::1' },
    { raw: ' 2001:DB8:0:0::1 ', canonical: '2001:db8::1' },
    { raw: '0:0:0:0:0:0:0:1', canonical: '::1' },
  ];
  for (const item of validCases) {
    assert.equal(isValidIpAddress(item.raw), true);
    assert.equal(canonicalizeIpAddress(item.raw), item.canonical);
  }

  for (const invalid of ['', 'example.org', '256.1.1.1', '2001:::1', '[2001:db8::1]']) {
    assert.equal(isValidIpAddress(invalid), false);
    assert.equal(canonicalizeIpAddress(invalid), null);
  }
});

test('validates IPv6 IPv4 tails and canonicalises them like their hex equivalents', () => {
  const cases = [
    ['2001:db8:0:0:0:0:8.8.8.8', '2001:db8::808:808'],
    ['2001:db8::8.8.8.8', '2001:db8::808:808'],
    ['::ffff:1.2.3.4', '::ffff:102:304'],
    ['::8.8.8.8', '::808:808'],
    [' 2001:DB8::192.0.2.255 ', '2001:db8::c000:2ff'],
    ['1:2:3:4:5:6:0.0.0.0', '1:2:3:4:5:6::'],
    ['::255.255.255.255', '::ffff:ffff'],
  ];
  for (const [raw, hex] of cases) {
    assert.equal(isValidIpAddress(raw), true, raw);
    assert.equal(canonicalizeIpAddress(raw), hex, raw);
    assert.equal(canonicalizeIpAddress(raw), canonicalizeIpAddress(hex), raw);
  }

  for (const raw of [
    '', '2001:db8::256.8.8.8', '::ffff:1.2.3', '::ffff:1.2.3.4.5',
    '::ffff:01.2.3.4', '::ffff:1.2.3.-4', '::ffff:1.2.3.4junk',
    '1:2:3:4:5:8.8.8.8', '1:2:3:4:5:6:7:8.8.8.8',
    '1:2:3:4:5:6::8.8.8.8', '2001:::8.8.8.8', '1.2.3.4::',
  ]) {
    assert.equal(isValidIpAddress(raw), false, raw);
    assert.equal(canonicalizeIpAddress(raw), null, raw);
  }
});

test('discards stale detection responses when concurrent requests overlap', async () => {
  const pending: Array<{
    url: string;
    signal?: AbortSignal | null;
    resolve: (res: { ok: boolean; status: number; json: () => Promise<DetectionResponse> }) => void;
  }> = [];

  const coordinator = createDetectionCoordinator((url, init) => {
    return new Promise((resolve) => {
      pending.push({ url, signal: init?.signal, resolve });
    });
  });

  const firstRun = coordinator.executeDetection('8.8.8.8');
  const secondRun = coordinator.executeDetection('8.8.4.4');

  assert.equal(pending.length, 2);
  assert.equal(pending[0]?.signal?.aborted, true);
  assert.equal(pending[1]?.signal?.aborted, false);

  pending[1]?.resolve({
    ok: true,
    status: 200,
    json: async () => makeDetectionPayload('8.8.4.4'),
  });
  await secondRun;
  assert.equal(coordinator.state.detectionData?.ip, '8.8.4.4');

  pending[0]?.resolve({
    ok: true,
    status: 200,
    json: async () => makeDetectionPayload('8.8.8.8'),
  });
  await firstRun;
  assert.equal(coordinator.state.detectionData?.ip, '8.8.4.4');
  assert.deepEqual(coordinator.state.ipHistory, ['8.8.4.4']);
});

test('resets session and cached state when detection returns HTTP 401', async () => {
  const initialState: DetectionCoordinatorState = {
    isLoading: false,
    isRefreshing: false,
    validationError: '',
    sessionExpiredMessage: '',
    refreshWarningMessage: '',
    lastRefreshedAt: '2026-11-20T00:00:00Z',
    detectionData: makeDetectionPayload('8.8.8.8'),
    diagnostic: {
      duration: 0.12,
      memory: 42,
      isCached: false,
    },
    user: {
      isLoggedIn: true,
      username: 'SysopUser',
      role: 'Local Administrator (sysop)',
      hasAccess: true,
    },
    ipHistory: ['8.8.8.8'],
  };

  const coordinator = createDetectionCoordinator(
    async () => ({
      ok: false,
      status: 401,
      json: async () => ({ error: 'unauthenticated' }),
    }),
    initialState.user,
    { state: initialState }
  );

  await coordinator.executeDetection('1.1.1.1');

  assert.equal(coordinator.state.user.isLoggedIn, false);
  assert.equal(coordinator.state.user.hasAccess, false);
  assert.equal(coordinator.state.detectionData, null);
  assert.equal(coordinator.state.diagnostic, null);
  assert.match(coordinator.state.sessionExpiredMessage, /session has expired/i);
  assert.equal(coordinator.state.validationError, coordinator.state.sessionExpiredMessage);
});

test('enforces allowlist admin authorisation strictly', () => {
  const cases = [
    { user: null, expected: false },
    { user: { isLoggedIn: false, hasAccess: true, isAdmin: true }, expected: false },
    { user: { isLoggedIn: true, hasAccess: false, isAdmin: true }, expected: false },
    { user: { isLoggedIn: true, hasAccess: true, isAdmin: false }, expected: false },
    { user: { isLoggedIn: true, hasAccess: true }, expected: false },
    { user: { isLoggedIn: true, hasAccess: true, isAdmin: true }, expected: true },
  ];

  for (const item of cases) {
    assert.equal(isAuthorisedAdminUser(item.user), item.expected);
  }
});
