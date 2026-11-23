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

test('surfaces non-401 stream errors without issuing a duplicate /api/v1/detect request', async () => {
  const cases: Array<{
    status: number;
    json: () => Promise<unknown>;
    expectedError: string;
  }> = [
    {
      status: 429,
      json: async () => ({
        error: 'rate_limited',
        message: 'Detection rate limit exceeded. Please wait before retrying.',
      }),
      expectedError: 'Detection rate limit exceeded. Please wait before retrying.',
    },
    {
      status: 400,
      json: async () => ({ error: 'Invalid IP address format.' }),
      expectedError: 'Invalid IP address format.',
    },
    {
      status: 403,
      json: async () => ({
        error: 'forbidden',
        message: 'Insufficient Wikimedia permissions.',
      }),
      expectedError: 'Insufficient Wikimedia permissions.',
    },
    {
      status: 500,
      json: async () => {
        throw new SyntaxError('Unexpected token < in JSON');
      },
      expectedError: 'Server returned HTTP 500',
    },
  ];

  for (const item of cases) {
    const requestedUrls: string[] = [];
    const coordinator = createDetectionCoordinator(async (url) => {
      requestedUrls.push(url);
      return {
        ok: false,
        status: item.status,
        headers: { get: () => 'application/json' },
        json: item.json,
      };
    });

    await coordinator.executeDetection('8.8.8.8');

    assert.deepEqual(
      requestedUrls,
      ['/api/v1/detect/stream?ip=8.8.8.8'],
      `HTTP ${item.status} should not fall back to /api/v1/detect`
    );
    assert.equal(coordinator.state.validationError, item.expectedError);
    assert.equal(coordinator.state.isLoading, false);
    assert.equal(coordinator.state.isStreaming, false);
    assert.equal(coordinator.state.user.isLoggedIn, true);
  }
});

test('falls back to /api/v1/detect when an OK SSE stream ends before a done event', async () => {
  const requestedUrls: string[] = [];
  const encoder = new TextEncoder();
  const coordinator = createDetectionCoordinator(async (url) => {
    requestedUrls.push(url);
    if (url.startsWith('/api/v1/detect/stream')) {
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode('event: snapshot\ndata: {"ip":"8.8.8.8","results":[]}\n\n'));
          controller.close();
        },
      });
      return {
        ok: true,
        status: 200,
        headers: { get: () => 'text/event-stream; charset=utf-8' },
        body,
        json: async () => ({}),
      };
    }
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/json' },
      json: async () => makeDetectionPayload('8.8.8.8'),
    };
  });

  await coordinator.executeDetection('8.8.8.8');

  assert.deepEqual(requestedUrls, ['/api/v1/detect/stream?ip=8.8.8.8', '/api/v1/detect?ip=8.8.8.8']);
  assert.equal(coordinator.state.validationError, '');
  assert.equal(coordinator.state.detectionData?.ip, '8.8.8.8');
});
