import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canonicalizeIpAddress,
  createDetectionCoordinator,
  getRefetchButtonState,
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

test('blocks refreshDetection while an SSE detection stream is still active, then allows it after done', async () => {
  const encoder = new TextEncoder();
  let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
  const streamBody = new ReadableStream<Uint8Array>({
    start(controller) {
      streamController = controller;
    },
  });

  const requestedUrls: string[] = [];
  const coordinator = createDetectionCoordinator(async (url) => {
    requestedUrls.push(url);
    if (url.startsWith('/api/v1/detect/stream')) {
      return {
        ok: true,
        status: 200,
        headers: {
          get(name: string) {
            return name.toLowerCase() === 'content-type' ? 'text/event-stream' : null;
          },
        },
        body: streamBody,
        json: async () => ({}),
      };
    }
    if (url === '/api/v1/detect/refresh') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ...makeDetectionPayload('8.8.8.8'),
          arbitrationVerdict: 'Refreshed Verdict',
          fetchedAt: '2026-11-24T00:00:00Z',
        }),
      };
    }
    throw new Error(`Unexpected URL: ${url}`);
  });

  const detectPromise = coordinator.executeDetection('8.8.8.8');

  // Deliver initial SSE snapshot while AbuseIPDB is still pending.
  const snapshotPayload: DetectionResponse = {
    ...makeDetectionPayload('8.8.8.8'),
    pendingProviders: ['AbuseIPDB'],
  };
  streamController!.enqueue(
    encoder.encode(`event: snapshot\ndata: ${JSON.stringify(snapshotPayload)}\n\n`)
  );

  // Wait for snapshot to be processed.
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(coordinator.state.detectionData?.ip, '8.8.8.8');
  assert.equal(coordinator.state.isLoading, false);
  assert.equal(coordinator.state.isStreaming, true);

  // Attempting to refresh while streaming must be a no-op and must not fire /api/v1/detect/refresh.
  await coordinator.refreshDetection();
  assert.deepEqual(requestedUrls, ['/api/v1/detect/stream?ip=8.8.8.8']);
  assert.equal(coordinator.state.isRefreshing, false);

  // Complete the stream with provider + done events.
  streamController!.enqueue(
    encoder.encode(
      `event: provider\ndata: ${JSON.stringify({
        provider: 'AbuseIPDB',
        providerKey: 'abuseipdb',
        pendingProviders: [],
        row: {
          provider: 'AbuseIPDB',
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
      })}\n\n`
    )
  );
  streamController!.enqueue(
    encoder.encode(
      `event: done\ndata: ${JSON.stringify({
        ip: '8.8.8.8',
        isCached: false,
        pendingProviders: [],
        arbitrationVerdict: 'Stream Done Verdict',
      })}\n\n`
    )
  );
  streamController!.close();
  await detectPromise;

  assert.equal(coordinator.state.isStreaming, false);
  assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Stream Done Verdict');
  assert.equal(coordinator.state.detectionData?.results.length, 2);

  // Once streaming finishes, Refetch is allowed and updates the result.
  await coordinator.refreshDetection();
  assert.deepEqual(requestedUrls, ['/api/v1/detect/stream?ip=8.8.8.8', '/api/v1/detect/refresh']);
  assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Refreshed Verdict');
});

test('disables Refetch button state while detector stream is active or has pending providers', () => {
  const basePayload = makeDetectionPayload('8.8.8.8');

  assert.deepEqual(getRefetchButtonState(basePayload, { isLoading: false, isStreaming: true, isRefreshing: false }), {
    visible: true,
    label: 'Refetch',
    disabled: true,
    isBusy: false,
  });

  assert.deepEqual(
    getRefetchButtonState(
      { ...basePayload, pendingProviders: ['AbuseIPDB'] },
      { isLoading: false, isStreaming: false, isRefreshing: false }
    ),
    {
      visible: true,
      label: 'Refetch',
      disabled: true,
      isBusy: false,
    }
  );

  assert.deepEqual(getRefetchButtonState(basePayload, { isLoading: false, isStreaming: false, isRefreshing: false }), {
    visible: true,
    label: 'Refetch',
    disabled: false,
    isBusy: false,
  });

  assert.deepEqual(getRefetchButtonState(basePayload, { isLoading: false, isStreaming: false, isRefreshing: true }), {
    visible: true,
    label: 'Updating...',
    disabled: true,
    isBusy: true,
  });
});

test('re-enables Refetch and clears pendingProviders when an SSE stream drops mid-flight', async () => {
  const encoder = new TextEncoder();
  let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
  const streamBody = new ReadableStream<Uint8Array>({
    start(controller) {
      streamController = controller;
    },
  });

  const requestedUrls: string[] = [];
  const coordinator = createDetectionCoordinator(async (url) => {
    requestedUrls.push(url);
    if (url.startsWith('/api/v1/detect/stream')) {
      return {
        ok: true,
        status: 200,
        headers: {
          get(name: string) {
            return name.toLowerCase() === 'content-type' ? 'text/event-stream' : null;
          },
        },
        body: streamBody,
        json: async () => ({}),
      };
    }
    if (url === '/api/v1/detect/refresh') {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ...makeDetectionPayload('8.8.8.8'),
          arbitrationVerdict: 'Recovered Verdict',
        }),
      };
    }
    throw new Error(`Unexpected URL: ${url}`);
  });

  const detectPromise = coordinator.executeDetection('8.8.8.8');
  streamController!.enqueue(
    encoder.encode(
      `event: snapshot\ndata: ${JSON.stringify({
        ...makeDetectionPayload('8.8.8.8'),
        pendingProviders: ['AbuseIPDB'],
      })}\n\n`
    )
  );
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(coordinator.state.isStreaming, true);

  // Drop the stream connection before `done` arrives.
  streamController!.error(new Error('network disconnected'));
  await detectPromise;

  assert.equal(coordinator.state.isStreaming, false);
  assert.deepEqual(coordinator.state.detectionData?.pendingProviders, []);
  assert.equal(
    getRefetchButtonState(coordinator.state.detectionData!, {
      isLoading: coordinator.state.isLoading,
      isStreaming: coordinator.state.isStreaming,
      isRefreshing: coordinator.state.isRefreshing,
    }).disabled,
    false
  );

  await coordinator.refreshDetection();
  assert.deepEqual(requestedUrls, ['/api/v1/detect/stream?ip=8.8.8.8', '/api/v1/detect/refresh']);
  assert.equal(coordinator.state.detectionData?.arbitrationVerdict, 'Recovered Verdict');
});
