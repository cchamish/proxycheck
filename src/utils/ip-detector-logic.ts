/**
 * Shared IP validation, canonicalization, result helpers, and detection request coordinator.
 */

export interface ProviderRawResult {
  provider:
    | 'Cloudflare Radar'
    | 'AbuseIPDB'
    | 'IPData'
    | 'IPRegistry'
    | 'IP2Location'
    | 'GetIPIntel'
    | 'Proxycheck'
    | 'IPHub'
    | 'IPHunter'
    | 'MaxMind'
    | 'Spamhaus ZEN'
    | 'SpamCop'
    | 'SORBS'
    | 'Tor Onionoo'
    | 'StopForumSpam'
    | 'DShield';
  status: string;
  statusCode: number | null;
  asn: string;
  isp: string;
  organisation: string;
  location: string;
  usageType: string;
  securityFlags: { label: string; isHighRisk: boolean }[];
  threatScore: number | null;
  chance?: number | null;
  block?: number | null;
  countryCode?: string;
  coordinates?: string;
  prefixLength?: number;
  port?: number | null;
  lastSeen?: string | null;
  isTor?: boolean;
  torIsExit?: boolean;
  torRunning?: boolean;
  torFlags?: string[];
  torLabel?: string | null;
  torSummary?: string | null;
  appears?: boolean;
  frequency?: number;
  confidence?: number;
  attacks?: number;
  count?: number;
  threatfeeds?: string[];
  maxDate?: string | null;
  rawJson: Record<string, unknown>;
}

export type PtrCategory = 'dynamic_residential' | 'hosting_or_gateway' | 'unclassified' | 'none';

export interface CacheMeta {
  status: 'hit' | 'partial' | 'miss';
  isPartial: boolean;
  hitCount: number;
  missCount: number;
  cooldownCount: number;
  totalSources: number;
  cachedAt: string | null;
}

export interface DetectionResponse {
  ip: string;
  isCached: boolean;
  cacheMeta?: CacheMeta;
  durationSeconds?: number;
  memoryMb?: number;
  isNonPublic?: boolean;
  nonPublicCategory?: string;
  nonPublicReason?: string;
  is_broadcast_ip: boolean;
  isTor?: boolean;
  torIsExit?: boolean;
  torRunning?: boolean;
  torFlags?: string[];
  torLabel?: string | null;
  torSummary?: string | null;
  prediction_score: number;
  predictionLabel?: string;
  predictionTier?: string;
  getipintel_chance: number | null;
  arbitrationVerdict: string;
  arbitrationTier?: string;
  isMajorityProxyVpn: boolean;
  comprehensiveScore: number;
  baseScore: number;
  primaryCountry: string;
  primaryCoordinates: string;
  primaryAsn: string;
  ptrHostname?: string | null;
  ptrCategory?: PtrCategory;
  ptrLabel?: string;
  ptrIsHighRisk?: boolean;
  recommendedCidr?: string | null;
  defaultCidr?: string | null;
  mmdbCidr?: string | null;
  cidrNote?: string | null;
  results: ProviderRawResult[];
}

export function isValidIpAddress(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();

  const ipv4Pattern = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
  if (ipv4Pattern.test(trimmed)) {
    const parts = trimmed.split('.');
    if (parts.length === 4 && parts.every((p) => {
      const n = Number(p);
      return n >= 0 && n <= 255;
    })) {
      return true;
    }
  }

  const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv6Pattern.test(trimmed);
}

/**
 * Normalizes a valid IPv4 or IPv6 address into its canonical compressed representation.
 */
export function canonicalizeIpAddress(rawIp: string): string | null {
  if (!isValidIpAddress(rawIp)) {
    return null;
  }
  const trimmed = rawIp.trim().toLowerCase();
  if (!trimmed.includes(':')) {
    return trimmed
      .split('.')
      .map((part) => String(Number(part)))
      .join('.');
  }

  const [addrWithoutZone, zoneId] = trimmed.split('%');
  let working = addrWithoutZone;
  const lastColon = working.lastIndexOf(':');
  const tail = working.slice(lastColon + 1);
  if (tail.includes('.')) {
    const octets = tail.split('.').map((o) => Number(o));
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    working = `${working.slice(0, lastColon + 1)}${high}:${low}`;
  }

  let groups: string[];
  if (working.includes('::')) {
    const [leftRaw, rightRaw] = working.split('::');
    const leftGroups = leftRaw ? leftRaw.split(':') : [];
    const rightGroups = rightRaw ? rightRaw.split(':') : [];
    const missingCount = 8 - (leftGroups.length + rightGroups.length);
    groups = [
      ...leftGroups,
      ...Array.from({ length: Math.max(0, missingCount) }, () => '0'),
      ...rightGroups,
    ];
  } else {
    groups = working.split(':');
  }

  const normalizedGroups = groups.map((g) => parseInt(g || '0', 16).toString(16));

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < normalizedGroups.length; i += 1) {
    if (normalizedGroups[i] === '0') {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
      if (curLen >= 2 && curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  let compressed: string;
  if (bestStart !== -1) {
    const prefix = normalizedGroups.slice(0, bestStart).join(':');
    const suffix = normalizedGroups.slice(bestStart + bestLen).join(':');
    if (!prefix && !suffix) {
      compressed = '::';
    } else if (!prefix) {
      compressed = `::${suffix}`;
    } else if (!suffix) {
      compressed = `${prefix}::`;
    } else {
      compressed = `${prefix}::${suffix}`;
    }
  } else {
    compressed = normalizedGroups.join(':');
  }

  return zoneId ? `${compressed}%${zoneId}` : compressed;
}

export function updateIpHistory(history: string[], newIp: string): string[] {
  const canonical = canonicalizeIpAddress(newIp);
  if (!canonical) return history;

  const filtered = history.filter((ip) => (canonicalizeIpAddress(ip) ?? ip.toLowerCase()) !== canonical);
  const updated = [canonical, ...filtered];
  return updated.slice(0, 5);
}

/**
 * Resolves a configured GitHub repository slug or URL into a normalized HTTPS base URL.
 */
export function resolveRepoBaseUrl(configuredRepo?: string | null): string {
  const trimmed = String(configuredRepo ?? '').trim();
  if (!trimmed) {
    return '';
  }
  return trimmed.startsWith('http')
    ? trimmed.replace(/\/$/, '')
    : `https://github.com/${trimmed}`;
}

export function filterComparisonResults(results: ProviderRawResult[] | undefined | null): ProviderRawResult[] {
  if (!Array.isArray(results)) return [];
  return results.filter((row) => row.provider !== 'GetIPIntel' && row.provider !== 'Tor Onionoo');
}

export function simplifySecurityFlags(
  flags: { label: string; isHighRisk: boolean }[] | undefined
): { label: string; isHighRisk: boolean }[] {
  if (!flags || flags.length === 0) {
    return [{ label: 'No Flags', isHighRisk: false }];
  }

  const highRisk = flags.filter((f) => f.isHighRisk);
  if (highRisk.length > 0) {
    return highRisk;
  }

  return [{ label: 'No Flags', isHighRisk: false }];
}

export interface DetectionCoordinatorState {
  isLoading: boolean;
  validationError: string;
  sessionExpiredMessage: string;
  detectionData: any | null;
  diagnostic: { duration: number; memory: number | null; isCached: boolean } | null;
  user: {
    isLoggedIn: boolean;
    username: string;
    role: string;
    hasAccess: boolean;
  };
  ipHistory: string[];
}

export interface DetectionCoordinatorOptions {
  state?: DetectionCoordinatorState;
  onHistoryUpdated?: (history: string[]) => void;
}

/**
 * Coordinates IP detection requests with monotonic request IDs to discard stale responses
 * during rapid history selections, and resets session state when HTTP 401 is returned.
 */
export function createDetectionCoordinator(
  fetchImpl: (url: string, init?: RequestInit) => Promise<{
    ok: boolean;
    status: number;
    json: () => Promise<any>;
  }>,
  initialUser: { isLoggedIn: boolean; username: string; role: string; hasAccess: boolean } = {
    isLoggedIn: true,
    username: 'AdminUser',
    role: 'Local Administrator (sysop)',
    hasAccess: true,
  },
  options?: DetectionCoordinatorOptions
) {
  const state: DetectionCoordinatorState = options?.state ?? {
    isLoading: false,
    validationError: '',
    sessionExpiredMessage: '',
    detectionData: null,
    diagnostic: null,
    user: { ...initialUser },
    ipHistory: [],
  };

  let latestRequestId = 0;
  let activeAbortController: AbortController | null = null;

  async function executeDetection(ipToQuery: string): Promise<void> {
    state.validationError = '';
    const targetIp = ipToQuery.trim();

    if (!isValidIpAddress(targetIp)) {
      state.validationError = 'Please provide a valid IPv4 or IPv6 address.';
      return;
    }

    const requestId = ++latestRequestId;
    if (activeAbortController) {
      activeAbortController.abort();
    }
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    activeAbortController = controller;

    state.isLoading = true;
    try {
      const fetchOptions = controller ? { signal: controller.signal } : undefined;
      const response = await fetchImpl(
        `/api/v1/detect?ip=${encodeURIComponent(targetIp)}`,
        fetchOptions
      );
      if (requestId !== latestRequestId) {
        return;
      }

      if (response.status === 401) {
        const expiredMessage = 'Your session has expired. Please log in again with Wikimedia.';
        state.sessionExpiredMessage = expiredMessage;
        state.validationError = expiredMessage;
        state.user = {
          isLoggedIn: false,
          username: '',
          role: '',
          hasAccess: false,
        };
        state.detectionData = null;
        state.diagnostic = null;
        return;
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        if (requestId !== latestRequestId) {
          return;
        }
        throw new Error(errData.message || errData.error || `Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      if (requestId !== latestRequestId) {
        return;
      }

      state.sessionExpiredMessage = '';
      state.detectionData = data;
      state.diagnostic = {
        duration: data.durationSeconds || 0.0,
        memory: data.memoryMb != null ? Math.round(data.memoryMb) : null,
        isCached: Boolean(data.isCached),
      };
      state.ipHistory = updateIpHistory(state.ipHistory, data.ip || targetIp);
      options?.onHistoryUpdated?.(state.ipHistory);
    } catch (err: any) {
      if (requestId !== latestRequestId || (err && err.name === 'AbortError')) {
        return;
      }
      state.validationError =
        err?.message || 'An error occurred whilst analysing the requested IP address.';
    } finally {
      if (requestId === latestRequestId) {
        state.isLoading = false;
      }
    }
  }

  return {
    state,
    executeDetection,
  };
}
