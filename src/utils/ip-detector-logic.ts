export const REQUIRED_USER_RIGHTS = [
  'checkuser-temporary-account',
  'checkuser-temporary-account-no-preference',
] as const;

export const PROVIDER_NAMES = [
  'Cloudflare Radar',
  'AbuseIPDB',
  'IPData',
  'IPRegistry',
  'IP2Location',
  'GetIPIntel',
  'Proxycheck',
  'IPHub',
  'IPHunter',
  'MaxMind',
  'Spamhaus ZEN',
  'SpamCop',
  'Tor Onionoo',
  'StopForumSpam',
  'DShield',
  'IPsum / DROP',
  'OpenASN',
  'Shodan InternetDB',
] as const;

export type ProviderName = (typeof PROVIDER_NAMES)[number];
export type ChipStatus = 'notice' | 'warning' | 'error' | 'success';
export type AppTab = 'detector' | 'rb';
export type PtrCategory =
  | 'dynamic_residential'
  | 'hosting_or_gateway'
  | 'mobile_or_cgnat'
  | 'unclassified'
  | 'none';
export type SharedPrivacyEgress = 'icloud_private_relay' | 'cloudflare_warp';
export type SharedCategory = 'cloud' | 'vpn' | 'relay' | 'enterprise_gateway' | 'cdn' | 'saas' | 'bot';
export type CacheStatus = 'hit' | 'stale' | 'partial' | 'miss' | 'bypassed';
export type CacheLayer = 'L1' | 'L2' | 'upstream' | 'bypassed';

export interface ProviderRawResult {
  provider: ProviderName;
  status: string;
  statusCode: number | null;
  asn: string;
  isp: string;
  organisation: string;
  location: string;
  usageType: string;
  securityFlags: { label: string; isHighRisk: boolean }[];
  riskScore?: number | null;
  chance?: number | null;
  residentialProxy?: number | null;
  block?: number | null;
  countryCode?: string;
  prefixLength?: number;
  port?: number | null;
  ports?: number[];
  openProxyPorts?: number[];
  tags?: string[];
  hostnames?: string[];
  lastSeen?: string | null;
  carrier?: string | null;
  mobileBrand?: string | null;
  totalReports?: number | null;
  numDistinctUsers?: number | null;
  isMobile?: boolean;
  sharedProvider?: string | null;
  sharedCidr?: string | null;
  sharedCategory?: SharedCategory | null;
  sharedPrefixLength?: number | null;
  coreVerdict?: string | null;
  coreSources?: string[];
  networkRole?: string | null;
  isCdn?: boolean;
  isEnterpriseGateway?: boolean;
  isBadAsn?: boolean;
  cloudProvider?: string | null;
  cloudCidr?: string | null;
  cloudPrefixLength?: number | null;
  hostingProvider?: string | null;
  isTor?: boolean;
  torIsExit?: boolean;
  torRunning?: boolean;
  torFlags?: string[];
  torLabel?: string | null;
  torSummary?: string | null;
  appears?: boolean;
  blacklisted?: boolean;
  toxicCidr?: string | null;
  frequency?: number;
  confidence?: number;
  attacks?: number;
  count?: number;
  threatfeeds?: string[];
  maxDate?: string | null;
  ipsumScore?: number;
  isIpsumListed?: boolean;
  inSpamhausDrop?: boolean;
  dropSblId?: string | null;
  dropCidr?: string | null;
  matchedCidr?: string | null;
  isVpn?: boolean;
  isDatacenter?: boolean;
  isHosting?: boolean;
  category?: string | null;
  sources?: string[];
  offlineDbUpdatedAt?: string | null;
  isCooldown?: boolean;
  isQuotaGuarded?: boolean;
  isQuotaGuard?: boolean;
  isDeferred?: boolean;
  isSkippedIpv6?: boolean;
  isListed?: boolean;
  isPolicyRange?: boolean;
  isQueryRestricted?: boolean;
  listedCodes?: string[];
  isCached?: boolean;
  cachedAt?: string | null;
  isHistoricalFallback?: boolean;
  isPending?: boolean;
  rawJson: Record<string, unknown>;
}

export interface RangeblockHitRow {
  target: string;
  cidr: number | null;
  upperBound: string;
  count: number;
  isActive: boolean;
  expiry: string | null;
  indefinite: boolean;
  lastBlockedAt?: string | null;
  logUrl: string;
  blockListUrl: string;
}

export interface RangeblockWikiSummary {
  wiki: string;
  isGlobal: boolean;
  count: number;
  hasActive: boolean;
  domain: string;
  rows: RangeblockHitRow[];
}

export interface RangeblockSummary {
  ip: string;
  ipVersion: 4 | 6;
  localTotal: number;
  globalTotal: number;
  hasActive: boolean;
  realtimeDegraded?: boolean;
  wikis: RangeblockWikiSummary[];
}

export interface CacheMeta {
  status: CacheStatus;
  layer?: CacheLayer;
  isPartial: boolean;
  hitCount: number;
  missCount: number;
  cooldownCount: number;
  totalSources: number;
  cachedAt: string | null;
  fetchedAt?: string | null;
  ageSeconds?: number;
  staleThresholdSeconds?: number;
  isStale?: boolean;
  shouldAutoRefresh?: boolean;
  refreshInProgress?: boolean;
  degradedRefreshFallback?: boolean;
  recommendFreshRecheck?: boolean;
  hitProviders?: string[];
  missedProviders?: string[];
}

export interface DetectionResponse {
  ip: string;
  fetchedAt?: string | null;
  queryMode?: 'light' | 'full';
  isPartialMode?: boolean;
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
  residentialProxy?: number | null;
  highlySuspectedResidentialProxy?: boolean;
  arbitrationVerdict: string;
  arbitrationTier?: string;
  isMajorityProxyVpn: boolean;
  suspectedResidentialProxy?: boolean;
  primaryCountry: string;
  primaryAsn: string;
  ptrHostname?: string | null;
  ptrCategory?: PtrCategory;
  ptrLabel?: string;
  ptrIsHighRisk?: boolean;
  recommendedCidr?: string | null;
  defaultCidr?: string | null;
  mmdbCidr?: string | null;
  sharedProvider?: string | null;
  sharedCidr?: string | null;
  sharedCategory?: SharedCategory | null;
  cloudCidr?: string | null;
  cloudProvider?: string | null;
  cidrNote?: string | null;
  bgpPrefix?: string | null;
  escalationCidr?: string | null;
  cidrRationale?: string | null;
  isMobileOrCgnat?: boolean;
  sharedPrivacyEgress?: SharedPrivacyEgress | null;
  openProxyPorts?: number[];
  rangeblock?: RangeblockSummary | null;
  pendingProviders?: string[];
  results: ProviderRawResult[];
}

export interface DiagnosticMetrics {
  duration: number;
  memory: number | null;
  isCached: boolean;
}

export interface DiagnosticPayload {
  durationSeconds?: number | null;
  memoryMb?: number | null;
  isCached?: boolean | null;
}

export interface UserSessionState {
  isLoggedIn: boolean;
  username: string;
  role: string;
  hasAccess: boolean;
  isAdmin?: boolean;
  localGroups?: string[];
  globalGroups?: string[];
}

export interface DetectionCoordinatorState {
  isLoading: boolean;
  isStreaming?: boolean;
  isRefreshing?: boolean;
  validationError: string;
  sessionExpiredMessage: string;
  refreshWarningMessage?: string;
  lastRefreshedAt?: string | null;
  detectionData: DetectionResponse | null;
  diagnostic: DiagnosticMetrics | null;
  user: UserSessionState;
  ipHistory: string[];
}

export interface DetectionCoordinatorOptions {
  state?: DetectionCoordinatorState;
  onHistoryUpdated?: (history: string[]) => void;
  onDetectionSuccess?: (canonicalIp: string, data: DetectionResponse) => void;
}

const IPV4_PATTERN = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/;
const IPV6_PATTERN =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

export function isValidIpAddress(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false;
  const trimmed = ip.trim();

  if (IPV4_PATTERN.test(trimmed)) {
    const parts = trimmed.split('.');
    if (parts.length === 4 && parts.every((p) => { const n = Number(p); return n >= 0 && n <= 255; })) {
      return true;
    }
  }

  return IPV6_PATTERN.test(trimmed);
}

// Keep IPv4 and RFC 5952 IPv6 normalisation symmetric with canonicalizeIpKey in scripts/user-gadget.js.
export function canonicalizeIpAddress(rawIp: string): string | null {
  if (!isValidIpAddress(rawIp)) return null;

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

  const normalisedGroups = groups.map((g) => parseInt(g || '0', 16).toString(16));

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;

  for (let i = 0; i < normalisedGroups.length; i += 1) {
    if (normalisedGroups[i] === '0') {
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
    const prefix = normalisedGroups.slice(0, bestStart).join(':');
    const suffix = normalisedGroups.slice(bestStart + bestLen).join(':');
    if (!prefix && !suffix) compressed = '::';
    else if (!prefix) compressed = `::${suffix}`;
    else if (!suffix) compressed = `${prefix}::`;
    else compressed = `${prefix}::${suffix}`;
  } else {
    compressed = normalisedGroups.join(':');
  }

  return zoneId ? `${compressed}%${zoneId}` : compressed;
}

export function buildOAuthLoginUrl(search?: string | null, fallbackIp?: string | null): string {
  const params = new URLSearchParams(search || '');
  const ip = canonicalizeIpAddress((params.get('ip') || '').trim()) ?? canonicalizeIpAddress(fallbackIp || '');
  const tab = (params.get('tab') || '').trim().toLowerCase();
  const wiki = (params.get('wiki') || '').trim().toLowerCase();
  const route = new URLSearchParams();
  if (ip) route.set('ip', ip);
  if (tab === 'rb' || tab === 'rangeblock') {
    route.set('tab', 'rb');
    if (/^[a-z0-9_]{2,64}$/.test(wiki)) route.set('wiki', wiki);
  }
  const query = route.toString();
  return query ? `/api/v1/auth/login/?${query}` : '/api/v1/auth/login/';
}

const ENGLISH_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export function normalizeUtcCommitTimestamp(timestamp?: string | null): string {
  const trimmed = String(timestamp ?? '').trim();
  if (!trimmed) return '';
  const withoutUtcSuffix = trimmed.replace(/\s*\(?\butc\)?$/i, '').trim();
  return withoutUtcSuffix ? `${withoutUtcSuffix} (UTC)` : trimmed;
}

export function formatUtcCommitTimestamp(date: Date = new Date()): string {
  const target = Number.isNaN(date.getTime()) ? new Date() : date;
  const hours = String(target.getUTCHours()).padStart(2, '0');
  const minutes = String(target.getUTCMinutes()).padStart(2, '0');
  const day = String(target.getUTCDate()).padStart(2, '0');
  const month = ENGLISH_MONTHS[target.getUTCMonth()];
  const year = target.getUTCFullYear();
  return `${hours}:${minutes} ${day} ${month} ${year} (UTC)`;
}

export function formatCompactDuration(totalMinutes: number): string {
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  return (
    [
      [days, 'd'],
      [hours, 'h'],
      [minutes, 'm'],
    ] as const
  )
    .filter(([value]) => value > 0)
    .map(([value, suffix]) => `${value}${suffix}`)
    .join('');
}

export function formatExactUtcTimestamp(timestamp?: string | Date | null): string | null {
  if (timestamp === null || timestamp === undefined) return null;
  const parsedMs = timestamp instanceof Date ? timestamp.getTime() : Date.parse(String(timestamp).trim());
  if (!Number.isFinite(parsedMs)) return null;
  return `${new Date(parsedMs).toISOString().slice(0, 19).replace('T', ' ')} UTC`;
}

export function formatOfflineDbTimestamp(
  lastModifiedIso?: string | null,
  now: Date | number = Date.now(),
  ageSeconds?: number | null
): string {
  if (!lastModifiedIso || typeof lastModifiedIso !== 'string') return 'Not downloaded';
  const parsedMs = Date.parse(lastModifiedIso.trim());
  if (Number.isNaN(parsedMs)) return lastModifiedIso;

  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const computedAge = Number.isFinite(nowMs)
    ? Math.max(0, Math.floor((nowMs - parsedMs) / 1000))
    : typeof ageSeconds === 'number' && Number.isFinite(ageSeconds)
      ? Math.max(0, Math.floor(ageSeconds))
      : 0;

  const utcStamp = `${new Date(parsedMs).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  const totalMinutes = Math.floor(computedAge / 60);
  const relativeText = totalMinutes < 1 ? 'just now' : `${formatCompactDuration(totalMinutes)} ago`;
  return `${utcStamp} (${relativeText})`;
}

export function buildDiagnosticMetrics(
  payload?: DiagnosticPayload | null,
  fallbackDuration = 0
): DiagnosticMetrics {
  const safeFallback =
    typeof fallbackDuration === 'number' && Number.isFinite(fallbackDuration) && fallbackDuration >= 0
      ? fallbackDuration
      : 0;
  const rawDuration = payload?.durationSeconds;
  const duration =
    typeof rawDuration === 'number' && Number.isFinite(rawDuration) && rawDuration >= 0
      ? rawDuration
      : safeFallback;

  const rawMemory = payload?.memoryMb;
  const memory =
    typeof rawMemory === 'number' && Number.isFinite(rawMemory) && rawMemory >= 0
      ? Math.round(rawMemory * 100) / 100
      : null;

  return { duration, memory, isCached: Boolean(payload?.isCached) };
}

export function formatDiagnosticSummary(diagnostic?: DiagnosticMetrics | null): string {
  const rawDuration = diagnostic?.duration;
  const duration =
    typeof rawDuration === 'number' && Number.isFinite(rawDuration) && rawDuration >= 0 ? rawDuration : 0;
  const parts = [`Executed in ${duration.toFixed(3)} seconds`];

  const rawMemory = diagnostic?.memory;
  if (typeof rawMemory === 'number' && Number.isFinite(rawMemory) && rawMemory >= 0) {
    parts.push(`Worker RSS ${rawMemory.toFixed(2)} MB`);
  }

  return parts.join(' \u00b7 ');
}

export function createLoggedOutUserState(): UserSessionState {
  return {
    isLoggedIn: false,
    username: '',
    role: '',
    hasAccess: false,
    isAdmin: false,
    localGroups: [],
    globalGroups: [],
  };
}

export function isAuthorisedAdminUser(user?: Partial<UserSessionState> | null): boolean {
  return Boolean(user && user.isLoggedIn && user.hasAccess && user.isAdmin === true);
}

export function readCsrfTokenFromDocumentCookie(): string {
  if (typeof document === 'undefined' || typeof document.cookie !== 'string' || !document.cookie) {
    return '';
  }
  for (const entry of document.cookie.split(';')) {
    const trimmed = entry.trim();
    if (trimmed.startsWith('csrftoken=')) {
      try {
        return decodeURIComponent(trimmed.slice('csrftoken='.length));
      } catch {
        return trimmed.slice('csrftoken='.length);
      }
    }
  }
  return '';
}

function prependIpToHistory(history: string[], newIp: string): string[] {
  const canonical = canonicalizeIpAddress(newIp);
  if (!canonical) return history;
  const filtered = history.filter((ip) => (canonicalizeIpAddress(ip) ?? ip.toLowerCase()) !== canonical);
  return [canonical, ...filtered].slice(0, 5);
}

interface CoordinatorFetchResponse {
  ok: boolean;
  status: number;
  headers?: { get?: (name: string) => string | null } | null;
  body?: ReadableStream<Uint8Array> | null;
  json: () => Promise<unknown>;
}

export function createDetectionCoordinator(
  fetchImpl: (url: string, init?: RequestInit) => Promise<CoordinatorFetchResponse>,
  initialUser: UserSessionState = {
    isLoggedIn: true,
    username: 'AdminUser',
    role: 'Temporary Account Access (local: checkuser-temporary-account)',
    hasAccess: true,
  },
  options?: DetectionCoordinatorOptions
) {
  const state: DetectionCoordinatorState = options?.state ?? {
    isLoading: false,
    isStreaming: false,
    isRefreshing: false,
    validationError: '',
    sessionExpiredMessage: '',
    refreshWarningMessage: '',
    lastRefreshedAt: null,
    detectionData: null,
    diagnostic: null,
    user: { ...initialUser },
    ipHistory: [],
  };

  state.isStreaming ??= false;
  state.isRefreshing ??= false;
  state.refreshWarningMessage ??= '';
  if (state.lastRefreshedAt === undefined) state.lastRefreshedAt = null;

  let latestRequestId = 0;
  let latestRefreshId = 0;
  let activeAbortController: AbortController | null = null;
  let activeRefreshAbortController: AbortController | null = null;
  let activeRefreshPromise: Promise<void> | null = null;

  function abortActiveRefresh(): void {
    latestRefreshId += 1;
    activeRefreshAbortController?.abort();
    activeRefreshAbortController = null;
    activeRefreshPromise = null;
    state.isRefreshing = false;
  }

  function cancelPending(): void {
    latestRequestId += 1;
    activeAbortController?.abort();
    activeAbortController = null;
    abortActiveRefresh();
    state.isLoading = false;
    state.isStreaming = false;
    state.refreshWarningMessage = '';
  }

  function handleSessionExpired(): void {
    const expiredMessage = 'Your session has expired. Please log in again with Wikimedia.';
    state.sessionExpiredMessage = expiredMessage;
    state.validationError = expiredMessage;
    state.refreshWarningMessage = '';
    state.lastRefreshedAt = null;
    state.user = createLoggedOutUserState();
    state.detectionData = null;
    state.diagnostic = null;
    state.isRefreshing = false;
  }

  function clearRefreshFlags(data: DetectionResponse | null): void {
    if (data?.cacheMeta) {
      data.cacheMeta = { ...data.cacheMeta, shouldAutoRefresh: false, refreshInProgress: false };
    }
  }

  function recordDetectionSuccess(data: DetectionResponse, fallbackIp: string): string {
    const resolvedIp = canonicalizeIpAddress(data.ip || fallbackIp) ?? (data.ip || fallbackIp);
    state.ipHistory = prependIpToHistory(state.ipHistory, resolvedIp);
    options?.onHistoryUpdated?.(state.ipHistory);
    options?.onDetectionSuccess?.(resolvedIp, data);
    return resolvedIp;
  }

  function maybeAutoRefresh(data: DetectionResponse, resolvedIp: string, requestId: number): void {
    if (
      data.cacheMeta?.shouldAutoRefresh === true &&
      !data.cacheMeta.refreshInProgress &&
      !data.isNonPublic
    ) {
      const canonical = canonicalizeIpAddress(resolvedIp);
      if (canonical) {
        void startRefreshForCanonicalIp(canonical, requestId);
      }
    }
  }

  function startRefreshForCanonicalIp(canonicalIp: string, boundRequestId: number): Promise<void> {
    if (state.isRefreshing && activeRefreshPromise) {
      return activeRefreshPromise;
    }

    const refreshId = ++latestRefreshId;
    activeRefreshAbortController?.abort();
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    activeRefreshAbortController = controller;

    state.isRefreshing = true;
    state.refreshWarningMessage = '';

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    const csrfToken = readCsrfTokenFromDocumentCookie();
    if (csrfToken) headers['X-CSRFToken'] = csrfToken;

    const refreshInit: RequestInit = {
      method: 'POST',
      credentials: 'same-origin',
      headers,
      body: JSON.stringify({ ip: canonicalIp, mode: 'full', compact: false }),
      ...(controller ? { signal: controller.signal } : {}),
    };

    const task = (async () => {
      try {
        const response = await fetchImpl('/api/v1/detect/refresh', refreshInit);
        if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) return;

        if (response.status === 401) {
          handleSessionExpired();
          return;
        }

        if (response.status === 429) {
          const rateData = (await response.json().catch(() => ({}))) as { retryAfterSeconds?: number };
          if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) return;
          clearRefreshFlags(state.detectionData);
          const retryHint =
            typeof rateData.retryAfterSeconds === 'number' && rateData.retryAfterSeconds > 0
              ? ` Please wait ${rateData.retryAfterSeconds}s before retrying.`
              : '';
          state.refreshWarningMessage =
            `Refresh rate limit is temporarily constrained; valid historical intelligence is preserved.${retryHint}`;
          return;
        }

        if (!response.ok) {
          const errData = (await response.json().catch(() => ({}))) as { message?: string; error?: string };
          if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) return;
          clearRefreshFlags(state.detectionData);
          if (state.detectionData) {
            state.refreshWarningMessage =
              'Upstream providers are temporarily constrained; valid historical intelligence is preserved.';
            return;
          }
          throw new Error(errData.message || errData.error || `Server returned HTTP ${response.status}`);
        }

        const data = (await response.json()) as DetectionResponse;
        if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) return;

        if (data.cacheMeta?.degradedRefreshFallback === true) {
          const hasPreservedRows = Array.isArray(data.results) && data.results.length > 0;
          if (state.detectionData && !hasPreservedRows) {
            state.detectionData = {
              ...state.detectionData,
              cacheMeta: {
                ...state.detectionData.cacheMeta,
                ...data.cacheMeta,
                shouldAutoRefresh: false,
                refreshInProgress: false,
                degradedRefreshFallback: true,
              },
            };
          } else {
            state.detectionData = {
              ...data,
              cacheMeta: {
                ...data.cacheMeta,
                shouldAutoRefresh: false,
                refreshInProgress: false,
                degradedRefreshFallback: true,
              },
            };
            state.diagnostic = buildDiagnosticMetrics(data);
          }
          state.refreshWarningMessage =
            'Upstream providers or quota limits are temporarily constrained; valid historical intelligence is preserved.';
          return;
        }

        state.sessionExpiredMessage = '';
        state.validationError = '';
        state.refreshWarningMessage = '';
        state.detectionData = data;
        state.diagnostic = buildDiagnosticMetrics(data);
        if (!data.cacheMeta?.refreshInProgress) {
          state.lastRefreshedAt = data.fetchedAt || data.cacheMeta?.fetchedAt || new Date().toISOString();
        }
        recordDetectionSuccess(data, canonicalIp);
      } catch (err: unknown) {
        if (
          boundRequestId !== latestRequestId ||
          refreshId !== latestRefreshId ||
          (err instanceof Error && err.name === 'AbortError')
        ) {
          return;
        }
        clearRefreshFlags(state.detectionData);
        if (state.detectionData) {
          state.refreshWarningMessage =
            'Unable to complete upstream refresh at this time; valid historical intelligence is preserved.';
        } else {
          state.validationError =
            (err instanceof Error && err.message) ||
            'An error occurred whilst refreshing the requested IP address.';
        }
      } finally {
        if (boundRequestId === latestRequestId && refreshId === latestRefreshId) {
          state.isRefreshing = false;
          activeRefreshPromise = null;
          activeRefreshAbortController = null;
        }
      }
    })();

    activeRefreshPromise = task;
    return task;
  }

  async function refreshDetection(ipOverride?: string): Promise<void> {
    if (state.isRefreshing) {
      if (activeRefreshPromise) await activeRefreshPromise;
      return;
    }
    const canonicalIp = canonicalizeIpAddress(String(ipOverride ?? state.detectionData?.ip ?? ''));
    if (!canonicalIp) {
      state.validationError = 'Please provide a valid IPv4 or IPv6 address.';
      return;
    }
    if (state.detectionData?.isNonPublic || state.detectionData?.cacheMeta?.refreshInProgress) {
      return;
    }
    await startRefreshForCanonicalIp(canonicalIp, latestRequestId);
  }

  function applyCompletePayload(data: DetectionResponse, targetIp: string, requestId: number): void {
    if (requestId !== latestRequestId) return;
    state.sessionExpiredMessage = '';
    state.detectionData = data;
    state.diagnostic = buildDiagnosticMetrics(data);
    const resolvedIp = recordDetectionSuccess(data, targetIp);
    maybeAutoRefresh(data, resolvedIp, requestId);
  }

  async function executeDetection(ipToQuery: string): Promise<void> {
    state.validationError = '';
    const targetIp = ipToQuery.trim();
    if (!isValidIpAddress(targetIp)) {
      state.validationError = 'Please provide a valid IPv4 or IPv6 address.';
      return;
    }

    const requestId = ++latestRequestId;
    activeAbortController?.abort();
    abortActiveRefresh();
    state.refreshWarningMessage = '';
    state.lastRefreshedAt = null;
    state.isStreaming = false;

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    activeAbortController = controller;
    state.isLoading = true;

    try {
      const streamHeaders = { Accept: 'text/event-stream' };
      const streamOptions: RequestInit = controller
        ? { signal: controller.signal, headers: streamHeaders }
        : { headers: streamHeaders };
      const response = await fetchImpl(`/api/v1/detect/stream?ip=${encodeURIComponent(targetIp)}`, streamOptions);
      if (requestId !== latestRequestId) return;

      if (response.status === 401) {
        handleSessionExpired();
        return;
      }

      const contentType = response.headers?.get?.('content-type') || '';
      if (response.ok && contentType.includes('text/event-stream') && response.body?.getReader) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let sawDone = false;

        while (true) {
          const { value, done } = await reader.read();
          if (done || requestId !== latestRequestId) break;
          buffer += decoder.decode(value, { stream: true });

          let separatorIdx = buffer.indexOf('\n\n');
          while (separatorIdx !== -1) {
            const block = buffer.slice(0, separatorIdx);
            buffer = buffer.slice(separatorIdx + 2);
            let eventName = 'message';
            const dataLines: string[] = [];
            for (const rawLine of block.split(/\r?\n/)) {
              if (rawLine.startsWith('event:')) eventName = rawLine.slice('event:'.length).trim();
              else if (rawLine.startsWith('data:')) dataLines.push(rawLine.slice('data:'.length).trim());
            }
            if (dataLines.length > 0) {
              let parsed: Record<string, unknown> | null = null;
              try {
                parsed = JSON.parse(dataLines.join('\n')) as Record<string, unknown>;
              } catch {
                parsed = null;
              }
              if (parsed && requestId === latestRequestId) {
                if (eventName === 'snapshot') {
                  const snapshot = parsed as unknown as DetectionResponse;
                  state.sessionExpiredMessage = '';
                  state.detectionData = snapshot;
                  state.diagnostic = buildDiagnosticMetrics(snapshot);
                  state.isLoading = false;
                  state.isStreaming = Array.isArray(snapshot.pendingProviders) && snapshot.pendingProviders.length > 0;
                  recordDetectionSuccess(snapshot, targetIp);
                } else if (eventName === 'provider' && state.detectionData) {
                  const existingResults = Array.isArray(state.detectionData.results)
                    ? [...state.detectionData.results]
                    : [];
                  const row = parsed.row as ProviderRawResult | undefined;
                  if (row?.provider) {
                    const idx = existingResults.findIndex((r) => r.provider === row.provider);
                    if (idx >= 0) existingResults[idx] = row;
                    else existingResults.push(row);
                  }
                  const { provider: _p, providerKey: _pk, row: _r, ...overviewPatch } = parsed;
                  state.detectionData = {
                    ...state.detectionData,
                    ...(overviewPatch as Partial<DetectionResponse>),
                    results: existingResults,
                  };
                } else if (eventName === 'done') {
                  sawDone = true;
                  state.isStreaming = false;
                  if (state.detectionData) {
                    const merged: DetectionResponse = {
                      ...state.detectionData,
                      ...(parsed as Partial<DetectionResponse>),
                      pendingProviders: [],
                    };
                    state.detectionData = merged;
                    state.diagnostic = buildDiagnosticMetrics(merged);
                    const resolvedIp = canonicalizeIpAddress(merged.ip || targetIp) ?? (merged.ip || targetIp);
                    maybeAutoRefresh(merged, resolvedIp, requestId);
                  }
                }
              }
            }
            separatorIdx = buffer.indexOf('\n\n');
          }
        }

        if (requestId !== latestRequestId || sawDone) return;
      } else if (response.ok && !contentType.includes('text/event-stream')) {
        const data = (await response.json()) as DetectionResponse;
        applyCompletePayload(data, targetIp, requestId);
        return;
      }

      const fallbackOptions = controller ? { signal: controller.signal } : undefined;
      const fallbackResponse = await fetchImpl(`/api/v1/detect?ip=${encodeURIComponent(targetIp)}`, fallbackOptions);
      if (requestId !== latestRequestId) return;

      if (fallbackResponse.status === 401) {
        handleSessionExpired();
        return;
      }
      if (!fallbackResponse.ok) {
        const errData = (await fallbackResponse.json().catch(() => ({}))) as { message?: string; error?: string };
        if (requestId !== latestRequestId) return;
        throw new Error(errData.message || errData.error || `Server returned HTTP ${fallbackResponse.status}`);
      }

      const fallbackData = (await fallbackResponse.json()) as DetectionResponse;
      applyCompletePayload(fallbackData, targetIp, requestId);
    } catch (err: unknown) {
      if (requestId !== latestRequestId || (err instanceof Error && err.name === 'AbortError')) {
        return;
      }
      state.validationError =
        (err instanceof Error && err.message) ||
        'An error occurred whilst analysing the requested IP address.';
    } finally {
      if (requestId === latestRequestId) {
        state.isLoading = false;
        state.isStreaming = false;
      }
    }
  }

  async function waitForActiveRefresh(): Promise<void> {
    if (activeRefreshPromise) await activeRefreshPromise;
  }

  return {
    state,
    executeDetection,
    refreshDetection,
    cancelPending,
    waitForActiveRefresh,
  };
}
