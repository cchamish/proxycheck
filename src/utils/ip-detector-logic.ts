/**
 * Shared IP validation, canonicalisation, result helpers, and detection request coordinator.
 */

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

export const COMMERCIAL_ARBITRATION_PROVIDERS = [
  'AbuseIPDB',
  'IPData',
  'IPRegistry',
  'IP2Location',
  'GetIPIntel',
  'Proxycheck',
  'IPHub',
  'IPHunter',
] as const;

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
  coordinates?: string;
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
  /** Legacy cache fields, read-only. */
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

export type AppTab = 'detector' | 'rb';

export interface OfflineDatabaseEntry {
  key: string;
  source: string;
  name: string;
  filename: string;
  exists: boolean;
  optional: boolean;
  sizeBytes: number | null;
  lastModifiedIso: string | null;
  ageSeconds: number | null;
  staleAfterSeconds: number;
  status: 'healthy' | 'stale' | 'missing';
  statusLabel: string;
}

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
  primaryCoordinates: string;
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
  /** Legacy cache fields, read-only. */
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
 * Normalises a valid IPv4 or IPv6 address into its canonical compressed representation.
 * Keep IPv4 and RFC 5952 IPv6 normalisation rules symmetric with canonicalizeIpKey in scripts/user-gadget.js.
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
 * Extracts and canonicalises the `ip` query parameter from a URL search string.
 */
export function extractCanonicalIpFromSearch(search?: string | null): string | null {
  try {
    const params = new URLSearchParams(search || '');
    const rawIp = (params.get('ip') || '').trim();
    return canonicalizeIpAddress(rawIp);
  } catch {
    return null;
  }
}

/**
 * Builds the backend OAuth login URL while preserving a validated IP target for post-login lookup.
 */
export function buildOAuthLoginUrl(search?: string | null, fallbackIp?: string | null): string {
  const targetIp = extractCanonicalIpFromSearch(search) ?? canonicalizeIpAddress(fallbackIp || '');
  if (!targetIp) {
    return '/api/v1/auth/login/';
  }
  return `/api/v1/auth/login/?ip=${encodeURIComponent(targetIp)}`;
}

/**
 * Updates the relative page URL with a canonical `ip` query parameter while keeping unrelated parameters intact.
 */
export function buildPageUrlWithIp(pathname: string, search: string, ip: string | null): string {
  const basePath = pathname && pathname.startsWith('/') ? pathname : '/';
  const params = new URLSearchParams(search || '');
  const canonical = ip ? canonicalizeIpAddress(ip) : null;
  if (canonical) {
    params.set('ip', canonical);
  } else {
    params.delete('ip');
  }
  const queryString = params.toString();
  return queryString ? `${basePath}?${queryString}` : basePath;
}

/**
 * Parses initial ip, tab, and wiki query parameters from window.location.search.
 */
export function parseInitialRouteParams(search?: string | null): {
  ip: string;
  tab: AppTab;
  wiki: string | null;
} {
  try {
    const params = new URLSearchParams(search || '');
    const rawIp = (params.get('ip') || '').trim();
    const rawTab = (params.get('tab') || '').trim().toLowerCase();
    const rawWiki = (params.get('wiki') || '').trim().toLowerCase();
    const tab: AppTab = rawTab === 'rb' || rawTab === 'rangeblock' ? 'rb' : 'detector';
    const wiki = /^[a-z0-9_]{2,64}$/.test(rawWiki) ? rawWiki : null;
    return { ip: rawIp, tab, wiki };
  } catch {
    return { ip: '', tab: 'detector', wiki: null };
  }
}

/**
 * Updates the relative page URL with ip, tab, and optional wiki query parameters.
 */
export function buildPageUrlWithState(
  pathname: string,
  search: string,
  routeState: { ip?: string | null; tab?: AppTab; wiki?: string | null }
): string {
  const basePath = pathname && pathname.startsWith('/') ? pathname : '/';
  const params = new URLSearchParams(search || '');
  const canonical = routeState.ip ? canonicalizeIpAddress(routeState.ip) : null;
  if (canonical) {
    params.set('ip', canonical);
  } else {
    params.delete('ip');
  }
  if (routeState.tab === 'rb') {
    params.set('tab', 'rb');
    if (routeState.wiki && /^[a-z0-9_]{2,64}$/.test(routeState.wiki)) {
      params.set('wiki', routeState.wiki);
    } else {
      params.delete('wiki');
    }
  } else {
    params.delete('tab');
    params.delete('wiki');
  }
  const queryString = params.toString();
  return queryString ? `${basePath}?${queryString}` : basePath;
}

/**
 * Resolves a configured GitHub repository slug or URL into a normalised HTTPS base URL.
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

const ENGLISH_MONTH_ABBREVIATIONS = [
  'Jan',
  'Feb',
  'Mar',
  'Apr',
  'May',
  'Jun',
  'Jul',
  'Aug',
  'Sep',
  'Oct',
  'Nov',
  'Dec',
];

/**
 * Normalises a commit timestamp string so non-empty values end with " (UTC)".
 */
export function normalizeUtcCommitTimestamp(timestamp?: string | null): string {
  const trimmed = String(timestamp ?? '').trim();
  if (!trimmed) {
    return '';
  }
  const withoutUtcSuffix = trimmed.replace(/\s*\(?\butc\)?$/i, '').trim();
  return withoutUtcSuffix ? `${withoutUtcSuffix} (UTC)` : trimmed;
}

/**
 * Formats a Date in UTC as "HH:MM DD Mon YYYY (UTC)" with English month abbreviations.
 */
export function formatUtcCommitTimestamp(date: Date = new Date()): string {
  const target = Number.isNaN(date.getTime()) ? new Date() : date;
  const hours = String(target.getUTCHours()).padStart(2, '0');
  const minutes = String(target.getUTCMinutes()).padStart(2, '0');
  const day = String(target.getUTCDate()).padStart(2, '0');
  const month = ENGLISH_MONTH_ABBREVIATIONS[target.getUTCMonth()];
  const year = target.getUTCFullYear();
  return `${hours}:${minutes} ${day} ${month} ${year} (UTC)`;
}

/**
 * Formats commit hash and optional commit timestamp into the parenthesized footer label.
 */
export function formatCommitVersionLabel(
  commitHash?: string | null,
  commitTimestamp?: string | null
): string {
  const normalizedHash = String(commitHash ?? '').trim() || 'dev';
  const normalizedTimestamp = normalizeUtcCommitTimestamp(commitTimestamp);
  return normalizedTimestamp
    ? `(r.${normalizedHash} @ ${normalizedTimestamp})`
    : `(r.${normalizedHash})`;
}

const MINUTES_PER_HOUR = 60;
const MINUTES_PER_DAY = 24 * MINUTES_PER_HOUR;
const MILLISECONDS_PER_MINUTE = 60_000;

/**
 * Formats a non-negative minute count as a compact continuous duration ("1d2h5m"),
 * omitting zero-valued units.
 */
function formatCompactDurationFromMinutes(totalMinutes: number): string {
  const days = Math.floor(totalMinutes / MINUTES_PER_DAY);
  const hours = Math.floor((totalMinutes % MINUTES_PER_DAY) / MINUTES_PER_HOUR);
  const minutes = totalMinutes % MINUTES_PER_HOUR;

  const parts = [
    [days, 'd'],
    [hours, 'h'],
    [minutes, 'm'],
  ] as const;

  return parts
    .filter(([value]) => value > 0)
    .map(([value, suffix]) => `${value}${suffix}`)
    .join('');
}

/**
 * Formats an ISO timestamp or Date as a compact relative update label ("Updated 1d2h5m ago"
 * or "Updated just now" under one minute), omitting zero-valued units.
 */
export function formatRelativeUpdatedLabel(
  cachedAt?: string | Date | null,
  now: Date | number = Date.now()
): string | null {
  if (cachedAt === null || cachedAt === undefined) {
    return null;
  }

  let cachedMs: number;
  if (cachedAt instanceof Date) {
    cachedMs = cachedAt.getTime();
  } else {
    const trimmed = String(cachedAt).trim();
    if (!trimmed) {
      return null;
    }
    cachedMs = Date.parse(trimmed);
  }

  if (!Number.isFinite(cachedMs)) {
    return null;
  }

  const resolvedNowMs = now instanceof Date ? now.getTime() : now;
  const nowMs = Number.isFinite(resolvedNowMs) ? resolvedNowMs : Date.now();
  const diffMs = nowMs - cachedMs;

  if (diffMs < MILLISECONDS_PER_MINUTE) {
    return 'Updated just now';
  }

  const totalMinutes = Math.floor(diffMs / MILLISECONDS_PER_MINUTE);
  return `Updated ${formatCompactDurationFromMinutes(totalMinutes)} ago`;
}

/**
 * Formats an offline database mtime ISO timestamp with UTC date-time and compact relative age.
 */
export function formatOfflineDbTimestamp(
  lastModifiedIso?: string | null,
  now: Date | number = Date.now(),
  ageSeconds?: number | null
): string {
  if (!lastModifiedIso || typeof lastModifiedIso !== 'string') {
    return 'Not downloaded';
  }
  const parsedMs = Date.parse(lastModifiedIso.trim());
  if (Number.isNaN(parsedMs)) {
    return lastModifiedIso;
  }
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const computedAge =
    Number.isFinite(nowMs)
      ? Math.max(0, Math.floor((nowMs - parsedMs) / 1000))
      : (typeof ageSeconds === 'number' && Number.isFinite(ageSeconds) ? Math.max(0, Math.floor(ageSeconds)) : 0);

  const utcStamp = `${new Date(parsedMs).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  const totalMinutes = Math.floor(computedAge / 60);
  const relativeText = totalMinutes < 1 ? 'just now' : `${formatCompactDurationFromMinutes(totalMinutes)} ago`;
  return `${utcStamp} (${relativeText})`;
}

/**
 * Formats byte counts cleanly for local database file listings.
 */
export function formatByteSize(sizeBytes?: number | null): string {
  if (typeof sizeBytes !== 'number' || !Number.isFinite(sizeBytes) || sizeBytes < 0) {
    return '-';
  }
  if (sizeBytes < 1024) {
    return `${Math.round(sizeBytes)} B`;
  }
  if (sizeBytes < 1024 * 1024) {
    return `${(sizeBytes / 1024).toFixed(1)} KB`;
  }
  if (sizeBytes < 1024 * 1024 * 1024) {
    return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
  }
  return `${(sizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/**
 * Resolves the relative "Updated ... ago" label for a cached provider row, or returns null when uncached.
 */
export function resolveProviderUpdatedLabel(
  row?: Pick<Partial<ProviderRawResult>, 'isCached' | 'cachedAt'> | null,
  detectionData?: Partial<DetectionResponse> | null,
  now: Date | number = Date.now()
): string | null {
  if (!row || typeof row !== 'object') {
    return null;
  }
  const rowIsCached =
    row.isCached !== undefined ? Boolean(row.isCached) : Boolean(detectionData?.isCached);
  if (!rowIsCached) {
    return null;
  }
  const cachedAt =
    row.cachedAt ||
    detectionData?.cacheMeta?.cachedAt ||
    detectionData?.cacheMeta?.fetchedAt ||
    detectionData?.fetchedAt ||
    null;
  return formatRelativeUpdatedLabel(cachedAt, now);
}

const DEFAULT_STALE_THRESHOLD_SECONDS = 7_776_000;
const FRESH_RECHECK_THRESHOLD_SECONDS = 7 * 86_400;

/**
 * Formats an ISO timestamp or Date as an exact UTC string for cache badge tooltips.
 */
export function formatExactUtcTimestamp(timestamp?: string | Date | null): string | null {
  if (timestamp === null || timestamp === undefined) {
    return null;
  }
  const parsedMs = timestamp instanceof Date ? timestamp.getTime() : Date.parse(String(timestamp).trim());
  if (!Number.isFinite(parsedMs)) {
    return null;
  }
  const iso = new Date(parsedMs).toISOString();
  return `${iso.slice(0, 19).replace('T', ' ')} UTC`;
}

/**
 * Determines whether a detection payload represents stale cache data exceeding the 90-day threshold.
 */
export function isCacheStale(data?: Partial<DetectionResponse> | null): boolean {
  if (!data || !data.cacheMeta) {
    return false;
  }
  if (data.cacheMeta.isStale === true || data.cacheMeta.status === 'stale') {
    return true;
  }
  const ageSeconds = data.cacheMeta.ageSeconds;
  const threshold = data.cacheMeta.staleThresholdSeconds ?? DEFAULT_STALE_THRESHOLD_SECONDS;
  return typeof ageSeconds === 'number' && Number.isFinite(ageSeconds) && ageSeconds > threshold;
}

/**
 * Formats the executive overview cache age badge label from backend cache metadata and live clock time.
 */
export function formatCacheAgeBadgeLabel(
  data?: Partial<DetectionResponse> | null,
  now: Date | number = Date.now(),
  lastRefreshedAt?: string | null
): string | null {
  if (!data || data.isNonPublic || data.cacheMeta?.status === 'bypassed') {
    return null;
  }

  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const safeNowMs = Number.isFinite(nowMs) ? nowMs : Date.now();

  if (lastRefreshedAt && !data.cacheMeta?.degradedRefreshFallback) {
    const refreshedMs = Date.parse(lastRefreshedAt);
    if (Number.isFinite(refreshedMs)) {
      const sinceRefreshSec = Math.max(0, Math.floor((safeNowMs - refreshedMs) / 1000));
      if (sinceRefreshSec < 60) {
        return 'Just updated';
      }
    }
  }

  const meta = data.cacheMeta;
  const isCachedPayload =
    Boolean(data.isCached) ||
    meta?.status === 'hit' ||
    meta?.status === 'stale' ||
    meta?.status === 'partial';

  const rawTimestamp = meta?.fetchedAt || data.fetchedAt || meta?.cachedAt || null;
  const parsedMs = rawTimestamp ? Date.parse(String(rawTimestamp).trim()) : Number.NaN;
  const timestampAgeSec = Number.isFinite(parsedMs)
    ? Math.max(0, Math.floor((safeNowMs - parsedMs) / 1000))
    : null;
  const metaAgeSec =
    typeof meta?.ageSeconds === 'number' && Number.isFinite(meta.ageSeconds)
      ? Math.max(0, Math.floor(meta.ageSeconds))
      : null;

  if (!isCachedPayload) {
    const freshAge = timestampAgeSec ?? metaAgeSec ?? 0;
    if (freshAge < 60) {
      return 'Just updated';
    }
    if (freshAge < 3600) {
      return `Updated ${Math.floor(freshAge / 60)}m ago`;
    }
    if (freshAge < 86_400) {
      return `Updated ${Math.floor(freshAge / 3600)}h ago`;
    }
    return `Updated ${Math.floor(freshAge / 86_400)}d ago`;
  }

  const effectiveAgeSec = Math.max(timestampAgeSec ?? 0, metaAgeSec ?? 0);
  if (effectiveAgeSec < 60) {
    return 'Cached just now';
  }
  if (effectiveAgeSec < 3600) {
    return `Cached ${Math.floor(effectiveAgeSec / 60)}m ago`;
  }
  if (effectiveAgeSec < 86_400) {
    return `Cached ${Math.floor(effectiveAgeSec / 3600)}h ago`;
  }
  return `Cached ${Math.floor(effectiveAgeSec / 86_400)}d ago`;
}

export interface RefetchButtonState {
  visible: boolean;
  label: 'Refetch' | 'Updating...';
  disabled: boolean;
  isBusy: boolean;
}

/**
 * Resolves unified refetch button visibility, label, and disabled state across manual and background updates.
 */
export function resolveRefetchButtonState(params: {
  data?: Partial<DetectionResponse> | null;
  isRefreshing?: boolean;
  isLoading?: boolean;
}): RefetchButtonState {
  const { data, isRefreshing = false, isLoading = false } = params;
  const visible = Boolean(data && !data.isNonPublic && data.cacheMeta?.status !== 'bypassed');
  const isBusy = Boolean(isRefreshing || data?.cacheMeta?.refreshInProgress);
  return {
    visible,
    label: isBusy ? 'Updating...' : 'Refetch',
    disabled: Boolean(isBusy || isLoading),
    isBusy,
  };
}

export function filterComparisonResults(results: ProviderRawResult[] | undefined | null): ProviderRawResult[] {
  if (!Array.isArray(results)) return [];
  return results.filter((row) => row.provider !== 'GetIPIntel' && row.provider !== 'Tor Onionoo');
}

/**
 * Merges resolved provider rows with pending SSE placeholder rows in canonical provider order.
 */
export function buildComparisonRowsWithPending(
  results: ProviderRawResult[] | undefined | null,
  pendingProviders: string[] | undefined | null
): ProviderRawResult[] {
  const resolvedByName = new Map<string, ProviderRawResult>();
  for (const row of filterComparisonResults(results)) {
    resolvedByName.set(row.provider, row);
  }
  const pendingSet = new Set(
    (Array.isArray(pendingProviders) ? pendingProviders : []).filter(
      (name) => name !== 'GetIPIntel' && name !== 'Tor Onionoo'
    )
  );
  const ordered: ProviderRawResult[] = [];
  for (const providerName of PROVIDER_NAMES) {
    if (providerName === 'GetIPIntel' || providerName === 'Tor Onionoo') {
      continue;
    }
    const existing = resolvedByName.get(providerName);
    if (existing) {
      ordered.push(existing);
      continue;
    }
    if (pendingSet.has(providerName)) {
      ordered.push({
        provider: providerName,
        status: 'Querying...',
        statusCode: null,
        asn: '-',
        isp: '-',
        organisation: '-',
        location: '-',
        usageType: '-',
        securityFlags: [],
        isPending: true,
        rawJson: {},
      });
    }
  }
  return ordered;
}

export function simplifySecurityFlags(
  flags: { label: string; isHighRisk: boolean }[] | undefined
): { label: string; isHighRisk: boolean }[] {
  if (!flags || flags.length === 0) {
    return [{ label: 'No Flags', isHighRisk: false }];
  }

  const visibleFlags = flags.filter((f) => f.isHighRisk || f.label === 'Open Ports');
  if (visibleFlags.length > 0) {
    return visibleFlags;
  }

  return [{ label: 'No Flags', isHighRisk: false }];
}

export type ChipStatus = 'notice' | 'warning' | 'error' | 'success';

/**
 * Resolves the Codex info chip status for a simplified security flag.
 */
export function getSecurityFlagChipStatus(flag: { label: string; isHighRisk: boolean }): ChipStatus {
  if (flag.isHighRisk) {
    return 'error';
  }
  if (flag.label === 'Open Ports') {
    return 'warning';
  }
  return 'success';
}

export type ProviderDisplayRow = Omit<Partial<ProviderRawResult>, 'port'> & {
  port?: number | string | null;
  last_seen?: string | null;
};

/**
 * Builds secondary metadata items for a provider comparison row.
 */
export function getProviderMetaItems(
  row: ProviderDisplayRow | null | undefined,
  now: Date | number = Date.now(),
  formatDbTimestamp: (iso?: string | null, currentNow?: Date | number) => string = formatOfflineDbTimestamp
): string[] {
  if (!row || typeof row !== 'object') return [];
  const items: string[] = [];
  if (row.port !== undefined && row.port !== null && row.port !== '') {
    items.push(`Port: ${row.port}`);
  }
  if (Array.isArray(row.openProxyPorts) && row.openProxyPorts.length > 0) {
    items.push(`Proxy ports: ${row.openProxyPorts.join(', ')}`);
  } else if (Array.isArray(row.ports) && row.ports.length > 0) {
    const portPreview = row.ports.slice(0, 8).join(', ');
    items.push(`Open ports: ${row.ports.length > 8 ? `${portPreview}…` : portPreview}`);
  }
  if (Array.isArray(row.tags) && row.tags.length > 0) {
    items.push(`Tags: ${row.tags.join(', ')}`);
  }
  if (Array.isArray(row.hostnames) && row.hostnames.length > 0) {
    const hostPreview = row.hostnames.slice(0, 3).join(', ');
    items.push(`Hostnames: ${row.hostnames.length > 3 ? `${hostPreview}…` : hostPreview}`);
  }
  if (typeof row.ipsumScore === 'number' && row.ipsumScore > 0) {
    items.push(`IPsum lists: ${row.ipsumScore}`);
  }
  if (row.inSpamhausDrop) {
    const dropParts = [row.dropSblId, row.dropCidr].filter(
      (part): part is string => typeof part === 'string' && part.trim().length > 0
    );
    items.push(dropParts.length > 0 ? `Spamhaus DROP: ${dropParts.join(' · ')}` : 'Spamhaus DROP: Listed');
  }
  if (row.category) {
    const normalizedCategory =
      row.category === 'vpn'
        ? 'VPN'
        : row.category === 'datacenter'
          ? 'Datacentre'
          : row.category === 'hosting'
            ? 'Hosting'
            : row.category;
    items.push(`Category: ${normalizedCategory}`);
  }
  if (row.matchedCidr && !row.dropCidr) {
    items.push(`Prefix: ${row.matchedCidr}`);
  }
  if (Array.isArray(row.sources) && row.sources.length > 0) {
    items.push(`Sources: ${row.sources.join(', ')}`);
  }
  if (row.provider === 'StopForumSpam' || row.frequency !== undefined || row.confidence !== undefined) {
    if (row.frequency !== undefined && row.frequency !== null) {
      items.push(`Frequency: ${row.frequency}`);
    }
    if (row.confidence !== undefined && row.confidence !== null) {
      items.push(`Confidence: ${row.confidence}%`);
    }
  }
  if (row.provider === 'DShield' || row.attacks !== undefined || row.count !== undefined) {
    if (row.attacks !== undefined && row.attacks !== null) {
      items.push(`Attacks: ${row.attacks}`);
    }
    if (row.count !== undefined && row.count !== null) {
      items.push(`Targets: ${row.count}`);
    }
    if (Array.isArray(row.threatfeeds) && row.threatfeeds.length > 0) {
      items.push(`Feeds: ${row.threatfeeds.join(', ')}`);
    }
  }
  if (row.carrier) {
    items.push(`Carrier: ${row.carrier}`);
  }
  if (row.mobileBrand) {
    items.push(`Mobile brand: ${row.mobileBrand}`);
  }
  if (row.coreVerdict) {
    items.push(`Core verdict: ${row.coreVerdict}`);
  }
  if (Array.isArray(row.coreSources) && row.coreSources.length > 0) {
    items.push(`Core sources: ${row.coreSources.join(', ')}`);
  }
  if (row.networkRole) {
    items.push(`Network role: ${row.networkRole}`);
  }
  const rowSharedProvider = row.sharedProvider || row.cloudProvider;
  if (rowSharedProvider) {
    items.push(
      row.sharedCategory
        ? `Shared egress: ${rowSharedProvider} (${row.sharedCategory})`
        : `Shared egress: ${rowSharedProvider}`
    );
  }
  if (row.provider === 'AbuseIPDB' || row.totalReports !== undefined || row.numDistinctUsers !== undefined) {
    if (row.totalReports !== undefined && row.totalReports !== null) {
      items.push(`Reports: ${row.totalReports}`);
    }
    if (row.numDistinctUsers !== undefined && row.numDistinctUsers !== null) {
      items.push(`Distinct users: ${row.numDistinctUsers}`);
    }
  }
  const lastSeenValue = row.lastSeen || row.last_seen || row.maxDate;
  if (lastSeenValue) {
    items.push(`Last seen: ${lastSeenValue}`);
  }
  if (row.offlineDbUpdatedAt) {
    items.push(`Offline DB: ${formatDbTimestamp(row.offlineDbUpdatedAt, now)}`);
  }
  if (row.isHistoricalFallback) {
    items.push('Historical L2 fallback');
  }
  return items;
}

/**
 * Maps a provider HTTP or circuit-breaker status string to a Codex info chip status.
 */
export function getStatusChipStatus(status?: string | null): ChipStatus {
  if (!status) return 'notice';
  if (status === '200 OK') return 'success';
  if (
    status === 'Querying...' ||
    status === 'No API Key' ||
    status === 'Database Missing' ||
    status === 'Offline DB Missing' ||
    status === 'Skipped (IPv6)' ||
    status === 'Deferred (Light Mode)'
  ) {
    return 'notice';
  }
  if (status.includes('429') || status.includes('Cooldown') || status.includes('Quota Guard')) {
    return 'warning';
  }
  return 'error';
}

/**
 * Resolves the executive Prediction gauge ring tier class from backend tier or fallback score.
 */
export function getPredictionScoreTierClass(
  data: Partial<DetectionResponse> | null | undefined
): string {
  if (!data) return 'score-tier-low';
  if (data.predictionTier === 'destructive') return 'score-tier-high';
  if (data.predictionTier === 'warning') return 'score-tier-moderate';
  if (data.predictionTier === 'success') return 'score-tier-low';
  const score = Number(data.prediction_score ?? 0);
  if (score >= 70) return 'score-tier-high';
  if (score >= 30) return 'score-tier-moderate';
  return 'score-tier-low';
}

/**
 * Resolves the multi-source arbitration info chip status from consensus tier or verdict text.
 */
export function getArbitrationChipStatus(
  data: Partial<DetectionResponse> | null | undefined
): ChipStatus {
  if (!data) return 'notice';
  if (data.arbitrationTier === 'destructive' || data.isMajorityProxyVpn) {
    return 'error';
  }
  if (data.arbitrationTier === 'warning' || String(data.arbitrationVerdict || '').startsWith('Disputed')) {
    return 'warning';
  }
  if (data.arbitrationTier === 'neutral') {
    return 'notice';
  }
  return 'success';
}

/**
 * Resolves the reverse DNS classification info chip status.
 */
export function getPtrChipStatus(data: Partial<DetectionResponse> | null | undefined): ChipStatus {
  if (!data || !data.ptrCategory) return 'notice';
  if (data.ptrCategory === 'hosting_or_gateway' || data.ptrIsHighRisk) {
    return 'error';
  }
  if (data.ptrCategory === 'mobile_or_cgnat') {
    return 'warning';
  }
  if (data.ptrCategory === 'dynamic_residential') {
    return 'success';
  }
  return 'notice';
}

export interface SharedPrivacyEgressInfo {
  kind: SharedPrivacyEgress;
  label: string;
  pillText: string;
  guidance: string;
}

/**
 * Resolves human-readable badge copy and guidance for shared client privacy relays.
 */
export function getSharedPrivacyEgressInfo(egress?: string | null): SharedPrivacyEgressInfo | null {
  if (egress === 'icloud_private_relay') {
    return {
      kind: 'icloud_private_relay',
      label: 'Apple iCloud Private Relay',
      pillText: 'Apple iCloud Private Relay · Shared egress',
      guidance: 'Shared Apple iCloud Private Relay client egress. Many unrelated users may share this address.',
    };
  }
  if (egress === 'cloudflare_warp') {
    return {
      kind: 'cloudflare_warp',
      label: 'Cloudflare WARP',
      pillText: 'Cloudflare WARP Egress · Shared egress',
      guidance: 'Shared Cloudflare WARP client egress. Many unrelated users may share this address.',
    };
  }
  return null;
}

/**
 * Returns true when either CIDR attribution or reverse DNS indicates mobile cellular or CGNAT sharing.
 */
export function isMobileOrCgnatDetection(data?: Partial<DetectionResponse> | null): boolean {
  if (!data) {
    return false;
  }
  return data.isMobileOrCgnat === true || data.ptrCategory === 'mobile_or_cgnat';
}

/**
 * Extracts deduplicated open proxy ports from top-level fields or the Shodan InternetDB row.
 */
export function extractOpenProxyPorts(data?: Partial<DetectionResponse> | null): number[] {
  if (!data) {
    return [];
  }
  const collected = new Set<number>();
  if (Array.isArray(data.openProxyPorts)) {
    for (const port of data.openProxyPorts) {
      if (typeof port === 'number' && Number.isInteger(port) && port > 0) {
        collected.add(port);
      }
    }
  }
  if (Array.isArray(data.results)) {
    for (const row of data.results) {
      if (row?.provider === 'Shodan InternetDB' && Array.isArray(row.openProxyPorts)) {
        for (const port of row.openProxyPorts) {
          if (typeof port === 'number' && Number.isInteger(port) && port > 0) {
            collected.add(port);
          }
        }
      }
    }
  }
  return [...collected].sort((a, b) => a - b);
}

/**
 * Extracts Shodan InternetDB tags from the comparison rows when available.
 */
export function extractShodanTags(data?: Partial<DetectionResponse> | null): string[] {
  if (!data || !Array.isArray(data.results)) {
    return [];
  }
  const shodanRow = data.results.find((row) => row?.provider === 'Shodan InternetDB');
  if (!shodanRow || !Array.isArray(shodanRow.tags)) {
    return [];
  }
  return shodanRow.tags.filter((tag): tag is string => typeof tag === 'string' && tag.trim().length > 0);
}

/**
 * Determines whether a cached residential proxy detection is older than seven days and warrants a fresh recheck.
 */
export function shouldRecommendFreshRecheck(data?: Partial<DetectionResponse> | null): boolean {
  if (!data) {
    return false;
  }
  if (data.cacheMeta?.recommendFreshRecheck === true) {
    return true;
  }
  if (data.suspectedResidentialProxy !== true) {
    return false;
  }
  const ageSeconds = data.cacheMeta?.ageSeconds ?? 0;
  return ageSeconds > FRESH_RECHECK_THRESHOLD_SECONDS;
}

/**
 * Returns the `SHARED/<provider>` badge text, falling back to the legacy cached cloud provider.
 */
export function formatSharedProviderBadge(data?: Partial<DetectionResponse> | null): string | null {
  if (!data) {
    return null;
  }
  for (const candidate of [data.sharedProvider, data.cloudProvider]) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return `SHARED/${candidate.trim()}`;
    }
  }
  return null;
}

function normaliseSafeIpWithoutZone(rawIp?: string | null): string | null {
  const canonical = rawIp ? canonicalizeIpAddress(rawIp) : null;
  if (!canonical) {
    return null;
  }
  return canonical.split('%')[0] || null;
}

function parseSafeCidr(rawTarget?: string | null): { addr: string; prefix: number; maxPrefix: number } | null {
  const trimmed = String(rawTarget || '').trim();
  if (!trimmed.includes('/')) {
    return null;
  }
  const [addrPart, prefixPart, ...extra] = trimmed.split('/');
  if (extra.length !== 0 || !/^\d{1,3}$/.test(prefixPart || '')) {
    return null;
  }
  const safeAddr = normaliseSafeIpWithoutZone(addrPart);
  if (!safeAddr) {
    return null;
  }
  const prefix = Number(prefixPart);
  const maxPrefix = safeAddr.includes(':') ? 128 : 32;
  if (prefix < 1 || prefix > maxPrefix) {
    return null;
  }
  return { addr: safeAddr, prefix, maxPrefix };
}

function normaliseSafeCidrOrIp(rawTarget?: string | null, fallbackIp?: string | null): string | null {
  const parsed = parseSafeCidr(rawTarget);
  if (parsed) {
    return `${parsed.addr}/${parsed.prefix}`;
  }
  const trimmed = String(rawTarget || '').trim();
  return normaliseSafeIpWithoutZone(trimmed) ?? normaliseSafeIpWithoutZone(fallbackIp);
}

function normaliseSafeRangeCidr(rawTarget?: string | null): string | null {
  const parsed = parseSafeCidr(rawTarget);
  if (!parsed || parsed.prefix >= parsed.maxPrefix) {
    return null;
  }
  return `${parsed.addr}/${parsed.prefix}`;
}

function normaliseWikiBaseUrl(wikiBaseUrl?: string | null): string {
  const trimmed = String(wikiBaseUrl || '').trim().replace(/\/+$/, '');
  if (/^https?:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(trimmed)) {
    return trimmed;
  }
  return 'https://meta.wikimedia.org';
}

function buildSpecialBlockTargetUrl(target: string, base: string): string {
  const encodedPathTarget = target
    .split('/')
    .map((segment) => encodeURIComponent(segment).replaceAll('%3A', ':'))
    .join('/');
  return `${base}/wiki/Special:Block/${encodedPathTarget}?wpHardBlock=1`;
}

/**
 * Builds a MediaWiki Special:Block URL for the recommended CIDR, always pre-filling a hard block.
 */
export function buildSpecialBlockUrl(
  data?: Partial<DetectionResponse> | null,
  wikiBaseUrl = 'https://meta.wikimedia.org'
): string | null {
  if (!data) {
    return null;
  }
  const target = normaliseSafeCidrOrIp(data.recommendedCidr, data.ip);
  if (!target) {
    return null;
  }
  return buildSpecialBlockTargetUrl(target, normaliseWikiBaseUrl(wikiBaseUrl));
}

export interface VerificationLinks {
  globalContributionsUrl: string;
  rangeblockFinderUrl: string;
  whoisGatewayUrl: string;
  specialBlockUrl: string;
  singleIpBlockUrl: string;
  rangeBlockUrl: string | null;
}

/**
 * Builds external verification deep links for anti-vandalism and checkuser workflows.
 */
export function buildVerificationLinks(
  data?: Partial<DetectionResponse> | null,
  wikiBaseUrl = 'https://meta.wikimedia.org'
): VerificationLinks | null {
  const safeIp = normaliseSafeIpWithoutZone(data?.ip);
  if (!data || !safeIp) {
    return null;
  }
  const base = normaliseWikiBaseUrl(wikiBaseUrl);
  const pathSafeIp = encodeURIComponent(safeIp).replaceAll('%3A', ':');
  const querySafeIp = encodeURIComponent(safeIp);
  const singleIpBlockUrl = buildSpecialBlockTargetUrl(safeIp, base);
  const rangeCidr = normaliseSafeRangeCidr(data.recommendedCidr);
  const rangeBlockUrl = rangeCidr ? buildSpecialBlockTargetUrl(rangeCidr, base) : null;
  const specialBlockUrl = buildSpecialBlockUrl(data, base) ?? singleIpBlockUrl;

  return {
    globalContributionsUrl: `${base}/wiki/Special:GlobalContributions/${pathSafeIp}`,
    rangeblockFinderUrl: `/?ip=${querySafeIp}&tab=rb`,
    whoisGatewayUrl: `https://whois.toolforge.org/gateway.py?lookup=true&ip=${querySafeIp}`,
    specialBlockUrl,
    singleIpBlockUrl,
    rangeBlockUrl,
  };
}

function ipv4ToBigInt(ip: string): bigint {
  const parts = ip.split('.').map((part) => BigInt(Number(part)));
  return (parts[0]! << 24n) | (parts[1]! << 16n) | (parts[2]! << 8n) | parts[3]!;
}

function bigIntToIpv4(val: bigint): string {
  return [
    Number((val >> 24n) & 0xffn),
    Number((val >> 16n) & 0xffn),
    Number((val >> 8n) & 0xffn),
    Number(val & 0xffn),
  ].join('.');
}

function ipv6ToBigInt(canonicalIp: string): bigint {
  const halves = canonicalIp.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  const groups = [
    ...left,
    ...Array.from({ length: Math.max(0, missing) }, () => '0'),
    ...right,
  ];
  let acc = 0n;
  for (const g of groups) {
    acc = (acc << 16n) | BigInt(parseInt(g || '0', 16));
  }
  return acc;
}

function bigIntToIpv6(val: bigint): string {
  const groups: string[] = [];
  for (let i = 7; i >= 0; i -= 1) {
    const shift = BigInt(i * 16);
    groups.push(((val >> shift) & 0xffffn).toString(16));
  }
  return canonicalizeIpAddress(groups.join(':')) ?? groups.join(':');
}

function buildRangeblockLinkPair(
  wikiDbname: string,
  domain: string,
  target: string
): { logUrl: string; blockListUrl: string } {
  const encoded = encodeURIComponent(target).replaceAll('%2F', '/').replaceAll('%3A', ':');
  if (wikiDbname === 'global') {
    return {
      logUrl: `https://meta.wikimedia.org/wiki/Special:Log?type=gblblock&page=User:${encoded}`,
      blockListUrl: `https://meta.wikimedia.org/wiki/Special:GlobalBlockList?ip=${encoded}`,
    };
  }
  return {
    logUrl: `https://${domain}/wiki/Special:Log?type=block&page=User:${encoded}`,
    blockListUrl: `https://${domain}/wiki/Special:BlockList?wpTarget=${encoded}`,
  };
}

/**
 * Expands the full IPv4 (single IP plus /32 to /16) or IPv6 (single IP plus /64 to /19)
 * rangeblock ladder for a selected wiki, merging in any hit counts and active flags.
 */
export function buildFullCidrLadder(
  rawIp: string,
  wikiSummary: RangeblockWikiSummary
): RangeblockHitRow[] {
  const canonical = canonicalizeIpAddress(rawIp)?.split('%')[0] ?? '';
  if (!canonical) {
    return wikiSummary.rows;
  }
  const hitByTarget = new Map<string, RangeblockHitRow>();
  for (const row of wikiSummary.rows) {
    hitByTarget.set(row.target, row);
  }

  const isV6 = canonical.includes(':');
  const maxBits = isV6 ? 128n : 32n;
  const addrInt = isV6 ? ipv6ToBigInt(canonical) : ipv4ToBigInt(canonical);
  const allMask = (1n << maxBits) - 1n;
  const prefixes = isV6
    ? Array.from({ length: 46 }, (_, i) => 64 - i)
    : Array.from({ length: 17 }, (_, i) => 32 - i);

  const makeRow = (target: string, cidr: number | null, upperBound: string): RangeblockHitRow => {
    const hit = hitByTarget.get(target);
    if (hit) {
      return hit;
    }
    const links = buildRangeblockLinkPair(wikiSummary.wiki, wikiSummary.domain, target);
    return {
      target,
      cidr,
      upperBound,
      count: 0,
      isActive: false,
      expiry: null,
      indefinite: false,
      lastBlockedAt: null,
      logUrl: links.logUrl,
      blockListUrl: links.blockListUrl,
    };
  };

  const rows: RangeblockHitRow[] = [makeRow(canonical, null, canonical)];
  for (const prefix of prefixes) {
    const hostBits = maxBits - BigInt(prefix);
    const netMask = (allMask << hostBits) & allMask;
    const netStart = addrInt & netMask;
    const netEnd = netStart | ((1n << hostBits) - 1n);
    const startStr = isV6 ? bigIntToIpv6(netStart) : bigIntToIpv4(netStart);
    const endStr = isV6 ? bigIntToIpv6(netEnd) : bigIntToIpv4(netEnd);
    rows.push(makeRow(`${startStr}/${prefix}`, prefix, endStr));
  }
  return rows;
}

function resolvePrimaryIspLabel(data: Partial<DetectionResponse>): string {
  const preferredProviders: ReadonlySet<string> = new Set([
    'Cloudflare Radar',
    'MaxMind',
    'DShield',
  ]);
  const rows = Array.isArray(data.results) ? data.results : [];
  for (const preferred of [true, false]) {
    for (const row of rows) {
      if (!row || row.status !== '200 OK') {
        continue;
      }
      if (preferred && !preferredProviders.has(row.provider)) {
        continue;
      }
      const candidate = String(row.isp || row.organisation || '').trim();
      if (candidate && candidate !== '-') {
        return candidate;
      }
    }
  }
  for (const candidate of [data.sharedProvider, data.cloudProvider]) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return candidate.trim();
    }
  }
  return 'Unknown ISP';
}

function resolveFetchedUtcDateString(
  data: Partial<DetectionResponse>,
  now: Date | number = Date.now()
): string {
  const rawFetched = data.fetchedAt || data.cacheMeta?.fetchedAt || data.cacheMeta?.cachedAt || null;
  const parsedMs = rawFetched ? Date.parse(String(rawFetched).trim()) : Number.NaN;
  const fallbackMs = now instanceof Date ? now.getTime() : Number(now);
  const effectiveMs = Number.isFinite(parsedMs)
    ? parsedMs
    : Number.isFinite(fallbackMs)
      ? fallbackMs
      : Date.now();
  return new Date(effectiveMs).toISOString().slice(0, 10);
}

/**
 * Builds a desensitised Wikitext evidence summary omitting proprietary vendor scores and raw payloads.
 */
export function buildWikitextSummary(
  data?: Partial<DetectionResponse> | null,
  now: Date | number = Date.now()
): string {
  if (!data) {
    return '';
  }
  const safeIp = normaliseSafeIpWithoutZone(data.ip) ?? String(data.ip || '').trim();
  if (!safeIp) {
    return '';
  }
  const safeCidr = normaliseSafeCidrOrIp(data.recommendedCidr, safeIp);
  const safeEscalation = data.escalationCidr
    ? normaliseSafeCidrOrIp(data.escalationCidr, safeIp)
    : null;
  const asnText =
    typeof data.primaryAsn === 'string' && data.primaryAsn.trim() && data.primaryAsn.trim() !== '-'
      ? data.primaryAsn.trim()
      : 'Unknown ASN';
  const ispText = resolvePrimaryIspLabel(data);
  const verdictText = String(data.arbitrationVerdict || 'Direct Connection (No Commercial Threats)').trim();

  const publicClassifications: string[] = [];
  if (data.isTor) {
    publicClassifications.push(data.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node'));
  }
  const privacyInfo = getSharedPrivacyEgressInfo(data.sharedPrivacyEgress);
  if (privacyInfo) {
    publicClassifications.push(privacyInfo.label);
  }
  const sharedProviderName = formatSharedProviderBadge(data)?.slice('SHARED/'.length);
  if (sharedProviderName) {
    publicClassifications.push(
      data.sharedCategory
        ? `Shared egress: ${sharedProviderName} (${data.sharedCategory})`
        : `Shared egress: ${sharedProviderName}`
    );
  }
  if (isMobileOrCgnatDetection(data)) {
    publicClassifications.push('Mobile cellular or CGNAT shared gateway');
  }
  if (data.suspectedResidentialProxy) {
    publicClassifications.push('Suspected Residential Proxy or Compromised Host');
  }
  const openPorts = extractOpenProxyPorts(data);
  if (openPorts.length > 0) {
    publicClassifications.push(`Open proxy ports: ${openPorts.join(', ')}`);
  }
  if (Array.isArray(data.results)) {
    const dropRow = data.results.find((row) => row?.provider === 'IPsum / DROP' && row.inSpamhausDrop);
    if (dropRow) {
      publicClassifications.push(
        dropRow.dropSblId ? `Spamhaus DROP (${dropRow.dropSblId})` : 'Spamhaus DROP'
      );
    }
  }

  const cidrSegment =
    safeCidr && safeCidr !== safeIp
      ? ` (recommended CIDR: <code>${safeCidr}</code>${safeEscalation ? `, escalation: <code>${safeEscalation}</code>` : ''})`
      : safeCidr
        ? ` (recommended CIDR: <code>${safeCidr}</code>)`
        : '';

  const parts = [
    `* '''IP''': <code>${safeIp}</code>${cidrSegment}`,
    `'''ASN''': <code>${asnText}</code> (${ispText})`,
    `'''Verdict''': ${verdictText}`,
  ];
  if (publicClassifications.length > 0) {
    parts.push(`'''Signals''': ${publicClassifications.join('; ')}`);
  }
  const fetchedDate = resolveFetchedUtcDateString(data, now);
  parts.push(`''(fetched ${fetchedDate} UTC)''`);

  return parts.join(' · ');
}

/**
 * Formats a numeric probability percentage to at most three decimal places.
 */
export function formatChance(score?: number | string | null): number {
  const num = Number(score ?? 0);
  if (Number.isNaN(num)) return 0;
  return Number(num.toFixed(3));
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

/**
 * Normalises backend diagnostic fields into non-negative duration and two-decimal megabyte values.
 */
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

  return {
    duration,
    memory,
    isCached: Boolean(payload?.isCached),
  };
}

/**
 * Formats execution duration and optional worker RSS memory usage into footer text.
 */
export function formatDiagnosticSummary(diagnostic?: DiagnosticMetrics | null): string {
  const rawDuration = diagnostic?.duration;
  const duration =
    typeof rawDuration === 'number' && Number.isFinite(rawDuration) && rawDuration >= 0
      ? rawDuration
      : 0;
  const parts = [`Executed in ${duration.toFixed(3)} seconds`];

  const rawMemory = diagnostic?.memory;
  if (typeof rawMemory === 'number' && Number.isFinite(rawMemory) && rawMemory >= 0) {
    parts.push(`Worker RSS ${rawMemory.toFixed(2)} MB`);
  }

  return parts.join(' \u00b7 ');
}

/**
 * Measures initial document load time in seconds from browser navigation timing when available.
 */
export function measureInitialLoadDurationSeconds(): number {
  if (typeof performance === 'undefined' || typeof performance.getEntriesByType !== 'function') {
    return 0;
  }
  try {
    const entries = performance.getEntriesByType('navigation');
    const navEntry = entries[0] as PerformanceNavigationTiming | undefined;
    if (
      navEntry &&
      typeof navEntry.responseEnd === 'number' &&
      Number.isFinite(navEntry.responseEnd) &&
      navEntry.responseEnd > 0
    ) {
      const start =
        typeof navEntry.startTime === 'number' && Number.isFinite(navEntry.startTime)
          ? navEntry.startTime
          : 0;
      const seconds = (navEntry.responseEnd - start) / 1000;
      if (Number.isFinite(seconds) && seconds >= 0) {
        return Number(seconds.toFixed(3));
      }
    }
  } catch {
    return 0;
  }
  return 0;
}

/**
 * Computes elapsed seconds since a performance.now() timestamp, returning 0 when unavailable.
 */
export function measureElapsedSeconds(startTimeMs: number): number {
  if (typeof performance === 'undefined' || typeof performance.now !== 'function' || !Number.isFinite(startTimeMs)) {
    return 0;
  }
  const elapsedMs = performance.now() - startTimeMs;
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) {
    return 0;
  }
  return Number((elapsedMs / 1000).toFixed(3));
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

export interface ProviderDashboardTelemetry {
  ok: number;
  cacheHit: number;
  rateLimited429: number;
  error5xx: number;
  timeout: number;
  quotaBlocked: number;
}

export interface ProviderDashboardRow {
  key: string;
  name: string;
  usesHttp: boolean;
  configured: boolean;
  status: string;
  statusKey: 'healthy' | 'quota_guarded' | 'cooldown' | 'no_api_key' | 'db_missing';
  cooldownTtlSeconds: number;
  cooldownReason?: string | null;
  minuteUsed: number;
  minuteLimit: number;
  dailyUsed: number;
  dailyLimit: number;
  upstreamRemaining: number | null;
  upstreamLimit: number | null;
  upstreamUsed: number | null;
  lastStatusAt: string | null;
  telemetry: ProviderDashboardTelemetry;
}

export interface ProviderDashboardCacheTelemetry {
  l1Hit: number;
  l2HitFresh: number;
  l2HitStaleSwr: number;
  upstreamMiss: number;
  refreshOk: number;
  refreshRateLimited: number;
  dualLayerHitRatePercent: number;
  l2EstimatedRows: number | null;
}

export interface ProviderDashboardGlobalMetrics {
  totalRequestsToday: number;
  authSession: number;
  authGadget: number;
  cacheHit: number;
  cachePartial: number;
  cacheMiss: number;
  fullCacheHitRatePercent: number;
  l1Hit?: number;
  l2HitFresh?: number;
  l2HitStaleSwr?: number;
  upstreamMiss?: number;
  refreshOk?: number;
  refreshRateLimited?: number;
  dualLayerHitRatePercent?: number;
  l2EstimatedRows?: number | null;
  totalQuotaBlocksToday: number;
  activeCooldownCount: number;
  activeQuotaGuardCount: number;
}

export interface ProviderDashboardResponse {
  generatedAt: string;
  dateBucket: string;
  redisAvailable: boolean;
  cacheTelemetry?: Partial<ProviderDashboardCacheTelemetry>;
  global: ProviderDashboardGlobalMetrics;
  providers: ProviderDashboardRow[];
  offlineDatabases?: OfflineDatabaseEntry[];
  durationSeconds?: number;
  memoryMb?: number | null;
}

function normaliseNonNegativeMetric(value: unknown): number {
  const num = Number(value ?? 0);
  return Number.isFinite(num) && num >= 0 ? num : 0;
}

/**
 * Normalises dual-layer cache and SWR telemetry counters from either cacheTelemetry or global fields.
 */
export function resolveDashboardCacheTelemetry(
  snapshot?: Partial<ProviderDashboardResponse> | null
): ProviderDashboardCacheTelemetry {
  const ct = snapshot?.cacheTelemetry;
  const globalMetrics = snapshot?.global;
  const rawEstimatedRows =
    ct?.l2EstimatedRows !== undefined ? ct.l2EstimatedRows : globalMetrics?.l2EstimatedRows;
  const l2EstimatedRows =
    typeof rawEstimatedRows === 'number' && Number.isFinite(rawEstimatedRows) && rawEstimatedRows >= 0
      ? Math.floor(rawEstimatedRows)
      : null;

  return {
    l1Hit: normaliseNonNegativeMetric(ct?.l1Hit ?? globalMetrics?.l1Hit),
    l2HitFresh: normaliseNonNegativeMetric(ct?.l2HitFresh ?? globalMetrics?.l2HitFresh),
    l2HitStaleSwr: normaliseNonNegativeMetric(ct?.l2HitStaleSwr ?? globalMetrics?.l2HitStaleSwr),
    upstreamMiss: normaliseNonNegativeMetric(ct?.upstreamMiss ?? globalMetrics?.upstreamMiss),
    refreshOk: normaliseNonNegativeMetric(ct?.refreshOk ?? globalMetrics?.refreshOk),
    refreshRateLimited: normaliseNonNegativeMetric(
      ct?.refreshRateLimited ?? globalMetrics?.refreshRateLimited
    ),
    dualLayerHitRatePercent: normaliseNonNegativeMetric(
      ct?.dualLayerHitRatePercent ?? globalMetrics?.dualLayerHitRatePercent
    ),
    l2EstimatedRows,
  };
}

/**
 * Returns true only when the backend verified the active session against ALLOWED_WIKI_USERS.
 */
export function isAuthorisedAdminUser(user?: Partial<UserSessionState> | null): boolean {
  if (!user || !user.isLoggedIn || !user.hasAccess) {
    return false;
  }
  return user.isAdmin === true;
}

/**
 * Computes clamped quota utilisation percentage for visual progress bars.
 */
export function computeQuotaUsagePercent(used: number, limit: number): number {
  if (!Number.isFinite(used) || !Number.isFinite(limit) || limit <= 0 || used <= 0) {
    return 0;
  }
  return Math.min(100, Math.round((used / limit) * 100));
}

/**
 * Determines the visual severity tone for a quota progress bar.
 */
export function getQuotaProgressTone(used: number, limit: number): 'normal' | 'warning' | 'danger' {
  if (!Number.isFinite(limit) || limit <= 0) {
    return 'normal';
  }
  const ratio = used / limit;
  if (ratio >= 1) {
    return 'danger';
  }
  if (ratio >= 0.8) {
    return 'warning';
  }
  return 'normal';
}

/**
 * Formats upstream-reported remaining quota or IPData usage counts for table display.
 */
export function formatUpstreamQuotaLabel(row: Pick<ProviderDashboardRow, 'upstreamRemaining' | 'upstreamLimit' | 'upstreamUsed'>): string {
  if (row.upstreamRemaining !== null && row.upstreamRemaining !== undefined) {
    if (row.upstreamLimit !== null && row.upstreamLimit !== undefined && row.upstreamLimit > 0) {
      return `${row.upstreamRemaining.toLocaleString('en-GB')} / ${row.upstreamLimit.toLocaleString('en-GB')} left`;
    }
    return `${row.upstreamRemaining.toLocaleString('en-GB')} left`;
  }
  if (row.upstreamUsed !== null && row.upstreamUsed !== undefined) {
    return `${row.upstreamUsed.toLocaleString('en-GB')} used`;
  }
  return '-';
}

export interface DetectionCoordinatorState {
  isLoading: boolean;
  isStreaming?: boolean;
  isRefreshing?: boolean;
  validationError: string;
  sessionExpiredMessage: string;
  refreshWarningMessage?: string;
  lastRefreshedAt?: string | null;
  detectionData: any | null;
  diagnostic: DiagnosticMetrics | null;
  user: UserSessionState;
  ipHistory: string[];
}

export interface DetectionCoordinatorOptions {
  state?: DetectionCoordinatorState;
  onHistoryUpdated?: (history: string[]) => void;
  onDetectionSuccess?: (canonicalIp: string, data: any) => void;
}

export function readCsrfTokenFromDocumentCookie(): string {
  if (typeof document === 'undefined' || typeof document.cookie !== 'string' || !document.cookie) {
    return '';
  }
  const entries = document.cookie.split(';');
  for (const entry of entries) {
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

function clearTransientCacheRefreshFlags(data: any): void {
  if (data && typeof data === 'object' && data.cacheMeta && typeof data.cacheMeta === 'object') {
    data.cacheMeta = {
      ...data.cacheMeta,
      shouldAutoRefresh: false,
      refreshInProgress: false,
    };
  }
}

/**
 * Coordinates IP detection and tiered 90-day SWR refresh requests with monotonic epochs and
 * AbortController cancellation so stale background responses never overwrite newer queries.
 */
export function createDetectionCoordinator(
  fetchImpl: (url: string, init?: RequestInit) => Promise<{
    ok: boolean;
    status: number;
    headers?: { get?: (name: string) => string | null } | null;
    body?: ReadableStream<Uint8Array> | null;
    json: () => Promise<any>;
  }>,
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

  if (state.isStreaming === undefined) {
    state.isStreaming = false;
  }

  if (state.isRefreshing === undefined) {
    state.isRefreshing = false;
  }
  if (state.refreshWarningMessage === undefined) {
    state.refreshWarningMessage = '';
  }
  if (state.lastRefreshedAt === undefined) {
    state.lastRefreshedAt = null;
  }

  let latestRequestId = 0;
  let latestRefreshId = 0;
  let activeAbortController: AbortController | null = null;
  let activeRefreshAbortController: AbortController | null = null;
  let activeRefreshPromise: Promise<void> | null = null;

  function abortActiveRefresh(): void {
    latestRefreshId += 1;
    if (activeRefreshAbortController) {
      activeRefreshAbortController.abort();
      activeRefreshAbortController = null;
    }
    activeRefreshPromise = null;
    state.isRefreshing = false;
  }

  function cancelPending(): void {
    latestRequestId += 1;
    if (activeAbortController) {
      activeAbortController.abort();
      activeAbortController = null;
    }
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

  function startRefreshForCanonicalIp(canonicalIp: string, boundRequestId: number): Promise<void> {
    if (state.isRefreshing && activeRefreshPromise) {
      return activeRefreshPromise;
    }

    const refreshId = ++latestRefreshId;
    if (activeRefreshAbortController) {
      activeRefreshAbortController.abort();
    }
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    activeRefreshAbortController = controller;

    state.isRefreshing = true;
    state.refreshWarningMessage = '';

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
    const csrfToken = readCsrfTokenFromDocumentCookie();
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }

    const refreshInit: RequestInit = {
      method: 'POST',
      credentials: 'same-origin',
      headers,
      body: JSON.stringify({
        ip: canonicalIp,
        mode: 'full',
        compact: false,
      }),
      ...(controller ? { signal: controller.signal } : {}),
    };

    const task = (async () => {
      try {
        const response = await fetchImpl('/api/v1/detect/refresh', refreshInit);
        if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) {
          return;
        }

        if (response.status === 401) {
          handleSessionExpired();
          return;
        }

        if (response.status === 429) {
          const rateData = await response.json().catch(() => ({}));
          if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) {
            return;
          }
          clearTransientCacheRefreshFlags(state.detectionData);
          const retryHint =
            typeof rateData?.retryAfterSeconds === 'number' && rateData.retryAfterSeconds > 0
              ? ` Please wait ${rateData.retryAfterSeconds}s before retrying.`
              : '';
          state.refreshWarningMessage =
            `Refresh rate limit is temporarily constrained; valid historical intelligence is preserved.${retryHint}`;
          return;
        }

        if (!response.ok) {
          const errData = await response.json().catch(() => ({}));
          if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) {
            return;
          }
          clearTransientCacheRefreshFlags(state.detectionData);
          if (state.detectionData) {
            state.refreshWarningMessage =
              'Upstream providers are temporarily constrained; valid historical intelligence is preserved.';
            return;
          }
          throw new Error(errData.message || errData.error || `Server returned HTTP ${response.status}`);
        }

        const data = await response.json();
        if (boundRequestId !== latestRequestId || refreshId !== latestRefreshId) {
          return;
        }

        if (data?.cacheMeta?.degradedRefreshFallback === true) {
          const hasPreservedRows = Array.isArray(data?.results) && data.results.length > 0;
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
        if (!data?.cacheMeta?.refreshInProgress) {
          state.lastRefreshedAt =
            data?.fetchedAt || data?.cacheMeta?.fetchedAt || new Date().toISOString();
        }
        const resolvedIp = canonicalizeIpAddress(data?.ip || canonicalIp) ?? canonicalIp;
        state.ipHistory = updateIpHistory(state.ipHistory, resolvedIp);
        options?.onHistoryUpdated?.(state.ipHistory);
        options?.onDetectionSuccess?.(resolvedIp, data);
      } catch (err: any) {
        if (
          boundRequestId !== latestRequestId ||
          refreshId !== latestRefreshId ||
          (err && err.name === 'AbortError')
        ) {
          return;
        }
        clearTransientCacheRefreshFlags(state.detectionData);
        if (state.detectionData) {
          state.refreshWarningMessage =
            'Unable to complete upstream refresh at this time; valid historical intelligence is preserved.';
        } else {
          state.validationError =
            err?.message || 'An error occurred whilst refreshing the requested IP address.';
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
      if (activeRefreshPromise) {
        await activeRefreshPromise;
      }
      return;
    }
    const candidateRaw = ipOverride ?? state.detectionData?.ip ?? '';
    const canonicalIp = canonicalizeIpAddress(String(candidateRaw));
    if (!canonicalIp) {
      state.validationError = 'Please provide a valid IPv4 or IPv6 address.';
      return;
    }
    if (state.detectionData?.isNonPublic || state.detectionData?.cacheMeta?.refreshInProgress) {
      return;
    }
    await startRefreshForCanonicalIp(canonicalIp, latestRequestId);
  }

  function applyCompleteDetectionPayload(data: any, targetIp: string, requestId: number): void {
    if (requestId !== latestRequestId) {
      return;
    }
    state.sessionExpiredMessage = '';
    state.detectionData = data;
    state.diagnostic = buildDiagnosticMetrics(data);
    const resolvedIp = canonicalizeIpAddress(data?.ip || targetIp) ?? (data?.ip || targetIp);
    state.ipHistory = updateIpHistory(state.ipHistory, resolvedIp);
    options?.onHistoryUpdated?.(state.ipHistory);
    options?.onDetectionSuccess?.(resolvedIp, data);

    if (
      data?.cacheMeta?.shouldAutoRefresh === true &&
      !data?.cacheMeta?.refreshInProgress &&
      !data?.isNonPublic
    ) {
      const canonicalForRefresh = canonicalizeIpAddress(resolvedIp);
      if (canonicalForRefresh) {
        void startRefreshForCanonicalIp(canonicalForRefresh, requestId);
      }
    }
  }

  function applyStreamEvent(eventName: string, payload: any, targetIp: string, requestId: number): void {
    if (requestId !== latestRequestId || !payload || typeof payload !== 'object') {
      return;
    }
    if (eventName === 'snapshot') {
      state.sessionExpiredMessage = '';
      state.detectionData = payload;
      state.diagnostic = buildDiagnosticMetrics(payload);
      state.isLoading = false;
      const pending = Array.isArray(payload.pendingProviders) ? payload.pendingProviders : [];
      state.isStreaming = pending.length > 0;
      const resolvedIp = canonicalizeIpAddress(payload?.ip || targetIp) ?? (payload?.ip || targetIp);
      state.ipHistory = updateIpHistory(state.ipHistory, resolvedIp);
      options?.onHistoryUpdated?.(state.ipHistory);
      options?.onDetectionSuccess?.(resolvedIp, payload);
      return;
    }
    if (eventName === 'provider' && state.detectionData) {
      const existingResults: ProviderRawResult[] = Array.isArray(state.detectionData.results)
        ? [...state.detectionData.results]
        : [];
      const row = payload.row as ProviderRawResult | undefined;
      if (row && row.provider) {
        const idx = existingResults.findIndex((r) => r.provider === row.provider);
        if (idx >= 0) {
          existingResults[idx] = row;
        } else {
          existingResults.push(row);
        }
      }
      const { provider: _p, providerKey: _pk, row: _r, ...overviewPatch } = payload;
      state.detectionData = {
        ...state.detectionData,
        ...overviewPatch,
        results: existingResults,
      };
      return;
    }
    if (eventName === 'done') {
      state.isStreaming = false;
      if (state.detectionData) {
        const merged = {
          ...state.detectionData,
          ...payload,
          pendingProviders: [],
        };
        state.detectionData = merged;
        state.diagnostic = buildDiagnosticMetrics(merged);
        if (
          merged?.cacheMeta?.shouldAutoRefresh === true &&
          !merged?.cacheMeta?.refreshInProgress &&
          !merged?.isNonPublic
        ) {
          const resolvedIp = canonicalizeIpAddress(merged?.ip || targetIp) ?? (merged?.ip || targetIp);
          if (resolvedIp) {
            void startRefreshForCanonicalIp(resolvedIp, requestId);
          }
        }
      }
    }
  }

  async function consumeSseResponse(
    body: ReadableStream<Uint8Array>,
    targetIp: string,
    requestId: number
  ): Promise<boolean> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let sawDone = false;

    while (true) {
      const { value, done } = await reader.read();
      if (done || requestId !== latestRequestId) {
        break;
      }
      buffer += decoder.decode(value, { stream: true });
      let separatorIdx = buffer.indexOf('\n\n');
      while (separatorIdx !== -1) {
        const block = buffer.slice(0, separatorIdx);
        buffer = buffer.slice(separatorIdx + 2);
        let eventName = 'message';
        const dataLines: string[] = [];
        for (const rawLine of block.split(/\r?\n/)) {
          if (rawLine.startsWith('event:')) {
            eventName = rawLine.slice('event:'.length).trim();
          } else if (rawLine.startsWith('data:')) {
            dataLines.push(rawLine.slice('data:'.length).trim());
          }
        }
        if (dataLines.length > 0) {
          try {
            const parsed = JSON.parse(dataLines.join('\n'));
            applyStreamEvent(eventName, parsed, targetIp, requestId);
            if (eventName === 'done') {
              sawDone = true;
            }
          } catch {
            // Ignore malformed SSE event payload.
          }
        }
        separatorIdx = buffer.indexOf('\n\n');
      }
    }
    return sawDone;
  }

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
      const response = await fetchImpl(
        `/api/v1/detect/stream?ip=${encodeURIComponent(targetIp)}`,
        streamOptions
      );
      if (requestId !== latestRequestId) {
        return;
      }

      if (response.status === 401) {
        handleSessionExpired();
        return;
      }

      const contentType = response.headers?.get?.('content-type') || '';
      if (response.ok && contentType.includes('text/event-stream') && response.body?.getReader) {
        const sawDone = await consumeSseResponse(response.body, targetIp, requestId);
        if (requestId !== latestRequestId) {
          return;
        }
        if (sawDone) {
          return;
        }
      } else if (response.ok && !contentType.includes('text/event-stream')) {
        const data = await response.json();
        applyCompleteDetectionPayload(data, targetIp, requestId);
        return;
      }

      const fallbackOptions = controller ? { signal: controller.signal } : undefined;
      const fallbackResponse = await fetchImpl(
        `/api/v1/detect?ip=${encodeURIComponent(targetIp)}`,
        fallbackOptions
      );
      if (requestId !== latestRequestId) {
        return;
      }
      if (fallbackResponse.status === 401) {
        handleSessionExpired();
        return;
      }
      if (!fallbackResponse.ok) {
        const errData = await fallbackResponse.json().catch(() => ({}));
        if (requestId !== latestRequestId) {
          return;
        }
        throw new Error(
          errData.message || errData.error || `Server returned HTTP ${fallbackResponse.status}`
        );
      }

      const fallbackData = await fallbackResponse.json();
      applyCompleteDetectionPayload(fallbackData, targetIp, requestId);
    } catch (err: any) {
      if (requestId !== latestRequestId || (err && err.name === 'AbortError')) {
        return;
      }
      state.validationError =
        err?.message || 'An error occurred whilst analysing the requested IP address.';
    } finally {
      if (requestId === latestRequestId) {
        state.isLoading = false;
        state.isStreaming = false;
      }
    }
  }

  async function waitForActiveRefresh(): Promise<void> {
    if (activeRefreshPromise) {
      await activeRefreshPromise;
    }
  }

  return {
    state,
    executeDetection,
    refreshDetection,
    cancelPending,
    waitForActiveRefresh,
  };
}
