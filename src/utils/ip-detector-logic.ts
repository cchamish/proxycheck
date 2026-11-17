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
  block?: number | null;
  countryCode?: string;
  coordinates?: string;
  prefixLength?: number;
  port?: number | null;
  lastSeen?: string | null;
  carrier?: string | null;
  mobileBrand?: string | null;
  totalReports?: number | null;
  numDistinctUsers?: number | null;
  isMobile?: boolean;
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
  rawJson: Record<string, unknown>;
}

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

export type PtrCategory = 'dynamic_residential' | 'hosting_or_gateway' | 'unclassified' | 'none';

export interface CacheMeta {
  status: 'hit' | 'partial' | 'miss' | 'bypassed';
  isPartial: boolean;
  hitCount: number;
  missCount: number;
  cooldownCount: number;
  totalSources: number;
  cachedAt: string | null;
}

export interface DetectionResponse {
  ip: string;
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
  arbitrationVerdict: string;
  arbitrationTier?: string;
  isMajorityProxyVpn: boolean;
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
  cloudCidr?: string | null;
  cloudProvider?: string | null;
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
  const cachedAt = row.cachedAt || detectionData?.cacheMeta?.cachedAt || null;
  return formatRelativeUpdatedLabel(cachedAt, now);
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
  if (row.cloudProvider) {
    items.push(`Cloud: ${row.cloudProvider}`);
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
  return items;
}

/**
 * Maps a provider HTTP or circuit-breaker status string to a Codex badge severity class.
 */
export function getStatusBadgeClass(status?: string | null): string {
  if (!status) return 'badge-neutral';
  if (status === '200 OK') return 'badge-success';
  if (
    status === 'No API Key' ||
    status === 'Database Missing' ||
    status === 'Offline DB Missing' ||
    status === 'Skipped (IPv6)' ||
    status === 'Deferred (Light Mode)'
  ) {
    return 'badge-neutral';
  }
  if (status.includes('429') || status.includes('Cooldown') || status.includes('Quota Guard')) {
    return 'badge-warning';
  }
  return 'badge-destructive';
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
 * Resolves the multi-source arbitration badge class from consensus tier or verdict text.
 */
export function getArbitrationBadgeClass(
  data: Partial<DetectionResponse> | null | undefined
): string {
  if (!data) return 'badge-neutral';
  if (data.arbitrationTier === 'destructive' || data.isMajorityProxyVpn) {
    return 'badge-destructive';
  }
  if (data.arbitrationTier === 'warning' || String(data.arbitrationVerdict || '').startsWith('Disputed')) {
    return 'badge-warning';
  }
  if (data.arbitrationTier === 'neutral') {
    return 'badge-neutral';
  }
  return 'badge-success';
}

/**
 * Resolves the reverse DNS classification badge class.
 */
export function getPtrBadgeClass(data: Partial<DetectionResponse> | null | undefined): string {
  if (!data || !data.ptrCategory) return 'badge-neutral';
  if (data.ptrCategory === 'hosting_or_gateway' || data.ptrIsHighRisk) {
    return 'badge-destructive';
  }
  if (data.ptrCategory === 'dynamic_residential') {
    return 'badge-success';
  }
  return 'badge-neutral';
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

export interface ProviderDashboardGlobalMetrics {
  totalRequestsToday: number;
  authSession: number;
  authGadget: number;
  cacheHit: number;
  cachePartial: number;
  cacheMiss: number;
  fullCacheHitRatePercent: number;
  totalQuotaBlocksToday: number;
  activeCooldownCount: number;
  activeQuotaGuardCount: number;
}

export interface ProviderDashboardResponse {
  generatedAt: string;
  dateBucket: string;
  redisAvailable: boolean;
  global: ProviderDashboardGlobalMetrics;
  providers: ProviderDashboardRow[];
  offlineDatabases?: OfflineDatabaseEntry[];
  durationSeconds?: number;
  memoryMb?: number | null;
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
  validationError: string;
  sessionExpiredMessage: string;
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
        state.user = createLoggedOutUserState();
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
      state.diagnostic = buildDiagnosticMetrics(data);
      const resolvedIp = canonicalizeIpAddress(data?.ip || targetIp) ?? (data?.ip || targetIp);
      state.ipHistory = updateIpHistory(state.ipHistory, resolvedIp);
      options?.onHistoryUpdated?.(state.ipHistory);
      options?.onDetectionSuccess?.(resolvedIp, data);
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
