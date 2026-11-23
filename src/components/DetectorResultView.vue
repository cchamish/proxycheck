<template>
  <div class="tab-panel">
    <section class="overview-section" aria-label="Detection overview">
      <div class="overview-header">
        <div class="overview-header__main">
          <div
            class="prediction__ring"
            :class="predictionScoreTierClass"
            :aria-label="`Prediction ${formatChance(detectionData.prediction_score)}%`"
          >
            <span
              class="prediction__score"
              :class="{ 'prediction__score--small': String(formatChance(detectionData.prediction_score)).length > 3 }"
            >
              {{ formatChance(detectionData.prediction_score) }}
            </span>
            <span class="prediction__unit text-subtle">%</span>
          </div>

          <div class="overview-header__summary">
            <div class="inline-group">
              <code class="ip-text">{{ detectionData.ip }}</code>
              <cdx-info-chip :status="predictionChipStatus">
                {{ predictionChipLabel }}
              </cdx-info-chip>
              <cdx-info-chip :status="arbitrationChipStatus">
                {{ detectionData.arbitrationVerdict || 'Direct Connection (No Commercial Threats)' }}
              </cdx-info-chip>
            </div>

            <div
              v-if="
                detectionData.is_broadcast_ip ||
                detectionData.isTor ||
                sharedProviderBadge ||
                sharedPrivacyInfo ||
                detectionData.suspectedResidentialProxy ||
                detectionData.highlySuspectedResidentialProxy ||
                openProxyPorts.length > 0 ||
                shodanTags.length > 0
              "
              class="inline-group"
            >
              <cdx-info-chip v-if="detectionData.is_broadcast_ip" status="warning">
                Broadcast IP?
              </cdx-info-chip>
              <cdx-info-chip
                v-if="detectionData.isTor"
                status="error"
                :title="detectionData.torSummary || detectionData.torLabel || 'Tor Relay'"
              >
                {{ detectionData.torLabel || (detectionData.torIsExit ? 'Tor Exit' : 'Tor Node') }}
              </cdx-info-chip>
              <span v-if="detectionData.isTor && detectionData.torSummary" class="text-destructive">
                {{ detectionData.torSummary }}
              </span>
              <cdx-info-chip
                v-if="sharedProviderBadge"
                status="error"
                :title="detectionData.sharedCidr || detectionData.cloudCidr || sharedProviderBadge"
              >
                {{ sharedProviderBadge }}
              </cdx-info-chip>
              <cdx-info-chip
                v-if="sharedPrivacyInfo"
                status="notice"
                :title="sharedPrivacyInfo.guidance"
              >
                {{ sharedPrivacyInfo.pillText }}
              </cdx-info-chip>
              <cdx-info-chip v-if="detectionData.suspectedResidentialProxy" status="warning">
                Suspected Residential Proxy / Compromised Host
              </cdx-info-chip>
              <cdx-info-chip
                v-if="detectionData.highlySuspectedResidentialProxy"
                status="error"
                :title="detectionData.residentialProxy != null ? `GetIPIntel ResidentialProxy: ${formatChance(detectionData.residentialProxy * 100)}%` : 'GetIPIntel ResidentialProxy'"
              >
                Highly Suspected Residential Proxy
              </cdx-info-chip>
              <cdx-info-chip
                v-for="proxyPort in openProxyPorts"
                :key="`proxy-port-${proxyPort}`"
                status="error"
                title="Open proxy port detected via Shodan InternetDB"
              >
                Open Proxy Port: {{ proxyPort }}
              </cdx-info-chip>
              <cdx-info-chip
                v-for="shodanTag in shodanTags"
                :key="`shodan-tag-${shodanTag}`"
                status="warning"
              >
                Shodan: {{ shodanTag }}
              </cdx-info-chip>
            </div>

            <span v-if="sharedPrivacyInfo" class="text-subtle">
              {{ sharedPrivacyInfo.guidance }}
            </span>
          </div>
        </div>

        <div v-if="refetchButtonState.visible" class="overview-header__controls">
          <cdx-info-chip
            v-if="cacheAgeBadgeLabel"
            :status="isCurrentCacheStale ? 'warning' : 'notice'"
            :title="cacheExactUtcTooltip || undefined"
          >
            {{ cacheAgeBadgeLabel }}
          </cdx-info-chip>
          <cdx-button
            type="button"
            action="progressive"
            size="small"
            :disabled="refetchButtonState.disabled"
            @click="emit('refetch')"
          >
            {{ refetchButtonState.label }}
          </cdx-button>
        </div>
      </div>

      <cdx-message v-if="refreshWarningMessage" type="warning" :inline="false">
        {{ refreshWarningMessage }}
      </cdx-message>
      <cdx-message v-if="showFreshRecheckPrompt" type="warning" :inline="false">
        Cached residential proxy evidence is older than 7 days. Click
        <cdx-button
          type="button"
          action="progressive"
          weight="quiet"
          size="small"
          :disabled="refetchButtonState.disabled"
          @click="emit('refetch')"
        >
          Refetch
        </cdx-button>
        to verify the current dynamic DHCP assignment before applying a long-term block.
      </cdx-message>

      <dl class="overview-grid">
        <div class="overview-grid__item">
          <dt class="overview-grid__label">Country</dt>
          <dd class="overview-grid__value">{{ detectionData.primaryCountry || '-' }}</dd>
        </div>

        <div class="overview-grid__item">
          <dt class="overview-grid__label">ASN</dt>
          <dd class="overview-grid__value"><code>{{ detectionData.primaryAsn || '-' }}</code></dd>
        </div>

        <div class="overview-grid__item">
          <dt class="overview-grid__label">Reverse DNS (PTR)</dt>
          <dd class="overview-grid__value">
            <div class="inline-group">
              <code>{{ detectionData.ptrHostname || 'No PTR Record' }}</code>
              <cdx-info-chip
                v-if="detectionData.ptrLabel && detectionData.ptrCategory && detectionData.ptrCategory !== 'none'"
                :status="ptrChipStatus"
              >
                {{ detectionData.ptrLabel }}
              </cdx-info-chip>
            </div>
          </dd>
        </div>

        <div class="overview-grid__item">
          <dt class="overview-grid__label">Recommended CIDR</dt>
          <dd class="overview-grid__value">
            <div class="stack">
              <div class="inline-group">
                <code>{{ detectionData.recommendedCidr || '-' }}</code>
                <span
                  v-if="!detectionData.highlySuspectedResidentialProxy && (detectionData.bgpPrefix || (detectionData.mmdbCidr && detectionData.mmdbCidr !== detectionData.recommendedCidr))"
                  class="text-subtle"
                >
                  (BGP: {{ detectionData.bgpPrefix || detectionData.mmdbCidr }})
                </span>
                <span v-if="!detectionData.highlySuspectedResidentialProxy && detectionData.escalationCidr" class="text-subtle">
                  Escalation CIDR: <code>{{ detectionData.escalationCidr }}</code>
                </span>
              </div>
              <cdx-message v-if="isMobileOrCgnat" type="warning" :inline="true">
                <strong>Mobile Cellular / CGNAT Shared Gateway</strong>
              </cdx-message>
              <cdx-message v-if="detectionData.highlySuspectedResidentialProxy" type="error" :inline="true">
                <strong>Highly Suspected Residential Proxy</strong>
              </cdx-message>
              <span
                v-if="!detectionData.highlySuspectedResidentialProxy && detectionData.cidrRationale"
                class="text-subtle"
              >
                {{ detectionData.cidrRationale }}
              </span>
            </div>
          </dd>
        </div>

        <div v-if="detectionData.rangeblock" class="overview-grid__item">
          <dt class="overview-grid__label">Rangeblock</dt>
          <dd class="overview-grid__value">
            <span v-if="detectionData.rangeblock.wikis.length === 0" class="text-subtle">
              No hits (0/0)
            </span>
            <span v-else>
              <template v-for="(item, idx) in detectionData.rangeblock.wikis" :key="item.wiki">
                <span v-if="Number(idx) > 0">, </span>
                <span>{{ item.count }} on </span>
                <a
                  :href="buildRangeblockWikiHref(detectionData.ip, item.wiki)"
                  @click.prevent="emit('open-rangeblock', item.wiki)"
                >{{ item.wiki }}</a>
                <span v-if="item.hasActive" class="text-destructive"> (active)</span>
              </template>
            </span>
          </dd>
        </div>
      </dl>

      <div v-if="verificationLinks" class="overview-actions">
        <a
          :href="verificationLinks.globalContributionsUrl"
          target="_blank"
          rel="noopener noreferrer"
        >
          Special:GlobalContributions
        </a>
        <a
          :href="verificationLinks.rangeblockFinderUrl"
          @click.prevent="emit('open-rangeblock', null)"
        >
          Rangeblock Finder
        </a>
        <a
          :href="verificationLinks.whoisGatewayUrl"
          target="_blank"
          rel="noopener noreferrer"
        >
          WHOIS Gateway
        </a>
        <a
          :href="verificationLinks.singleIpBlockUrl"
          target="_blank"
          rel="noopener noreferrer"
        >
          Special:Block
        </a>
        <a
          v-if="verificationLinks.rangeBlockUrl"
          :href="verificationLinks.rangeBlockUrl"
          target="_blank"
          rel="noopener noreferrer"
        >
          Special:Block (range)
        </a>
        <cdx-button type="button" size="small" @click="handleCopyWikitext">
          {{ wikitextCopied ? 'Copied Wikitext!' : 'Copy Wikitext Summary' }}
        </cdx-button>
      </div>
    </section>

    <cdx-table
      caption="Sources"
      :columns="groundTruthColumns"
      :data="comparisonRows"
    >
      <template #item-provider="{ row }">
        <div class="stack stack--tight">
          <span
            v-if="getProviderUpdatedLabel(row as ProviderRawResult)"
            class="text-subtle"
            :title="row.cachedAt || detectionData.cacheMeta?.cachedAt || undefined"
          >
            {{ getProviderUpdatedLabel(row as ProviderRawResult) }}
          </span>
          <strong>{{ row.provider }}</strong>
          <cdx-info-chip
            :status="getStatusChipStatus(row.status)"
            :class="{ 'is-pending': row.status === 'Querying...' }"
            :title="row.status === 'Offline DB Missing' ? 'Local offline database file not yet downloaded' : undefined"
          >
            {{ row.status }}
          </cdx-info-chip>
        </div>
      </template>
      <template #item-asn="{ row }">
        <code>{{ row.asn || '-' }}</code>
      </template>
      <template #item-isp="{ row }">
        {{ row.isp || row.organisation || '-' }}
      </template>
      <template #item-location="{ row }">
        {{ row.location }}
      </template>
      <template #item-usageType="{ row }">
        <div class="stack stack--tight">
          <span>{{ row.usageType }}</span>
          <span
            v-for="meta in getProviderMetaItems(row as ProviderRawResult)"
            :key="meta"
            class="text-subtle"
          >
            {{ meta }}
          </span>
        </div>
      </template>
      <template #item-securityFlags="{ row }">
        <div class="inline-group">
          <cdx-info-chip
            v-for="flag in getVisibleSecurityFlags(row.securityFlags)"
            :key="flag.label"
            :status="flag.isHighRisk ? 'error' : flag.label === 'Open Ports' ? 'warning' : 'success'"
          >
            {{ flag.label }}
          </cdx-info-chip>
        </div>
      </template>
    </cdx-table>
  </div>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import {
  CdxButton,
  CdxInfoChip,
  CdxMessage,
  CdxTable,
  type TableColumn,
} from '@wikimedia/codex';
import {
  PROVIDER_NAMES,
  canonicalizeIpAddress,
  formatCompactDuration,
  formatExactUtcTimestamp,
  formatOfflineDbTimestamp,
  type ChipStatus,
  type DetectionResponse,
  type ProviderRawResult,
} from '../utils/ip-detector-logic';

const DEFAULT_STALE_THRESHOLD_SECONDS = 7_776_000;
const FRESH_RECHECK_THRESHOLD_SECONDS = 7 * 86_400;
const META_WIKI_BASE = 'https://meta.wikimedia.org';

const groundTruthColumns: TableColumn[] = [
  { id: 'provider', label: 'Provider' },
  { id: 'asn', label: 'ASN', width: '120px' },
  { id: 'isp', label: 'ISP / Organisation' },
  { id: 'location', label: 'Location' },
  { id: 'usageType', label: 'Usage type' },
  { id: 'securityFlags', label: 'Security flags' },
];

const props = defineProps<{
  detectionData: DetectionResponse;
  isLoading: boolean;
  isRefreshing: boolean;
  refreshWarningMessage: string;
  lastRefreshedAt: string | null;
  nowTimestampMs: number;
}>();

const emit = defineEmits<{
  (event: 'refetch'): void;
  (event: 'open-rangeblock', wiki: string | null): void;
}>();

const wikitextCopied = ref(false);
let wikitextCopyResetTimer: ReturnType<typeof setTimeout> | null = null;

function formatChance(score?: number | string | null): number {
  const num = Number(score ?? 0);
  return Number.isNaN(num) ? 0 : Number(num.toFixed(3));
}

function parseSafeCidr(rawTarget?: string | null): { addr: string; prefix: number; maxPrefix: number } | null {
  const trimmed = String(rawTarget || '').trim();
  if (!trimmed.includes('/')) return null;
  const [addrPart, prefixPart, ...extra] = trimmed.split('/');
  if (extra.length !== 0 || !/^\d{1,3}$/.test(prefixPart || '')) return null;
  const safeAddr = addrPart ? canonicalizeIpAddress(addrPart)?.split('%')[0] : null;
  if (!safeAddr) return null;
  const prefix = Number(prefixPart);
  const maxPrefix = safeAddr.includes(':') ? 128 : 32;
  if (prefix < 1 || prefix > maxPrefix) return null;
  return { addr: safeAddr, prefix, maxPrefix };
}

function normaliseSafeCidrOrIp(rawTarget?: string | null, fallbackIp?: string | null): string | null {
  const parsed = parseSafeCidr(rawTarget);
  if (parsed) return `${parsed.addr}/${parsed.prefix}`;
  const trimmed = String(rawTarget || '').trim();
  return (
    (trimmed ? canonicalizeIpAddress(trimmed)?.split('%')[0] : null) ??
    (fallbackIp ? canonicalizeIpAddress(fallbackIp)?.split('%')[0] : null) ??
    null
  );
}

const predictionScoreTierClass = computed(() => {
  const data = props.detectionData;
  if (data.predictionTier === 'destructive') return 'score-tier-high';
  if (data.predictionTier === 'warning') return 'score-tier-moderate';
  if (data.predictionTier === 'success') return 'score-tier-low';
  const score = Number(data.prediction_score ?? 0);
  if (score >= 70) return 'score-tier-high';
  if (score >= 30) return 'score-tier-moderate';
  return 'score-tier-low';
});

const predictionChipStatus = computed<ChipStatus>(() => {
  const tier = props.detectionData.predictionTier;
  if (tier === 'destructive') return 'error';
  if (tier === 'success') return 'success';
  return 'notice';
});

const predictionChipLabel = computed(() => {
  const data = props.detectionData;
  if (data.predictionTier === 'destructive') return data.predictionLabel || 'Proxy / VPN';
  if (data.predictionTier === 'success') return data.predictionLabel || 'Safe Residential';
  const label = data.predictionLabel || 'Needs Human Review';
  return data.getipintel_chance !== null && data.getipintel_chance !== undefined
    ? `${label} (${formatChance(data.prediction_score)}%)`
    : label;
});

const arbitrationChipStatus = computed<ChipStatus>(() => {
  const data = props.detectionData;
  if (data.arbitrationTier === 'destructive' || data.isMajorityProxyVpn) return 'error';
  if (data.arbitrationTier === 'warning' || String(data.arbitrationVerdict || '').startsWith('Disputed')) {
    return 'warning';
  }
  if (data.arbitrationTier === 'neutral') return 'notice';
  return 'success';
});

const ptrChipStatus = computed<ChipStatus>(() => {
  const data = props.detectionData;
  if (!data.ptrCategory) return 'notice';
  if (data.ptrCategory === 'hosting_or_gateway' || data.ptrIsHighRisk) return 'error';
  if (data.ptrCategory === 'mobile_or_cgnat') return 'warning';
  if (data.ptrCategory === 'dynamic_residential') return 'success';
  return 'notice';
});

const sharedPrivacyInfo = computed(() => {
  const egress = props.detectionData.sharedPrivacyEgress;
  if (egress === 'icloud_private_relay') {
    return {
      label: 'Apple iCloud Private Relay',
      pillText: 'Apple iCloud Private Relay · Shared egress',
      guidance: 'Shared Apple iCloud Private Relay client egress. Many unrelated users may share this address.',
    };
  }
  if (egress === 'cloudflare_warp') {
    return {
      label: 'Cloudflare WARP',
      pillText: 'Cloudflare WARP Egress · Shared egress',
      guidance: 'Shared Cloudflare WARP client egress. Many unrelated users may share this address.',
    };
  }
  return null;
});

const sharedProviderBadge = computed(() => {
  for (const candidate of [props.detectionData.sharedProvider, props.detectionData.cloudProvider]) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return `SHARED/${candidate.trim()}`;
    }
  }
  return null;
});

const isMobileOrCgnat = computed(
  () => props.detectionData.isMobileOrCgnat === true || props.detectionData.ptrCategory === 'mobile_or_cgnat'
);

const openProxyPorts = computed(() => {
  const collected = new Set<number>();
  const addPorts = (ports?: number[]) => {
    if (!Array.isArray(ports)) return;
    for (const port of ports) {
      if (typeof port === 'number' && Number.isInteger(port) && port > 0) collected.add(port);
    }
  };
  addPorts(props.detectionData.openProxyPorts);
  for (const row of props.detectionData.results ?? []) {
    if (row?.provider === 'Shodan InternetDB') addPorts(row.openProxyPorts);
  }
  return [...collected].sort((a, b) => a - b);
});

const shodanTags = computed(() => {
  const shodanRow = props.detectionData.results?.find((row) => row?.provider === 'Shodan InternetDB');
  if (!shodanRow || !Array.isArray(shodanRow.tags)) return [];
  return shodanRow.tags.filter((tag): tag is string => typeof tag === 'string' && tag.trim().length > 0);
});

const refetchButtonState = computed(() => {
  const data = props.detectionData;
  const visible = Boolean(!data.isNonPublic && data.cacheMeta?.status !== 'bypassed');
  const isBusy = Boolean(props.isRefreshing || data.cacheMeta?.refreshInProgress);
  return {
    visible,
    label: isBusy ? 'Updating...' : 'Refetch',
    disabled: Boolean(isBusy || props.isLoading),
    isBusy,
  };
});

const isCurrentCacheStale = computed(() => {
  const meta = props.detectionData.cacheMeta;
  if (!meta) return false;
  if (meta.isStale === true || meta.status === 'stale') return true;
  const threshold = meta.staleThresholdSeconds ?? DEFAULT_STALE_THRESHOLD_SECONDS;
  return typeof meta.ageSeconds === 'number' && Number.isFinite(meta.ageSeconds) && meta.ageSeconds > threshold;
});

const cacheAgeBadgeLabel = computed(() => {
  const data = props.detectionData;
  if (data.isNonPublic || data.cacheMeta?.status === 'bypassed') return null;

  const safeNowMs = Number.isFinite(props.nowTimestampMs) ? props.nowTimestampMs : Date.now();
  if (props.lastRefreshedAt && !data.cacheMeta?.degradedRefreshFallback) {
    const refreshedMs = Date.parse(props.lastRefreshedAt);
    if (Number.isFinite(refreshedMs) && Math.max(0, Math.floor((safeNowMs - refreshedMs) / 1000)) < 60) {
      return 'Just updated';
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
    const age = timestampAgeSec ?? metaAgeSec ?? 0;
    if (age < 60) return 'Just updated';
    if (age < 3600) return `Updated ${Math.floor(age / 60)}m ago`;
    if (age < 86_400) return `Updated ${Math.floor(age / 3600)}h ago`;
    return `Updated ${Math.floor(age / 86_400)}d ago`;
  }

  const age = Math.max(timestampAgeSec ?? 0, metaAgeSec ?? 0);
  if (age < 60) return 'Cached just now';
  if (age < 3600) return `Cached ${Math.floor(age / 60)}m ago`;
  if (age < 86_400) return `Cached ${Math.floor(age / 3600)}h ago`;
  return `Cached ${Math.floor(age / 86_400)}d ago`;
});

const cacheExactUtcTooltip = computed(() => {
  const data = props.detectionData;
  const rawStamp = data.cacheMeta?.fetchedAt || data.fetchedAt || data.cacheMeta?.cachedAt || null;
  const formatted = formatExactUtcTimestamp(rawStamp);
  return formatted ? `Fetched ${formatted}` : null;
});

const showFreshRecheckPrompt = computed(() => {
  if (refetchButtonState.value.isBusy) return false;
  const data = props.detectionData;
  if (data.cacheMeta?.recommendFreshRecheck === true) return true;
  if (data.suspectedResidentialProxy !== true) return false;
  return (data.cacheMeta?.ageSeconds ?? 0) > FRESH_RECHECK_THRESHOLD_SECONDS;
});

const verificationLinks = computed(() => {
  const safeIp = canonicalizeIpAddress(props.detectionData.ip)?.split('%')[0];
  if (!safeIp) return null;

  const encodeBlockUrl = (target: string) => {
    const encoded = target
      .split('/')
      .map((segment) => encodeURIComponent(segment).replaceAll('%3A', ':'))
      .join('/');
    return `${META_WIKI_BASE}/wiki/Special:Block/${encoded}?wpHardBlock=1`;
  };

  const pathSafeIp = encodeURIComponent(safeIp).replaceAll('%3A', ':');
  const querySafeIp = encodeURIComponent(safeIp);
  const parsedRange = parseSafeCidr(props.detectionData.recommendedCidr);
  const rangeCidr = parsedRange && parsedRange.prefix < parsedRange.maxPrefix
    ? `${parsedRange.addr}/${parsedRange.prefix}`
    : null;

  return {
    globalContributionsUrl: `${META_WIKI_BASE}/wiki/Special:GlobalContributions/${pathSafeIp}`,
    rangeblockFinderUrl: `/?ip=${querySafeIp}&tab=rb`,
    whoisGatewayUrl: `https://whois.toolforge.org/gateway.py?lookup=true&ip=${querySafeIp}`,
    singleIpBlockUrl: encodeBlockUrl(safeIp),
    rangeBlockUrl: rangeCidr ? encodeBlockUrl(rangeCidr) : null,
  };
});

const comparisonRows = computed<ProviderRawResult[]>(() => {
  const resolvedByName = new Map<string, ProviderRawResult>();
  for (const row of props.detectionData.results ?? []) {
    if (row.provider !== 'GetIPIntel' && row.provider !== 'Tor Onionoo') {
      resolvedByName.set(row.provider, row);
    }
  }
  const pendingSet = new Set(
    (props.detectionData.pendingProviders ?? []).filter(
      (name) => name !== 'GetIPIntel' && name !== 'Tor Onionoo'
    )
  );
  const ordered: ProviderRawResult[] = [];
  for (const providerName of PROVIDER_NAMES) {
    if (providerName === 'GetIPIntel' || providerName === 'Tor Onionoo') continue;
    const existing = resolvedByName.get(providerName);
    if (existing) {
      ordered.push(existing);
    } else if (pendingSet.has(providerName)) {
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
});

function buildRangeblockWikiHref(ip: string, wiki: string): string {
  const canonical = canonicalizeIpAddress(ip) ?? ip;
  const params = new URLSearchParams({ ip: canonical, tab: 'rb', wiki });
  return `/?${params.toString()}`;
}

function getProviderUpdatedLabel(row: ProviderRawResult): string | null {
  const rowIsCached = row.isCached !== undefined ? Boolean(row.isCached) : Boolean(props.detectionData.isCached);
  if (!rowIsCached) return null;
  const cachedAt =
    row.cachedAt ||
    props.detectionData.cacheMeta?.cachedAt ||
    props.detectionData.cacheMeta?.fetchedAt ||
    props.detectionData.fetchedAt ||
    null;
  if (!cachedAt) return null;
  const cachedMs = Date.parse(String(cachedAt).trim());
  if (!Number.isFinite(cachedMs)) return null;
  const nowMs = Number.isFinite(props.nowTimestampMs) ? props.nowTimestampMs : Date.now();
  const diffMs = nowMs - cachedMs;
  if (diffMs < 60_000) return 'Updated just now';
  return `Updated ${formatCompactDuration(Math.floor(diffMs / 60_000))} ago`;
}

function getStatusChipStatus(status?: string | null): ChipStatus {
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

function getVisibleSecurityFlags(
  flags?: ProviderRawResult['securityFlags'] | null
): { label: string; isHighRisk: boolean }[] {
  if (!flags || flags.length === 0) return [{ label: 'No Flags', isHighRisk: false }];
  const visible = flags.filter((f) => f.isHighRisk || f.label === 'Open Ports');
  return visible.length > 0 ? visible : [{ label: 'No Flags', isHighRisk: false }];
}

function getProviderMetaItems(row: ProviderRawResult): string[] {
  const items: string[] = [];
  if (row.port !== undefined && row.port !== null) items.push(`Port: ${row.port}`);
  if (Array.isArray(row.openProxyPorts) && row.openProxyPorts.length > 0) {
    items.push(`Proxy ports: ${row.openProxyPorts.join(', ')}`);
  } else if (Array.isArray(row.ports) && row.ports.length > 0) {
    const preview = row.ports.slice(0, 8).join(', ');
    items.push(`Open ports: ${row.ports.length > 8 ? `${preview}…` : preview}`);
  }
  if (Array.isArray(row.tags) && row.tags.length > 0) items.push(`Tags: ${row.tags.join(', ')}`);
  if (Array.isArray(row.hostnames) && row.hostnames.length > 0) {
    const preview = row.hostnames.slice(0, 3).join(', ');
    items.push(`Hostnames: ${row.hostnames.length > 3 ? `${preview}…` : preview}`);
  }
  if (typeof row.ipsumScore === 'number' && row.ipsumScore > 0) items.push(`IPsum lists: ${row.ipsumScore}`);
  if (row.inSpamhausDrop) {
    const dropParts = [row.dropSblId, row.dropCidr].filter(
      (part): part is string => typeof part === 'string' && part.trim().length > 0
    );
    items.push(dropParts.length > 0 ? `Spamhaus DROP: ${dropParts.join(' · ')}` : 'Spamhaus DROP: Listed');
  }
  if (row.category) {
    const normalisedCategory =
      row.category === 'vpn'
        ? 'VPN'
        : row.category === 'datacenter'
          ? 'Datacentre'
          : row.category === 'hosting'
            ? 'Hosting'
            : row.category;
    items.push(`Category: ${normalisedCategory}`);
  }
  if (row.matchedCidr && !row.dropCidr) items.push(`Prefix: ${row.matchedCidr}`);
  if (Array.isArray(row.sources) && row.sources.length > 0) items.push(`Sources: ${row.sources.join(', ')}`);
  if (row.provider === 'StopForumSpam' || row.frequency !== undefined || row.confidence !== undefined) {
    if (row.frequency !== undefined && row.frequency !== null) items.push(`Frequency: ${row.frequency}`);
    if (row.confidence !== undefined && row.confidence !== null) items.push(`Confidence: ${row.confidence}%`);
  }
  if (row.provider === 'DShield' || row.attacks !== undefined || row.count !== undefined) {
    if (row.attacks !== undefined && row.attacks !== null) items.push(`Attacks: ${row.attacks}`);
    if (row.count !== undefined && row.count !== null) items.push(`Targets: ${row.count}`);
    if (Array.isArray(row.threatfeeds) && row.threatfeeds.length > 0) {
      items.push(`Feeds: ${row.threatfeeds.join(', ')}`);
    }
  }
  if (row.carrier) items.push(`Carrier: ${row.carrier}`);
  if (row.mobileBrand) items.push(`Mobile brand: ${row.mobileBrand}`);
  if (row.coreVerdict) items.push(`Core verdict: ${row.coreVerdict}`);
  if (Array.isArray(row.coreSources) && row.coreSources.length > 0) {
    items.push(`Core sources: ${row.coreSources.join(', ')}`);
  }
  if (row.networkRole) items.push(`Network role: ${row.networkRole}`);
  const rowSharedProvider = row.sharedProvider || row.cloudProvider;
  if (rowSharedProvider) {
    items.push(
      row.sharedCategory
        ? `Shared egress: ${rowSharedProvider} (${row.sharedCategory})`
        : `Shared egress: ${rowSharedProvider}`
    );
  }
  if (row.provider === 'AbuseIPDB' || row.totalReports !== undefined || row.numDistinctUsers !== undefined) {
    if (row.totalReports !== undefined && row.totalReports !== null) items.push(`Reports: ${row.totalReports}`);
    if (row.numDistinctUsers !== undefined && row.numDistinctUsers !== null) {
      items.push(`Distinct users: ${row.numDistinctUsers}`);
    }
  }
  const lastSeenValue = row.lastSeen || row.maxDate;
  if (lastSeenValue) items.push(`Last seen: ${lastSeenValue}`);
  if (row.offlineDbUpdatedAt) items.push(`Offline DB: ${formatOfflineDbTimestamp(row.offlineDbUpdatedAt, props.nowTimestampMs)}`);
  if (row.isHistoricalFallback) items.push('Historical L2 fallback');
  return items;
}

async function handleCopyWikitext(): Promise<void> {
  const data = props.detectionData;
  const safeIp = canonicalizeIpAddress(data.ip)?.split('%')[0] ?? String(data.ip || '').trim();
  if (!safeIp) return;

  const safeCidr = normaliseSafeCidrOrIp(data.recommendedCidr, safeIp);
  const safeEscalation = data.escalationCidr ? normaliseSafeCidrOrIp(data.escalationCidr, safeIp) : null;
  const asnText =
    typeof data.primaryAsn === 'string' && data.primaryAsn.trim() && data.primaryAsn.trim() !== '-'
      ? data.primaryAsn.trim()
      : 'Unknown ASN';

  const preferredIspProviders = new Set(['Cloudflare Radar', 'MaxMind', 'DShield']);
  let ispText = 'Unknown ISP';
  outer: for (const preferredOnly of [true, false]) {
    for (const row of data.results ?? []) {
      if (!row || row.status !== '200 OK') continue;
      if (preferredOnly && !preferredIspProviders.has(row.provider)) continue;
      const candidate = String(row.isp || row.organisation || '').trim();
      if (candidate && candidate !== '-') {
        ispText = candidate;
        break outer;
      }
    }
  }
  if (ispText === 'Unknown ISP') {
    for (const candidate of [data.sharedProvider, data.cloudProvider]) {
      if (typeof candidate === 'string' && candidate.trim()) {
        ispText = candidate.trim();
        break;
      }
    }
  }

  const verdictText = String(data.arbitrationVerdict || 'Direct Connection (No Commercial Threats)').trim();
  const signals: string[] = [];
  if (data.isTor) signals.push(data.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node'));
  if (sharedPrivacyInfo.value) signals.push(sharedPrivacyInfo.value.label);
  const sharedName = sharedProviderBadge.value?.slice('SHARED/'.length);
  if (sharedName) {
    signals.push(
      data.sharedCategory ? `Shared egress: ${sharedName} (${data.sharedCategory})` : `Shared egress: ${sharedName}`
    );
  }
  if (isMobileOrCgnat.value) signals.push('Mobile cellular or CGNAT shared gateway');
  if (data.suspectedResidentialProxy) signals.push('Suspected Residential Proxy or Compromised Host');
  if (openProxyPorts.value.length > 0) signals.push(`Open proxy ports: ${openProxyPorts.value.join(', ')}`);
  const dropRow = data.results?.find((row) => row?.provider === 'IPsum / DROP' && row.inSpamhausDrop);
  if (dropRow) signals.push(dropRow.dropSblId ? `Spamhaus DROP (${dropRow.dropSblId})` : 'Spamhaus DROP');

  const cidrSegment =
    safeCidr && safeCidr !== safeIp
      ? ` (recommended CIDR: <code>${safeCidr}</code>${safeEscalation ? `, escalation: <code>${safeEscalation}</code>` : ''})`
      : safeCidr
        ? ` (recommended CIDR: <code>${safeCidr}</code>)`
        : '';

  const rawFetched = data.fetchedAt || data.cacheMeta?.fetchedAt || data.cacheMeta?.cachedAt || null;
  const parsedFetchedMs = rawFetched ? Date.parse(String(rawFetched).trim()) : Number.NaN;
  const effectiveMs = Number.isFinite(parsedFetchedMs)
    ? parsedFetchedMs
    : Number.isFinite(props.nowTimestampMs)
      ? props.nowTimestampMs
      : Date.now();
  const fetchedDate = new Date(effectiveMs).toISOString().slice(0, 10);

  const parts = [
    `* '''IP''': <code>${safeIp}</code>${cidrSegment}`,
    `'''ASN''': <code>${asnText}</code> (${ispText})`,
    `'''Verdict''': ${verdictText}`,
  ];
  if (signals.length > 0) parts.push(`'''Signals''': ${signals.join('; ')}`);
  parts.push(`''(fetched ${fetchedDate} UTC)''`);
  const snippet = parts.join(' · ');

  let copied = false;
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(snippet);
      copied = true;
    } catch {
      copied = false;
    }
  }
  if (!copied && typeof document !== 'undefined') {
    const textarea = document.createElement('textarea');
    textarea.value = snippet;
    textarea.setAttribute('readonly', 'true');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      copied = document.execCommand('copy');
    } catch {
      copied = false;
    } finally {
      document.body.removeChild(textarea);
    }
  }
  if (copied) {
    wikitextCopied.value = true;
    if (wikitextCopyResetTimer !== null) clearTimeout(wikitextCopyResetTimer);
    wikitextCopyResetTimer = setTimeout(() => {
      wikitextCopied.value = false;
      wikitextCopyResetTimer = null;
    }, 2000);
  }
}

watch(
  () => props.detectionData,
  () => {
    wikitextCopied.value = false;
    if (wikitextCopyResetTimer !== null) {
      clearTimeout(wikitextCopyResetTimer);
      wikitextCopyResetTimer = null;
    }
  }
);

onUnmounted(() => {
  if (wikitextCopyResetTimer !== null) {
    clearTimeout(wikitextCopyResetTimer);
    wikitextCopyResetTimer = null;
  }
});
</script>
