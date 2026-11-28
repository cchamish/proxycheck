<template>
  <div class="tab-panel">
    <section class="overview-section" :aria-label="t('detector-overview-aria')">
      <div class="overview-header">
        <div class="overview-header__main">
          <div
            class="prediction__ring"
            :class="predictionScoreTierClass"
            :aria-label="t('detector-prediction-aria', { score: formatChance(detectionData.prediction_score) })"
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
                {{ t('detector-broadcast-ip') }}
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
                {{ t('detector-suspected-residential') }}
              </cdx-info-chip>
              <cdx-info-chip
                v-if="detectionData.highlySuspectedResidentialProxy"
                status="error"
                :title="detectionData.residentialProxy != null ? `GetIPIntel ResidentialProxy: ${formatChance(detectionData.residentialProxy * 100)}%` : 'GetIPIntel ResidentialProxy'"
              >
                {{ t('detector-highly-suspected-residential') }}
              </cdx-info-chip>
              <cdx-info-chip
                v-for="proxyPort in openProxyPorts"
                :key="`proxy-port-${proxyPort}`"
                status="error"
                :title="t('detector-open-proxy-port-title')"
              >
                {{ t('detector-open-proxy-port', { port: proxyPort }) }}
              </cdx-info-chip>
              <cdx-info-chip
                v-for="shodanTag in shodanTags"
                :key="`shodan-tag-${shodanTag}`"
                status="warning"
              >
                {{ t('detector-shodan-tag', { tag: shodanTag }) }}
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
        {{ t('detector-fresh-recheck-prefix') }}
        <cdx-button
          type="button"
          action="progressive"
          weight="quiet"
          size="small"
          :disabled="refetchButtonState.disabled"
          @click="emit('refetch')"
        >
          {{ t('detector-refetch') }}
        </cdx-button>
        {{ t('detector-fresh-recheck-suffix') }}
      </cdx-message>

      <dl class="overview-grid">
        <div class="overview-grid__item">
          <dt class="overview-grid__label">{{ t('detector-label-country') }}</dt>
          <dd class="overview-grid__value">{{ detectionData.primaryCountry || '-' }}</dd>
        </div>

        <div class="overview-grid__item">
          <dt class="overview-grid__label">{{ t('detector-label-asn') }}</dt>
          <dd class="overview-grid__value"><code>{{ detectionData.primaryAsn || '-' }}</code></dd>
        </div>

        <div class="overview-grid__item">
          <dt class="overview-grid__label">{{ t('detector-label-ptr') }}</dt>
          <dd class="overview-grid__value">
            <div class="inline-group">
              <code>{{ detectionData.ptrHostname || t('detector-no-ptr') }}</code>
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
          <dt class="overview-grid__label">{{ t('detector-label-recommended-cidr') }}</dt>
          <dd class="overview-grid__value">
            <div class="stack">
              <div class="inline-group">
                <code>{{ detectionData.recommendedCidr || '-' }}</code>
                <span
                  v-if="!isSingleIpResidentialProxy && (detectionData.bgpPrefix || (detectionData.mmdbCidr && detectionData.mmdbCidr !== detectionData.recommendedCidr))"
                  class="text-subtle"
                >
                  {{ t('detector-bgp-prefix', { prefix: detectionData.bgpPrefix || detectionData.mmdbCidr || '' }) }}
                </span>
                <span v-if="!isSingleIpResidentialProxy && detectionData.escalationCidr" class="text-subtle">
                  {{ t('detector-escalation-cidr') }} <code>{{ detectionData.escalationCidr }}</code>
                </span>
              </div>
              <cdx-message v-if="isMobileOrCgnat" type="warning" :inline="true">
                <strong>{{ t('detector-mobile-cgnat') }}</strong>
              </cdx-message>
              <cdx-message v-if="detectionData.confirmedResidentialProxy" type="error" :inline="true">
                <strong>{{
                  t('detector-confirmed-residential-cidr-warning', {
                    provider: detectionData.confirmedResidentialProxyProvider || 'Oxylabs',
                  })
                }}</strong>
              </cdx-message>
              <cdx-message v-else-if="detectionData.highlySuspectedResidentialProxy" type="error" :inline="true">
                <strong>{{ t('detector-highly-suspected-residential') }}</strong>
              </cdx-message>
              <span
                v-if="!isSingleIpResidentialProxy && detectionData.cidrRationale"
                class="text-subtle"
              >
                {{ detectionData.cidrRationale }}
              </span>
            </div>
          </dd>
        </div>

        <div v-if="detectionData.rangeblock" class="overview-grid__item">
          <dt class="overview-grid__label">{{ t('detector-label-rangeblock') }}</dt>
          <dd class="overview-grid__value">
            <cdx-message
              v-if="detectionData.rangeblock.wikis.length === 0 && detectionData.rangeblock.blockDataDegraded"
              type="warning"
              :inline="true"
            >
              {{ t('detector-rangeblock-unavailable') }}
            </cdx-message>
            <span v-else-if="detectionData.rangeblock.wikis.length === 0" class="text-subtle">
              {{ t('detector-rangeblock-no-hits') }}
            </span>
            <div v-else class="stack stack--tight">
              <span>
                <template v-for="(item, idx) in detectionData.rangeblock.wikis" :key="item.wiki">
                  <span v-if="Number(idx) > 0">, </span>
                  <span>{{ t('detector-rangeblock-on-wiki', { count: item.count }) }}</span>
                  <a
                    :href="buildRangeblockWikiHref(detectionData.ip, item.wiki)"
                    @click.prevent="emit('open-rangeblock', item.wiki)"
                  >{{ item.wiki }}</a>
                  <span v-if="item.hasActive" class="text-destructive">{{ t('detector-rangeblock-active-suffix') }}</span>
                </template>
              </span>
              <cdx-message
                v-if="detectionData.rangeblock.blockDataDegraded"
                type="warning"
                :inline="true"
              >
                {{ t('detector-rangeblock-partial') }}
              </cdx-message>
            </div>
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
          {{ t('detector-link-rangeblock-finder') }}
        </a>
        <a
          :href="verificationLinks.whoisGatewayUrl"
          target="_blank"
          rel="noopener noreferrer"
        >
          {{ t('detector-link-whois-gateway') }}
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
          {{ t('detector-link-special-block-range') }}
        </a>
        <cdx-button type="button" size="small" @click="handleCopyWikitext">
          {{ wikitextCopied ? t('detector-copied-wikitext') : t('detector-copy-wikitext') }}
        </cdx-button>
      </div>
    </section>

    <cdx-table
      :caption="t('detector-sources-caption')"
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
            :title="row.status === 'Offline DB Missing' ? t('detector-offline-db-missing-title') : undefined"
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
  canonicalizeIpAddress,
  formatCompactDuration,
  formatExactUtcTimestamp,
  formatOfflineDbTimestamp,
  type ChipStatus,
  type DetectionResponse,
  type ProviderRawResult,
} from '../utils/ip-detector-logic';
import { useI18n } from '../utils/i18n';

const { t } = useI18n();

const DEFAULT_STALE_THRESHOLD_SECONDS = 7_776_000;
const FRESH_RECHECK_THRESHOLD_SECONDS = 7 * 86_400;
const META_WIKI_BASE = 'https://meta.wikimedia.org';

const groundTruthColumns = computed<TableColumn[]>(() => [
  { id: 'provider', label: t('detector-col-provider') },
  { id: 'asn', label: t('detector-col-asn'), width: '120px' },
  { id: 'isp', label: t('detector-col-isp') },
  { id: 'location', label: t('detector-col-location') },
  { id: 'usageType', label: t('detector-col-usage-type') },
  { id: 'securityFlags', label: t('detector-col-security-flags') },
]);

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

const isSingleIpResidentialProxy = computed(() =>
  Boolean(props.detectionData.confirmedResidentialProxy || props.detectionData.highlySuspectedResidentialProxy)
);

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
      pillText: t('detector-shared-icloud-pill'),
      guidance: t('detector-shared-icloud-guidance'),
    };
  }
  if (egress === 'cloudflare_warp') {
    return {
      label: 'Cloudflare WARP',
      pillText: t('detector-shared-warp-pill'),
      guidance: t('detector-shared-warp-guidance'),
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
    label: isBusy ? t('detector-refetch-updating') : t('detector-refetch'),
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
      return t('detector-cache-just-updated');
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
    if (age < 60) return t('detector-cache-just-updated');
    if (age < 3600) return t('detector-cache-updated-minutes', { count: Math.floor(age / 60) });
    if (age < 86_400) return t('detector-cache-updated-hours', { count: Math.floor(age / 3600) });
    return t('detector-cache-updated-days', { count: Math.floor(age / 86_400) });
  }

  const age = Math.max(timestampAgeSec ?? 0, metaAgeSec ?? 0);
  if (age < 60) return t('detector-cache-just-now');
  if (age < 3600) return t('detector-cache-minutes', { count: Math.floor(age / 60) });
  if (age < 86_400) return t('detector-cache-hours', { count: Math.floor(age / 3600) });
  return t('detector-cache-days', { count: Math.floor(age / 86_400) });
});

const cacheExactUtcTooltip = computed(() => {
  const data = props.detectionData;
  const rawStamp = data.cacheMeta?.fetchedAt || data.fetchedAt || data.cacheMeta?.cachedAt || null;
  const formatted = formatExactUtcTimestamp(rawStamp);
  return formatted ? t('detector-fetched-at', { timestamp: formatted }) : null;
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
  const ordered: ProviderRawResult[] = [];
  const seenProviders = new Set<string>();
  for (const row of props.detectionData.results ?? []) {
    if (row.provider === 'GetIPIntel' || row.provider === 'Tor Onionoo' || seenProviders.has(row.provider)) {
      continue;
    }
    seenProviders.add(row.provider);
    ordered.push(row);
  }
  for (const providerName of props.detectionData.pendingProviders ?? []) {
    if (providerName === 'GetIPIntel' || providerName === 'Tor Onionoo' || seenProviders.has(providerName)) {
      continue;
    }
    seenProviders.add(providerName);
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
  if (diffMs < 60_000) return t('detector-updated-just-now');
  return t('detector-updated-ago', { duration: formatCompactDuration(Math.floor(diffMs / 60_000)) });
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
  if (row.port !== undefined && row.port !== null) items.push(t('detector-meta-port', { value: row.port }));
  if (Array.isArray(row.openProxyPorts) && row.openProxyPorts.length > 0) {
    items.push(t('detector-meta-proxy-ports', { value: row.openProxyPorts.join(', ') }));
  } else if (Array.isArray(row.ports) && row.ports.length > 0) {
    const preview = row.ports.slice(0, 8).join(', ');
    items.push(t('detector-meta-open-ports', { value: row.ports.length > 8 ? `${preview}…` : preview }));
  }
  if (Array.isArray(row.tags) && row.tags.length > 0) {
    items.push(t('detector-meta-tags', { value: row.tags.join(', ') }));
  }
  if (Array.isArray(row.hostnames) && row.hostnames.length > 0) {
    const preview = row.hostnames.slice(0, 3).join(', ');
    items.push(t('detector-meta-hostnames', { value: row.hostnames.length > 3 ? `${preview}…` : preview }));
  }
  if (typeof row.ipsumScore === 'number' && row.ipsumScore > 0) {
    items.push(t('detector-meta-ipsum-lists', { value: row.ipsumScore }));
  }
  if (row.inSpamhausDrop) {
    const dropParts = [row.dropSblId, row.dropCidr].filter(
      (part): part is string => typeof part === 'string' && part.trim().length > 0
    );
    items.push(
      dropParts.length > 0
        ? t('detector-meta-spamhaus-drop', { value: dropParts.join(' · ') })
        : t('detector-meta-spamhaus-drop-listed')
    );
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
    items.push(t('detector-meta-category', { value: normalisedCategory }));
  }
  if (row.matchedCidr && !row.dropCidr) items.push(t('detector-meta-prefix', { value: row.matchedCidr }));
  if (Array.isArray(row.sources) && row.sources.length > 0) {
    items.push(t('detector-meta-sources', { value: row.sources.join(', ') }));
  }
  if (row.provider === 'StopForumSpam' || row.frequency !== undefined || row.confidence !== undefined) {
    if (row.frequency !== undefined && row.frequency !== null) {
      items.push(t('detector-meta-frequency', { value: row.frequency }));
    }
    if (row.confidence !== undefined && row.confidence !== null) {
      items.push(t('detector-meta-confidence', { value: row.confidence }));
    }
  }
  if (row.provider === 'DShield' || row.attacks !== undefined || row.count !== undefined) {
    if (row.attacks !== undefined && row.attacks !== null) {
      items.push(t('detector-meta-attacks', { value: row.attacks }));
    }
    if (row.count !== undefined && row.count !== null) {
      items.push(t('detector-meta-targets', { value: row.count }));
    }
    if (Array.isArray(row.threatfeeds) && row.threatfeeds.length > 0) {
      items.push(t('detector-meta-feeds', { value: row.threatfeeds.join(', ') }));
    }
  }
  if (row.carrier) items.push(t('detector-meta-carrier', { value: row.carrier }));
  if (row.mobileBrand) items.push(t('detector-meta-mobile-brand', { value: row.mobileBrand }));
  if (row.coreVerdict) items.push(t('detector-meta-core-verdict', { value: row.coreVerdict }));
  if (Array.isArray(row.coreSources) && row.coreSources.length > 0) {
    items.push(t('detector-meta-core-sources', { value: row.coreSources.join(', ') }));
  }
  if (row.networkRole) items.push(t('detector-meta-network-role', { value: row.networkRole }));
  const rowSharedProvider = row.sharedProvider || row.cloudProvider;
  if (rowSharedProvider) {
    items.push(
      row.sharedCategory
        ? t('detector-meta-shared-egress-category', {
            provider: rowSharedProvider,
            category: row.sharedCategory,
          })
        : t('detector-meta-shared-egress', { value: rowSharedProvider })
    );
  }
  if (row.provider === 'AbuseIPDB' || row.totalReports !== undefined || row.numDistinctUsers !== undefined) {
    if (row.totalReports !== undefined && row.totalReports !== null) {
      items.push(t('detector-meta-reports', { value: row.totalReports }));
    }
    if (row.numDistinctUsers !== undefined && row.numDistinctUsers !== null) {
      items.push(t('detector-meta-distinct-users', { value: row.numDistinctUsers }));
    }
  }
  const lastSeenValue = row.lastSeen || row.maxDate;
  if (lastSeenValue) items.push(t('detector-meta-last-seen', { value: lastSeenValue }));
  if (row.offlineDbUpdatedAt) {
    items.push(
      t('detector-meta-offline-db', {
        value: formatOfflineDbTimestamp(row.offlineDbUpdatedAt, props.nowTimestampMs),
      })
    );
  }
  if (row.isHistoricalFallback) items.push(t('detector-meta-historical-fallback'));
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
  if (data.confirmedResidentialProxy) {
    signals.push(`Confirmed Residential Proxy: ${data.confirmedResidentialProxyProvider || 'Oxylabs'}`);
  }
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
