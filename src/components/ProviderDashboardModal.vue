<template>
  <cdx-dialog
    v-model:open="dialogOpen"
    :title="t('dashboard-title')"
    :subtitle="t('dashboard-subtitle')"
    :use-close-button="true"
    :default-action="{ label: t('common-close') }"
    class="provider-dashboard-dialog"
    @default="dialogOpen = false"
  >
    <div class="dashboard">
      <div class="dashboard__toolbar">
        <div class="inline-group">
          <cdx-info-chip :status="snapshot?.redisAvailable ? 'success' : 'warning'">
            {{ snapshot?.redisAvailable ? t('dashboard-redis-connected') : t('dashboard-redis-unavailable') }}
          </cdx-info-chip>
          <span v-if="generatedTimestamp" class="text-subtle">
            {{ t('dashboard-updated', { timestamp: generatedTimestamp }) }}
          </span>
        </div>
        <cdx-button
          action="progressive"
          size="small"
          :disabled="isLoading"
          @click="loadDashboard"
        >
          {{ isLoading ? t('dashboard-refreshing') : t('dashboard-refresh') }}
        </cdx-button>
      </div>

      <cdx-message v-if="errorMessage" type="error" :inline="false">
        {{ errorMessage }}
      </cdx-message>

      <div v-if="snapshot" class="kpi-grid">
        <div class="kpi">
          <span class="kpi__label">{{ t('dashboard-kpi-requests') }}</span>
          <strong class="kpi__value">{{ formatCount(snapshot.global.totalRequestsToday) }}</strong>
          <span class="text-subtle">
            {{ t('dashboard-kpi-session', { count: formatCount(snapshot.global.authSession) }) }} &middot;
            {{ t('dashboard-kpi-gadget', { count: formatCount(snapshot.global.authGadget) }) }}
          </span>
        </div>

        <div class="kpi">
          <span class="kpi__label">{{ t('dashboard-kpi-cache-rate') }}</span>
          <strong class="kpi__value">{{ snapshot.global.fullCacheHitRatePercent.toFixed(1) }}%</strong>
          <span class="text-subtle">
            {{ t('dashboard-kpi-hit', { count: formatCount(snapshot.global.cacheHit) }) }} &middot;
            {{ t('dashboard-kpi-partial', { count: formatCount(snapshot.global.cachePartial) }) }} &middot;
            {{ t('dashboard-kpi-miss', { count: formatCount(snapshot.global.cacheMiss) }) }}
          </span>
        </div>

        <div class="kpi">
          <span class="kpi__label">{{ t('dashboard-kpi-quota-blocks') }}</span>
          <strong
            class="kpi__value"
            :class="{ 'text-warning': snapshot.global.totalQuotaBlocksToday > 0 }"
          >
            {{ formatCount(snapshot.global.totalQuotaBlocksToday) }}
          </strong>
          <span class="text-subtle">
            {{ t('dashboard-kpi-local-guards', { count: formatCount(snapshot.global.activeQuotaGuardCount) }) }}
          </span>
        </div>

        <div class="kpi">
          <span class="kpi__label">{{ t('dashboard-kpi-cooldowns') }}</span>
          <strong
            class="kpi__value"
            :class="{ 'text-warning': snapshot.global.activeCooldownCount > 0 }"
          >
            {{ formatCount(snapshot.global.activeCooldownCount) }}
          </strong>
          <span class="text-subtle">{{ t('dashboard-kpi-circuit-breakers') }}</span>
        </div>
      </div>

      <section v-if="snapshot" class="dashboard__section">
        <h3 class="card-heading">{{ t('dashboard-section-cache') }}</h3>
        <div class="kpi-grid">
          <div class="kpi">
            <span class="kpi__label">{{ t('dashboard-kpi-dual-layer-rate') }}</span>
            <strong class="kpi__value">{{ cacheTelemetry.dualLayerHitRatePercent.toFixed(1) }}%</strong>
            <span class="text-subtle">
              {{ t('dashboard-kpi-l1-hit', { count: formatCount(cacheTelemetry.l1Hit) }) }} &middot;
              {{ t('dashboard-kpi-upstream-miss', { count: formatCount(cacheTelemetry.upstreamMiss) }) }}
            </span>
          </div>

          <div class="kpi">
            <span class="kpi__label">{{ t('dashboard-kpi-l2-hits') }}</span>
            <strong class="kpi__value">
              {{ formatCount(cacheTelemetry.l2HitFresh + cacheTelemetry.l2HitStaleSwr) }}
            </strong>
            <span class="text-subtle">
              {{ t('dashboard-kpi-l2-fresh', { count: formatCount(cacheTelemetry.l2HitFresh) }) }} &middot;
              {{ t('dashboard-kpi-l2-stale', { count: formatCount(cacheTelemetry.l2HitStaleSwr) }) }}
            </span>
          </div>

          <div class="kpi">
            <span class="kpi__label">{{ t('dashboard-kpi-l2-rows') }}</span>
            <strong class="kpi__value">
              {{ cacheTelemetry.l2EstimatedRows !== null ? formatCount(cacheTelemetry.l2EstimatedRows) : t('dashboard-kpi-unavailable') }}
            </strong>
            <span class="text-subtle">{{ t('dashboard-kpi-l2-subtitle') }}</span>
          </div>

          <div class="kpi">
            <span class="kpi__label">{{ t('dashboard-kpi-refreshes') }}</span>
            <strong
              class="kpi__value"
              :class="{ 'text-warning': cacheTelemetry.refreshRateLimited > 0 }"
            >
              {{ formatCount(cacheTelemetry.refreshOk) }}
            </strong>
            <span class="text-subtle">
              {{ t('dashboard-kpi-refresh-ok', { count: formatCount(cacheTelemetry.refreshOk) }) }} &middot;
              {{ t('dashboard-kpi-refresh-429', { count: formatCount(cacheTelemetry.refreshRateLimited) }) }}
            </span>
          </div>
        </div>
      </section>

      <cdx-table
        v-if="snapshot"
        :caption="t('dashboard-providers-caption')"
        :hide-caption="true"
        :columns="providerColumns"
        :data="snapshot.providers"
      >
        <template #item-name="{ row }">
          <strong>{{ row.name }}</strong>
        </template>
        <template #item-status="{ row }">
          <cdx-info-chip
            :status="getProviderChipStatus(row as ProviderDashboardRow)"
            :title="row.cooldownReason || undefined"
          >
            {{ row.status }}
          </cdx-info-chip>
        </template>
        <template #item-minuteQuota="{ row }">
          <span class="table-cell-inline">
            <span>{{ formatQuotaPair(row.minuteUsed, row.minuteLimit, t('dashboard-quota-unit-min')) }}</span>
            <template v-if="row.minuteLimit > 0">
              <cdx-info-chip
                v-if="getQuotaChipStatus(row.minuteUsed, row.minuteLimit)"
                :status="getQuotaChipStatus(row.minuteUsed, row.minuteLimit)!"
                :aria-label="t('dashboard-quota-minute-aria', { provider: row.name })"
              >
                {{ computeQuotaUsagePercent(row.minuteUsed, row.minuteLimit) }}%
              </cdx-info-chip>
              <span v-else>({{ computeQuotaUsagePercent(row.minuteUsed, row.minuteLimit) }}%)</span>
            </template>
          </span>
        </template>
        <template #item-dailyQuota="{ row }">
          <span class="table-cell-inline">
            <span>{{ formatQuotaPair(row.dailyUsed, row.dailyLimit, t('dashboard-quota-unit-day')) }}</span>
            <template v-if="row.dailyLimit > 0">
              <cdx-info-chip
                v-if="getQuotaChipStatus(row.dailyUsed, row.dailyLimit)"
                :status="getQuotaChipStatus(row.dailyUsed, row.dailyLimit)!"
                :aria-label="t('dashboard-quota-daily-aria', { provider: row.name })"
              >
                {{ computeQuotaUsagePercent(row.dailyUsed, row.dailyLimit) }}%
              </cdx-info-chip>
              <span v-else>({{ computeQuotaUsagePercent(row.dailyUsed, row.dailyLimit) }}%)</span>
            </template>
          </span>
        </template>
        <template #item-upstream="{ row }">
          {{ formatUpstreamQuotaLabel(row as ProviderDashboardRow) }}
        </template>
        <template #item-telemetry="{ row }">
          <span class="table-cell-inline">
            <span>
              {{ formatCount(row.telemetry.ok) }} / {{ formatCount(row.telemetry.cacheHit) }} /
              {{ formatCount(row.telemetry.rateLimited429) }} / {{ formatCount(row.telemetry.quotaBlocked) }}
            </span>
            <cdx-info-chip
              v-if="row.telemetry.rateLimited429 > 0"
              status="warning"
              :title="t('dashboard-telemetry-429-title')"
            >
              429
            </cdx-info-chip>
            <cdx-info-chip
              v-if="row.telemetry.quotaBlocked > 0"
              status="warning"
              :title="t('dashboard-telemetry-blocked-title')"
            >
              {{ t('dashboard-telemetry-blocked') }}
            </cdx-info-chip>
            <span v-if="row.telemetry.error5xx > 0 || row.telemetry.timeout > 0" class="text-subtle">
              {{ t('dashboard-telemetry-5xx', { count: formatCount(row.telemetry.error5xx) }) }} &middot;
              {{ t('dashboard-telemetry-timeouts', { count: formatCount(row.telemetry.timeout) }) }}
            </span>
          </span>
        </template>
      </cdx-table>

      <section v-if="snapshot?.offlineDatabases?.length" class="dashboard__section">
        <cdx-table
          :caption="t('dashboard-offline-caption')"
          :columns="offlineDbColumns"
          :data="snapshot.offlineDatabases"
        >
          <template #item-filename="{ row }">
            <code>{{ row.filename }}</code>
          </template>
          <template #item-status="{ row }">
            <cdx-info-chip :status="getOfflineDbChipStatus(row as OfflineDatabaseEntry)">
              {{ row.statusLabel }}
            </cdx-info-chip>
          </template>
          <template #item-size="{ row }">
            {{ formatByteSize(row.sizeBytes) }}
          </template>
          <template #item-mtime="{ row }">
            {{ formatOfflineDbTimestamp(row.lastModifiedIso, Date.now(), row.ageSeconds) }}
          </template>
        </cdx-table>
      </section>
    </div>
  </cdx-dialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import {
  CdxButton,
  CdxDialog,
  CdxInfoChip,
  CdxMessage,
  CdxTable,
  type TableColumn,
} from '@wikimedia/codex';
import { formatOfflineDbTimestamp, type ChipStatus } from '../utils/ip-detector-logic';
import { useI18n } from '../utils/i18n';

const { t } = useI18n();

interface OfflineDatabaseEntry {
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

interface ProviderDashboardTelemetry {
  ok: number;
  cacheHit: number;
  rateLimited429: number;
  error5xx: number;
  timeout: number;
  quotaBlocked: number;
}

interface ProviderDashboardRow {
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

interface ProviderDashboardCacheTelemetry {
  l1Hit: number;
  l2HitFresh: number;
  l2HitStaleSwr: number;
  upstreamMiss: number;
  refreshOk: number;
  refreshRateLimited: number;
  dualLayerHitRatePercent: number;
  l2EstimatedRows: number | null;
}

interface ProviderDashboardResponse {
  generatedAt: string;
  dateBucket: string;
  redisAvailable: boolean;
  cacheTelemetry?: Partial<ProviderDashboardCacheTelemetry>;
  global: {
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
  };
  providers: ProviderDashboardRow[];
  offlineDatabases?: OfflineDatabaseEntry[];
  durationSeconds?: number;
  memoryMb?: number | null;
}

const providerColumns = computed<TableColumn[]>(() => [
  { id: 'name', label: t('dashboard-col-provider') },
  { id: 'status', label: t('dashboard-col-status') },
  { id: 'minuteQuota', label: t('dashboard-col-minute-quota'), minWidth: '150px' },
  { id: 'dailyQuota', label: t('dashboard-col-daily-quota'), minWidth: '150px' },
  { id: 'upstream', label: t('dashboard-col-upstream') },
  { id: 'telemetry', label: t('dashboard-col-telemetry'), minWidth: '240px' },
]);

const offlineDbColumns = computed<TableColumn[]>(() => [
  { id: 'name', label: t('dashboard-col-database') },
  { id: 'filename', label: t('dashboard-col-file') },
  { id: 'status', label: t('dashboard-col-status') },
  { id: 'size', label: t('dashboard-col-size') },
  { id: 'mtime', label: t('dashboard-col-mtime') },
]);

const props = defineProps<{
  open: boolean;
}>();

const emit = defineEmits<{
  (event: 'update:open', value: boolean): void;
  (event: 'unauthorised'): void;
}>();

const dialogOpen = computed({
  get: () => props.open,
  set: (value: boolean) => emit('update:open', value),
});

const isLoading = ref(false);
const errorMessage = ref('');
const snapshot = ref<ProviderDashboardResponse | null>(null);
let activeController: AbortController | null = null;

const generatedTimestamp = computed(() => {
  const isoValue = snapshot.value?.generatedAt;
  if (!isoValue) return '';
  const parsed = new Date(isoValue);
  return Number.isNaN(parsed.getTime()) ? isoValue : `${parsed.toISOString().slice(11, 19)} UTC`;
});

const cacheTelemetry = computed<ProviderDashboardCacheTelemetry>(() => {
  const ct = snapshot.value?.cacheTelemetry;
  const globalMetrics = snapshot.value?.global;
  const nonNeg = (value: unknown): number => {
    const num = Number(value ?? 0);
    return Number.isFinite(num) && num >= 0 ? num : 0;
  };
  const rawEstimatedRows =
    ct?.l2EstimatedRows !== undefined ? ct.l2EstimatedRows : globalMetrics?.l2EstimatedRows;

  return {
    l1Hit: nonNeg(ct?.l1Hit ?? globalMetrics?.l1Hit),
    l2HitFresh: nonNeg(ct?.l2HitFresh ?? globalMetrics?.l2HitFresh),
    l2HitStaleSwr: nonNeg(ct?.l2HitStaleSwr ?? globalMetrics?.l2HitStaleSwr),
    upstreamMiss: nonNeg(ct?.upstreamMiss ?? globalMetrics?.upstreamMiss),
    refreshOk: nonNeg(ct?.refreshOk ?? globalMetrics?.refreshOk),
    refreshRateLimited: nonNeg(ct?.refreshRateLimited ?? globalMetrics?.refreshRateLimited),
    dualLayerHitRatePercent: nonNeg(ct?.dualLayerHitRatePercent ?? globalMetrics?.dualLayerHitRatePercent),
    l2EstimatedRows:
      typeof rawEstimatedRows === 'number' && Number.isFinite(rawEstimatedRows) && rawEstimatedRows >= 0
        ? Math.floor(rawEstimatedRows)
        : null,
  };
});

function formatCount(value: number | null | undefined): string {
  const num = Number(value ?? 0);
  return Number.isFinite(num) ? num.toLocaleString('en-GB') : '0';
}

function formatQuotaPair(used: number, limit: number, unit: string): string {
  return limit <= 0
    ? t('dashboard-quota-unlimited', { used: formatCount(used) })
    : `${formatCount(used)} / ${formatCount(limit)} ${unit}`;
}

function computeQuotaUsagePercent(used: number, limit: number): number {
  if (!Number.isFinite(used) || !Number.isFinite(limit) || limit <= 0 || used <= 0) return 0;
  return Math.min(100, Math.round((used / limit) * 100));
}

function getQuotaChipStatus(used: number, limit: number): ChipStatus | null {
  if (limit <= 0 || used / limit < 0.7) return null;
  return used >= limit ? 'error' : 'warning';
}

function getProviderChipStatus(row: ProviderDashboardRow): ChipStatus {
  if (row.statusKey === 'healthy') return 'success';
  if (row.statusKey === 'no_api_key' || row.statusKey === 'db_missing') return 'notice';
  return 'warning';
}

function getOfflineDbChipStatus(entry: OfflineDatabaseEntry): ChipStatus {
  if (entry.status === 'healthy') return 'success';
  if (entry.status === 'stale') return 'warning';
  return entry.optional ? 'notice' : 'error';
}

function formatUpstreamQuotaLabel(row: ProviderDashboardRow): string {
  if (row.upstreamRemaining !== null && row.upstreamRemaining !== undefined) {
    if (row.upstreamLimit !== null && row.upstreamLimit !== undefined && row.upstreamLimit > 0) {
      return t('dashboard-upstream-left-of', {
        remaining: row.upstreamRemaining.toLocaleString('en-GB'),
        limit: row.upstreamLimit.toLocaleString('en-GB'),
      });
    }
    return t('dashboard-upstream-left', { remaining: row.upstreamRemaining.toLocaleString('en-GB') });
  }
  if (row.upstreamUsed !== null && row.upstreamUsed !== undefined) {
    return t('dashboard-upstream-used', { used: row.upstreamUsed.toLocaleString('en-GB') });
  }
  return '-';
}

function formatByteSize(sizeBytes?: number | null): string {
  if (typeof sizeBytes !== 'number' || !Number.isFinite(sizeBytes) || sizeBytes < 0) return '-';
  if (sizeBytes < 1024) return `${Math.round(sizeBytes)} B`;
  if (sizeBytes < 1024 * 1024) return `${(sizeBytes / 1024).toFixed(1)} KB`;
  if (sizeBytes < 1024 * 1024 * 1024) return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(sizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function loadDashboard(): Promise<void> {
  activeController?.abort();
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  activeController = controller;

  isLoading.value = true;
  errorMessage.value = '';
  try {
    const res = await fetch('/api/v1/admin/provider-dashboard', {
      cache: 'no-store',
      signal: controller?.signal,
    });
    if (res.status === 401 || res.status === 403) {
      const errData = (await res.json().catch(() => ({}))) as { error?: string };
      errorMessage.value = errData.error || t('dashboard-error-unauthorised');
      if (res.status === 401) emit('unauthorised');
      return;
    }
    if (!res.ok) {
      const errData = (await res.json().catch(() => ({}))) as { error?: string };
      errorMessage.value = errData.error || t('dashboard-error-load-http', { status: res.status });
      return;
    }
    snapshot.value = (await res.json()) as ProviderDashboardResponse;
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') return;
    errorMessage.value = t('dashboard-error-unreachable');
  } finally {
    if (activeController === controller) {
      isLoading.value = false;
    }
  }
}

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      void loadDashboard();
    } else {
      activeController?.abort();
      activeController = null;
    }
  }
);

onUnmounted(() => {
  activeController?.abort();
  activeController = null;
});
</script>
