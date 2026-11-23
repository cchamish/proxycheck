<template>
  <cdx-dialog
    v-model:open="dialogOpen"
    title="API Quota &amp; Health"
    subtitle="Anonymised backend quota usage, reactive cooldowns, and daily request telemetry"
    :use-close-button="true"
    :default-action="{ label: 'Close' }"
    class="provider-dashboard-dialog"
    @default="dialogOpen = false"
  >
    <div class="dashboard">
      <div class="dashboard__toolbar">
        <div class="inline-group">
          <cdx-info-chip :status="snapshot?.redisAvailable ? 'success' : 'warning'">
            {{ snapshot?.redisAvailable ? 'Redis Connected' : 'Redis Unavailable (Fail-open)' }}
          </cdx-info-chip>
          <span v-if="generatedTimestamp" class="text-subtle">
            Updated {{ generatedTimestamp }}
          </span>
        </div>
        <cdx-button
          action="progressive"
          size="small"
          :disabled="isLoading"
          @click="loadDashboard"
        >
          {{ isLoading ? 'Refreshing...' : 'Refresh' }}
        </cdx-button>
      </div>

      <cdx-message v-if="errorMessage" type="error" :inline="false">
        {{ errorMessage }}
      </cdx-message>

      <div v-if="snapshot" class="kpi-grid">
        <div class="kpi">
          <span class="kpi__label">Total Requests Today</span>
          <strong class="kpi__value">{{ formatCount(snapshot.global.totalRequestsToday) }}</strong>
          <span class="text-subtle">
            Session: {{ formatCount(snapshot.global.authSession) }} &middot;
            Gadget: {{ formatCount(snapshot.global.authGadget) }}
          </span>
        </div>

        <div class="kpi">
          <span class="kpi__label">Full Cache Hit Rate</span>
          <strong class="kpi__value">{{ snapshot.global.fullCacheHitRatePercent.toFixed(1) }}%</strong>
          <span class="text-subtle">
            Hit: {{ formatCount(snapshot.global.cacheHit) }} &middot;
            Partial: {{ formatCount(snapshot.global.cachePartial) }} &middot;
            Miss: {{ formatCount(snapshot.global.cacheMiss) }}
          </span>
        </div>

        <div class="kpi">
          <span class="kpi__label">Proactive Quota Blocks Today</span>
          <strong
            class="kpi__value"
            :class="{ 'text-warning': snapshot.global.totalQuotaBlocksToday > 0 }"
          >
            {{ formatCount(snapshot.global.totalQuotaBlocksToday) }}
          </strong>
          <span class="text-subtle">
            Active local guards: {{ formatCount(snapshot.global.activeQuotaGuardCount) }}
          </span>
        </div>

        <div class="kpi">
          <span class="kpi__label">Active Reactive Cooldowns</span>
          <strong
            class="kpi__value"
            :class="{ 'text-warning': snapshot.global.activeCooldownCount > 0 }"
          >
            {{ formatCount(snapshot.global.activeCooldownCount) }}
          </strong>
          <span class="text-subtle">Upstream 429 or 5xx circuit breakers</span>
        </div>
      </div>

      <section v-if="snapshot" class="dashboard__section">
        <h3 class="card-heading">Dual-Layer Cache &amp; SWR Telemetry</h3>
        <div class="kpi-grid">
          <div class="kpi">
            <span class="kpi__label">Dual-Layer Cache Hit Rate</span>
            <strong class="kpi__value">{{ cacheTelemetry.dualLayerHitRatePercent.toFixed(1) }}%</strong>
            <span class="text-subtle">
              L1 Hit: {{ formatCount(cacheTelemetry.l1Hit) }} &middot;
              Upstream Miss: {{ formatCount(cacheTelemetry.upstreamMiss) }}
            </span>
          </div>

          <div class="kpi">
            <span class="kpi__label">ToolsDB L2 Hits (Fresh vs Stale)</span>
            <strong class="kpi__value">
              {{ formatCount(cacheTelemetry.l2HitFresh + cacheTelemetry.l2HitStaleSwr) }}
            </strong>
            <span class="text-subtle">
              Fresh (&le;90d): {{ formatCount(cacheTelemetry.l2HitFresh) }} &middot;
              Stale SWR (&gt;90d): {{ formatCount(cacheTelemetry.l2HitStaleSwr) }}
            </span>
          </div>

          <div class="kpi">
            <span class="kpi__label">ToolsDB L2 Estimated Rows</span>
            <strong class="kpi__value">
              {{ cacheTelemetry.l2EstimatedRows !== null ? formatCount(cacheTelemetry.l2EstimatedRows) : 'Unavailable' }}
            </strong>
            <span class="text-subtle">Persistent MariaDB IP intelligence records</span>
          </div>

          <div class="kpi">
            <span class="kpi__label">SWR &amp; Manual Refreshes</span>
            <strong
              class="kpi__value"
              :class="{ 'text-warning': cacheTelemetry.refreshRateLimited > 0 }"
            >
              {{ formatCount(cacheTelemetry.refreshOk) }}
            </strong>
            <span class="text-subtle">
              OK: {{ formatCount(cacheTelemetry.refreshOk) }} &middot;
              429 Rate-Limited: {{ formatCount(cacheTelemetry.refreshRateLimited) }}
            </span>
          </div>
        </div>
      </section>

      <cdx-table
        v-if="snapshot"
        caption="Provider quota and health"
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
            <span>{{ formatQuotaPair(row.minuteUsed, row.minuteLimit, 'req/min') }}</span>
            <template v-if="row.minuteLimit > 0">
              <cdx-info-chip
                v-if="getQuotaChipStatus(row.minuteUsed, row.minuteLimit)"
                :status="getQuotaChipStatus(row.minuteUsed, row.minuteLimit)!"
                :aria-label="`${row.name} minute quota usage`"
              >
                {{ computeQuotaUsagePercent(row.minuteUsed, row.minuteLimit) }}%
              </cdx-info-chip>
              <span v-else>({{ computeQuotaUsagePercent(row.minuteUsed, row.minuteLimit) }}%)</span>
            </template>
          </span>
        </template>
        <template #item-dailyQuota="{ row }">
          <span class="table-cell-inline">
            <span>{{ formatQuotaPair(row.dailyUsed, row.dailyLimit, 'req/day') }}</span>
            <template v-if="row.dailyLimit > 0">
              <cdx-info-chip
                v-if="getQuotaChipStatus(row.dailyUsed, row.dailyLimit)"
                :status="getQuotaChipStatus(row.dailyUsed, row.dailyLimit)!"
                :aria-label="`${row.name} daily quota usage`"
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
              title="Upstream HTTP 429 responses today"
            >
              429
            </cdx-info-chip>
            <cdx-info-chip
              v-if="row.telemetry.quotaBlocked > 0"
              status="warning"
              title="Proactive local quota blocks today"
            >
              Blocked
            </cdx-info-chip>
            <span v-if="row.telemetry.error5xx > 0 || row.telemetry.timeout > 0" class="text-subtle">
              5xx: {{ formatCount(row.telemetry.error5xx) }} &middot;
              Timeouts: {{ formatCount(row.telemetry.timeout) }}
            </span>
          </span>
        </template>
      </cdx-table>

      <section v-if="snapshot?.offlineDatabases?.length" class="dashboard__section">
        <cdx-table
          caption="Offline Databases Status"
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

const providerColumns: TableColumn[] = [
  { id: 'name', label: 'Provider' },
  { id: 'status', label: 'Status' },
  { id: 'minuteQuota', label: 'Minute quota', minWidth: '150px' },
  { id: 'dailyQuota', label: 'Daily quota', minWidth: '150px' },
  { id: 'upstream', label: 'Upstream remaining' },
  { id: 'telemetry', label: 'OK / cache hit / 429 / quota blocked', minWidth: '240px' },
];

const offlineDbColumns: TableColumn[] = [
  { id: 'name', label: 'Database' },
  { id: 'filename', label: 'File' },
  { id: 'status', label: 'Status' },
  { id: 'size', label: 'Size' },
  { id: 'mtime', label: 'Last updated (mtime)' },
];

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
  return limit <= 0 ? `${formatCount(used)} (Unlimited)` : `${formatCount(used)} / ${formatCount(limit)} ${unit}`;
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
      return `${row.upstreamRemaining.toLocaleString('en-GB')} / ${row.upstreamLimit.toLocaleString('en-GB')} left`;
    }
    return `${row.upstreamRemaining.toLocaleString('en-GB')} left`;
  }
  if (row.upstreamUsed !== null && row.upstreamUsed !== undefined) {
    return `${row.upstreamUsed.toLocaleString('en-GB')} used`;
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
      errorMessage.value = errData.error || 'You are not authorised to view this diagnostic dashboard.';
      if (res.status === 401) emit('unauthorised');
      return;
    }
    if (!res.ok) {
      const errData = (await res.json().catch(() => ({}))) as { error?: string };
      errorMessage.value = errData.error || `Failed to load quota telemetry (HTTP ${res.status}).`;
      return;
    }
    snapshot.value = (await res.json()) as ProviderDashboardResponse;
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') return;
    errorMessage.value = 'Unable to reach the backend quota telemetry endpoint.';
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
