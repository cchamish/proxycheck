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
          <span v-if="snapshot?.generatedAt" class="text-subtle">
            Updated {{ formatGeneratedTimestamp(snapshot.generatedAt) }}
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
import {
  computeQuotaUsagePercent,
  formatByteSize,
  formatOfflineDbTimestamp,
  formatUpstreamQuotaLabel,
  resolveDashboardCacheTelemetry,
  type ChipStatus,
  type OfflineDatabaseEntry,
  type ProviderDashboardResponse,
  type ProviderDashboardRow,
} from '../utils/ip-detector-logic';

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
const cacheTelemetry = computed(() => resolveDashboardCacheTelemetry(snapshot.value));
let activeController: AbortController | null = null;

function formatCount(value: number | null | undefined): string {
  const num = Number(value ?? 0);
  return Number.isFinite(num) ? num.toLocaleString('en-GB') : '0';
}

function formatQuotaPair(used: number, limit: number, unit: string): string {
  if (limit <= 0) {
    return `${formatCount(used)} (Unlimited)`;
  }
  return `${formatCount(used)} / ${formatCount(limit)} ${unit}`;
}

function formatGeneratedTimestamp(isoValue: string): string {
  const parsed = new Date(isoValue);
  if (Number.isNaN(parsed.getTime())) {
    return isoValue;
  }
  return `${parsed.toISOString().slice(11, 19)} UTC`;
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

async function loadDashboard(): Promise<void> {
  if (activeController) {
    activeController.abort();
  }
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
      const errData = await res.json().catch(() => ({}));
      errorMessage.value = errData?.error || 'You are not authorised to view this diagnostic dashboard.';
      if (res.status === 401) {
        emit('unauthorised');
      }
      return;
    }
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      errorMessage.value = errData?.error || `Failed to load quota telemetry (HTTP ${res.status}).`;
      return;
    }
    snapshot.value = (await res.json()) as ProviderDashboardResponse;
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      return;
    }
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
      loadDashboard();
    } else if (activeController) {
      activeController.abort();
      activeController = null;
    }
  }
);

onUnmounted(() => {
  if (activeController) {
    activeController.abort();
    activeController = null;
  }
});
</script>
