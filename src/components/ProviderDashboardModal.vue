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
    <div class="dashboard-modal-content">
      <div class="dashboard-toolbar">
        <div class="dashboard-meta">
          <span
            class="cdx-badge"
            :class="snapshot?.redisAvailable ? 'badge-success' : 'badge-warning'"
          >
            {{ snapshot?.redisAvailable ? 'Redis Connected' : 'Redis Unavailable (Fail-open)' }}
          </span>
          <span v-if="snapshot?.generatedAt" class="dashboard-updated-text">
            Updated {{ formatGeneratedTimestamp(snapshot.generatedAt) }}
          </span>
        </div>
        <cdx-button
          action="progressive"
          weight="normal"
          size="small"
          :disabled="isLoading"
          @click="loadDashboard"
        >
          {{ isLoading ? 'Refreshing...' : 'Refresh' }}
        </cdx-button>
      </div>

      <cdx-message
        v-if="errorMessage"
        type="error"
        :inline="false"
        class="dashboard-alert"
      >
        {{ errorMessage }}
      </cdx-message>

      <div v-if="snapshot" class="dashboard-kpi-grid">
        <div class="dashboard-kpi-card">
          <span class="kpi-label">Total Requests Today</span>
          <strong class="kpi-value">{{ formatCount(snapshot.global.totalRequestsToday) }}</strong>
          <span class="kpi-subtext">
            Session: {{ formatCount(snapshot.global.authSession) }} &middot;
            Gadget: {{ formatCount(snapshot.global.authGadget) }}
          </span>
        </div>

        <div class="dashboard-kpi-card">
          <span class="kpi-label">Full Cache Hit Rate</span>
          <strong class="kpi-value">{{ snapshot.global.fullCacheHitRatePercent.toFixed(1) }}%</strong>
          <span class="kpi-subtext">
            Hit: {{ formatCount(snapshot.global.cacheHit) }} &middot;
            Partial: {{ formatCount(snapshot.global.cachePartial) }} &middot;
            Miss: {{ formatCount(snapshot.global.cacheMiss) }}
          </span>
        </div>

        <div class="dashboard-kpi-card">
          <span class="kpi-label">Proactive Quota Blocks Today</span>
          <strong
            class="kpi-value"
            :class="{ 'kpi-value--warning': snapshot.global.totalQuotaBlocksToday > 0 }"
          >
            {{ formatCount(snapshot.global.totalQuotaBlocksToday) }}
          </strong>
          <span class="kpi-subtext">
            Active local guards: {{ formatCount(snapshot.global.activeQuotaGuardCount) }}
          </span>
        </div>

        <div class="dashboard-kpi-card">
          <span class="kpi-label">Active Reactive Cooldowns</span>
          <strong
            class="kpi-value"
            :class="{ 'kpi-value--warning': snapshot.global.activeCooldownCount > 0 }"
          >
            {{ formatCount(snapshot.global.activeCooldownCount) }}
          </strong>
          <span class="kpi-subtext">
            Upstream 429 or 5xx circuit breakers
          </span>
        </div>
      </div>

      <div v-if="snapshot" class="dashboard-table-wrapper">
        <table class="dashboard-table">
          <thead>
            <tr>
              <th scope="col">PROVIDER</th>
              <th scope="col">STATUS</th>
              <th scope="col">MINUTE QUOTA</th>
              <th scope="col">DAILY QUOTA</th>
              <th scope="col">UPSTREAM REMAINING</th>
              <th scope="col">OK / CACHE HIT / 429 / QUOTA BLOCKED</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in snapshot.providers" :key="row.key">
              <td class="dashboard-col-provider">
                <span class="provider-name">{{ row.name }}</span>
              </td>

              <td>
                <span
                  class="cdx-badge"
                  :class="getProviderStatusClass(row)"
                  :title="row.cooldownReason || undefined"
                >
                  {{ row.status }}
                </span>
              </td>

              <td class="dashboard-col-quota">
                <div class="quota-metric-header">
                  <span class="quota-metric-value">
                    {{ formatQuotaPair(row.minuteUsed, row.minuteLimit, 'req/min') }}
                  </span>
                </div>
                <div
                  v-if="row.minuteLimit > 0"
                  class="quota-progress-track"
                  role="progressbar"
                  :aria-valuenow="row.minuteUsed"
                  aria-valuemin="0"
                  :aria-valuemax="row.minuteLimit"
                  :aria-label="`${row.name} minute quota usage`"
                >
                  <div
                    class="quota-progress-fill"
                    :class="`quota-progress-fill--${getQuotaProgressTone(row.minuteUsed, row.minuteLimit)}`"
                    :style="{ width: `${computeQuotaUsagePercent(row.minuteUsed, row.minuteLimit)}%` }"
                  />
                </div>
              </td>

              <td class="dashboard-col-quota">
                <div class="quota-metric-header">
                  <span class="quota-metric-value">
                    {{ formatQuotaPair(row.dailyUsed, row.dailyLimit, 'req/day') }}
                  </span>
                </div>
                <div
                  v-if="row.dailyLimit > 0"
                  class="quota-progress-track"
                  role="progressbar"
                  :aria-valuenow="row.dailyUsed"
                  aria-valuemin="0"
                  :aria-valuemax="row.dailyLimit"
                  :aria-label="`${row.name} daily quota usage`"
                >
                  <div
                    class="quota-progress-fill"
                    :class="`quota-progress-fill--${getQuotaProgressTone(row.dailyUsed, row.dailyLimit)}`"
                    :style="{ width: `${computeQuotaUsagePercent(row.dailyUsed, row.dailyLimit)}%` }"
                  />
                </div>
              </td>

              <td class="dashboard-col-upstream">
                <span>{{ formatUpstreamQuotaLabel(row) }}</span>
              </td>

              <td class="dashboard-col-telemetry">
                <div class="telemetry-chip-row">
                  <span class="telemetry-chip telemetry-chip--ok" title="Successful upstream lookups today">
                    OK {{ formatCount(row.telemetry.ok) }}
                  </span>
                  <span class="telemetry-chip telemetry-chip--cache" title="Redis cache hits today">
                    Hit {{ formatCount(row.telemetry.cacheHit) }}
                  </span>
                  <span
                    class="telemetry-chip"
                    :class="row.telemetry.rateLimited429 > 0 ? 'telemetry-chip--warn' : 'telemetry-chip--muted'"
                    title="Upstream HTTP 429 responses today"
                  >
                    429 {{ formatCount(row.telemetry.rateLimited429) }}
                  </span>
                  <span
                    class="telemetry-chip"
                    :class="row.telemetry.quotaBlocked > 0 ? 'telemetry-chip--warn' : 'telemetry-chip--muted'"
                    title="Proactive local quota blocks today"
                  >
                    Blocked {{ formatCount(row.telemetry.quotaBlocked) }}
                  </span>
                </div>
                <div
                  v-if="row.telemetry.error5xx > 0 || row.telemetry.timeout > 0"
                  class="telemetry-extra-line"
                >
                  5xx: {{ formatCount(row.telemetry.error5xx) }} &middot;
                  Timeouts: {{ formatCount(row.telemetry.timeout) }}
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </cdx-dialog>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import { CdxButton, CdxDialog, CdxMessage } from '@wikimedia/codex';
import {
  computeQuotaUsagePercent,
  formatUpstreamQuotaLabel,
  getQuotaProgressTone,
  type ProviderDashboardResponse,
  type ProviderDashboardRow,
} from '../utils/ip-detector-logic';

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

function getProviderStatusClass(row: ProviderDashboardRow): string {
  if (row.statusKey === 'healthy') return 'badge-success';
  if (row.statusKey === 'no_api_key') return 'badge-neutral';
  return 'badge-warning';
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
