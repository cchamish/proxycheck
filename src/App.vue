<template>
  <div class="proxy-detector-layout">
    <header class="cdx-header">
      <div class="header-left">
        <img
          :src="proxycheckLogo"
          alt=""
          class="app-logo"
          aria-hidden="true"
        />
        <h1 class="app-title">Proxy Detector</h1>
      </div>
      <div class="header-right">
        <template v-if="user.isLoggedIn">
          <span class="user-pill">
            {{ user.username }}
          </span>
          <cdx-button
            action="default"
            weight="quiet"
            size="medium"
            @click="handleLogout"
          >
            Log out
          </cdx-button>
        </template>
      </div>
    </header>

    <main class="cdx-main-container">
      <div v-if="!user.isLoggedIn" class="barrier-wrapper">
        <cdx-message
          v-if="sessionExpiredMessage"
          type="warning"
          :inline="false"
          class="unauthorised-message"
        >
          {{ sessionExpiredMessage }}
        </cdx-message>
        <cdx-button
          action="progressive"
          weight="primary"
          size="large"
          class="login-btn"
          @click="handleLogin"
        >
          Log in with Wikimedia
        </cdx-button>
        <p class="login-groups-note">
          This tool is designed for users with either the
          <code>{{ REQUIRED_USER_RIGHTS[0] }}</code> or
          <code>{{ REQUIRED_USER_RIGHTS[1] }}</code> right on any Wikimedia project.
        </p>
      </div>

      <div v-else-if="!user.hasAccess" class="barrier-wrapper">
        <cdx-message
          type="error"
          :inline="false"
          class="unauthorised-message"
        >
          Access Denied: your Wikimedia account is not authorised to use this tool.
        </cdx-message>
      </div>

      <div v-else class="tool-content">
        <div class="search-section">
          <form @submit.prevent="handleSearch" class="search-form">
            <div class="search-input-group">
              <cdx-text-input
                v-model="inputIp"
                placeholder="Enter IPv4 or IPv6 address..."
                size="large"
                class="ip-input"
                :disabled="isLoading"
                aria-label="IP Address Input"
              />
              <cdx-button
                type="submit"
                action="progressive"
                weight="primary"
                size="large"
                :disabled="isLoading || !inputIp.trim()"
              >
                {{ isLoading ? 'Analysing...' : 'Detect' }}
              </cdx-button>
            </div>
          </form>

          <cdx-message
            v-if="validationError"
            type="error"
            :inline="true"
            class="validation-alert"
          >
            {{ validationError }}
          </cdx-message>

          <div v-if="ipHistory.length > 0" class="history-section">
            <span class="history-label">Recent queries:</span>
            <div class="history-pills">
              <button
                v-for="historyIp in ipHistory"
                :key="historyIp"
                type="button"
                class="cdx-pill-tag"
                @click="queryFromHistory(historyIp)"
              >
                {{ historyIp }}
              </button>
            </div>
          </div>
        </div>

        <cdx-card v-if="detectionData" class="executive-overview-card">
          <template #title>
            <h2 class="overview-card-title">Executive Overview</h2>
          </template>
          <template #description>
            <div class="overview-body">
              <div class="overview-gauges">
                <div class="score-gauge-container">
                  <span class="gauge-title">Threat Score</span>
                  <div
                    class="gauge-circle"
                    :class="getScoreTierClass(detectionData.comprehensiveScore ?? 0)"
                  >
                    <span
                      class="gauge-score-value"
                      :class="{ 'gauge-score-value--sm': String(detectionData.comprehensiveScore ?? 0).length > 3 }"
                    >
                      {{ detectionData.comprehensiveScore ?? 0 }}
                    </span>
                    <span class="gauge-score-max">/ 100</span>
                  </div>
                  <span
                    class="gauge-tier-pill cdx-badge"
                    :class="getScoreTierBadge(detectionData.comprehensiveScore ?? 0)"
                  >
                    {{ getScoreTierLabel(detectionData.comprehensiveScore ?? 0) }}
                  </span>
                </div>

                <div class="score-gauge-container prediction-gauge-container">
                  <span class="gauge-title">Prediction</span>
                  <div
                    class="gauge-circle"
                    :class="getPredictionScoreTierClass(detectionData)"
                  >
                    <span
                      class="gauge-score-value"
                      :class="{ 'gauge-score-value--sm': String(formatChance(detectionData.prediction_score)).length > 3 }"
                    >
                      {{ formatChance(detectionData.prediction_score) }}
                    </span>
                    <span class="gauge-score-max">%</span>
                  </div>
                  <div class="prediction-badge-wrapper">
                    <span
                      v-if="detectionData.predictionTier === 'destructive'"
                      class="prediction-badge prediction-badge--destructive"
                    >
                      <span aria-hidden="true">✘</span>
                      {{ detectionData.predictionLabel || 'Proxy / VPN' }}
                    </span>
                    <span
                      v-else-if="detectionData.predictionTier === 'success'"
                      class="prediction-badge prediction-badge--success"
                    >
                      <span aria-hidden="true">✔</span>
                      {{ detectionData.predictionLabel || 'Safe Residential' }}
                    </span>
                    <span
                      v-else
                      class="prediction-badge prediction-badge--neutral"
                    >
                      {{ detectionData.predictionLabel || 'Needs Human Review' }}
                      <template v-if="detectionData.getipintel_chance !== null && detectionData.getipintel_chance !== undefined">
                        ({{ formatChance(detectionData.prediction_score) }}%)
                      </template>
                    </span>
                  </div>
                </div>
              </div>

              <div class="basic-info-container">
                <table class="basic-info-table">
                  <tbody>
                    <tr>
                      <th scope="row">IP ADDRESS</th>
                      <td>
                        <div class="ip-value-wrapper">
                          <span class="ip-text-bold">{{ detectionData.ip }}</span>
                          <span v-if="detectionData.is_broadcast_ip" class="broadcast-ip-badge">
                            Broadcast IP?
                          </span>
                          <span
                            v-if="detectionData.isTor"
                            class="badge-destructive tor-ip-badge"
                            :title="detectionData.torSummary || detectionData.torLabel || 'Tor Relay'"
                          >
                            {{ detectionData.torLabel || (detectionData.torIsExit ? 'Tor Exit' : 'Tor Node') }}
                          </span>
                          <span
                            v-if="detectionData.isTor && detectionData.torSummary"
                            class="tor-summary-text"
                          >
                            {{ detectionData.torSummary }}
                          </span>
                        </div>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">ARBITRATION</th>
                      <td>
                        <span
                          class="arbitration-pill"
                          :class="getArbitrationBadgeClass(detectionData)"
                        >
                          {{ detectionData.arbitrationVerdict || 'Direct Connection (No Commercial Threats)' }}
                        </span>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">PRIMARY COUNTRY</th>
                      <td>{{ detectionData.primaryCountry || '-' }}</td>
                    </tr>
                    <tr>
                      <th scope="row">COORDINATES</th>
                      <td>{{ detectionData.primaryCoordinates || 'Unknown' }}</td>
                    </tr>
                    <tr>
                      <th scope="row">PRIMARY ASN</th>
                      <td>
                        <code class="asn-tag">{{ detectionData.primaryAsn || '-' }}</code>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">REVERSE DNS (PTR)</th>
                      <td>
                        <div class="ip-value-wrapper">
                          <code class="asn-tag">{{ detectionData.ptrHostname || 'No PTR Record' }}</code>
                          <span
                            v-if="detectionData.ptrLabel && detectionData.ptrCategory && detectionData.ptrCategory !== 'none'"
                            class="cdx-badge"
                            :class="getPtrBadgeClass(detectionData)"
                          >
                            {{ detectionData.ptrLabel }}
                          </span>
                        </div>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">RECOMMENDED CIDR</th>
                      <td>
                        <div class="ip-value-wrapper">
                          <code class="asn-tag">{{ detectionData.recommendedCidr || '-' }}</code>
                          <span
                            v-if="detectionData.mmdbCidr && detectionData.mmdbCidr !== detectionData.recommendedCidr"
                            class="text-muted"
                          >
                            (BGP: {{ detectionData.mmdbCidr }})
                          </span>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </template>
        </cdx-card>

        <div v-if="detectionData" class="results-section">
          <div class="results-header">
            <h2 class="results-title">Multi-Source Ground Truth Comparison</h2>
          </div>
          <table class="ground-truth-table">
            <thead>
              <tr>
                <th scope="col">PROVIDER</th>
                <th scope="col" style="width: 120px;">ASN</th>
                <th scope="col">ISP / ORGANISATION</th>
                <th scope="col">LOCATION</th>
                <th scope="col">USAGE TYPE</th>
                <th scope="col">SECURITY FLAGS</th>
                <th scope="col">THREAT SCORE</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in filteredResults" :key="row.provider">
                <td class="col-provider">
                  <div class="provider-cell">
                    <span
                      v-if="getProviderUpdatedLabel(row)"
                      class="provider-updated-time"
                      :title="row.cachedAt || detectionData?.cacheMeta?.cachedAt || undefined"
                    >
                      {{ getProviderUpdatedLabel(row) }}
                    </span>
                    <span class="provider-name">{{ row.provider }}</span>
                    <span
                      class="cdx-badge"
                      :class="getStatusBadgeClass(row.status)"
                    >
                      {{ row.status }}
                    </span>
                  </div>
                </td>

                <td class="col-asn">
                  <code class="asn-tag">{{ row.asn || '-' }}</code>
                </td>

                <td class="col-isp">{{ row.isp || row.organisation || '-' }}</td>

                <td class="col-location">{{ row.location }}</td>

                <td class="col-usage">
                  <span class="usage-text">{{ row.usageType }}</span>
                  <div v-if="getProviderMetaItems(row).length > 0" class="provider-meta-list">
                    <span
                      v-for="meta in getProviderMetaItems(row)"
                      :key="meta"
                      class="provider-meta-item"
                    >
                      {{ meta }}
                    </span>
                  </div>
                </td>

                <td class="col-flags">
                  <div class="flags-container">
                    <span
                      v-for="flag in getSimplifiedFlags(row.securityFlags)"
                      :key="flag.label"
                      class="flag-pill"
                      :class="flag.isHighRisk ? 'flag-high-risk' : 'flag-safe'"
                    >
                      {{ flag.label }}
                    </span>
                  </div>
                </td>

                <td class="col-score">
                  <div v-if="row.threatScore !== null" class="score-display">
                    <span
                      class="score-number"
                      :class="getScoreColorClass(row.threatScore)"
                    >
                      {{ row.threatScore }}
                    </span>
                    <span class="score-scale">/100</span>
                  </div>
                  <span v-else class="text-muted">-</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </main>

    <footer class="cdx-footer">
      <div class="footer-left">
        <span class="diagnostic-text">
          &copy; 2026 &middot;
          <a
            v-if="repoBaseUrl"
            :href="`${repoBaseUrl}/commit/${commitHash}`"
            target="_blank"
            rel="noopener noreferrer"
            class="commit-link"
          >
            {{ commitVersionLabel }}
          </a>
          <span v-else class="commit-link">{{ commitVersionLabel }}</span>
          &middot; {{ formatDiagnosticSummary(footerDiagnostic) }}
          <span v-if="footerDiagnostic.isCached" class="cached-pill">Cached</span>
        </span>
      </div>
      <div class="footer-right">
        <div class="footer-banner">
          <a
            href="https://wikitech.wikimedia.org/wiki/Portal:Toolforge"
            target="_blank"
            rel="noopener noreferrer"
            title="Hosted on Wikimedia Toolforge"
          >
            <img :src="toolforgeLogo" alt="Toolforge" class="footer-logo">
          </a>
          <a
            href="https://wikitech.wikimedia.org/wiki/Help:Cloud_Services_introduction"
            target="_blank"
            rel="noopener noreferrer"
            title="Powered by Wikimedia Cloud Services"
          >
            <img :src="wmcsLogo" alt="Powered by Wikimedia Cloud Services" class="footer-logo">
          </a>
        </div>
      </div>
    </footer>
  </div>
</template>

<script setup lang="ts">
import { reactive, toRefs, ref, computed, watch, onMounted, onUnmounted } from 'vue';
import proxycheckLogo from './assets/Proxycheck.svg';
import toolforgeLogo from './assets/Toolforge.svg';
import wmcsLogo from './assets/WMCS.svg';
import {
  CdxTextInput,
  CdxButton,
  CdxCard,
  CdxMessage,
} from '@wikimedia/codex';
import {
  REQUIRED_USER_RIGHTS,
  buildOAuthLoginUrl,
  buildPageUrlWithIp,
  isValidIpAddress,
  filterComparisonResults,
  simplifySecurityFlags,
  createDetectionCoordinator,
  resolveRepoBaseUrl,
  formatCommitVersionLabel,
  resolveProviderUpdatedLabel,
  buildDiagnosticMetrics,
  formatDiagnosticSummary,
  measureInitialLoadDurationSeconds,
  measureElapsedSeconds,
  type DiagnosticMetrics,
  type DetectionCoordinatorState,
  type DetectionResponse,
  type ProviderRawResult,
} from './utils/ip-detector-logic';

const HISTORY_STORAGE_KEY = 'proxy_detector_ip_history';

function loadStoredHistory(): string[] {
  try {
    const stored = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!stored) {
      return [];
    }
    const parsed: unknown = JSON.parse(stored);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed
      .filter((item): item is string => typeof item === 'string' && isValidIpAddress(item))
      .slice(0, 5);
  } catch {
    return [];
  }
}

function saveStoredHistory(history: string[]): void {
  try {
    localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
  } catch {
    // Ignore storage quota or private-browsing exceptions.
  }
}

const uiState = reactive<DetectionCoordinatorState>({
  isLoading: false,
  validationError: '',
  sessionExpiredMessage: '',
  detectionData: null,
  diagnostic: null,
  user: {
    isLoggedIn: false,
    username: '',
    role: '',
    hasAccess: false,
  },
  ipHistory: loadStoredHistory(),
});

const {
  user,
  isLoading,
  validationError,
  sessionExpiredMessage,
  ipHistory,
  detectionData,
  diagnostic,
} = toRefs(uiState);

const inputIp = ref('');
const commitHash = typeof __COMMIT_HASH__ !== 'undefined' ? __COMMIT_HASH__ : 'dev';
const commitTimestamp = typeof __COMMIT_TIMESTAMP__ !== 'undefined' ? __COMMIT_TIMESTAMP__ : '';
const commitVersionLabel = formatCommitVersionLabel(commitHash, commitTimestamp);
const repoBaseUrl = resolveRepoBaseUrl(import.meta.env.VITE_GITHUB_REPO);
const initialDiagnostic = ref<DiagnosticMetrics>({
  duration: measureInitialLoadDurationSeconds(),
  memory: null,
  isCached: false,
});
const footerDiagnostic = computed<DiagnosticMetrics>(
  () => diagnostic.value ?? initialDiagnostic.value
);

function syncBrowserUrlIp(ip: string | null): void {
  if (typeof window === 'undefined' || !window.history || typeof window.history.replaceState !== 'function') {
    return;
  }
  const nextUrl = buildPageUrlWithIp(window.location.pathname, window.location.search, ip);
  const currentRelativeUrl = `${window.location.pathname}${window.location.search}`;
  if (nextUrl !== currentRelativeUrl) {
    window.history.replaceState(window.history.state, '', nextUrl);
  }
}

const coordinator = createDetectionCoordinator(
  (url, init) => fetch(url, init),
  undefined,
  {
    state: uiState,
    onHistoryUpdated: saveStoredHistory,
    onDetectionSuccess: (resolvedIp) => syncBrowserUrlIp(resolvedIp),
  }
);

const filteredResults = computed(() => {
  if (!detectionData.value || !Array.isArray(detectionData.value.results)) {
    return [];
  }
  return filterComparisonResults(detectionData.value.results);
});

async function executeDetection(ipToQuery: string): Promise<void> {
  await coordinator.executeDetection(ipToQuery);
}

function handleSearch(): void {
  if (inputIp.value) {
    executeDetection(inputIp.value);
  }
}

function queryFromHistory(ip: string): void {
  inputIp.value = ip;
  executeDetection(ip);
}

type ProviderDisplayRow = Omit<Partial<ProviderRawResult>, 'port'> & {
  port?: number | string | null;
  last_seen?: string | null;
};

const nowTimestampMs = ref(Date.now());

watch(detectionData, () => {
  nowTimestampMs.value = Date.now();
});

function getProviderUpdatedLabel(row: ProviderDisplayRow | null | undefined): string | null {
  return resolveProviderUpdatedLabel(row, detectionData.value, nowTimestampMs.value);
}

function getProviderMetaItems(row: ProviderDisplayRow | null | undefined): string[] {
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
  return items;
}

function getStatusBadgeClass(status?: string | null): string {
  if (!status) return 'badge-neutral';
  if (status === '200 OK') return 'badge-success';
  if (status === 'No API Key' || status === 'Database Missing' || status === 'Skipped (IPv6)') {
    return 'badge-neutral';
  }
  if (status.includes('429') || status.includes('Cooldown')) return 'badge-warning';
  return 'badge-destructive';
}

function getScoreColorClass(score: number): string {
  if (score >= 70) return 'score-high';
  if (score >= 30) return 'score-medium';
  return 'score-low';
}

function getScoreTierClass(score: number): string {
  if (score >= 70) return 'score-tier-high';
  if (score >= 30) return 'score-tier-moderate';
  return 'score-tier-low';
}

function getScoreTierBadge(score: number): string {
  if (score >= 70) return 'badge-destructive';
  if (score >= 30) return 'badge-warning';
  return 'badge-success';
}

function getScoreTierLabel(score: number): string {
  if (score >= 70) return 'High Risk';
  if (score >= 30) return 'Moderate Risk';
  return 'Low Risk';
}

function getPredictionScoreTierClass(data: DetectionResponse | null | undefined): string {
  if (!data) return 'score-tier-low';
  if (data.predictionTier === 'destructive') return 'score-tier-high';
  if (data.predictionTier === 'warning') return 'score-tier-moderate';
  if (data.predictionTier === 'success') return 'score-tier-low';
  const score = Number(data.prediction_score ?? 0);
  if (score >= 70) return 'score-tier-high';
  if (score >= 30) return 'score-tier-moderate';
  return 'score-tier-low';
}

function getArbitrationBadgeClass(data: DetectionResponse | null | undefined): string {
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

function getPtrBadgeClass(data: DetectionResponse | null | undefined): string {
  if (!data || !data.ptrCategory) return 'badge-neutral';
  if (data.ptrCategory === 'hosting_or_gateway' || data.ptrIsHighRisk) {
    return 'badge-destructive';
  }
  if (data.ptrCategory === 'dynamic_residential') {
    return 'badge-success';
  }
  return 'badge-neutral';
}

function getSimplifiedFlags(flags?: ProviderRawResult['securityFlags'] | null) {
  return simplifySecurityFlags(flags ?? []);
}

function formatChance(score?: number | string | null): number {
  const num = Number(score ?? 0);
  if (Number.isNaN(num)) return 0;
  return Number(num.toFixed(3));
}

async function fetchUserStatus() {
  const requestStart = typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : 0;
  try {
    const res = await fetch('/api/v1/auth/user/');
    const fallbackDuration = measureElapsedSeconds(requestStart);
    if (res.ok) {
      const data = await res.json();
      user.value = {
        isLoggedIn: Boolean(data?.isLoggedIn),
        username: String(data?.username || ''),
        role: String(data?.role || ''),
        hasAccess: Boolean(data?.hasAccess),
      };
      initialDiagnostic.value = buildDiagnosticMetrics(
        {
          durationSeconds: data?.durationSeconds,
          memoryMb: data?.memoryMb,
          isCached: false,
        },
        fallbackDuration
      );
    } else {
      initialDiagnostic.value = buildDiagnosticMetrics(null, fallbackDuration);
    }
  } catch (err) {
    initialDiagnostic.value = buildDiagnosticMetrics(null, measureElapsedSeconds(requestStart));
    console.warn('Authentication status query failed:', err);
  }
}

function handleLogin() {
  window.location.href = buildOAuthLoginUrl(window.location.search, inputIp.value);
}

async function handleLogout() {
  const requestStart = typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : 0;
  try {
    const res = await fetch('/api/v1/auth/logout/');
    const fallbackDuration = measureElapsedSeconds(requestStart);
    if (!res.ok) {
      console.error('Logout failed with HTTP status:', res.status);
      return;
    }
    const data = await res.json().catch(() => null);
    user.value = {
      isLoggedIn: false,
      username: '',
      role: '',
      hasAccess: false,
    };
    inputIp.value = '';
    detectionData.value = null;
    diagnostic.value = null;
    syncBrowserUrlIp(null);
    initialDiagnostic.value = buildDiagnosticMetrics(
      data
        ? {
            durationSeconds: data?.durationSeconds,
            memoryMb: data?.memoryMb,
            isCached: false,
          }
        : null,
      fallbackDuration
    );
  } catch (err) {
    console.error('Logout error:', err);
  }
}

function getInitialIpParam(): string {
  try {
    const params = new URLSearchParams(window.location.search);
    return (params.get('ip') || '').trim();
  } catch {
    return '';
  }
}

let relativeTimeTimer: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  relativeTimeTimer = setInterval(() => {
    nowTimestampMs.value = Date.now();
  }, 30_000);
  const initialIp = getInitialIpParam();
  if (initialIp) {
    inputIp.value = initialIp;
  }
  await fetchUserStatus();
  if (initialIp && user.value.isLoggedIn && user.value.hasAccess) {
    executeDetection(initialIp);
  }
});

onUnmounted(() => {
  if (relativeTimeTimer !== null) {
    clearInterval(relativeTimeTimer);
    relativeTimeTimer = null;
  }
});
</script>
