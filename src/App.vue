<template>
  <div class="app-layout">
    <header class="app-header">
      <div class="app-header__brand">
        <h1 class="app-title">Proxycheck</h1>
      </div>
      <div class="app-header__actions">
        <template v-if="user.isLoggedIn">
          <cdx-button v-if="isAdminUser" weight="quiet" @click="isDashboardOpen = true">
            Status
          </cdx-button>
          <span class="app-username">{{ user.username }}</span>
          <cdx-button weight="quiet" @click="handleLogout">
            Log out
          </cdx-button>
        </template>
        <cdx-button
          weight="quiet"
          :aria-label="themeToggleAriaLabel"
          :title="themeToggleAriaLabel"
          @click="handleToggleTheme"
        >
          <cdx-icon :icon="themeToggleIcon" />
        </cdx-button>
      </div>
    </header>

    <provider-dashboard-modal
      v-if="isAdminUser"
      v-model:open="isDashboardOpen"
      @unauthorised="handleDashboardUnauthorised"
    />

    <main class="app-main">
      <div v-if="!user.isLoggedIn" class="barrier">
        <cdx-message
          v-if="sessionExpiredMessage"
          type="warning"
          :inline="false"
          class="barrier__message"
        >
          {{ sessionExpiredMessage }}
        </cdx-message>
        <cdx-button
          action="progressive"
          weight="primary"
          size="large"
          @click="handleLogin"
        >
          Log in with Wikimedia
        </cdx-button>
        <p class="barrier__note">
          This tool is designed for users with the
          <code>{{ REQUIRED_USER_RIGHTS[0] }}(-no-preference)</code>
          right on any Wikimedia project.
        </p>
        <cdx-message type="notice" :inline="false" class="barrier__message">
          <p>
            Entered IPs are checked against local offline databases and configured
            third-party proxy/RDAP providers without being access-logged by Proxycheck.
            Lookups remain subject to the policies below.
          </p>
          <ul>
            <li>
              <a href="https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy" target="_blank" rel="noopener">Foundation Privacy Policy</a>
            </li>
            <li>
              <a href="https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_Access_to_Nonpublic_Personal_Data_Policy" target="_blank" rel="noopener">Foundation Access to Nonpublic Personal Data Policy</a>
            </li>
            <li>
              <a href="https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Access_to_Temporary_Account_IP_Addresses_Policy" target="_blank" rel="noopener">Foundation Access to Temporary Account IP Addresses Policy</a>
            </li>
            <li>
              <a href="https://wikitech.wikimedia.org/wiki/Wikitech:Cloud_Services_Terms_of_use" target="_blank" rel="noopener">Cloud Services Terms of use</a>
            </li>
          </ul>
        </cdx-message>
      </div>

      <div v-else-if="!user.hasAccess" class="barrier">
        <cdx-message type="error" :inline="false" class="barrier__message">
          Access Denied: You must hold either the <code>{{ REQUIRED_USER_RIGHTS[0] }}</code> or <code>{{ REQUIRED_USER_RIGHTS[1] }}</code> user right on any Wikimedia project to use this tool.
        </cdx-message>
      </div>

      <div v-else class="tool-content">
        <section class="search-section">
          <form class="search-form" @submit.prevent="handleSearch">
            <cdx-text-input
              v-model="inputIp"
              placeholder="Enter IPv4 or IPv6 address..."
              size="large"
              class="search-form__input"
              :disabled="isActiveSearchBusy"
              aria-label="IP Address Input"
            />
            <cdx-button
              type="submit"
              action="progressive"
              weight="primary"
              size="large"
              :disabled="isActiveSearchBusy || !inputIp.trim()"
            >
              {{ isActiveSearchBusy ? 'Analysing...' : (activeTab === 'rb' ? 'Lookup' : 'Detect') }}
            </cdx-button>
          </form>

          <cdx-message v-if="validationError" type="error" :inline="true">
            {{ validationError }}
          </cdx-message>

          <div v-if="ipHistory.length > 0" class="history">
            <span class="text-subtle">Recent queries:</span>
            <cdx-button
              v-for="historyIp in ipHistory"
              :key="historyIp"
              weight="quiet"
              size="small"
              @click="queryFromHistory(historyIp)"
            >
              <code>{{ historyIp }}</code>
            </cdx-button>
          </div>
        </section>

        <cdx-tabs v-model:active="activeTab">
          <cdx-tab name="detector" label="Detector">
            <detector-result-view
              v-if="detectionData"
              :detection-data="detectionData"
              :is-loading="isLoading"
              :is-refreshing="Boolean(isRefreshing)"
              :refresh-warning-message="refreshWarningMessage ?? ''"
              :last-refreshed-at="lastRefreshedAt ?? null"
              :now-timestamp-ms="nowTimestampMs"
              @refetch="handleRefetch"
              @open-rangeblock="openRangeblockTab"
            />
          </cdx-tab>

          <cdx-tab name="rb" label="RB Finder">
            <rangeblock-finder-view
              v-if="activeTab === 'rb'"
              :rangeblock="activeRangeblockData"
              :selected-wiki="selectedRbWiki"
              :is-loading="rbLoading"
              :error-message="rbError"
              @select-wiki="handleSelectRbWiki"
            />
          </cdx-tab>
        </cdx-tabs>
      </div>
    </main>

    <footer class="app-footer">
      <span class="app-footer__meta">
        &copy; 2026 &middot;
        <a href="#" @click.prevent="isAboutOpen = true">About</a>
        &middot;
        <a
          v-if="repoBaseUrl"
          :href="`${repoBaseUrl}/tree/${commitHash}`"
          target="_blank"
          rel="noopener noreferrer"
        >
          {{ commitVersionLabel }}
        </a>
        <span v-else>{{ commitVersionLabel }}</span>
        &middot; {{ formatDiagnosticSummary(footerDiagnostic) }}
        <cdx-info-chip v-if="footerDiagnostic.isCached">Cached</cdx-info-chip>
      </span>
      <div class="app-footer__logos">
        <a
          href="https://wikitech.wikimedia.org/wiki/Portal:Toolforge"
          target="_blank"
          rel="noopener noreferrer"
          title="Hosted on Wikimedia Toolforge"
        >
          <img :src="toolforgeLogo" alt="Toolforge" class="footer-logo" />
        </a>
        <a
          href="https://wikitech.wikimedia.org/wiki/Help:Cloud_Services_introduction"
          target="_blank"
          rel="noopener noreferrer"
          title="Powered by Wikimedia Cloud Services"
        >
          <img :src="activeWmcsLogo" alt="Powered by Wikimedia Cloud Services" class="footer-logo" />
        </a>
      </div>
    </footer>

    <about-note-modal v-model:open="isAboutOpen" />
  </div>
</template>

<script setup lang="ts">
import { reactive, toRefs, ref, computed, watch, onMounted, onUnmounted } from 'vue';
import toolforgeLogo from './assets/Toolforge.svg';
import wmcsLogo from './assets/WMCS.svg';
import wmcsDarkLogo from './assets/WMCS-dark.svg';
import {
  CdxTextInput,
  CdxButton,
  CdxIcon,
  CdxInfoChip,
  CdxMessage,
  CdxTab,
  CdxTabs,
} from '@wikimedia/codex';
import AboutNoteModal from './components/AboutNoteModal.vue';
import DetectorResultView from './components/DetectorResultView.vue';
import ProviderDashboardModal from './components/ProviderDashboardModal.vue';
import RangeblockFinderView from './components/RangeblockFinderView.vue';
import {
  REQUIRED_USER_RIGHTS,
  buildDiagnosticMetrics,
  canonicalizeIpAddress,
  createDetectionCoordinator,
  createLoggedOutUserState,
  formatDiagnosticSummary,
  isAuthorisedAdminUser,
  isValidIpAddress,
  normalizeUtcCommitTimestamp,
  readCsrfTokenFromDocumentCookie,
  type AppTab,
  type DetectionCoordinatorState,
  type DiagnosticMetrics,
  type RangeblockSummary,
} from './utils/ip-detector-logic';

type ThemeMode = 'dark' | 'light';

const THEME_STORAGE_KEY = 'proxy_detector_theme';
const HISTORY_STORAGE_KEY = 'proxy_detector_ip_history';
const DARK_THEME_COLOUR = '#101418';
const LIGHT_THEME_COLOUR = '#f6f7f8';

const BRIGHT_ICON = {
  path: 'm7.866 15.696-2 3.464-1.732-1 2-3.464zm8 2.464-1.732 1-2-3.464 1.732-1zM10 6a4 4 0 1 1 0 8 4 4 0 0 1 0-8m0 2a2 2 0 1 0 0 4 2 2 0 0 0 0-4m-6 3H0V9h4zm16 0h-4V9h4zM7.866 4.304l-1.732 1-2-3.464 1.732-1zm8-2.464-2 3.464-1.732-1 2-3.464z',
};
const MOON_ICON = {
  path: 'M11.426 2.525c-1.287 2.085-1.379 4.72 0 6.948 1.385 2.239 3.924 3.522 6.575 3.525l.85 1.525a9.27 9.27 0 0 1-3.515 3.285c-4.54 2.445-10.375 1.018-13.037-3.283C-.39 10.18 1.24 4.657 5.814 2.191A10 10 0 0 1 10.577 1zm-2.511.644a8 8 0 0 0-2.153.783C3.137 5.905 1.954 10.166 4 13.472c2.073 3.352 6.726 4.547 10.387 2.575a7.5 7.5 0 0 0 1.687-1.236c-2.562-.496-4.916-1.97-6.35-4.286a8.5 8.5 0 0 1-.81-7.356Z',
};

function applyTheme(nextTheme: ThemeMode): void {
  if (typeof document === 'undefined') return;
  document.documentElement.dataset.theme = nextTheme;
  document.documentElement.style.colorScheme = nextTheme;
  const themeMeta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  if (themeMeta) {
    themeMeta.content = nextTheme === 'dark' ? DARK_THEME_COLOUR : LIGHT_THEME_COLOUR;
  }
}

let initialTheme: ThemeMode = 'dark';
try {
  if (typeof localStorage !== 'undefined' && localStorage.getItem(THEME_STORAGE_KEY) === 'light') {
    initialTheme = 'light';
  }
} catch {
  initialTheme = 'dark';
}
const theme = ref<ThemeMode>(initialTheme);
applyTheme(theme.value);

const themeToggleIcon = computed(() => (theme.value === 'dark' ? BRIGHT_ICON : MOON_ICON));
const themeToggleAriaLabel = computed(() =>
  theme.value === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'
);
const activeWmcsLogo = computed(() => (theme.value === 'dark' ? wmcsDarkLogo : wmcsLogo));

function handleToggleTheme(): void {
  const nextTheme: ThemeMode = theme.value === 'dark' ? 'light' : 'dark';
  theme.value = nextTheme;
  try {
    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
  } catch {
    // Storage quota or private browsing may reject writes.
  }
  applyTheme(nextTheme);
}

function handleThemeStorageSync(event: StorageEvent): void {
  if (event.key !== THEME_STORAGE_KEY) return;
  const syncedTheme: ThemeMode = event.newValue === 'light' ? 'light' : 'dark';
  theme.value = syncedTheme;
  applyTheme(syncedTheme);
}

function loadStoredHistory(): string[] {
  try {
    const stored = localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!stored) return [];
    const parsed: unknown = JSON.parse(stored);
    if (!Array.isArray(parsed)) return [];
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
    // Storage quota or private browsing may reject writes.
  }
}

const uiState = reactive<DetectionCoordinatorState>({
  isLoading: false,
  isStreaming: false,
  isRefreshing: false,
  validationError: '',
  sessionExpiredMessage: '',
  refreshWarningMessage: '',
  lastRefreshedAt: null,
  detectionData: null,
  diagnostic: null,
  user: createLoggedOutUserState(),
  ipHistory: loadStoredHistory(),
});

const {
  user,
  isLoading,
  isRefreshing,
  validationError,
  sessionExpiredMessage,
  refreshWarningMessage,
  lastRefreshedAt,
  ipHistory,
  detectionData,
  diagnostic,
} = toRefs(uiState);

const activeTab = ref<AppTab>('detector');
const selectedRbWiki = ref<string | null>(null);
const rbData = ref<RangeblockSummary | null>(null);
const rbLoading = ref(false);
const rbError = ref('');
let rbAbortController: AbortController | null = null;
let rbRequestSeq = 0;

const isDashboardOpen = ref(false);
const isAboutOpen = ref(false);
const inputIp = ref('');
const nowTimestampMs = ref(Date.now());
const isAdminUser = computed(() => isAuthorisedAdminUser(user.value));

const commitHash = typeof __COMMIT_HASH__ !== 'undefined' ? __COMMIT_HASH__ : 'dev';
const commitTimestamp = typeof __COMMIT_TIMESTAMP__ !== 'undefined' ? __COMMIT_TIMESTAMP__ : '';
const normalisedCommitTimestamp = normalizeUtcCommitTimestamp(commitTimestamp);
const commitVersionLabel = normalisedCommitTimestamp
  ? `(r.${commitHash.trim() || 'dev'} @ ${normalisedCommitTimestamp})`
  : `(r.${commitHash.trim() || 'dev'})`;

const configuredRepo = String(import.meta.env.VITE_GITHUB_REPO ?? '').trim();
const repoBaseUrl = !configuredRepo
  ? ''
  : configuredRepo.startsWith('http')
    ? configuredRepo.replace(/\/$/, '')
    : `https://github.com/${configuredRepo}`;

let initialLoadDuration = 0;
try {
  const navEntry = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
  if (navEntry && Number.isFinite(navEntry.responseEnd) && navEntry.responseEnd > 0) {
    const start = Number.isFinite(navEntry.startTime) ? navEntry.startTime : 0;
    const secs = (navEntry.responseEnd - start) / 1000;
    if (Number.isFinite(secs) && secs >= 0) initialLoadDuration = Number(secs.toFixed(3));
  }
} catch {
  initialLoadDuration = 0;
}

const initialDiagnostic = ref<DiagnosticMetrics>({
  duration: initialLoadDuration,
  memory: null,
  isCached: false,
});
const footerDiagnostic = computed<DiagnosticMetrics>(() => diagnostic.value ?? initialDiagnostic.value);

function syncBrowserUrlState(
  ip: string | null,
  tab: AppTab = activeTab.value,
  wiki: string | null = selectedRbWiki.value
): void {
  if (typeof window === 'undefined' || !window.history?.replaceState) return;
  const basePath = window.location.pathname.startsWith('/') ? window.location.pathname : '/';
  const params = new URLSearchParams(window.location.search || '');
  const canonical = ip ? canonicalizeIpAddress(ip) : null;
  if (canonical) params.set('ip', canonical);
  else params.delete('ip');

  if (tab === 'rb') {
    params.set('tab', 'rb');
    if (wiki && /^[a-z0-9_]{2,64}$/.test(wiki)) params.set('wiki', wiki);
    else params.delete('wiki');
  } else {
    params.delete('tab');
    params.delete('wiki');
  }

  const queryString = params.toString();
  const nextUrl = queryString ? `${basePath}?${queryString}` : basePath;
  if (nextUrl !== `${window.location.pathname}${window.location.search}`) {
    window.history.replaceState(window.history.state, '', nextUrl);
  }
}

const coordinator = createDetectionCoordinator((url, init) => fetch(url, init), undefined, {
  state: uiState,
  onHistoryUpdated: saveStoredHistory,
  onDetectionSuccess: (resolvedIp) => syncBrowserUrlState(resolvedIp, activeTab.value, selectedRbWiki.value),
});

const activeRangeblockData = computed<RangeblockSummary | null>(() => {
  const currentInputCanonical = canonicalizeIpAddress(inputIp.value);
  if (rbData.value && (!currentInputCanonical || rbData.value.ip === currentInputCanonical)) {
    return rbData.value;
  }
  const detectRb = detectionData.value?.rangeblock ?? null;
  if (detectRb && (!currentInputCanonical || detectRb.ip === currentInputCanonical)) {
    return detectRb;
  }
  return rbData.value ?? detectRb;
});

const isActiveSearchBusy = computed(() => (activeTab.value === 'rb' ? rbLoading.value : isLoading.value));

function cancelPendingRangeblock(): void {
  rbRequestSeq += 1;
  rbAbortController?.abort();
  rbAbortController = null;
  rbLoading.value = false;
}

async function executeRangeblockLookup(ipToQuery: string, wikiOverride?: string | null): Promise<void> {
  validationError.value = '';
  rbError.value = '';
  const canonical = canonicalizeIpAddress(ipToQuery.trim());
  if (!canonical) {
    validationError.value = 'Please provide a valid IPv4 or IPv6 address.';
    return;
  }

  cancelPendingRangeblock();
  const seq = ++rbRequestSeq;
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  rbAbortController = controller;
  rbLoading.value = true;
  if (wikiOverride !== undefined) selectedRbWiki.value = wikiOverride;

  try {
    const params = new URLSearchParams({ ip: canonical });
    if (selectedRbWiki.value) params.set('wiki', selectedRbWiki.value);
    const res = await fetch(
      `/api/v1/rangeblock?${params.toString()}`,
      controller ? { signal: controller.signal } : undefined
    );
    if (seq !== rbRequestSeq) return;
    if (res.status === 401) {
      user.value = createLoggedOutUserState();
      sessionExpiredMessage.value = 'Your session has expired. Please log in again with Wikimedia.';
      return;
    }
    const payload = (await res.json().catch(() => ({}))) as RangeblockSummary & {
      message?: string;
      error?: string;
      durationSeconds?: number | null;
      memoryMb?: number | null;
      isCached?: boolean | null;
    };
    if (!res.ok) {
      throw new Error(payload.message || payload.error || `Server returned HTTP ${res.status}`);
    }
    rbData.value = payload;
    diagnostic.value = buildDiagnosticMetrics(payload);
    syncBrowserUrlState(payload.ip || canonical, 'rb', selectedRbWiki.value);
  } catch (err: unknown) {
    if (seq !== rbRequestSeq || (err instanceof Error && err.name === 'AbortError')) return;
    rbError.value =
      (err instanceof Error && err.message) || 'Unable to query rangeblock records at this time.';
  } finally {
    if (seq === rbRequestSeq) {
      rbLoading.value = false;
      rbAbortController = null;
    }
  }
}

watch(activeTab, (nextTab) => {
  const currentIp = canonicalizeIpAddress(inputIp.value) ?? detectionData.value?.ip ?? rbData.value?.ip ?? null;
  syncBrowserUrlState(currentIp, nextTab, selectedRbWiki.value);
  if (
    nextTab === 'rb' &&
    currentIp &&
    user.value.isLoggedIn &&
    user.value.hasAccess &&
    !activeRangeblockData.value
  ) {
    void executeRangeblockLookup(currentIp);
  }
});

watch(detectionData, () => {
  nowTimestampMs.value = Date.now();
});

function openRangeblockTab(wiki: string | null): void {
  selectedRbWiki.value = wiki;
  const currentIp = canonicalizeIpAddress(inputIp.value) ?? detectionData.value?.ip ?? rbData.value?.ip ?? null;
  if (detectionData.value?.rangeblock && (!currentIp || detectionData.value.rangeblock.ip === currentIp)) {
    rbData.value = detectionData.value.rangeblock;
    rbError.value = '';
  }
  activeTab.value = 'rb';
}

function handleSelectRbWiki(wiki: string | null): void {
  selectedRbWiki.value = wiki;
  const currentIp = canonicalizeIpAddress(inputIp.value) ?? rbData.value?.ip ?? detectionData.value?.ip ?? null;
  syncBrowserUrlState(currentIp, 'rb', wiki);
}

async function executeDetection(ipToQuery: string): Promise<void> {
  rbData.value = null;
  rbError.value = '';
  await coordinator.executeDetection(ipToQuery);
}

async function handleRefetch(): Promise<void> {
  await coordinator.refreshDetection();
  nowTimestampMs.value = Date.now();
}

function handleSearch(): void {
  if (!inputIp.value) return;
  if (activeTab.value === 'rb') void executeRangeblockLookup(inputIp.value);
  else void executeDetection(inputIp.value);
}

function queryFromHistory(ip: string): void {
  inputIp.value = ip;
  if (activeTab.value === 'rb') void executeRangeblockLookup(ip);
  else void executeDetection(ip);
}

function elapsedSecondsSince(startMs: number): number {
  if (typeof performance === 'undefined' || !Number.isFinite(startMs)) return 0;
  const diff = performance.now() - startMs;
  return Number.isFinite(diff) && diff >= 0 ? Number((diff / 1000).toFixed(3)) : 0;
}

async function fetchUserStatus(): Promise<void> {
  const requestStart = typeof performance !== 'undefined' ? performance.now() : 0;
  try {
    const res = await fetch('/api/v1/auth/user/');
    const fallbackDuration = elapsedSecondsSince(requestStart);
    if (res.ok) {
      const data = await res.json();
      user.value = {
        isLoggedIn: Boolean(data?.isLoggedIn),
        username: String(data?.username || ''),
        role: String(data?.role || ''),
        hasAccess: Boolean(data?.hasAccess),
        isAdmin: typeof data?.isAdmin === 'boolean' ? data.isAdmin : undefined,
        localGroups: Array.isArray(data?.localGroups) ? data.localGroups : [],
        globalGroups: Array.isArray(data?.globalGroups) ? data.globalGroups : [],
      };
      initialDiagnostic.value = buildDiagnosticMetrics(
        { durationSeconds: data?.durationSeconds, memoryMb: data?.memoryMb, isCached: false },
        fallbackDuration
      );
    } else {
      initialDiagnostic.value = buildDiagnosticMetrics(null, fallbackDuration);
    }
  } catch (err) {
    initialDiagnostic.value = buildDiagnosticMetrics(null, elapsedSecondsSince(requestStart));
    console.warn('Authentication status query failed:', err);
  }
}

function handleLogin(): void {
  const params = new URLSearchParams(window.location.search || '');
  const targetIp =
    canonicalizeIpAddress((params.get('ip') || '').trim()) ?? canonicalizeIpAddress(inputIp.value);
  window.location.href = targetIp
    ? `/api/v1/auth/login/?ip=${encodeURIComponent(targetIp)}`
    : '/api/v1/auth/login/';
}

async function handleLogout(): Promise<void> {
  const requestStart = typeof performance !== 'undefined' ? performance.now() : 0;
  try {
    const csrfToken = readCsrfTokenFromDocumentCookie();
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (csrfToken) headers['X-CSRFToken'] = csrfToken;

    const res = await fetch('/api/v1/auth/logout/', {
      method: 'POST',
      credentials: 'same-origin',
      headers,
    });
    const fallbackDuration = elapsedSecondsSince(requestStart);
    if (!res.ok) {
      console.error('Logout failed with HTTP status:', res.status);
      return;
    }
    const data = await res.json().catch(() => null);
    coordinator.cancelPending();
    cancelPendingRangeblock();
    user.value = createLoggedOutUserState();
    isDashboardOpen.value = false;
    inputIp.value = '';
    detectionData.value = null;
    rbData.value = null;
    rbError.value = '';
    selectedRbWiki.value = null;
    activeTab.value = 'detector';
    diagnostic.value = null;
    syncBrowserUrlState(null, 'detector', null);
    initialDiagnostic.value = buildDiagnosticMetrics(
      data ? { durationSeconds: data?.durationSeconds, memoryMb: data?.memoryMb, isCached: false } : null,
      fallbackDuration
    );
  } catch (err) {
    console.error('Logout error:', err);
  }
}

function handleDashboardUnauthorised(): void {
  isDashboardOpen.value = false;
  void fetchUserStatus();
}

let relativeTimeTimer: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  window.addEventListener('storage', handleThemeStorageSync);
  relativeTimeTimer = setInterval(() => {
    nowTimestampMs.value = Date.now();
  }, 30_000);

  const params = new URLSearchParams(window.location.search || '');
  const initialIp = (params.get('ip') || '').trim();
  const rawTab = (params.get('tab') || '').trim().toLowerCase();
  const rawWiki = (params.get('wiki') || '').trim().toLowerCase();
  const initialTab: AppTab = rawTab === 'rb' || rawTab === 'rangeblock' ? 'rb' : 'detector';
  const initialWiki = /^[a-z0-9_]{2,64}$/.test(rawWiki) ? rawWiki : null;

  activeTab.value = initialTab;
  selectedRbWiki.value = initialWiki;
  if (initialIp) inputIp.value = initialIp;

  await fetchUserStatus();
  if (initialIp && user.value.isLoggedIn && user.value.hasAccess) {
    if (initialTab === 'rb') void executeRangeblockLookup(initialIp, initialWiki);
    else void executeDetection(initialIp);
  }
});

onUnmounted(() => {
  window.removeEventListener('storage', handleThemeStorageSync);
  coordinator.cancelPending();
  cancelPendingRangeblock();
  if (relativeTimeTimer !== null) {
    clearInterval(relativeTimeTimer);
    relativeTimeTimer = null;
  }
});
</script>
