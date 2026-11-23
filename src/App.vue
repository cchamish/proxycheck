<template>
  <div class="app-layout">
    <header class="app-header">
      <div class="app-header__brand">
        <img
          :src="proxycheckLogo"
          alt=""
          class="app-logo"
          aria-hidden="true"
        />
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
            <div v-if="detectionData" class="tab-panel">
              <section class="overview-section" aria-label="Detection overview">
                <div class="overview-header">
                  <div class="overview-header__main">
                    <div
                      class="prediction__ring"
                      :class="getPredictionScoreTierClass(detectionData)"
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
                        <cdx-info-chip :status="getArbitrationChipStatus(detectionData)">
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
                      @click="handleRefetch"
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
                    @click="handleRefetch"
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
                          :status="getPtrChipStatus(detectionData)"
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
                            @click.prevent="openRangeblockTab(item.wiki)"
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
                    @click.prevent="openRangeblockTab(null)"
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
                :data="filteredResults"
              >
                <template #item-provider="{ row }">
                  <div class="stack stack--tight">
                    <span
                      v-if="getProviderUpdatedLabel(row as ProviderDisplayRow)"
                      class="text-subtle"
                      :title="row.cachedAt || detectionData?.cacheMeta?.cachedAt || undefined"
                    >
                      {{ getProviderUpdatedLabel(row as ProviderDisplayRow) }}
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
                      v-for="meta in getProviderMetaItems(row as ProviderDisplayRow)"
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
                      v-for="flag in getSimplifiedFlags(row.securityFlags)"
                      :key="flag.label"
                      :status="getSecurityFlagChipStatus(flag)"
                    >
                      {{ flag.label }}
                    </cdx-info-chip>
                  </div>
                </template>
              </cdx-table>
            </div>
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
import proxycheckLogo from './assets/Proxycheck.svg';
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
  CdxTable,
  CdxTabs,
  type TableColumn,
} from '@wikimedia/codex';
import AboutNoteModal from './components/AboutNoteModal.vue';
import ProviderDashboardModal from './components/ProviderDashboardModal.vue';
import RangeblockFinderView from './components/RangeblockFinderView.vue';
import {
  applyThemeToDocument,
  getNextTheme,
  normalizeTheme,
  readStoredTheme,
  saveStoredTheme,
  THEME_STORAGE_KEY,
  type ThemeMode,
} from './utils/theme';
import {
  REQUIRED_USER_RIGHTS,
  buildOAuthLoginUrl,
  buildPageUrlWithState,
  buildVerificationLinks,
  buildWikitextSummary,
  canonicalizeIpAddress,
  createLoggedOutUserState,
  extractOpenProxyPorts,
  extractShodanTags,
  formatCacheAgeBadgeLabel,
  formatExactUtcTimestamp,
  formatSharedProviderBadge,
  getSharedPrivacyEgressInfo,
  isAuthorisedAdminUser,
  isCacheStale,
  isMobileOrCgnatDetection,
  isValidIpAddress,
  buildComparisonRowsWithPending,
  parseInitialRouteParams,
  resolveRefetchButtonState,
  shouldRecommendFreshRecheck,
  getSecurityFlagChipStatus,
  simplifySecurityFlags,
  createDetectionCoordinator,
  resolveRepoBaseUrl,
  formatCommitVersionLabel,
  resolveProviderUpdatedLabel,
  formatOfflineDbTimestamp,
  getProviderMetaItems as buildProviderMetaItems,
  getStatusChipStatus,
  getPredictionScoreTierClass,
  getArbitrationChipStatus,
  getPtrChipStatus,
  formatChance,
  buildDiagnosticMetrics,
  formatDiagnosticSummary,
  measureInitialLoadDurationSeconds,
  measureElapsedSeconds,
  readCsrfTokenFromDocumentCookie,
  type AppTab,
  type DiagnosticMetrics,
  type DetectionCoordinatorState,
  type ProviderDisplayRow,
  type ProviderRawResult,
  type RangeblockSummary,
} from './utils/ip-detector-logic';

const BRIGHT_ICON = {
  path: 'm7.866 15.696-2 3.464-1.732-1 2-3.464zm8 2.464-1.732 1-2-3.464 1.732-1zM10 6a4 4 0 1 1 0 8 4 4 0 0 1 0-8m0 2a2 2 0 1 0 0 4 2 2 0 0 0 0-4m-6 3H0V9h4zm16 0h-4V9h4zM7.866 4.304l-1.732 1-2-3.464 1.732-1zm8-2.464-2 3.464-1.732-1 2-3.464z',
};

const MOON_ICON = {
  path: 'M11.426 2.525c-1.287 2.085-1.379 4.72 0 6.948 1.385 2.239 3.924 3.522 6.575 3.525l.85 1.525a9.27 9.27 0 0 1-3.515 3.285c-4.54 2.445-10.375 1.018-13.037-3.283C-.39 10.18 1.24 4.657 5.814 2.191A10 10 0 0 1 10.577 1zm-2.511.644a8 8 0 0 0-2.153.783C3.137 5.905 1.954 10.166 4 13.472c2.073 3.352 6.726 4.547 10.387 2.575a7.5 7.5 0 0 0 1.687-1.236c-2.562-.496-4.916-1.97-6.35-4.286a8.5 8.5 0 0 1-.81-7.356Z',
};

const theme = ref<ThemeMode>(readStoredTheme());
applyThemeToDocument(theme.value);

const themeToggleIcon = computed(() => (theme.value === 'dark' ? BRIGHT_ICON : MOON_ICON));
const themeToggleAriaLabel = computed(() =>
  theme.value === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'
);
const activeWmcsLogo = computed(() => (theme.value === 'dark' ? wmcsDarkLogo : wmcsLogo));

function handleToggleTheme(): void {
  const nextTheme = getNextTheme(theme.value);
  theme.value = nextTheme;
  saveStoredTheme(nextTheme);
  applyThemeToDocument(nextTheme);
}

function handleThemeStorageSync(event: StorageEvent): void {
  if (event.key !== THEME_STORAGE_KEY) {
    return;
  }
  const syncedTheme = normalizeTheme(event.newValue);
  theme.value = syncedTheme;
  applyThemeToDocument(syncedTheme);
}

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

const activeTab = ref<AppTab>('detector');
const selectedRbWiki = ref<string | null>(null);
const rbData = ref<RangeblockSummary | null>(null);
const rbLoading = ref(false);
const rbError = ref('');
let rbAbortController: AbortController | null = null;
let rbRequestSeq = 0;

const isDashboardOpen = ref(false);
const isAboutOpen = ref(false);
const isAdminUser = computed(() => isAuthorisedAdminUser(user.value));

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

const inputIp = ref('');
const wikitextCopied = ref(false);
let wikitextCopyResetTimer: ReturnType<typeof setTimeout> | null = null;

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

function syncBrowserUrlState(ip: string | null, tab: AppTab = activeTab.value, wiki: string | null = selectedRbWiki.value): void {
  if (typeof window === 'undefined' || !window.history || typeof window.history.replaceState !== 'function') {
    return;
  }
  const nextUrl = buildPageUrlWithState(window.location.pathname, window.location.search, { ip, tab, wiki });
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
    onDetectionSuccess: (resolvedIp) => syncBrowserUrlState(resolvedIp, activeTab.value, selectedRbWiki.value),
  }
);

const nowTimestampMs = ref(Date.now());

const refetchButtonState = computed(() =>
  resolveRefetchButtonState({
    data: detectionData.value,
    isRefreshing: Boolean(isRefreshing?.value),
    isLoading: isLoading.value,
  })
);

const isCurrentCacheStale = computed(() => isCacheStale(detectionData.value));

const cacheAgeBadgeLabel = computed(() =>
  formatCacheAgeBadgeLabel(
    detectionData.value,
    nowTimestampMs.value,
    lastRefreshedAt?.value ?? null
  )
);

const cacheExactUtcTooltip = computed(() => {
  const data = detectionData.value;
  const rawStamp =
    data?.cacheMeta?.fetchedAt || data?.fetchedAt || data?.cacheMeta?.cachedAt || null;
  const formatted = formatExactUtcTimestamp(rawStamp);
  return formatted ? `Fetched ${formatted}` : null;
});

const sharedPrivacyInfo = computed(() =>
  getSharedPrivacyEgressInfo(detectionData.value?.sharedPrivacyEgress)
);

const sharedProviderBadge = computed(() => formatSharedProviderBadge(detectionData.value));

const isMobileOrCgnat = computed(() => isMobileOrCgnatDetection(detectionData.value));

const openProxyPorts = computed(() => extractOpenProxyPorts(detectionData.value));

const shodanTags = computed(() => extractShodanTags(detectionData.value));

const showFreshRecheckPrompt = computed(
  () => shouldRecommendFreshRecheck(detectionData.value) && !refetchButtonState.value.isBusy
);

const verificationLinks = computed(() => buildVerificationLinks(detectionData.value));

const filteredResults = computed(() => {
  if (!detectionData.value || !Array.isArray(detectionData.value.results)) {
    return [];
  }
  return buildComparisonRowsWithPending(
    detectionData.value.results,
    detectionData.value.pendingProviders
  );
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

const groundTruthColumns: TableColumn[] = [
  { id: 'provider', label: 'Provider' },
  { id: 'asn', label: 'ASN', width: '120px' },
  { id: 'isp', label: 'ISP / Organisation' },
  { id: 'location', label: 'Location' },
  { id: 'usageType', label: 'Usage type' },
  { id: 'securityFlags', label: 'Security flags' },
];

const predictionChipStatus = computed(() => {
  const tier = detectionData.value?.predictionTier;
  if (tier === 'destructive') return 'error';
  if (tier === 'success') return 'success';
  return 'notice';
});

const predictionChipLabel = computed(() => {
  const data = detectionData.value;
  if (!data) return '';
  if (data.predictionTier === 'destructive') return data.predictionLabel || 'Proxy / VPN';
  if (data.predictionTier === 'success') return data.predictionLabel || 'Safe Residential';
  const label = data.predictionLabel || 'Needs Human Review';
  return data.getipintel_chance !== null && data.getipintel_chance !== undefined
    ? `${label} (${formatChance(data.prediction_score)}%)`
    : label;
});

const isActiveSearchBusy = computed(() => (activeTab.value === 'rb' ? rbLoading.value : isLoading.value));

function cancelPendingRangeblock(): void {
  rbRequestSeq += 1;
  if (rbAbortController) {
    rbAbortController.abort();
    rbAbortController = null;
  }
  rbLoading.value = false;
}

function buildRangeblockWikiHref(ip: string, wiki: string): string {
  return buildPageUrlWithState('/', '', { ip, tab: 'rb', wiki });
}

async function executeRangeblockLookup(ipToQuery: string, wikiOverride?: string | null): Promise<void> {
  validationError.value = '';
  rbError.value = '';
  const trimmed = ipToQuery.trim();
  const canonical = canonicalizeIpAddress(trimmed);
  if (!canonical) {
    validationError.value = 'Please provide a valid IPv4 or IPv6 address.';
    return;
  }

  cancelPendingRangeblock();
  const seq = ++rbRequestSeq;
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  rbAbortController = controller;
  rbLoading.value = true;
  if (wikiOverride !== undefined) {
    selectedRbWiki.value = wikiOverride;
  }

  try {
    const params = new URLSearchParams({ ip: canonical });
    if (selectedRbWiki.value) {
      params.set('wiki', selectedRbWiki.value);
    }
    const res = await fetch(
      `/api/v1/rangeblock?${params.toString()}`,
      controller ? { signal: controller.signal } : undefined
    );
    if (seq !== rbRequestSeq) {
      return;
    }
    if (res.status === 401) {
      user.value = createLoggedOutUserState();
      sessionExpiredMessage.value = 'Your session has expired. Please log in again with Wikimedia.';
      return;
    }
    const payload = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(payload?.message || payload?.error || `Server returned HTTP ${res.status}`);
    }
    rbData.value = payload as RangeblockSummary;
    diagnostic.value = buildDiagnosticMetrics(payload);
    syncBrowserUrlState(payload.ip || canonical, 'rb', selectedRbWiki.value);
  } catch (err: any) {
    if (seq !== rbRequestSeq || (err && err.name === 'AbortError')) {
      return;
    }
    rbError.value = err?.message || 'Unable to query rangeblock records at this time.';
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

function clearWikitextCopyTimer(): void {
  if (wikitextCopyResetTimer !== null) {
    clearTimeout(wikitextCopyResetTimer);
    wikitextCopyResetTimer = null;
  }
}

async function handleCopyWikitext(): Promise<void> {
  const snippet = buildWikitextSummary(detectionData.value, nowTimestampMs.value);
  if (!snippet) {
    return;
  }
  let copied = false;
  if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
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
    clearWikitextCopyTimer();
    wikitextCopyResetTimer = setTimeout(() => {
      wikitextCopied.value = false;
      wikitextCopyResetTimer = null;
    }, 2000);
  }
}

function handleSearch(): void {
  if (!inputIp.value) {
    return;
  }
  if (activeTab.value === 'rb') {
    void executeRangeblockLookup(inputIp.value);
  } else {
    void executeDetection(inputIp.value);
  }
}

function queryFromHistory(ip: string): void {
  inputIp.value = ip;
  if (activeTab.value === 'rb') {
    void executeRangeblockLookup(ip);
  } else {
    void executeDetection(ip);
  }
}

watch(detectionData, () => {
  nowTimestampMs.value = Date.now();
  wikitextCopied.value = false;
  clearWikitextCopyTimer();
});

function getProviderUpdatedLabel(row: ProviderDisplayRow | null | undefined): string | null {
  return resolveProviderUpdatedLabel(row, detectionData.value, nowTimestampMs.value);
}

function getProviderMetaItems(row: ProviderDisplayRow | null | undefined): string[] {
  return buildProviderMetaItems(row, nowTimestampMs.value, formatOfflineDbTimestamp);
}

function getSimplifiedFlags(flags?: ProviderRawResult['securityFlags'] | null) {
  return simplifySecurityFlags(flags ?? []);
}

function nowPerfMs(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : 0;
}

async function fetchUserStatus() {
  const requestStart = nowPerfMs();
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
        isAdmin: typeof data?.isAdmin === 'boolean' ? data.isAdmin : undefined,
        localGroups: Array.isArray(data?.localGroups) ? data.localGroups : [],
        globalGroups: Array.isArray(data?.globalGroups) ? data.globalGroups : [],
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
  const requestStart = nowPerfMs();
  try {
    const csrfToken = readCsrfTokenFromDocumentCookie();
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }
    const res = await fetch('/api/v1/auth/logout/', {
      method: 'POST',
      credentials: 'same-origin',
      headers,
    });
    const fallbackDuration = measureElapsedSeconds(requestStart);
    if (!res.ok) {
      console.error('Logout failed with HTTP status:', res.status);
      return;
    }
    const data = await res.json().catch(() => null);
    coordinator.cancelPending();
    cancelPendingRangeblock();
    clearWikitextCopyTimer();
    wikitextCopied.value = false;
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

function handleDashboardUnauthorised(): void {
  isDashboardOpen.value = false;
  fetchUserStatus();
}

let relativeTimeTimer: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  window.addEventListener('storage', handleThemeStorageSync);
  relativeTimeTimer = setInterval(() => {
    nowTimestampMs.value = Date.now();
  }, 30_000);
  const initialRoute = parseInitialRouteParams(window.location.search);
  activeTab.value = initialRoute.tab;
  selectedRbWiki.value = initialRoute.wiki;
  if (initialRoute.ip) {
    inputIp.value = initialRoute.ip;
  }
  await fetchUserStatus();
  if (initialRoute.ip && user.value.isLoggedIn && user.value.hasAccess) {
    if (initialRoute.tab === 'rb') {
      void executeRangeblockLookup(initialRoute.ip, initialRoute.wiki);
    } else {
      void executeDetection(initialRoute.ip);
    }
  }
});

onUnmounted(() => {
  window.removeEventListener('storage', handleThemeStorageSync);
  coordinator.cancelPending();
  cancelPendingRangeblock();
  clearWikitextCopyTimer();
  if (relativeTimeTimer !== null) {
    clearInterval(relativeTimeTimer);
    relativeTimeTimer = null;
  }
});
</script>
