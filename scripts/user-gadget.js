/**
 * Disclaimer:
 * By using this script, you acknowledge that you fully understand and agree to comply with:
 * - Wikimedia Foundation Access to Nonpublic Personal Data Policy (https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_Access_to_Nonpublic_Personal_Data_Policy)
 * - Privacy Policy (https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy)
 * as well as all other applicable policies and guidelines regarding Temporary Account IP reveal.
 */
// Partly adopted from https://www.mediawiki.org/w/index.php?title=XTools/ArticleInfo.js&action=raw&ctype=text/javascript
(function (mw, $) {
    'use strict';

    const username = mw.config.get('wgUserName');
    if (!username || mw.config.get('wgUserIsTemp') || username.charAt(0) === '~') return;

    const TOOL_BASE_URL = 'https://proxycheck.toolforge.org';
    const REVEAL_ANCHOR_SELECTOR = 'a.ext-checkuser-tempaccount-reveal-ip-anchor';
    const REVEAL_CONTAINER_SELECTOR = '.ext-checkuser-tempaccount-reveal-ip';
    const TARGET_SELECTOR = `${REVEAL_ANCHOR_SELECTOR}, ${REVEAL_CONTAINER_SELECTOR}`;
    const BADGE_CLASS = 'proxycheck-ip-badge';
    const STYLE_ELEMENT_ID = 'proxycheck-userscript-styles';
    const INTERNAL_NODE_SELECTOR = '#proxycheck-pageinfo, #proxycheck_result, #proxycheck-userscript-styles, .proxycheck-ip-badge, .proxycheck-details-panel, .proxycheck-light-upgrade-notice, .proxycheck-dialog-cache-bar, .proxycheck-cache-controls, .proxycheck-refetch-btn, .proxycheck-refresh-warning, .proxycheck-temp-ip-switcher, .proxycheck-quick-links';
    const IPINFO_PANEL_SELECTOR = '.ext-ipinfo-panel-layout';
    const OBSERVER_THROTTLE_MS = 100;
    const IPINFO_FALLBACK_DELAY_MS = 400;
    const MAX_CONCURRENT_REQUESTS = 4;
    const BATCH_DEBOUNCE_MS = 40;
    const MAX_BATCH_IPS = 25;
    const CONSENT_KEY = 'proxycheck-ip-policy-consent';
    const TOKEN_KEY = 'proxycheck-gadget-token';
    const TOKEN_USER_KEY = 'proxycheck-gadget-token-user';
    const TOKEN_EXPIRY_KEY = 'proxycheck-gadget-token-exp';
    const TOKEN_REFRESH_LOCK_KEY = 'proxycheck-gadget-token-refresh-lock';
    const TOKEN_REFRESH_LOCK_TTL_MS = 8000;
    const TOKEN_REFRESH_POLL_INTERVAL_MS = 250;
    const TOKEN_REFRESH_WAIT_TIMEOUT_MS = 4000;
    const RESULT_CACHE_STORAGE_KEY = 'proxycheck-ip-result-cache-v1';
    const RESULT_CACHE_TTL_MS = 30 * 60 * 1000;
    const DEGRADED_CACHE_TTL_MS = 60 * 1000;
    const CONTRIB_FULL_TRIGGER_DELAY_MS = 500;
    const RESULT_CACHE_MAX_ENTRIES = 200;
    const AUTO_SWR_STORAGE_KEY = 'proxycheck-auto-swr-timestamps-v1';
    const AUTO_SWR_WINDOW_MS = 60 * 1000;
    const AUTO_SWR_MAX_REQUESTS = 3;
    const RESIDENTIAL_RECHECK_THRESHOLD_SECONDS = 7 * 86400;
    const BLOCK_REASON_ATTRIBUTION = '([[:m:User:Hamish/proxycheck.js|proxycheck]])';

    const IPV4_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    const IPV6_PATTERN = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
    var COMMERCIAL_PROVIDERS = {
        'AbuseIPDB': true,
        'IPData': true,
        'IPRegistry': true,
        'IP2Location': true,
        'GetIPIntel': true,
        'Proxycheck': true,
        'IPHub': true,
        'IPHunter': true
    };
    var PROVIDER_BADGE_PALETTES = {
        'MaxMind': { bg: '#e6f2ff', border: '#a3ccf5', color: '#0b4f8a', darkBg: '#162a42', darkBorder: '#2f5a8a', darkColor: '#8ec5ff' },
        'IP2Location': { bg: '#e3f8fc', border: '#99dfec', color: '#0b5d6b', darkBg: '#133038', darkBorder: '#296878', darkColor: '#7fd8e8' },
        'IPData': { bg: '#eaedff', border: '#b3bdf5', color: '#2c3e99', darkBg: '#1d2345', darkBorder: '#3e4a8f', darkColor: '#a3b3ff' },
        'IPRegistry': { bg: '#f0ebff', border: '#c5b6f2', color: '#4b2d8f', darkBg: '#271e42', darkBorder: '#55418c', darkColor: '#c3b0ff' },
        'Proxycheck': { bg: '#e4f7f2', border: '#9cd9cb', color: '#0d5e4e', darkBg: '#13332b', darkBorder: '#296b5b', darkColor: '#7be0c8' },
        'Cloudflare Radar': { bg: '#e8f0fe', border: '#a6c4f7', color: '#174ea6', darkBg: '#182947', darkBorder: '#355794', darkColor: '#94bfff' },
        'AbuseIPDB': { bg: '#e8eff5', border: '#aec2d4', color: '#294661', darkBg: '#1d2936', darkBorder: '#3e5773', darkColor: '#a3c2e0' },
        'IPHub': { bg: '#e5f5fa', border: '#9dd4e6', color: '#0d536b', darkBg: '#142e3b', darkBorder: '#2b637d', darkColor: '#84d0ed' },
        'IPHunter': { bg: '#ebf0f5', border: '#b8c6d6', color: '#324a63', darkBg: '#1f2a36', darkBorder: '#425870', darkColor: '#adc4db' },
        'GetIPIntel': { bg: '#eeeafd', border: '#bfb4f5', color: '#46328a', darkBg: '#252045', darkBorder: '#4f458f', darkColor: '#bdb2ff' },
        'Tor Onionoo': { bg: '#f1ecf8', border: '#c9bce3', color: '#4e3475', darkBg: '#29203d', darkBorder: '#574480', darkColor: '#cbb8f2' },
        'DShield': { bg: '#e7f3f3', border: '#a7cfd1', color: '#1f5357', darkBg: '#172e2f', darkBorder: '#316163', darkColor: '#8cd4d6' },
        'StopForumSpam': { bg: '#e6f8f5', border: '#9fdcd2', color: '#125c51', darkBg: '#13332e', darkBorder: '#286b60', darkColor: '#7ee0d1' },
        'Spamhaus ZEN': { bg: '#eaedf7', border: '#b5c0de', color: '#2e3f6e', darkBg: '#1e243b', darkBorder: '#404d7d', darkColor: '#a8b8eb' },
        'SpamCop': { bg: '#eaf4fb', border: '#add2ec', color: '#1c537d', darkBg: '#172c3d', darkBorder: '#315c80', darkColor: '#91c6f2' },
        'IPsum / DROP': { bg: '#f4ecfb', border: '#ceb3ea', color: '#512b78', darkBg: '#2a1d3b', darkBorder: '#5d4180', darkColor: '#d4b8f8' },
        'X4BNet VPN': { bg: '#e6f4f8', border: '#9fd0df', color: '#0e5266', darkBg: '#132d36', darkBorder: '#285f70', darkColor: '#82d2e8' },
        'Shodan InternetDB': { bg: '#fbeee8', border: '#e8bca8', color: '#783416', darkBg: '#361f16', darkBorder: '#734330', darkColor: '#f5bba3' },
        'Privacy Relay': { bg: '#eef0ff', border: '#b5bff7', color: '#2b3a94', darkBg: '#1c2247', darkBorder: '#3f4d96', darkColor: '#a8b5ff' },
        'Cloud CIDR': { bg: '#e8f6ff', border: '#a8d8f8', color: '#0e527d', darkBg: '#152c3d', darkBorder: '#2c5c80', darkColor: '#8ac7f5' },
        'Multi-Source': { bg: '#eef2f6', border: '#b9c6d4', color: '#3b4f66', darkBg: '#222830', darkBorder: '#475466', darkColor: '#b3c2d4' },
        'Reverse DNS': { bg: '#e8f7f7', border: '#a6dada', color: '#185b5e', darkBg: '#153030', darkBorder: '#2c6666', darkColor: '#87dbdb' },
        'Spur': { bg: '#e3f1f8', border: '#95cce6', color: '#0f4c6e', darkBg: '#152b38', darkBorder: '#2c5973', darkColor: '#8bc8eb' }
    };
    const FALLBACK_COOL_PALETTES = [
        { bg: '#e6f2ff', border: '#a3ccf5', color: '#0b4f8a', darkBg: '#162a42', darkBorder: '#2f5a8a', darkColor: '#8ec5ff' },
        { bg: '#e3f8fc', border: '#99dfec', color: '#0b5d6b', darkBg: '#133038', darkBorder: '#296878', darkColor: '#7fd8e8' },
        { bg: '#eaedff', border: '#b3bdf5', color: '#2c3e99', darkBg: '#1d2345', darkBorder: '#3e4a8f', darkColor: '#a3b3ff' },
        { bg: '#e4f7f2', border: '#9cd9cb', color: '#0d5e4e', darkBg: '#13332b', darkBorder: '#296b5b', darkColor: '#7be0c8' },
        { bg: '#f0ebff', border: '#c5b6f2', color: '#4b2d8f', darkBg: '#271e42', darkBorder: '#55418c', darkColor: '#c3b0ff' },
        { bg: '#e8eff5', border: '#aec2d4', color: '#294661', darkBg: '#1d2936', darkBorder: '#3e5773', darkColor: '#a3c2e0' }
    ];

    const ipPromiseCache = new Map();
    const ipFullPromiseCache = new Map();
    const inflightFullPromisesByIp = new Map();
    const inflightRefreshByIp = new Map();
    const latestResultByIp = new Map();
    const fullResultMetaByIp = new Map();
    const renderedBadgeEntriesByIp = new Map();
    const batchOriginatedPayloads = typeof WeakSet === 'function' ? new WeakSet() : null;
    const autoSwrAttemptedKeys = new Set();

    let activeContributionsController = null;
    let persistedCacheRaw = null;
    let persistedCacheStore = null;
    let storageFailureWarned = false;
    let stylesInjected = false;
    let observer = null;
    let viewportObserver = null;
    let accessBlocked = false;
    let consentGranted = false;
    let consentDeclined = false;
    let consentPromise = null;
    let authPromise = null;
    let tokenRefreshWaitTimer = null;
    let tokenRefreshWaitCancel = null;
    let memoryToken = null;
    let memoryTokenExpiry = null;
    let memoryAutoSwrTimestamps = [];

    function isContributionsSpecialPage() {
        const specialName = mw.config.get('wgCanonicalSpecialPageName');
        if (specialName === 'IPContributions' || specialName === 'Contributions' || specialName === 'IContributions') return true;
        if (specialName) return false;
        return /^[^:]+:(IPContributions|IContributions|Contributions)(\/|$)/i.test(mw.config.get('wgPageName') || '');
    }

    let ipContributionsPending = false;
    let ipContributionsInvalidTarget = false;
    const isIpContributionsPage = isContributionsSpecialPage();
    let infoDialogPromise = null;
    let refreshPageInfoSpur = null;
    let activeLoadingInterval = null;
    let ipContributionsObserverTimer = null;
    let ipContributionsFallbackTimer = null;
    let ipContributionsDelayTimer = null;
    let ipContributionsVisibilityHandler = null;
    let pendingContributionsPageCheck = false;
    let pendingSpurRefresh = false;
    let activeRequestCount = 0;
    const requestQueue = [];
    let batchEndpointSupported = true;
    const pendingBatchQueue = [];
    let batchDebounceTimer = null;

    function warn(msg, err) {
        if (typeof console !== 'undefined' && typeof console.warn === 'function') {
            console.warn('[proxycheck] ' + msg, err !== undefined ? err : '');
        }
    }

    function clearTimer(id, isInterval) {
        if (id !== null) {
            (isInterval ? window.clearInterval : window.clearTimeout)(id);
        }
        return null;
    }

    function clearLoadingInterval() { activeLoadingInterval = clearTimer(activeLoadingInterval, true); }
    function clearBatchDebounceTimer() { batchDebounceTimer = clearTimer(batchDebounceTimer, false); }
    function clearContributionsFallbackTimer() { ipContributionsFallbackTimer = clearTimer(ipContributionsFallbackTimer, false); }

    function clearTokenRefreshWait() {
        tokenRefreshWaitTimer = clearTimer(tokenRefreshWaitTimer, false);
        if (typeof tokenRefreshWaitCancel === 'function') {
            const cancelFn = tokenRefreshWaitCancel;
            tokenRefreshWaitCancel = null;
            cancelFn();
        }
    }

    function clearRequestQueue() {
        clearBatchDebounceTimer();
        while (pendingBatchQueue.length > 0) pendingBatchQueue.shift().resolve(null);
        while (requestQueue.length > 0) requestQueue.shift().resolve(null);
    }

    function clearContributionsSchedule() {
        ipContributionsDelayTimer = clearTimer(ipContributionsDelayTimer, false);
        if (ipContributionsVisibilityHandler && typeof document !== 'undefined' && typeof document.removeEventListener === 'function') {
            document.removeEventListener('visibilitychange', ipContributionsVisibilityHandler);
            ipContributionsVisibilityHandler = null;
        }
    }

    function blockAccess() {
        accessBlocked = true;
        clearLoadingInterval();
        clearTokenRefreshWait();
        clearContributionsSchedule();
        ipContributionsObserverTimer = clearTimer(ipContributionsObserverTimer, false);
        clearContributionsFallbackTimer();
        pendingContributionsPageCheck = false;
        pendingSpurRefresh = false;
        clearRequestQueue();
        if (observer) observer.disconnect();
        if (viewportObserver) viewportObserver.disconnect();
    }

    function clearStoredToken() {
        memoryToken = null;
        memoryTokenExpiry = null;
        mw.storage.remove(TOKEN_KEY);
        mw.storage.remove(TOKEN_USER_KEY);
        mw.storage.remove(TOKEN_EXPIRY_KEY);
    }

    function readStoredToken() {
        const storedUser = mw.storage.get(TOKEN_USER_KEY);
        const token = mw.storage.get(TOKEN_KEY);
        const storedExpiry = mw.storage.get(TOKEN_EXPIRY_KEY);
        const hasStoredExpiry = (typeof storedExpiry === 'string' && storedExpiry.trim() !== '') ||
            (typeof storedExpiry === 'number' && isFinite(storedExpiry));
        if (hasStoredExpiry) {
            const expiryMs = Number(storedExpiry);
            if (!isFinite(expiryMs) || Date.now() >= expiryMs) {
                clearStoredToken();
                return null;
            }
        }
        if (typeof token === 'string' && token) {
            if (storedUser !== username) {
                clearStoredToken();
                return null;
            }
            memoryToken = token;
            memoryTokenExpiry = hasStoredExpiry ? Number(storedExpiry) : null;
            return token;
        }
        if (typeof storedUser === 'string' && storedUser && storedUser !== username) {
            clearStoredToken();
            return null;
        }
        if (memoryToken && memoryTokenExpiry !== null && Date.now() >= memoryTokenExpiry) {
            clearStoredToken();
            return null;
        }
        return memoryToken;
    }

    function storeToken(token, expiresInSeconds) {
        memoryToken = token;
        memoryTokenExpiry = null;
        mw.storage.set(TOKEN_KEY, token);
        mw.storage.set(TOKEN_USER_KEY, username);
        if (typeof expiresInSeconds === 'number' && isFinite(expiresInSeconds) && expiresInSeconds > 0 && Math.floor(expiresInSeconds) === expiresInSeconds) {
            const expiryMs = Date.now() + Math.max(0, expiresInSeconds - 60) * 1000;
            memoryTokenExpiry = expiryMs;
            mw.storage.set(TOKEN_EXPIRY_KEY, String(expiryMs));
        } else {
            mw.storage.remove(TOKEN_EXPIRY_KEY);
        }
    }

    function isValidIp(ip) {
        return Boolean(ip && (IPV4_PATTERN.test(ip) || IPV6_PATTERN.test(ip)));
    }

    function parseIpv4Octets(text) {
        if (!text || !text.includes('.') || text.includes(':')) return null;
        const parts = text.split('.');
        if (parts.length !== 4) return null;
        const octets = [];
        for (const p of parts) {
            if (!/^\d{1,3}$/.test(p)) return null;
            const num = parseInt(p, 10);
            if (isNaN(num) || num < 0 || num > 255) return null;
            octets.push(num);
        }
        return octets;
    }

    function canonicalizeIpKey(rawIp) {
        if (rawIp === null || rawIp === undefined) return '';
        let normalized = String(rawIp).trim().toLowerCase();
        if (!normalized) return '';
        if (normalized.includes(':')) {
            const zoneIdx = normalized.indexOf('%');
            if (zoneIdx !== -1) normalized = normalized.slice(0, zoneIdx);
            if (!normalized) return '';
        }
        const v4 = parseIpv4Octets(normalized);
        if (v4) return v4.join('.');
        if (!normalized.includes(':')) return normalized;

        const halves = normalized.split('::');
        if (halves.length > 2) return normalized;
        const hasComp = halves.length === 2;
        const left = halves[0] ? halves[0].split(':') : [];
        const right = hasComp && halves[1] ? halves[1].split(':') : [];
        const tail = hasComp ? right : left;
        if (tail.length > 0 && tail[tail.length - 1].includes('.')) {
            const emb = parseIpv4Octets(tail[tail.length - 1]);
            if (!emb) return normalized;
            tail.pop();
            tail.push(((emb[0] << 8) | emb[1]).toString(16), ((emb[2] << 8) | emb[3]).toString(16));
        }
        const total = left.length + right.length;
        if ((hasComp && total >= 8) || (!hasComp && total !== 8)) return normalized;

        const expanded = [
            ...left,
            ...(hasComp ? Array(8 - total).fill('0') : []),
            ...right
        ];
        for (let i = 0; i < 8; i++) {
            if (!/^[0-9a-f]{1,4}$/.test(expanded[i])) return normalized;
            expanded[i] = expanded[i].replace(/^0+/, '') || '0';
        }
        if (expanded[0] === '0' && expanded[1] === '0' && expanded[2] === '0' && expanded[3] === '0' && expanded[4] === '0' && expanded[5] === 'ffff') {
            const hi = parseInt(expanded[6], 16);
            const lo = parseInt(expanded[7], 16);
            return `::ffff:${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
        }
        let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (let i = 0; i < 8; i++) {
            if (expanded[i] === '0') {
                if (curStart === -1) { curStart = i; curLen = 1; } else { curLen += 1; }
                if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; }
            } else {
                curStart = -1; curLen = 0;
            }
        }
        if (bestLen <= 1) return expanded.join(':');
        if (bestLen === 8) return '::';
        return expanded.slice(0, bestStart).join(':') + '::' + expanded.slice(bestStart + bestLen).join(':');
    }

    function warnPersistedCacheOnce(context, err) {
        if (storageFailureWarned) return;
        storageFailureWarned = true;
        warn('Persisted cache ' + context + ':', err);
    }

    function wrapWebStorage(name) {
        try {
            const s = typeof window !== 'undefined' ? window[name] : null;
            if (!s || typeof s.getItem !== 'function' || typeof s.setItem !== 'function') return null;
            return {
                get: (k) => s.getItem(k),
                set: (k, v) => { s.setItem(k, v); return true; },
                remove: (k) => { if (typeof s.removeItem === 'function') s.removeItem(k); }
            };
        } catch (err) {
            warnPersistedCacheOnce('storage access failed for ' + name, err);
            return null;
        }
    }

    function wrapMwStorage(contextLabel) {
        try {
            if (mw && mw.storage && typeof mw.storage.get === 'function' && typeof mw.storage.set === 'function') {
                return {
                    get: (k) => mw.storage.get(k),
                    set: (k, v) => mw.storage.set(k, v) !== false,
                    remove: (k) => { if (typeof mw.storage.remove === 'function') mw.storage.remove(k); }
                };
            }
        } catch (err) {
            warnPersistedCacheOnce(contextLabel + ' for mw.storage', err);
        }
        return null;
    }

    function getResultStorageBackend() {
        return wrapWebStorage('localStorage') || wrapMwStorage('storage access failed') || wrapWebStorage('sessionStorage');
    }

    function getAutoSwrStorageBackend() {
        return wrapMwStorage('auto-refresh limiter access failed') || wrapWebStorage('localStorage');
    }

    function tryConsumeAutoSwrBudget() {
        const now = Date.now();
        const backend = getAutoSwrStorageBackend();
        let recent = [];
        let raw = null;
        if (backend) {
            try { raw = backend.get(AUTO_SWR_STORAGE_KEY); } catch (err) { warnPersistedCacheOnce('auto-refresh limiter read failed', err); }
        }
        if (typeof raw === 'string' && raw) {
            try {
                const parsed = JSON.parse(raw);
                if (Array.isArray(parsed)) {
                    recent = parsed.filter((ts) => typeof ts === 'number' && isFinite(ts) && (now - ts) > -5000 && (now - ts) < AUTO_SWR_WINDOW_MS);
                }
            } catch (err) {
                warnPersistedCacheOnce('auto-refresh limiter parse failed', err);
                recent = [];
            }
        } else if (!backend) {
            recent = memoryAutoSwrTimestamps.filter((ts) => (now - ts) > -5000 && (now - ts) < AUTO_SWR_WINDOW_MS);
        }

        const persist = (list, label) => {
            memoryAutoSwrTimestamps = list.slice();
            if (backend) {
                try { backend.set(AUTO_SWR_STORAGE_KEY, JSON.stringify(list)); } catch (err) { warnPersistedCacheOnce(label, err); }
            }
        };

        if (recent.length >= AUTO_SWR_MAX_REQUESTS) {
            persist(recent, 'auto-refresh limiter trim failed');
            return false;
        }
        recent.push(now);
        persist(recent, 'auto-refresh limiter write failed');
        return true;
    }

    function compactIpResultForStorage(data) {
        if (!data || typeof data !== 'object') return null;
        const copy = {};
        for (const [k, v] of Object.entries(data)) {
            if (k === 'results' && Array.isArray(v)) {
                copy.results = v.map((row) => {
                    if (!row || typeof row !== 'object') return row;
                    const compactRow = {};
                    for (const [rk, rv] of Object.entries(row)) {
                        if (rk !== 'rawJson') compactRow[rk] = rv;
                    }
                    return compactRow;
                });
            } else {
                copy[k] = v;
            }
        }
        return copy;
    }

    function clearCorruptPersistedStore(backend) {
        persistedCacheRaw = null;
        persistedCacheStore = null;
        try { backend.remove(RESULT_CACHE_STORAGE_KEY); } catch (err) { warnPersistedCacheOnce('cleanup failed', err); }
    }

    function readPersistedResultStore(backend) {
        if (!backend) return null;
        let raw = null;
        try { raw = backend.get(RESULT_CACHE_STORAGE_KEY); } catch (err) {
            persistedCacheRaw = null;
            persistedCacheStore = null;
            warnPersistedCacheOnce('read failed', err);
            return null;
        }
        if (typeof raw !== 'string' || !raw) {
            persistedCacheRaw = null;
            persistedCacheStore = null;
            return null;
        }
        if (raw === persistedCacheRaw && persistedCacheStore) return persistedCacheStore;
        let parsed = null;
        try { parsed = JSON.parse(raw); } catch (err) {
            warnPersistedCacheOnce('parse failed', err);
            clearCorruptPersistedStore(backend);
            return null;
        }
        if (!parsed || typeof parsed !== 'object' || !parsed.entries || typeof parsed.entries !== 'object' || Array.isArray(parsed.entries)) {
            clearCorruptPersistedStore(backend);
            return null;
        }
        persistedCacheRaw = raw;
        persistedCacheStore = parsed;
        return parsed;
    }

    function isRowQuotaGuarded(row) {
        return Boolean(row && typeof row === 'object' && (row.isQuotaGuarded || row.isQuotaGuard));
    }

    function hasDegradedQuotaOrCooldown(data) {
        if (!data || typeof data !== 'object' || !Array.isArray(data.results)) return false;
        return data.results.some((row) => row && typeof row === 'object' && (
            isRowQuotaGuarded(row) ||
            (row.isCooldown && (!row.provider || Object.prototype.hasOwnProperty.call(COMMERCIAL_PROVIDERS, row.provider)))
        ));
    }

    function getResultEntryTtlMs(entry) {
        if (entry && typeof entry.ttlMs === 'number' && isFinite(entry.ttlMs) && entry.ttlMs > 0) {
            return Math.min(entry.ttlMs, RESULT_CACHE_TTL_MS);
        }
        return entry && entry.data && hasDegradedQuotaOrCooldown(entry.data) ? DEGRADED_CACHE_TTL_MS : RESULT_CACHE_TTL_MS;
    }

    function isResultEntryValid(entry, now) {
        return Boolean(entry && typeof entry === 'object' && typeof entry.ts === 'number' && isFinite(entry.ts) &&
            (now - entry.ts < getResultEntryTtlMs(entry)) && entry.data && typeof entry.data === 'object');
    }

    function cloneEntriesExcluding(sourceEntries, excludedKey) {
        const nextEntries = Object.create(null);
        if (!sourceEntries) return nextEntries;
        for (const [k, v] of Object.entries(sourceEntries)) {
            if (k !== excludedKey) nextEntries[k] = v;
        }
        return nextEntries;
    }

    function pruneExpiredResultEntries(entries, now) {
        for (const k of Object.keys(entries)) {
            if (!isResultEntryValid(entries[k], now)) delete entries[k];
        }
    }

    function evictOldestResultEntries(entries, maxEntries, protectedKey) {
        const keys = Object.keys(entries);
        if (keys.length <= maxEntries) return;
        const sortable = keys.map((key, order) => ({
            key,
            ts: entries[key].ts,
            order,
            isProtected: Boolean(protectedKey && key === protectedKey)
        })).sort((a, b) => (a.isProtected !== b.isProtected ? (a.isProtected ? 1 : -1) : (a.ts !== b.ts ? a.ts - b.ts : a.order - b.order)));
        for (let i = 0; i < sortable.length - maxEntries; i++) delete entries[sortable[i].key];
    }

    function writePersistedResultStore(backend, store, protectedKey) {
        if (!backend || !store) return false;
        persistedCacheRaw = null;
        persistedCacheStore = null;
        const count = Object.keys(store.entries).length;
        const limits = count === 0 ? [0] : [count, Math.floor(RESULT_CACHE_MAX_ENTRIES / 2), 20, 1];
        const tried = Object.create(null);
        let lastErr = null;
        for (const limit of limits) {
            if (tried[limit]) continue;
            tried[limit] = true;
            evictOldestResultEntries(store.entries, limit, protectedKey);
            let serialized;
            try { serialized = JSON.stringify(store); } catch (err) { warnPersistedCacheOnce('serialization failed', err); return false; }
            try {
                if (backend.set(RESULT_CACHE_STORAGE_KEY, serialized)) {
                    persistedCacheRaw = serialized;
                    persistedCacheStore = store;
                    return true;
                }
            } catch (err) { lastErr = err; }
        }
        if (lastErr) warnPersistedCacheOnce('write failed', lastErr);
        return false;
    }

    function normalizeQueryMode(mode) {
        return String(mode || 'light').trim().toLowerCase() === 'full' ? 'full' : 'light';
    }

    function isPartialLightResult(data) {
        return Boolean(data && typeof data === 'object' && data.queryMode === 'light' && data.isPartialMode);
    }

    function recordFullResultMeta(cacheKey, data, timestampMs) {
        if (!cacheKey || !data || typeof data !== 'object' || isPartialLightResult(data)) return;
        const ts = typeof timestampMs === 'number' && isFinite(timestampMs) ? timestampMs : Date.now();
        fullResultMetaByIp.set(cacheKey, { ts, ttlMs: hasDegradedQuotaOrCooldown(data) ? DEGRADED_CACHE_TTL_MS : RESULT_CACHE_TTL_MS });
    }

    function isMemoryFullResultFresh(cacheKey, data) {
        if (!cacheKey || !data || typeof data !== 'object' || isPartialLightResult(data)) return false;
        const meta = fullResultMetaByIp.get(cacheKey);
        return meta ? (Date.now() - meta.ts) < meta.ttlMs : !hasDegradedQuotaOrCooldown(data);
    }

    function recordLatestIpResult(cacheKey, data) {
        if (!cacheKey || !data || typeof data !== 'object') return;
        const existing = latestResultByIp.get(cacheKey);
        if (existing && !isPartialLightResult(existing) && isPartialLightResult(data)) return;
        latestResultByIp.set(cacheKey, data);
    }

    function deleteKeyFromPersistedStore(backend, store, cacheKey, now) {
        const nextEntries = cloneEntriesExcluding(store.entries, cacheKey);
        pruneExpiredResultEntries(nextEntries, now);
        writePersistedResultStore(backend, { entries: nextEntries }, null);
    }

    function readPersistedIpResultEntry(cacheKey) {
        if (!cacheKey || typeof cacheKey !== 'string') return null;
        const backend = getResultStorageBackend();
        const store = readPersistedResultStore(backend);
        if (!store || !Object.prototype.hasOwnProperty.call(store.entries, cacheKey)) return null;
        const now = Date.now();
        const entry = store.entries[cacheKey];
        if (!isResultEntryValid(entry, now)) {
            deleteKeyFromPersistedStore(backend, store, cacheKey, now);
            return null;
        }
        return entry;
    }

    function readPersistedIpResult(cacheKey) {
        const entry = readPersistedIpResultEntry(cacheKey);
        return entry ? entry.data : null;
    }

    function removePersistedIpResult(cacheKey) {
        if (!cacheKey || typeof cacheKey !== 'string') return;
        const backend = getResultStorageBackend();
        const store = readPersistedResultStore(backend);
        if (store && Object.prototype.hasOwnProperty.call(store.entries, cacheKey)) {
            deleteKeyFromPersistedStore(backend, store, cacheKey, Date.now());
        }
    }

    function invalidateIpResultCache(ip) {
        const cacheKey = canonicalizeIpKey(ip);
        const rawLower = typeof ip === 'string' ? ip.trim().toLowerCase() : '';
        const keys = [cacheKey, rawLower].filter((k, idx, arr) => k && arr.indexOf(k) === idx);
        for (const key of keys) {
            ipPromiseCache.delete(key);
            ipFullPromiseCache.delete(key);
            latestResultByIp.delete(key);
            fullResultMetaByIp.delete(key);
            removePersistedIpResult(key);
        }
    }

    function writePersistedIpResult(cacheKey, data) {
        if (!cacheKey || typeof cacheKey !== 'string' || !data || typeof data !== 'object') return;
        const compactData = compactIpResultForStorage(data);
        const backend = compactData ? getResultStorageBackend() : null;
        if (!backend) return;
        const now = Date.now();
        const existingStore = readPersistedResultStore(backend);
        const existingEntry = existingStore && existingStore.entries ? existingStore.entries[cacheKey] : null;
        if (isPartialLightResult(compactData) && isResultEntryValid(existingEntry, now) && !isPartialLightResult(existingEntry.data)) return;
        const nextEntries = cloneEntriesExcluding(existingStore && existingStore.entries, cacheKey);
        pruneExpiredResultEntries(nextEntries, now);
        nextEntries[cacheKey] = {
            ts: now,
            ttlMs: hasDegradedQuotaOrCooldown(compactData) ? DEGRADED_CACHE_TTL_MS : RESULT_CACHE_TTL_MS,
            data: compactData
        };
        evictOldestResultEntries(nextEntries, RESULT_CACHE_MAX_ENTRIES, cacheKey);
        writePersistedResultStore(backend, { entries: nextEntries }, cacheKey);
    }

    function ensureConsent(forcePrompt) {
        if (accessBlocked) return Promise.resolve(false);
        if (consentGranted || mw.storage.get(CONSENT_KEY) === '1') {
            consentGranted = true;
            consentDeclined = false;
            return Promise.resolve(true);
        }
        if (consentDeclined && !forcePrompt) return Promise.resolve(false);
        if (consentPromise) return consentPromise;

        consentDeclined = false;
        consentPromise = mw.loader.using('oojs-ui-windows').then(() => {
            const $msg = $('<div>').append(
                $('<p>').text('By using this script, you acknowledge that you fully understand and agree to comply with:'),
                $('<ul>').append(
                    $('<li>').append($('<a>', {
                        href: 'https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_Access_to_Nonpublic_Personal_Data_Policy',
                        target: '_blank', rel: 'noopener noreferrer',
                        text: 'Wikimedia Foundation Access to Nonpublic Personal Data Policy'
                    })),
                    $('<li>').append($('<a>', {
                        href: 'https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy',
                        target: '_blank', rel: 'noopener noreferrer',
                        text: 'Wikimedia Foundation Privacy Policy'
                    }))
                ),
                $('<p>').text('and all other applicable policies and guidelines regarding Temporary Account IP reveal.'),
                $('<p>').text('Do you agree and wish to proceed?')
            );
            return OO.ui.confirm($msg, { title: 'Proxy Detector on Temporary Account IP', size: 'medium' });
        }).then((agreed) => {
            consentPromise = null;
            if (agreed) {
                consentGranted = true;
                consentDeclined = false;
                mw.storage.set(CONSENT_KEY, '1');
                return true;
            }
            consentDeclined = true;
            return false;
        }).catch((err) => {
            warn('Consent dialog failed:', err);
            consentPromise = null;
            consentDeclined = true;
            return false;
        });
        return consentPromise;
    }

    function isTokenRefreshLockActive() {
        const raw = mw.storage.get(TOKEN_REFRESH_LOCK_KEY);
        if (raw === false || raw === null || raw === undefined || raw === '') return false;
        const ts = Number(raw);
        if (!isFinite(ts) || ts <= 0) return false;
        const age = Date.now() - ts;
        return age >= -5000 && age < TOKEN_REFRESH_LOCK_TTL_MS;
    }

    function acquireTokenRefreshLock() {
        const lockVal = String(Date.now());
        mw.storage.set(TOKEN_REFRESH_LOCK_KEY, lockVal);
        return lockVal;
    }

    function releaseTokenRefreshLock(lockVal) {
        if (!lockVal) { mw.storage.remove(TOKEN_REFRESH_LOCK_KEY); return; }
        const cur = mw.storage.get(TOKEN_REFRESH_LOCK_KEY);
        if (cur !== null && cur !== undefined && cur !== false && String(cur) === String(lockVal)) {
            mw.storage.remove(TOKEN_REFRESH_LOCK_KEY);
        }
    }

    function waitForCrossTabTokenRefresh(failedToken) {
        return new Promise((resolve) => {
            const startedAt = Date.now();
            let settled = false;
            const finish = (token) => {
                if (settled) return;
                settled = true;
                tokenRefreshWaitTimer = clearTimer(tokenRefreshWaitTimer, false);
                if (tokenRefreshWaitCancel === cancelWait) tokenRefreshWaitCancel = null;
                resolve(token || null);
            };
            const cancelWait = () => finish(null);
            tokenRefreshWaitCancel = cancelWait;

            const poll = () => {
                if (accessBlocked) return finish(null);
                const stored = readStoredToken();
                if (stored && (!failedToken || stored !== failedToken)) return finish(stored);
                if (!isTokenRefreshLockActive() || Date.now() - startedAt >= TOKEN_REFRESH_WAIT_TIMEOUT_MS) return finish(null);
                tokenRefreshWaitTimer = window.setTimeout(poll, TOKEN_REFRESH_POLL_INTERVAL_MS);
            };
            tokenRefreshWaitTimer = window.setTimeout(poll, TOKEN_REFRESH_POLL_INTERVAL_MS);
        });
    }

    function performGadgetTokenExchange() {
        if (accessBlocked) return Promise.resolve(null);
        const lockVal = acquireTokenRefreshLock();
        clearStoredToken();
        const wikiDomain = mw.config.get('wgServerName');

        return Promise.resolve(mw.loader.using('mediawiki.api')).then(() => {
            if (accessBlocked) return null;
            return new mw.Api().get({ action: 'centralauthtoken' }).then((d) => d, (code, details) => {
                warn('centralauthtoken request failed:', { code, details });
                return null;
            });
        }).then((apiData) => {
            if (!apiData || accessBlocked) return null;
            const cat = apiData.centralauthtoken && apiData.centralauthtoken.centralauthtoken;
            if (!cat || typeof cat !== 'string') {
                warn('Missing centralauthtoken:', apiData);
                return null;
            }
            return fetch(TOOL_BASE_URL + '/api/v1/auth/gadget-token', {
                method: 'POST', mode: 'cors', credentials: 'omit',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ centralauthtoken: cat, domain: wikiDomain })
            }).then((res) => {
                if (!res.ok) {
                    return res.text().then((txt) => {
                        warn(`Gadget token HTTP ${res.status}:`, txt);
                        if (res.status === 403) { clearStoredToken(); blockAccess(); }
                        else if (res.status === 401) clearStoredToken();
                        return null;
                    });
                }
                return res.json().then((payload) => {
                    const tok = payload && payload.token;
                    if (!tok || typeof tok !== 'string') {
                        warn('Token missing in response:', payload);
                        return null;
                    }
                    storeToken(tok, payload.expires_in);
                    return tok;
                });
            });
        }).catch((err) => {
            warn('CentralAuth token exchange failed:', err);
            return null;
        }).then((tok) => {
            releaseTokenRefreshLock(lockVal);
            return tok;
        });
    }

    function refreshGadgetToken(failedToken) {
        if (accessBlocked) return Promise.resolve(null);
        if (authPromise) return authPromise;
        const latest = readStoredToken();
        if (latest && (!failedToken || latest !== failedToken)) return Promise.resolve(latest);

        const pending = isTokenRefreshLockActive()
            ? waitForCrossTabTokenRefresh(failedToken).then((shared) => {
                if (accessBlocked) return null;
                if (shared && (!failedToken || shared !== failedToken)) return shared;
                const cur = readStoredToken();
                if (cur && (!failedToken || cur !== failedToken)) return cur;
                return performGadgetTokenExchange();
            })
            : performGadgetTokenExchange();

        const tracked = pending.then((tok) => {
            if (authPromise === tracked) authPromise = null;
            return tok;
        }, (err) => {
            if (authPromise === tracked) authPromise = null;
            throw err;
        });
        authPromise = tracked;
        return tracked;
    }

    function ensureGadgetToken() {
        if (accessBlocked) return Promise.resolve(null);
        const stored = readStoredToken();
        return stored ? Promise.resolve(stored) : refreshGadgetToken(null);
    }

    function handleDetectAuthStatus(status, token, hasRetried, retryFn) {
        if (status === 403 || (status === 401 && hasRetried)) {
            clearStoredToken();
            blockAccess();
            return null;
        }
        return refreshGadgetToken(token).then((fresh) => (!fresh || accessBlocked) ? null : retryFn(fresh));
    }

    function apiFetchWithAuth(path, opts, token, hasRetried) {
        const headers = Object.assign({ 'Authorization': 'Bearer ' + token }, opts.headers || {});
        return fetch(TOOL_BASE_URL + path, Object.assign({ mode: 'cors', credentials: 'omit' }, opts, { headers }))
            .then((response) => {
                if (response.status === 401 || response.status === 403) {
                    return handleDetectAuthStatus(response.status, token, hasRetried, (fresh) =>
                        apiFetchWithAuth(path, opts, fresh, true)
                    );
                }
                return response;
            });
    }

    function fetchDetectWithToken(ip, token, hasRetried, mode) {
        if (!isValidIp(ip)) return Promise.resolve(null);
        const resolvedMode = normalizeQueryMode(mode);
        return apiFetchWithAuth(
            `/api/v1/detect?ip=${encodeURIComponent(ip)}&compact=1&mode=${encodeURIComponent(resolvedMode)}`,
            { method: 'GET' },
            token,
            hasRetried
        ).then((res) => {
            if (!res) return null;
            if (!res.ok) { warn(`Detection API HTTP ${res.status} for ${ip}`); return null; }
            return res.json();
        });
    }

    function fetchRefreshDetectWithToken(ip, token, hasRetried, mode) {
        if (!isValidIp(ip)) return Promise.resolve({ ok: false, status: 0, rateLimited: false, data: null });
        const resolvedMode = normalizeQueryMode(mode || 'full');
        return apiFetchWithAuth(
            '/api/v1/detect/refresh',
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, mode: resolvedMode, compact: false })
            },
            token,
            hasRetried
        ).then((res) => {
            if (!res) return { ok: false, status: 401, rateLimited: false, data: null };
            if (res.status === 429) {
                return res.json().catch(() => ({})).then((errBody) => ({
                    ok: false,
                    status: 429,
                    rateLimited: true,
                    retryAfterSeconds: errBody && typeof errBody.retryAfterSeconds === 'number' ? errBody.retryAfterSeconds : null,
                    message: errBody && typeof errBody.message === 'string' ? errBody.message : '',
                    data: null
                }));
            }
            if (!res.ok) {
                warn(`Refresh API HTTP ${res.status} for ${ip}`);
                return { ok: false, status: res.status, rateLimited: false, data: null };
            }
            return res.json().then((payload) => ({ ok: true, status: 200, rateLimited: false, data: payload }));
        });
    }

    function pumpRequestQueue() {
        if (accessBlocked) { clearRequestQueue(); return; }
        while (activeRequestCount < MAX_CONCURRENT_REQUESTS && requestQueue.length > 0) {
            const item = requestQueue.shift();
            runQueuedNetworkTask(item.taskFn, item.resolve, item.reject);
        }
    }

    function runQueuedNetworkTask(taskFn, resolve, reject) {
        if (accessBlocked) { clearRequestQueue(); resolve(null); return; }
        activeRequestCount += 1;
        let p;
        try { p = Promise.resolve(taskFn()); } catch (err) { p = Promise.reject(err); }
        p.then((res) => { activeRequestCount -= 1; pumpRequestQueue(); resolve(res); },
               (err) => { activeRequestCount -= 1; pumpRequestQueue(); reject(err); });
    }

    function enqueueNetworkTask(taskFn) {
        if (accessBlocked) { clearRequestQueue(); return Promise.resolve(null); }
        return new Promise((resolve, reject) => {
            if (activeRequestCount < MAX_CONCURRENT_REQUESTS) runQueuedNetworkTask(taskFn, resolve, reject);
            else requestQueue.push({ taskFn, resolve, reject });
        });
    }

    function runWithToken(fn) {
        return enqueueNetworkTask(() => {
            if (accessBlocked) return null;
            return ensureGadgetToken().then((token) => (!token || accessBlocked) ? null : fn(token));
        });
    }

    function enqueueSingleIpDetection(ip, mode) {
        const resolvedMode = normalizeQueryMode(mode);
        return runWithToken((token) => fetchDetectWithToken(ip, token, false, resolvedMode));
    }

    function fetchBatchDetectWithToken(ips, token, hasRetried, mode) {
        const validIps = Array.isArray(ips) ? ips.filter(isValidIp) : [];
        if (validIps.length === 0) return Promise.resolve(null);
        return apiFetchWithAuth(
            '/api/v1/detect/batch?compact=1',
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ips: validIps, mode: normalizeQueryMode(mode) })
            },
            token,
            hasRetried
        ).then((res) => {
            if (!res) return null;
            if (res.status === 404 || res.status === 405) { batchEndpointSupported = false; return { fallbackSingle: true }; }
            if (!res.ok) { warn(`Batch API HTTP ${res.status}`); return null; }
            return res.json();
        });
    }

    function markBatchOriginatedPayload(entry) {
        if (batchOriginatedPayloads && entry && typeof entry === 'object') batchOriginatedPayloads.add(entry);
        return entry;
    }

    function extractIpResultFromBatch(batchPayload, rawIp) {
        if (!batchPayload || typeof batchPayload !== 'object') return null;
        const results = batchPayload.results;
        if (!results || typeof results !== 'object') return null;
        const trimmed = String(rawIp || '').trim();
        const lower = trimmed.toLowerCase();
        const canonical = canonicalizeIpKey(trimmed);
        for (const k of [trimmed, lower, canonical]) {
            if (k && Object.prototype.hasOwnProperty.call(results, k) && results[k]) return markBatchOriginatedPayload(results[k]);
        }
        const inputMap = batchPayload.inputMap;
        if (inputMap && typeof inputMap === 'object') {
            const mapped = inputMap[rawIp] || inputMap[trimmed] || inputMap[lower] || (canonical ? inputMap[canonical] : '');
            if (mapped && Object.prototype.hasOwnProperty.call(results, mapped) && results[mapped]) {
                return markBatchOriginatedPayload(results[mapped]);
            }
        }
        for (const [k, entry] of Object.entries(results)) {
            if (k.toLowerCase() === lower || (canonical && canonicalizeIpKey(k) === canonical)) return markBatchOriginatedPayload(entry);
            if (entry && typeof entry.ip === 'string' && (entry.ip.toLowerCase() === lower || (canonical && canonicalizeIpKey(entry.ip) === canonical))) {
                return markBatchOriginatedPayload(entry);
            }
        }
        return null;
    }

    function fallbackBatchItemsToSingle(batchItems) {
        for (const item of batchItems) enqueueSingleIpDetection(item.ip, item.mode).then(item.resolve, item.reject);
    }

    function dispatchBatchBucket(bucketItems, bucketMode) {
        if (!bucketItems || bucketItems.length === 0) return;
        const uniqueIps = [];
        const seen = Object.create(null);
        for (const item of bucketItems) {
            const key = canonicalizeIpKey(item.ip) || item.ip.toLowerCase();
            if (!seen[key]) { seen[key] = true; uniqueIps.push(item.ip); }
        }
        runWithToken((token) => batchEndpointSupported ? fetchBatchDetectWithToken(uniqueIps, token, false, bucketMode) : { fallbackSingle: true })
            .then((batchPayload) => {
                if (batchPayload && batchPayload.fallbackSingle) {
                    clearBatchDebounceTimer();
                    fallbackBatchItemsToSingle(bucketItems.concat(pendingBatchQueue.splice(0, pendingBatchQueue.length)));
                    return;
                }
                for (const item of bucketItems) item.resolve(extractIpResultFromBatch(batchPayload, item.ip));
            }, (err) => {
                for (const item of bucketItems) item.reject(err);
            });
    }

    function dispatchBatchItems(batchItems) {
        if (!batchItems || batchItems.length === 0) return;
        if (accessBlocked) { batchItems.forEach((i) => i.resolve(null)); return; }
        if (!batchEndpointSupported) { fallbackBatchItemsToSingle(batchItems); return; }
        const light = [], full = [];
        for (const item of batchItems) (normalizeQueryMode(item.mode) === 'full' ? full : light).push(item);
        dispatchBatchBucket(light, 'light');
        dispatchBatchBucket(full, 'full');
    }

    function flushPendingBatch() {
        clearBatchDebounceTimer();
        if (accessBlocked) { clearRequestQueue(); return; }
        while (pendingBatchQueue.length > 0) dispatchBatchItems(pendingBatchQueue.splice(0, MAX_BATCH_IPS));
    }

    function enqueueBatchIpDetection(ip, mode) {
        const resolvedMode = normalizeQueryMode(mode);
        if (accessBlocked) return Promise.resolve(null);
        if (!batchEndpointSupported) return enqueueSingleIpDetection(ip, resolvedMode);
        return new Promise((resolve, reject) => {
            pendingBatchQueue.push({ ip, mode: resolvedMode, resolve, reject });
            if (pendingBatchQueue.length >= MAX_BATCH_IPS) flushPendingBatch();
            else if (batchDebounceTimer === null) {
                batchDebounceTimer = window.setTimeout(() => { batchDebounceTimer = null; flushPendingBatch(); }, BATCH_DEBOUNCE_MS);
            }
        });
    }

    function syncResolvedIpAliases(cacheKey, data, promise, includeFullCache, recordedTs) {
        const resolvedTs = typeof recordedTs === 'number' && isFinite(recordedTs) ? recordedTs : Date.now();
        const writeAlias = (k) => {
            recordLatestIpResult(k, data);
            if (includeFullCache) recordFullResultMeta(k, data, resolvedTs);
            writePersistedIpResult(k, data);
        };
        writeAlias(cacheKey);
        if (typeof data.ip !== 'string') return;
        const resolvedKey = canonicalizeIpKey(data.ip);
        if (!resolvedKey || resolvedKey === cacheKey) return;
        writeAlias(resolvedKey);
        if (!ipPromiseCache.has(resolvedKey) || includeFullCache) ipPromiseCache.set(resolvedKey, promise);
        if (includeFullCache && !ipFullPromiseCache.has(resolvedKey)) ipFullPromiseCache.set(resolvedKey, promise);
    }

    function pruneExpiredFullMemoryCache(cacheKey) {
        if (!ipFullPromiseCache.has(cacheKey)) return false;
        const cachedLatest = latestResultByIp.get(cacheKey);
        if (cachedLatest && fullResultMetaByIp.has(cacheKey) && !isMemoryFullResultFresh(cacheKey, cachedLatest)) {
            const expired = ipFullPromiseCache.get(cacheKey);
            ipFullPromiseCache.delete(cacheKey);
            fullResultMetaByIp.delete(cacheKey);
            if (ipPromiseCache.get(cacheKey) === expired) ipPromiseCache.delete(cacheKey);
            return true;
        }
        return false;
    }

    function executeIpRefresh(ip) {
        const failOutcome = (extra) => Object.assign({ ok: false, rateLimited: false, retryAfterSeconds: null, degradedFallback: false, data: null }, extra);
        if (accessBlocked || !isValidIp(ip)) return Promise.resolve(failOutcome());
        const cacheKey = canonicalizeIpKey(ip);
        if (!cacheKey) return Promise.resolve(failOutcome());
        if (inflightRefreshByIp.has(cacheKey)) return inflightRefreshByIp.get(cacheKey);

        const refreshPromise = runWithToken((token) => fetchRefreshDetectWithToken(ip, token, false, 'full'))
            .then((res) => {
                if (inflightRefreshByIp.get(cacheKey) === refreshPromise) inflightRefreshByIp.delete(cacheKey);
                autoSwrAttemptedKeys.add(cacheKey);
                if (!res || !res.ok || !res.data || typeof res.data !== 'object') {
                    return failOutcome({
                        rateLimited: Boolean(res && res.rateLimited),
                        retryAfterSeconds: res && typeof res.retryAfterSeconds === 'number' ? res.retryAfterSeconds : null
                    });
                }
                const aliasKey = typeof res.data.ip === 'string' ? canonicalizeIpKey(res.data.ip) : '';
                if (aliasKey) {
                    autoSwrAttemptedKeys.add(aliasKey);
                    if (inflightRefreshByIp.get(aliasKey) === refreshPromise) inflightRefreshByIp.delete(aliasKey);
                }
                const meta = res.data.cacheMeta && typeof res.data.cacheMeta === 'object' ? res.data.cacheMeta : null;
                if (meta && meta.degradedRefreshFallback === true) {
                    const existingCached = latestResultByIp.get(cacheKey) || readPersistedIpResult(cacheKey);
                    if (!existingCached) {
                        const fallbackPromise = Promise.resolve(res.data);
                        ipFullPromiseCache.set(cacheKey, fallbackPromise);
                        ipPromiseCache.set(cacheKey, fallbackPromise);
                        syncResolvedIpAliases(cacheKey, res.data, fallbackPromise, true, Date.now());
                    }
                    return failOutcome({ degradedFallback: true, data: existingCached || res.data });
                }
                const freshPromise = Promise.resolve(res.data);
                ipFullPromiseCache.set(cacheKey, freshPromise);
                ipPromiseCache.set(cacheKey, freshPromise);
                syncResolvedIpAliases(cacheKey, res.data, freshPromise, true, Date.now());
                refreshRenderedBadgesForIp(res.data.ip || ip, res.data);
                return { ok: true, rateLimited: false, retryAfterSeconds: null, degradedFallback: false, data: res.data };
            }).catch((err) => {
                if (inflightRefreshByIp.get(cacheKey) === refreshPromise) inflightRefreshByIp.delete(cacheKey);
                autoSwrAttemptedKeys.add(cacheKey);
                warn(`Refresh failed for ${ip}:`, err);
                return failOutcome();
            });

        inflightRefreshByIp.set(cacheKey, refreshPromise);
        return refreshPromise;
    }

    function fetchIpIntelligence(ip, mode, options) {
        if (accessBlocked || !isValidIp(ip)) return Promise.resolve(null);
        const cacheKey = canonicalizeIpKey(ip);
        if (!cacheKey) return Promise.resolve(null);

        const resolvedMode = normalizeQueryMode(mode);
        if (resolvedMode === 'full') {
            if (options && options.forceRefresh) {
                return executeIpRefresh(ip).then((o) => (o && o.ok ? o.data : null));
            }
            if (inflightFullPromisesByIp.has(cacheKey)) return inflightFullPromisesByIp.get(cacheKey);
            pruneExpiredFullMemoryCache(cacheKey);
            if (ipFullPromiseCache.has(cacheKey)) return ipFullPromiseCache.get(cacheKey);

            const cachedLatest = latestResultByIp.get(cacheKey);
            if (cachedLatest && !isPartialLightResult(cachedLatest) && isMemoryFullResultFresh(cacheKey, cachedLatest)) {
                const p = Promise.resolve(cachedLatest);
                ipFullPromiseCache.set(cacheKey, p);
                return p;
            }
            const persistedFull = readPersistedIpResultEntry(cacheKey);
            if (persistedFull && persistedFull.data && !isPartialLightResult(persistedFull.data)) {
                recordLatestIpResult(cacheKey, persistedFull.data);
                recordFullResultMeta(cacheKey, persistedFull.data, persistedFull.ts);
                const p = Promise.resolve(persistedFull.data);
                ipFullPromiseCache.set(cacheKey, p);
                ipPromiseCache.set(cacheKey, p);
                return p;
            }
            const fullPromise = enqueueSingleIpDetection(ip, 'full').then((data) => {
                if (inflightFullPromisesByIp.get(cacheKey) === fullPromise) inflightFullPromisesByIp.delete(cacheKey);
                if (!data || typeof data !== 'object') return null;
                const alias = typeof data.ip === 'string' ? canonicalizeIpKey(data.ip) : '';
                if (alias && inflightFullPromisesByIp.get(alias) === fullPromise) inflightFullPromisesByIp.delete(alias);
                ipFullPromiseCache.set(cacheKey, fullPromise);
                ipPromiseCache.set(cacheKey, fullPromise);
                syncResolvedIpAliases(cacheKey, data, fullPromise, true, Date.now());
                return data;
            }).catch((err) => {
                if (inflightFullPromisesByIp.get(cacheKey) === fullPromise) inflightFullPromisesByIp.delete(cacheKey);
                warn(`Full detection failed for ${ip}:`, err);
                return null;
            });
            inflightFullPromisesByIp.set(cacheKey, fullPromise);
            return fullPromise;
        }

        if (inflightFullPromisesByIp.has(cacheKey)) return inflightFullPromisesByIp.get(cacheKey);
        pruneExpiredFullMemoryCache(cacheKey);
        if (ipFullPromiseCache.has(cacheKey)) return ipFullPromiseCache.get(cacheKey);
        if (ipPromiseCache.has(cacheKey)) return ipPromiseCache.get(cacheKey);

        const persistedEntry = readPersistedIpResultEntry(cacheKey);
        if (persistedEntry && persistedEntry.data) {
            recordLatestIpResult(cacheKey, persistedEntry.data);
            if (!isPartialLightResult(persistedEntry.data)) recordFullResultMeta(cacheKey, persistedEntry.data, persistedEntry.ts);
            const p = Promise.resolve(persistedEntry.data);
            ipPromiseCache.set(cacheKey, p);
            if (!isPartialLightResult(persistedEntry.data)) ipFullPromiseCache.set(cacheKey, p);
            return p;
        }

        const promise = enqueueBatchIpDetection(ip, 'light').then((data) => {
            if (!data || typeof data !== 'object') {
                if (ipPromiseCache.get(cacheKey) === promise) ipPromiseCache.delete(cacheKey);
                return null;
            }
            const isFullReady = !isPartialLightResult(data);
            if (isFullReady && !ipFullPromiseCache.has(cacheKey)) ipFullPromiseCache.set(cacheKey, promise);
            syncResolvedIpAliases(cacheKey, data, promise, isFullReady, Date.now());
            return data;
        }).catch((err) => {
            warn(`Detection failed for ${ip}:`, err);
            if (ipPromiseCache.get(cacheKey) === promise) ipPromiseCache.delete(cacheKey);
            return null;
        });
        ipPromiseCache.set(cacheKey, promise);
        return promise;
    }

    function evaluateRisk(data) {
        const isNonPublic = Boolean(data.isNonPublic);
        const nonPublicCategory = typeof data.nonPublicCategory === 'string' ? data.nonPublicCategory.trim().toLowerCase() : '';
        const nonPublicReason = typeof data.nonPublicReason === 'string' && data.nonPublicReason.trim()
            ? data.nonPublicReason.trim() : 'Non-Public / Reserved IP';
        const nonPublicBadgeCode = (nonPublicCategory === 'private' || nonPublicCategory === 'loopback' || nonPublicCategory === 'link_local') ? 'LOCAL' : 'RESERVED';

        const prediction = Number(data.prediction_score) || 0;
        const hasPrediction = data.getipintel_chance !== null && data.getipintel_chance !== undefined && !isNaN(Number(data.getipintel_chance));
        const broadcastIp = Boolean(data.is_broadcast_ip);
        const isTor = Boolean(data.isTor);
        const isMajorityProxyVpn = Boolean(data.isMajorityProxyVpn);
        const arbitrationTier = typeof data.arbitrationTier === 'string' ? data.arbitrationTier.trim().toLowerCase() : '';
        const ptrIsHighRisk = Boolean(data.ptrIsHighRisk);
        const hasCloudProvider = Boolean(typeof data.cloudProvider === 'string' && data.cloudProvider.trim());
        const arbitrationVerdict = typeof data.arbitrationVerdict === 'string' ? data.arbitrationVerdict.trim() : '';
        const torLabel = typeof data.torLabel === 'string' && data.torLabel.trim() ? data.torLabel.trim() : (isTor ? 'Tor Node' : '');
        const torSummary = typeof data.torSummary === 'string' && data.torSummary.trim() ? data.torSummary.trim() : '';
        const torFlags = Array.isArray(data.torFlags) ? data.torFlags.map((f) => typeof f === 'string' ? f.trim() : '').filter(Boolean) : [];

        const rows = Array.isArray(data.results) ? data.results : [];
        let getipintelRow = null, stopforumspamRow = null;
        let hasQuotaGuardedProvider = false, hasCooldownProvider = false;
        let validCommercialCount = 0, positiveCommercialVotes = 0, validTotalSourceCount = 0;

        for (const r of rows) {
            if (!r || typeof r !== 'object') continue;
            if (r.provider === 'GetIPIntel') getipintelRow = r;
            else if (r.provider === 'StopForumSpam') stopforumspamRow = r;
            if (isRowQuotaGuarded(r)) hasQuotaGuardedProvider = true;
            else if (r.isCooldown) hasCooldownProvider = true;
            if (isValidProviderRow(r)) {
                validTotalSourceCount += 1;
                if (Object.prototype.hasOwnProperty.call(COMMERCIAL_PROVIDERS, r.provider)) {
                    validCommercialCount += 1;
                    const flags = Array.isArray(r.securityFlags) ? r.securityFlags : [];
                    const hasRiskFlag = flags.some((f) => f && f.isHighRisk) ||
                        (typeof r.usageType === 'string' && /datacenter|data center|hosting|cloud|transit|cdn/i.test(r.usageType));
                    if (hasRiskFlag) positiveCommercialVotes += 1;
                }
            }
        }

        const isSfsBlacklisted = Boolean(stopforumspamRow && (stopforumspamRow.blacklisted || stopforumspamRow.toxicCidr));
        const isSfsListed = Boolean(stopforumspamRow && (stopforumspamRow.appears || (stopforumspamRow.frequency && Number(stopforumspamRow.frequency) > 0)));
        const suspectedResidentialProxy = Boolean(data.suspectedResidentialProxy);
        const highlySuspectedResidentialProxy = Boolean(data.highlySuspectedResidentialProxy);
        const sharedPrivacyEgress = typeof data.sharedPrivacyEgress === 'string' && data.sharedPrivacyEgress.trim()
            ? data.sharedPrivacyEgress.trim().toLowerCase() : '';
        const isMobileOrCgnat = isMobileOrCgnatPayload(data);
        const openProxyPorts = extractShodanOpenProxyPorts(data);
        const isPartialLight = Boolean(data.isPartialMode || String(data.queryMode || '').trim().toLowerCase() === 'light');
        const isGetIpIntelDeferred = Boolean(getipintelRow && (getipintelRow.isDeferred || getipintelRow.status === 'Deferred (Light Mode)'));

        const hasHighOrMediumSignals = Boolean(
            isTor || isMajorityProxyVpn || highlySuspectedResidentialProxy || suspectedResidentialProxy ||
            openProxyPorts.length > 0 || sharedPrivacyEgress || arbitrationTier === 'destructive' ||
            hasCloudProvider || ptrIsHighRisk || arbitrationTier === 'warning' || broadcastIp || isSfsBlacklisted || isSfsListed
        );
        const isLightDeferredClean = Boolean(!hasPrediction && !hasHighOrMediumSignals && !hasQuotaGuardedProvider && !hasCooldownProvider && (isPartialLight || isGetIpIntelDeferred));
        const hasValidNonPredictionClean = Boolean(!hasPrediction && !hasHighOrMediumSignals && !isLightDeferredClean &&
            (validCommercialCount > 0 || (!hasQuotaGuardedProvider && !hasCooldownProvider && (validTotalSourceCount > 0 || arbitrationTier === 'success'))));

        let riskTier = 'low';
        if (isNonPublic) riskTier = 'nonpublic';
        else if ((hasPrediction && prediction > 80) || isTor || isMajorityProxyVpn || highlySuspectedResidentialProxy || arbitrationTier === 'destructive' || isSfsBlacklisted) riskTier = 'high';
        else if ((hasPrediction && prediction >= 30) || broadcastIp || suspectedResidentialProxy || openProxyPorts.length > 0 || sharedPrivacyEgress || arbitrationTier === 'warning' || ptrIsHighRisk || hasCloudProvider || isSfsListed) riskTier = 'medium';

        const predictionText = hasPrediction ? String(Number(prediction.toFixed(2))) : '';
        const giiStatus = getipintelRow && getipintelRow.status ? ` (${getipintelRow.status})` : '';
        const commSuffix = validCommercialCount > 0 ? `; ${validCommercialCount} commercial sources OK` : '';
        let predictionTooltip = '';
        if (hasPrediction) predictionTooltip = predictionText + '%';
        else if (isLightDeferredClean) predictionTooltip = 'Light screening passed (no local/free-tier flags). Click to run full commercial check.';
        else if (isPartialLight || isGetIpIntelDeferred) predictionTooltip = 'Light Mode (commercial sources deferred; click for full check)';
        else if (hasQuotaGuardedProvider) predictionTooltip = 'Quota Guard Active' + giiStatus + commSuffix;
        else if (hasCooldownProvider) predictionTooltip = 'Provider Cooldown' + giiStatus + commSuffix;
        else if (validCommercialCount > 0) predictionTooltip = `Unavailable (${positiveCommercialVotes}/${validCommercialCount} commercial sources flagged)`;
        else predictionTooltip = 'Unavailable' + (data.predictionLabel ? ` (${data.predictionLabel})` : '');

        let badgePrimaryLabel = 'N/A';
        if (highlySuspectedResidentialProxy || suspectedResidentialProxy) badgePrimaryLabel = 'RES-PROXY';
        else if (isMajorityProxyVpn || arbitrationTier === 'destructive') badgePrimaryLabel = /datacenter|hosting/i.test(arbitrationVerdict) ? 'HOSTING' : 'PROXY';
        else if (isSfsBlacklisted) badgePrimaryLabel = 'BLACKLIST';
        else if (openProxyPorts.length > 0) badgePrimaryLabel = 'PROXY-PORT';
        else if (sharedPrivacyEgress) badgePrimaryLabel = 'RELAY';
        else if (hasCloudProvider) badgePrimaryLabel = 'CLOUD';
        else if (ptrIsHighRisk) badgePrimaryLabel = 'PTR-RISK';
        else if (isSfsListed) badgePrimaryLabel = 'SPAM';
        else if (arbitrationTier === 'warning') badgePrimaryLabel = 'REVIEW';
        else if (isLightDeferredClean) badgePrimaryLabel = 'LIGHT';
        else if (hasValidNonPredictionClean) badgePrimaryLabel = validCommercialCount > 0 ? `OK ${positiveCommercialVotes}/${validCommercialCount}` : 'CLEAN';
        else if (hasQuotaGuardedProvider) badgePrimaryLabel = 'QUOTA';
        else if (hasCooldownProvider) badgePrimaryLabel = 'COOLDOWN';

        return {
            isNonPublic, nonPublicCategory, nonPublicReason, nonPublicBadgeCode,
            prediction, hasPrediction, broadcastIp, isTor, isMajorityProxyVpn,
            suspectedResidentialProxy, highlySuspectedResidentialProxy, sharedPrivacyEgress,
            isMobileOrCgnat, openProxyPorts, arbitrationTier, ptrIsHighRisk, hasCloudProvider,
            isSfsBlacklisted, isSfsListed, hasQuotaGuardedProvider, hasCooldownProvider,
            isLightDeferredClean, validCommercialCount, positiveCommercialVotes, validTotalSourceCount,
            torLabel, torFlags, torSummary, riskTier, predictionText, predictionTooltip, badgePrimaryLabel
        };
    }

    function formatTorDescription(risk) {
        if (!risk.isTor) return '';
        const label = risk.torLabel || 'Tor Node';
        if (risk.torFlags.length > 0) return `${label} (Flags: ${risk.torFlags.join(', ')})`;
        return risk.torSummary && risk.torSummary !== label ? `${label} (${risk.torSummary})` : label;
    }

    function formatCloudDescription(data) {
        if (!data || typeof data.cloudProvider !== 'string' || !data.cloudProvider.trim()) return '';
        const p = data.cloudProvider.trim();
        return typeof data.cloudCidr === 'string' && data.cloudCidr.trim() ? `${p} (${data.cloudCidr.trim()})` : p;
    }

    function getCacheMeta(data) {
        return data && typeof data === 'object' && data.cacheMeta && typeof data.cacheMeta === 'object' ? data.cacheMeta : null;
    }

    function getCacheAgeSeconds(data) {
        const meta = getCacheMeta(data);
        if (meta && typeof meta.ageSeconds === 'number' && isFinite(meta.ageSeconds) && meta.ageSeconds >= 0) {
            return Math.floor(meta.ageSeconds);
        }
        const tsRaw = (meta && (meta.fetchedAt || meta.cachedAt)) || (data && data.fetchedAt);
        const ms = tsRaw ? Date.parse(tsRaw) : NaN;
        return isNaN(ms) ? null : Math.max(0, Math.floor((Date.now() - ms) / 1000));
    }

    function formatRelativeCacheAge(ageSeconds) {
        if (typeof ageSeconds !== 'number' || !isFinite(ageSeconds) || ageSeconds < 0) return '';
        const mins = Math.floor(ageSeconds / 60);
        if (mins < 1) return 'Cached just now';
        const d = Math.floor(mins / 1440);
        const h = Math.floor((mins % 1440) / 60);
        const m = mins % 60;
        const parts = [];
        if (d > 0) parts.push(`${d}d`);
        if (h > 0) parts.push(`${h}h`);
        if (m > 0 || parts.length === 0) parts.push(`${m}m`);
        return `Cached ${parts.join('')} ago`;
    }

    function formatCacheStatusLabel(data, isJustUpdated) {
        if (isJustUpdated) return 'Just updated';
        const meta = getCacheMeta(data);
        if (meta && meta.status === 'miss') return 'Just updated';
        const ageSec = getCacheAgeSeconds(data);
        if (ageSec !== null) return formatRelativeCacheAge(ageSec);
        return data && data.isCached ? 'Cached' : 'Just updated';
    }

    function shouldAutoRefreshPayload(data, cacheKey) {
        const meta = getCacheMeta(data);
        if (!meta || meta.shouldAutoRefresh !== true) return false;
        const key = cacheKey || canonicalizeIpKey(data && data.ip);
        return !(key && autoSwrAttemptedKeys.has(key));
    }

    function isMobileOrCgnatPayload(data) {
        return Boolean(data && (data.isMobileOrCgnat === true ||
            (typeof data.ptrCategory === 'string' && data.ptrCategory.trim().toLowerCase() === 'mobile_or_cgnat')));
    }

    function getSharedPrivacyEgressLabel(data) {
        const val = data && typeof data.sharedPrivacyEgress === 'string' ? data.sharedPrivacyEgress.trim().toLowerCase() : '';
        if (val === 'icloud_private_relay') return 'Apple iCloud Private Relay';
        if (val === 'cloudflare_warp') return 'Cloudflare WARP';
        return val ? data.sharedPrivacyEgress.trim() : '';
    }

    function extractShodanOpenProxyPorts(data) {
        const ports = [];
        const addPort = (p) => {
            const n = Number(p);
            if (isFinite(n) && n > 0 && ports.indexOf(n) === -1) ports.push(n);
        };
        if (data && Array.isArray(data.openProxyPorts)) data.openProxyPorts.forEach(addPort);
        if (data && Array.isArray(data.results)) {
            data.results.forEach((r) => {
                if (r && r.provider === 'Shodan InternetDB' && Array.isArray(r.openProxyPorts)) r.openProxyPorts.forEach(addPort);
            });
        }
        return ports;
    }

    function shouldRecommendFreshResidentialRecheck(data) {
        const meta = getCacheMeta(data);
        if (meta && meta.recommendFreshRecheck === true) return true;
        const age = getCacheAgeSeconds(data);
        return Boolean(data && data.suspectedResidentialProxy && age !== null && age > RESIDENTIAL_RECHECK_THRESHOLD_SECONDS);
    }

    function isSoftBlockAdvised(data) {
        return Boolean(getSharedPrivacyEgressLabel(data) || isMobileOrCgnatPayload(data));
    }

    function buildWikiPageUrl(pageTitle, queryParams) {
        let baseUrl = '';
        if (mw && mw.util && typeof mw.util.getUrl === 'function') baseUrl = mw.util.getUrl(pageTitle);
        if (!baseUrl) {
            const pathTpl = (mw && mw.config && mw.config.get('wgArticlePath')) || '/wiki/$1';
            baseUrl = pathTpl.replace('$1', encodeURIComponent(pageTitle).replace(/%2F/g, '/').replace(/%3A/g, ':'));
        }
        if (queryParams && typeof queryParams === 'object') {
            const pairs = Object.entries(queryParams)
                .filter(([, v]) => v !== undefined && v !== null && v !== '')
                .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
            if (pairs.length > 0) baseUrl += (baseUrl.includes('?') ? '&' : '?') + pairs.join('&');
        }
        return baseUrl;
    }

    function formatUtcFetchDate(data) {
        const meta = getCacheMeta(data);
        const raw = (data && data.fetchedAt) || (meta && (meta.fetchedAt || meta.cachedAt)) || '';
        const ms = raw ? Date.parse(raw) : NaN;
        return new Date(isNaN(ms) ? Date.now() : ms).toISOString().slice(0, 10) + ' UTC';
    }

    function sanitizeWikitextFragment(value) {
        return String(value || '').replace(/[\r\n]+/g, ' ').replace(/<!--|-->|\{\{|\}\}|\[\[|\]\]/g, '').trim();
    }

    function buildDesensitisedWikitextSummary(data, rows, fallbackIp) {
        const targetIp = sanitizeWikitextFragment((data && data.ip) || fallbackIp || '');
        const cidr = sanitizeWikitextFragment((data && data.recommendedCidr) || targetIp);
        const esc = data && !data.highlySuspectedResidentialProxy && typeof data.escalationCidr === 'string' && data.escalationCidr.trim()
            ? sanitizeWikitextFragment(data.escalationCidr) : '';
        const asn = sanitizeWikitextFragment((data && data.primaryAsn) || (collectAsnEntries(rows)[0] && collectAsnEntries(rows)[0].value) || '');
        const isp = sanitizeWikitextFragment((collectIspEntries(rows)[0] && collectIspEntries(rows)[0].value) || '');
        const verdict = sanitizeWikitextFragment((data && data.arbitrationVerdict) || 'IP Intelligence Summary');
        const signals = [];
        if (data && data.isTor) signals.push(sanitizeWikitextFragment(data.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node')));
        const shared = getSharedPrivacyEgressLabel(data);
        if (shared) signals.push(sanitizeWikitextFragment(shared));
        if (isMobileOrCgnatPayload(data)) signals.push('Mobile/CGNAT');
        const ports = extractShodanOpenProxyPorts(data);
        if (ports.length > 0) signals.push(`Open proxy ports: ${ports.join(', ')}`);
        for (const r of rows) {
            if (r && r.provider === 'IPsum / DROP' && r.inSpamhausDrop) {
                signals.push(r.dropSblId ? `Spamhaus DROP (${sanitizeWikitextFragment(r.dropSblId)})` : 'Spamhaus DROP');
                break;
            }
        }
        const net = [asn, isp].filter(Boolean).join(' / ');
        const parts = [
            `<code>${targetIp}</code>`,
            `CIDR <code>${cidr}</code>${esc ? ` (escalation: <code>${esc}</code>)` : ''}`
        ];
        if (net) parts.push(net);
        parts.push(verdict);
        if (signals.length > 0) parts.push(signals.join('; '));
        parts.push(`fetched ${formatUtcFetchDate(data)}`);
        return `* ${parts.join(' \u00b7 ')}`;
    }

    function sanitizeHtmlCommentContent(text) {
        let s = String(text || '');
        while (s.includes('<!--') || s.includes('-->')) s = s.replace(/<!--|-->/g, '');
        return s.replace(/--!?>/g, '').replace(/--+$/g, '').trim();
    }

    function isUsableProviderValue(value) {
        if (value === null || value === undefined) return false;
        const text = String(value).trim();
        const lower = text.toLowerCase();
        return Boolean(text) && text !== '-' && lower !== 'n/a' && lower !== 'unknown';
    }

    function isValidProviderRow(row) {
        return Boolean(row && typeof row === 'object' && !row.isCooldown && !isRowQuotaGuarded(row) &&
            (row.status === '200 OK' || row.statusCode === 200));
    }

    function getProviderRows(data) {
        const results = Array.isArray(data && data.results) ? data.results : [];
        const ordered = [];
        for (const name of ['MaxMind', 'IP2Location']) {
            for (const row of results) {
                if (isValidProviderRow(row) && row.provider === name && ordered.indexOf(row) === -1) ordered.push(row);
            }
        }
        for (const row of results) {
            if (isValidProviderRow(row) && ordered.indexOf(row) === -1) ordered.push(row);
        }
        return ordered;
    }

    function stripTrailingMetadataParens(value, stripTrailingAsn) {
        let text = String(value || '').trim();
        const coordRe = /\s*\(\s*[+-]?\d+(?:\.\d+)?\s*,\s*[+-]?\d+(?:\.\d+)?\s*\)\s*$/;
        const asnRe = /\s*\(\s*AS\s*\d+\s*\)\s*$/i;
        let changed = true;
        while (text && changed) {
            changed = false;
            if (coordRe.test(text)) { text = text.replace(coordRe, '').trim(); changed = true; }
            if (stripTrailingAsn && asnRe.test(text)) { text = text.replace(asnRe, '').trim(); changed = true; }
        }
        return text.replace(/,\s*$/, '').trim();
    }

    function normalizeAsnValue(value) {
        if (!isUsableProviderValue(value)) return '';
        const text = String(value).trim();
        const match = text.match(/^(?:as\s*)?(\d+)$/i);
        return match ? 'AS' + match[1] : text.toUpperCase();
    }

    function collectAsnEntries(rows) {
        const byAsn = new Map();
        const entries = [];
        rows.forEach((row, idx) => {
            const asn = normalizeAsnValue(row && row.asn);
            if (!asn) return;
            const provider = (row && row.provider) || 'Provider';
            let entry = byAsn.get(asn);
            if (!entry) {
                entry = { value: asn, providers: [], voteCount: 0, firstIndex: idx };
                byAsn.set(asn, entry);
                entries.push(entry);
            }
            entry.voteCount += 1;
            if (entry.providers.indexOf(provider) === -1) entry.providers.push(provider);
        });
        entries.sort((a, b) => b.voteCount !== a.voteCount ? b.voteCount - a.voteCount : a.firstIndex - b.firstIndex);
        return entries.map((e, i) => ({ value: e.value, providers: e.providers, showProviders: i > 0, defaultChecked: i === 0 }));
    }

    function upsertProviderEntry(byKey, entries, key, value, provider) {
        let entry = byKey.get(key);
        if (!entry) {
            entry = { value, providers: [], showProviders: true, defaultChecked: false };
            byKey.set(key, entry);
            entries.push(entry);
        }
        if (provider && entry.providers.indexOf(provider) === -1) entry.providers.push(provider);
    }

    function collectGroupedProviderValues(rows, extractItem) {
        const byKey = new Map();
        const entries = [];
        for (const row of rows) {
            const ext = row ? extractItem(row) : null;
            if (ext && ext.key && ext.value) upsertProviderEntry(byKey, entries, ext.key, ext.value, row.provider || 'Provider');
        }
        return entries;
    }

    function collectIspEntries(rows) {
        return collectGroupedProviderValues(rows, (row) => {
            const raw = isUsableProviderValue(row.isp) ? row.isp : (isUsableProviderValue(row.organisation) ? row.organisation : '');
            if (!raw) return null;
            const cleaned = stripTrailingMetadataParens(raw, true);
            if (!isUsableProviderValue(cleaned)) return null;
            return { key: cleaned.toLowerCase().replace(/\./g, '').replace(/[,;:]+/g, ' ').replace(/\s+/g, ' ').trim(), value: cleaned };
        });
    }

    function collectLocationEntries(rows) {
        return collectGroupedProviderValues(rows, (row) => {
            if (!isUsableProviderValue(row.location)) return null;
            const parts = stripTrailingMetadataParens(row.location, false).split(',').map((p) => p.trim()).filter(Boolean);
            const collapsed = parts.filter((p, i) => i === 0 || parts[i - 1].toLowerCase() !== p.toLowerCase());
            const norm = collapsed.join(', ');
            if (!isUsableProviderValue(norm)) return null;
            return { key: norm.toLowerCase().replace(/\s*,\s*/g, ', ').replace(/\s+/g, ' ').trim(), value: norm };
        });
    }

    function collectPredictionEntries(data, risk) {
        if (data.getipintel_chance === null || data.getipintel_chance === undefined) return [];
        return [{
            value: `Prediction ${risk.predictionText}%`,
            copyValue: `${risk.predictionText}% Prediction`,
            providers: ['GetIPIntel'],
            showProviders: true,
            defaultChecked: true
        }];
    }

    function collectRiskEntries(data, rows, risk) {
        const byKey = new Map();
        const entries = [];
        const addEntry = (val, provider) => {
            const text = typeof val === 'string' ? val.trim() : '';
            if (text) upsertProviderEntry(byKey, entries, text.toLowerCase(), text, provider);
        };
        if (risk.isTor) addEntry(risk.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node'), 'Tor Onionoo');
        for (const row of rows) {
            if (!row || !Array.isArray(row.securityFlags) || row.provider === 'GetIPIntel') continue;
            const provider = row.provider || 'Provider';
            for (const flag of row.securityFlags) {
                if (flag && flag.isHighRisk && typeof flag.label === 'string') {
                    const lbl = flag.label.trim();
                    addEntry(lbl.toLowerCase() === 'tor exit node' ? 'Tor Exit' : lbl, provider);
                }
            }
        }
        const cloudProvider = typeof data.cloudProvider === 'string' ? data.cloudProvider.trim() : '';
        if (cloudProvider) {
            const matchRow = rows.find((r) => r && r.cloudProvider === cloudProvider && r.provider);
            addEntry(`Cloud (${cloudProvider})`, matchRow ? matchRow.provider : 'Cloud CIDR');
        }
        if (risk.broadcastIp) addEntry('Broadcast IP', 'Multi-Source');
        if (data.ptrIsHighRisk && typeof data.ptrLabel === 'string' && data.ptrLabel.trim()) addEntry(`PTR (${data.ptrLabel.trim()})`, 'Reverse DNS');
        if (data.suspectedResidentialProxy) addEntry('Suspected Residential Proxy / Compromised Host', 'Multi-Source');
        if (data.highlySuspectedResidentialProxy) addEntry('Highly Suspected Residential Proxy', 'GetIPIntel ResidentialProxy');
        const ports = extractShodanOpenProxyPorts(data);
        if (ports.length > 0) addEntry(`Open Proxy Ports (${ports.join(', ')})`, 'Shodan InternetDB');
        const shared = getSharedPrivacyEgressLabel(data);
        if (shared) addEntry(`Shared Privacy Egress (${shared})`, 'Privacy Relay');
        return entries;
    }

    function extractDomLines(element) {
        if (!element) return [];
        const chunks = [];
        const walk = (node) => {
            if (!node) return;
            if (node.nodeType === 3) { chunks.push(node.nodeValue || ''); return; }
            if (node.nodeType !== 1) return;
            const tag = (node.tagName || '').toUpperCase();
            if (tag === 'BR') { chunks.push('\n'); return; }
            const isBlock = tag === 'DIV' || tag === 'P' || tag === 'LI';
            if (isBlock) chunks.push('\n');
            for (const child of (node.childNodes || [])) walk(child);
            if (isBlock) chunks.push('\n');
        };
        walk(element);
        return chunks.join('').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    }

    function getSpurProxyText() {
        if (!isContributionsSpecialPage()) return '';
        const $panel = $('.ext-ipinfo-panel-layout').first();
        if ($panel.length === 0) return '';
        const $nodes = $panel.find('.ext-ipinfo-widget-property[data-property="proxies"]:not(.ext-ipinfo-widget-property-no-data) .ext-ipinfo-widget-property-value');
        if ($nodes.length === 0) return '';
        const seen = Object.create(null);
        const lines = [];
        $nodes.each(function () {
            if ($(this).closest('.ext-ipinfo-widget-error, .ext-ipinfo-contains-error').length > 0) return;
            for (const line of extractDomLines(this)) {
                if (!seen[line]) { seen[line] = true; lines.push(line); }
            }
        });
        return lines.join(', ');
    }

    function collectSpurEntriesFromDom() {
        const text = getSpurProxyText();
        return text ? [{ value: text, providers: ['Spur'], showProviders: true, defaultChecked: true }] : [];
    }

    function buildDarkThemeRuleBlock(scope) {
        return [
            `${scope} { --proxycheck-surface-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-surface-color: var(--color-base, #eaecf0); --proxycheck-subtle-color: var(--color-subtle, #a2a9b1); --proxycheck-muted-color: var(--color-subtle, #a2a9b1); --proxycheck-border-color: var(--border-color-subtle, #54595d); --proxycheck-divider-color: var(--border-color-subtle, #3a3f47); --proxycheck-link-color: var(--color-progressive, #88a3e8); --proxycheck-high-bg: #3d1414; --proxycheck-high-color: #ff9999; --proxycheck-high-border: #7a2929; --proxycheck-medium-bg: #382b0c; --proxycheck-medium-color: #ffd966; --proxycheck-medium-border: #755918; --proxycheck-nonpublic-bg: #222b36; --proxycheck-nonpublic-color: #c2d4e8; --proxycheck-nonpublic-border: #4a5d73; --proxycheck-low-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-low-color: var(--color-base, #eaecf0); --proxycheck-low-border: var(--border-color-subtle, #54595d); --proxycheck-error-border: var(--border-color-subtle, #6c737c); --proxycheck-banner-high-bg: #2c1414; --proxycheck-banner-high-accent: #ff6666; --proxycheck-banner-medium-bg: #2b220d; --proxycheck-banner-medium-accent: #f0b144; --proxycheck-banner-nonpublic-bg: #1e242c; --proxycheck-banner-nonpublic-accent: #8c959f; --proxycheck-banner-low-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-banner-low-accent: var(--color-progressive, #6d9cff); --proxycheck-banner-low-badge-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-code-bg: var(--background-color-neutral-subtle, rgba(255, 255, 255, 0.08)); }`,
            `${scope} a.proxycheck-anchor-risk-high, ${scope} a.proxycheck-anchor-risk-high:visited, ${scope} .proxycheck-anchor-risk-high { background-color: #3d1414 !important; color: #ff9999 !important; }`,
            `${scope} a.proxycheck-anchor-risk-medium, ${scope} a.proxycheck-anchor-risk-medium:visited, ${scope} .proxycheck-anchor-risk-medium { background-color: #382b0c !important; color: #ffd966 !important; }`,
            `${scope} .proxycheck-source-tag { background-color: var(--proxycheck-tag-dark-bg, #1c2a3a); border-color: var(--proxycheck-tag-dark-border, #3a5778); color: var(--proxycheck-tag-dark-color, #9cc9ff); }`,
            `${scope} .proxycheck-signal-privacy { background-color: #1c2345; color: #b0bfff; border-color: #3d4b8f; }`
        ].join('\n');
    }

    function buildUserscriptCss() {
        const boldTiers = ['high', 'medium', 'nonpublic'];
        const allTiers = ['high', 'medium', 'nonpublic', 'low'];
        return [
            ':root { --proxycheck-surface-bg: var(--background-color-interactive-subtle, #f8f9fa); --proxycheck-surface-color: var(--color-base, #202122); --proxycheck-subtle-color: var(--color-subtle, #54595d); --proxycheck-muted-color: var(--color-placeholder, #72777d); --proxycheck-border-color: var(--border-color-subtle, #c8ccd1); --proxycheck-divider-color: var(--border-color-subtle, #eaecf0); --proxycheck-link-color: var(--color-progressive, #3366cc); --proxycheck-high-bg: #ffe6e6; --proxycheck-high-color: #990000; --proxycheck-high-border: #f5b7b1; --proxycheck-medium-bg: #fff8e1; --proxycheck-medium-color: #856404; --proxycheck-medium-border: #ffe082; --proxycheck-nonpublic-bg: #eef2f6; --proxycheck-nonpublic-color: #3b4f66; --proxycheck-nonpublic-border: #b9c6d4; --proxycheck-low-bg: var(--background-color-interactive-subtle, #f8f9fa); --proxycheck-low-color: var(--color-subtle, #54595d); --proxycheck-low-border: var(--border-color-subtle, #c8ccd1); --proxycheck-error-border: #a2a9b1; --proxycheck-banner-high-bg: #fffafa; --proxycheck-banner-high-accent: #d33; --proxycheck-banner-medium-bg: #fffdf5; --proxycheck-banner-medium-accent: #fc3; --proxycheck-banner-nonpublic-bg: #f4f6f8; --proxycheck-banner-nonpublic-accent: #72777d; --proxycheck-banner-low-bg: var(--background-color-interactive-subtle, #f8f9fa); --proxycheck-banner-low-accent: var(--color-progressive, #36c); --proxycheck-banner-low-badge-bg: var(--background-color-base, #ffffff); --proxycheck-code-bg: var(--background-color-neutral-subtle, rgba(0, 0, 0, 0.04)); }',
            'a.proxycheck-ip-badge, a.proxycheck-ip-badge:visited { margin-left: 4px; font-size: 0.85em; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; padding: 1px 5px; border-radius: 3px; text-decoration: none; white-space: nowrap; }',
            ...boldTiers.map((t) => `a.proxycheck-ip-badge.proxycheck-tier-${t}, a.proxycheck-ip-badge.proxycheck-tier-${t}:visited { background-color: var(--proxycheck-${t}-bg); color: var(--proxycheck-${t}-color) !important; border: 1px solid var(--proxycheck-${t}-border); font-weight: bold; }`),
            'a.proxycheck-ip-badge.proxycheck-tier-low, a.proxycheck-ip-badge.proxycheck-tier-low:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-low-color) !important; border: 1px solid var(--proxycheck-low-border); font-weight: normal; }',
            'a.proxycheck-ip-badge.proxycheck-badge-lite, a.proxycheck-ip-badge.proxycheck-badge-lite:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-subtle-color) !important; border: 1px solid var(--proxycheck-low-border); opacity: 0.9; }',
            'a.proxycheck-ip-badge.proxycheck-badge-quota, a.proxycheck-ip-badge.proxycheck-badge-quota:visited { background-color: var(--proxycheck-medium-bg); color: var(--proxycheck-medium-color) !important; border: 1px dashed var(--proxycheck-medium-border); }',
            'a.proxycheck-ip-badge.proxycheck-ip-badge-error, a.proxycheck-ip-badge.proxycheck-ip-badge-error:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-muted-color) !important; border: 1px dashed var(--proxycheck-error-border); }',
            'a.proxycheck-ip-badge.proxycheck-ip-badge-consent, a.proxycheck-ip-badge.proxycheck-ip-badge-consent:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-low-color) !important; border: 1px solid var(--proxycheck-low-border); }',
            'a.proxycheck-ip-badge.proxycheck-badge-stale, a.proxycheck-ip-badge.proxycheck-badge-stale:visited { border-style: dashed; }',
            '#proxycheck-pageinfo { font-size: 92%; line-height: 1.5em; padding: 8px 12px; margin-bottom: 12px; background-color: var(--proxycheck-surface-bg); color: var(--proxycheck-surface-color); border: 1px solid var(--proxycheck-divider-color); border-left: 4px solid var(--proxycheck-border-color); border-radius: 2px; }',
            ...allTiers.map((t) => `#proxycheck-pageinfo.proxycheck-banner-tier-${t} { border-left-color: var(--proxycheck-banner-${t}-accent); background-color: var(--proxycheck-banner-${t}-bg); }`),
            '#proxycheck-pageinfo code { background-color: var(--proxycheck-code-bg); color: inherit; border-color: var(--proxycheck-border-color); }',
            '.proxycheck-banner-badge { padding: 1px 6px; border-radius: 3px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }',
            ...boldTiers.map((t) => `.proxycheck-banner-badge.proxycheck-tier-${t} { background-color: var(--proxycheck-${t}-bg); color: var(--proxycheck-${t}-color); border: 1px solid var(--proxycheck-${t}-border); font-weight: bold; }`),
            '.proxycheck-banner-badge.proxycheck-tier-low { background-color: var(--proxycheck-banner-low-badge-bg); color: var(--proxycheck-low-color); border: 1px solid var(--proxycheck-low-border); }',
            '.proxycheck-ptr-label-risk, .proxycheck-banner-danger-text { color: var(--proxycheck-high-color); }',
            '.proxycheck-ptr-label-risk { font-weight: bold; }',
            '.proxycheck-ptr-label-normal, .proxycheck-light-upgrade-notice { color: var(--proxycheck-subtle-color); }',
            '.proxycheck-banner-warning-text { color: var(--proxycheck-medium-color); }',
            '.proxycheck-pageinfo-details { margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--proxycheck-divider-color); }',
            '.proxycheck-details-panel, .proxycheck-dialog-content, .proxycheck-result-value { color: var(--proxycheck-surface-color); }',
            '.proxycheck-details-label { color: var(--proxycheck-subtle-color); }',
            '.proxycheck-details-empty { color: var(--proxycheck-muted-color); }',
            '.proxycheck-result-value-risk { color: var(--proxycheck-high-color); font-weight: 500; }',
            '.proxycheck-result-checkbox { accent-color: var(--proxycheck-link-color); }',
            '.proxycheck-source-tag { display: inline-block; font-size: 0.82em; color: var(--proxycheck-tag-color, #0b4f8a); background-color: var(--proxycheck-tag-bg, #e6f2ff); border: 1px solid var(--proxycheck-tag-border, #a3ccf5); border-radius: 3px; padding: 0 5px; line-height: 1.4; margin-left: 5px; vertical-align: middle; }',
            '.proxycheck-dialog-cache-bar { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid var(--proxycheck-divider-color); font-size: 12px; }',
            '.proxycheck-cache-controls { display: inline-flex; align-items: center; flex-wrap: wrap; gap: 6px; }',
            '.proxycheck-cache-age { color: var(--proxycheck-subtle-color); font-size: 12px; }',
            '.proxycheck-cache-age-stale { color: var(--proxycheck-medium-color); font-weight: 600; }',
            '.proxycheck-refetch-btn { cursor: pointer; font-size: 11.5px; font-weight: 600; padding: 1px 8px; border-radius: 3px; background-color: var(--proxycheck-surface-bg); color: var(--proxycheck-link-color); border: 1px solid var(--proxycheck-border-color); }',
            '.proxycheck-refetch-btn:disabled { opacity: 0.65; cursor: wait; }',
            '.proxycheck-refresh-warning { margin-top: 6px; padding: 5px 8px; border-radius: 3px; font-size: 12px; background-color: var(--proxycheck-medium-bg); color: var(--proxycheck-medium-color); border: 1px solid var(--proxycheck-medium-border); }',
            '.proxycheck-signal-banners { display: flex; flex-direction: column; gap: 5px; margin-bottom: 8px; }',
            '.proxycheck-signal-pill { padding: 5px 8px; border-radius: 3px; font-size: 12px; line-height: 1.45; border: 1px solid var(--proxycheck-border-color); }',
            '.proxycheck-signal-privacy { background-color: #eef2ff; color: #2c3e99; border-color: #b3bdf5; }',
            '.proxycheck-signal-cgnat { background-color: var(--proxycheck-medium-bg); color: var(--proxycheck-medium-color); border-color: var(--proxycheck-medium-border); }',
            '.proxycheck-signal-danger { background-color: var(--proxycheck-high-bg); color: var(--proxycheck-high-color); border-color: var(--proxycheck-high-border); }',
            '.proxycheck-inline-pill { display: inline-block; font-size: 0.85em; padding: 0 5px; margin-left: 6px; border-radius: 3px; background-color: var(--proxycheck-code-bg); border: 1px solid var(--proxycheck-border-color); }',
            '.proxycheck-cidr-rationale { font-size: 0.9em; color: var(--proxycheck-subtle-color); margin-top: 2px; }',
            '.proxycheck-residential-proxy-warning { color: var(--proxycheck-high-color); font-weight: 600; }',
            '.proxycheck-quick-links { margin-top: 8px; padding-top: 6px; border-top: 1px solid var(--proxycheck-divider-color); display: flex; align-items: center; flex-wrap: wrap; gap: 10px; font-size: 12px; }',
            '.proxycheck-temp-ip-switcher { margin-bottom: 6px; padding-bottom: 6px; border-bottom: 1px solid var(--proxycheck-divider-color); display: flex; align-items: center; flex-wrap: wrap; gap: 6px; font-size: 12px; }',
            '.proxycheck-ip-pill { cursor: pointer; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11.5px; padding: 1px 8px; border-radius: 10px; background-color: var(--proxycheck-surface-bg); color: var(--proxycheck-surface-color); border: 1px solid var(--proxycheck-border-color); }',
            '.proxycheck-ip-pill-active { background-color: var(--proxycheck-link-color); color: #ffffff; border-color: var(--proxycheck-link-color); font-weight: 600; }',
            '#proxycheck-pageinfo a, .proxycheck-details-panel a, .proxycheck-dialog-link { color: var(--proxycheck-link-color); }',
            buildDarkThemeRuleBlock('html.skin-theme-clientpref-night'),
            `@media (prefers-color-scheme: dark) {\n${buildDarkThemeRuleBlock('html.skin-theme-clientpref-os')}\n}`
        ].join('\n');
    }

    function createEl(tag, className, text, attrs) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        if (text !== undefined && text !== null) el.textContent = String(text);
        if (attrs && typeof attrs === 'object') {
            for (const [k, v] of Object.entries(attrs)) {
                if (v === undefined || v === null || /^on/i.test(k)) continue;
                if (k === 'href' || k === 'title' || k === 'target' || k === 'rel' || k === 'id' || k === 'type') el[k] = String(v);
                else if (typeof el.setAttribute === 'function') el.setAttribute(k, String(v));
            }
        }
        return el;
    }

    function ensureUserscriptStyles() {
        if (stylesInjected || typeof document === 'undefined') return;
        if (typeof document.getElementById === 'function' && document.getElementById(STYLE_ELEMENT_ID)) {
            stylesInjected = true;
            return;
        }
        const cssText = buildUserscriptCss();
        const parent = document.head || document.body || document.documentElement;
        if (parent && typeof document.createElement === 'function' && typeof parent.appendChild === 'function') {
            parent.appendChild(createEl('style', '', cssText, { id: STYLE_ELEMENT_ID, type: 'text/css' }));
            stylesInjected = true;
        } else if (mw && mw.util && typeof mw.util.addCSS === 'function') {
            mw.util.addCSS(cssText);
            stylesInjected = true;
        }
    }

    function getProviderBadgePalette(provider) {
        if (Object.prototype.hasOwnProperty.call(PROVIDER_BADGE_PALETTES, provider)) return PROVIDER_BADGE_PALETTES[provider];
        let hash = 0;
        const text = String(provider || '');
        for (let i = 0; i < text.length; i++) hash = ((hash * 31) + text.charCodeAt(i)) | 0;
        return FALLBACK_COOL_PALETTES[Math.abs(hash) % FALLBACK_COOL_PALETTES.length];
    }

    function formatOfflineDbDateShort(iso) {
        if (typeof iso !== 'string' || !iso.trim()) return '';
        const ms = Date.parse(iso.trim());
        return isNaN(ms) ? iso.trim() : new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    }

    function createSourceBadge(provider, providerUpdatedAtMap) {
        const p = getProviderBadgePalette(provider);
        const updatedIso = providerUpdatedAtMap && providerUpdatedAtMap[provider];
        const formatted = updatedIso ? formatOfflineDbDateShort(updatedIso) : '';
        const attrs = {
            'class': 'proxycheck-source-tag',
            style: `--proxycheck-tag-bg: ${p.bg}; --proxycheck-tag-border: ${p.border}; --proxycheck-tag-color: ${p.color}; --proxycheck-tag-dark-bg: ${p.darkBg}; --proxycheck-tag-dark-border: ${p.darkBorder}; --proxycheck-tag-dark-color: ${p.darkColor};`,
            text: provider
        };
        if (formatted) attrs.title = 'Offline DB updated: ' + formatted;
        return $('<span>', attrs);
    }

    function buildResultDetailsPanel(data, risk, fallbackIp) {
        ensureUserscriptStyles();
        const rows = getProviderRows(data);
        const resolvedIp = isValidIp(data && data.ip) ? String(data.ip).trim() : (isValidIp(fallbackIp) ? String(fallbackIp).trim() : '');
        const providerUpdatedAtMap = {};
        for (const r of rows) {
            if (r && r.provider && typeof r.offlineDbUpdatedAt === 'string' && r.offlineDbUpdatedAt.trim()) {
                providerUpdatedAtMap[r.provider] = r.offlineDbUpdatedAt.trim();
            }
        }

        const sections = [
            { label: 'Prediction', entries: collectPredictionEntries(data, risk), isRisk: false, emptyText: 'Unavailable', copyWithSource: true },
            { label: 'ASN', entries: collectAsnEntries(rows), isRisk: false, emptyText: '-', copyWithSource: false },
            { label: 'ISP', entries: collectIspEntries(rows), isRisk: false, emptyText: '-', copyWithSource: true },
            { label: 'Location', entries: collectLocationEntries(rows), isRisk: false, emptyText: '-', copyWithSource: true },
            { label: 'Risk', entries: collectRiskEntries(data, rows, risk).concat(collectSpurEntriesFromDom()), isRisk: true, emptyText: 'No high-risk signals detected', copyWithSource: true }
        ];

        const $panel = $('<div>', { 'class': 'proxycheck-details-panel' });
        const sharedEgressLabel = getSharedPrivacyEgressLabel(data);
        const mobileOrCgnat = isMobileOrCgnatPayload(data);
        const residentialParadox = Boolean(data && data.suspectedResidentialProxy);
        const highlySuspectedResidentialProxy = Boolean(data && data.highlySuspectedResidentialProxy);
        const shodanPorts = extractShodanOpenProxyPorts(data);

        const bannerPills = [];
        if (sharedEgressLabel) bannerPills.push(['proxycheck-signal-privacy', `Shared Privacy Egress: ${sharedEgressLabel} \u2014 Soft / anon-only block recommended to avoid collateral impact on logged-in editors.`]);
        if (mobileOrCgnat) bannerPills.push(['proxycheck-signal-cgnat', 'Mobile / CGNAT Network: Collateral-damage warning \u2014 recommended block locked to /32 (IPv4) or /64 (IPv6); prefer soft / anon-only block.']);
        if (residentialParadox) bannerPills.push(['proxycheck-signal-danger', 'Suspected Residential Proxy / Compromised Host' + (shouldRecommendFreshResidentialRecheck(data) ? ' \u2014 Cached signal is older than 7 days; click Refetch to verify current DHCP assignment before issuing a long-term block.' : '')]);
        if (highlySuspectedResidentialProxy) bannerPills.push(['proxycheck-signal-danger', 'Highly Suspected Residential Proxy']);
        if (shodanPorts.length > 0) bannerPills.push(['proxycheck-signal-danger', `Shodan Open Proxy Ports: ${shodanPorts.join(', ')}`]);
        if (bannerPills.length > 0) {
            const $banners = $('<div>', { 'class': 'proxycheck-signal-banners' });
            bannerPills.forEach(([cls, text]) => $banners.append($('<div>', { 'class': 'proxycheck-signal-pill ' + cls, text })));
            $panel.append($banners);
        }

        const $table = $('<table>', { style: 'width: 100%; border-collapse: collapse;' });
        const appendRow = (label, $cell) => {
            $('<tr>').append(
                $('<th>', { 'class': 'proxycheck-details-label', style: 'text-align: left; vertical-align: top; padding: 4px 12px 4px 0; width: 78px; font-weight: 600; white-space: nowrap;' }).text(label),
                $('<td>', { style: 'padding: 4px 0; vertical-align: top;' }).append($cell)
            ).appendTo($table);
        };

        const checkboxItems = [];
        for (const section of sections) {
            const $content = $('<div>', { style: 'display: flex; flex-direction: column; gap: 3px;' });
            if (section.entries.length === 0) {
                $content.append($('<span>', { 'class': 'proxycheck-details-empty', text: section.emptyText }));
            } else {
                for (const entry of section.entries) {
                    const $checkbox = $('<input>', {
                        type: 'checkbox', 'class': 'proxycheck-result-checkbox',
                        checked: Boolean(entry.defaultChecked), style: 'margin: 3px 0 0 0; flex-shrink: 0; cursor: pointer;'
                    });
                    const $body = $('<span>', { style: 'display: block; flex: 1; min-width: 0; line-height: 1.5;' })
                        .append($('<span>', { 'class': 'proxycheck-result-value' + (section.isRisk ? ' proxycheck-result-value-risk' : ''), text: entry.value }));
                    if (entry.showProviders && entry.providers.length > 0) {
                        entry.providers.forEach((p) => $body.append(createSourceBadge(p, providerUpdatedAtMap)));
                    }
                    $content.append($('<label>', { style: 'display: flex; align-items: flex-start; gap: 6px; margin: 0; cursor: pointer; font-weight: normal;' }).append($checkbox, $body));
                    checkboxItems.push({ checkbox: $checkbox, copyValue: entry.copyValue || entry.value, providers: entry.providers || [], copyWithSource: section.copyWithSource });
                }
            }
            appendRow(section.label, $content);
        }

        const verdictText = data && typeof data.arbitrationVerdict === 'string' ? data.arbitrationVerdict.trim() : '';
        if (verdictText) appendRow('Verdict', $('<span>', { 'class': 'proxycheck-result-value', text: verdictText }));

        const recCidr = data && typeof data.recommendedCidr === 'string' && data.recommendedCidr.trim() ? data.recommendedCidr.trim() : 'N/A';
        const escCidr = data && typeof data.escalationCidr === 'string' ? data.escalationCidr.trim() : '';
        const bgpCidr = (data && typeof data.bgpPrefix === 'string' && data.bgpPrefix.trim()) || (data && typeof data.mmdbCidr === 'string' && data.mmdbCidr.trim()) || '';
        const cidrRationale = (data && typeof data.cidrRationale === 'string' && data.cidrRationale.trim()) || (data && typeof data.cidrNote === 'string' && data.cidrNote.trim()) || '';

        const $cidrLine = $('<div>').append($('<code>').text(recCidr));
        if (!highlySuspectedResidentialProxy) {
            if (escCidr) $cidrLine.append($('<span>', { 'class': 'proxycheck-inline-pill', text: 'Escalation: ' + escCidr }));
            if (bgpCidr) $cidrLine.append($('<span>', { 'class': 'proxycheck-inline-pill', text: 'BGP: ' + bgpCidr }));
        }
        const $cidrCell = $('<div>').append($cidrLine);
        if (highlySuspectedResidentialProxy) {
            $cidrCell.append($('<div>', {
                'class': 'proxycheck-cidr-rationale proxycheck-residential-proxy-warning',
                text: 'Highly Suspected Residential Proxy: this IP is highly likely to use residential proxy infrastructure. Restrict CIDR blocking to this single IP and proceed with discretion on CIDR.'
            }));
        } else if (cidrRationale) {
            $cidrCell.append($('<div>', { 'class': 'proxycheck-cidr-rationale', text: cidrRationale }));
        }
        appendRow('CIDR', $cidrCell);

        const $copyLink = $('<a>', { href: '#', role: 'button', 'class': 'proxycheck-copy-result', text: 'Copy result' });
        const $copyWikitextBtn = $('<a>', { href: '#', role: 'button', 'class': 'proxycheck-copy-wikitext', text: 'Copy Wikitext' });
        let resetTimerId = null, wikitextResetTimerId = null, panelDisposed = false;

        const scheduleLabelReset = (isWikitext, delayMs, label) => {
            if (isWikitext) wikitextResetTimerId = clearTimer(wikitextResetTimerId, false);
            else resetTimerId = clearTimer(resetTimerId, false);
            if (panelDisposed) return;
            const id = window.setTimeout(() => {
                if (isWikitext) wikitextResetTimerId = null; else resetTimerId = null;
                if (!panelDisposed) (isWikitext ? $copyWikitextBtn : $copyLink).text(label);
            }, delayMs);
            if (isWikitext) wikitextResetTimerId = id; else resetTimerId = id;
        };

        $copyLink.on('click', (e) => {
            e.preventDefault(); e.stopPropagation();
            if (panelDisposed) return;
            const selected = checkboxItems.filter((item) => item.checkbox.prop('checked')).map((item) =>
                sanitizeHtmlCommentContent((item.copyWithSource && item.providers.length > 0) ? `${item.providers.join(', ')}: ${item.copyValue}` : item.copyValue)
            ).filter(Boolean);
            if (selected.length === 0) {
                $copyLink.text('Select at least one item');
                return scheduleLabelReset(false, 1500, 'Copy result');
            }
            const comment = `<!-- ${(sanitizeHtmlCommentContent(selected.join(', ')) + ' ' + BLOCK_REASON_ATTRIBUTION).trim()} -->`;
            copyText(comment).then(() => {
                if (!panelDisposed) { $copyLink.text('Copied'); scheduleLabelReset(false, 1500, 'Copy result'); }
            }).catch((err) => {
                warn('Copy result failed:', err);
                if (!panelDisposed) { $copyLink.text('Copy failed'); scheduleLabelReset(false, 2000, 'Copy result'); }
            });
        });

        $copyWikitextBtn.on('click', (e) => {
            e.preventDefault(); e.stopPropagation();
            if (panelDisposed) return;
            copyText(buildDesensitisedWikitextSummary(data, rows, resolvedIp)).then(() => {
                if (!panelDisposed) { $copyWikitextBtn.text('Copied Wikitext'); scheduleLabelReset(true, 1500, 'Copy Wikitext'); }
            }).catch((err) => {
                warn('Copy Wikitext failed:', err);
                if (!panelDisposed) { $copyWikitextBtn.text('Copy failed'); scheduleLabelReset(true, 2000, 'Copy Wikitext'); }
            });
        });

        $panel.append($table, $('<div>', { style: 'margin-top: 8px; display: flex; align-items: center; flex-wrap: wrap; gap: 12px;' }).append($copyLink, $copyWikitextBtn));

        if (resolvedIp) {
            const blockTarget = recCidr !== 'N/A' ? recCidr : resolvedIp;
            const softBlock = isSoftBlockAdvised(data);
            const mkLink = (cls, href, text) => $('<a>', { 'class': cls, href, target: '_blank', rel: 'noopener noreferrer', text });
            $panel.append($('<div>', { 'class': 'proxycheck-quick-links' }).append(
                mkLink('proxycheck-link-globalcontribs', buildWikiPageUrl('Special:GlobalContributions/' + resolvedIp, null), 'GlobalContributions ↗'),
                mkLink('proxycheck-link-rangeblock', 'https://rangeblockfinder.toolforge.org/?ip=' + encodeURIComponent(resolvedIp), 'Rangeblock Finder ↗'),
                mkLink('proxycheck-link-whois', 'https://whois.toolforge.org/gateway.py?lookup=true&ip=' + encodeURIComponent(resolvedIp), 'WHOIS ↗'),
                mkLink('proxycheck-link-block', buildWikiPageUrl('Special:Block/' + blockTarget, softBlock ? { wpAnonOnly: '1', wpHardBlock: '0', wpDisableUTEdit: '0' } : null), softBlock ? 'Special:Block (soft) ↗' : 'Special:Block ↗')
            ));
        }

        $panel._proxycheckDispose = () => {
            panelDisposed = true;
            resetTimerId = clearTimer(resetTimerId, false);
            wikitextResetTimerId = clearTimer(wikitextResetTimerId, false);
        };
        return $panel;
    }

    function disposeDetailsPanel($panel) {
        if ($panel && typeof $panel._proxycheckDispose === 'function') $panel._proxycheckDispose();
    }

    function copyText(text) {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            return navigator.clipboard.writeText(text);
        }
        return new Promise((resolve, reject) => {
            const ta = createEl('textarea', '', null, { readonly: '' });
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            try {
                if (!document.execCommand('copy')) throw new Error('execCommand copy failed');
                resolve();
            } catch (err) { reject(err); } finally { document.body.removeChild(ta); }
        });
    }

    function buildBadgeTitleText(data, risk) {
        if (risk.isNonPublic) {
            return `Address Type: ${risk.nonPublicReason} [${risk.nonPublicBadgeCode}]\nStatus: External threat lookups skipped (non-public or reserved IP)`;
        }
        const torDesc = formatTorDescription(risk);
        const cloudDesc = formatCloudDescription(data);
        const lines = [risk.isLightDeferredClean
            ? 'Light screening passed (no local/free-tier flags). Click to run full commercial check.'
            : 'Prediction: ' + risk.predictionTooltip];
        if (typeof data.arbitrationVerdict === 'string' && data.arbitrationVerdict.trim()) lines.push('Verdict: ' + data.arbitrationVerdict.trim());
        lines.push('Recommended CIDR: ' + (data.recommendedCidr || 'N/A'));
        lines.push('BGP CIDR: ' + (data.bgpPrefix || data.mmdbCidr || 'N/A'));
        if (cloudDesc) lines.push('Cloud: ' + cloudDesc);
        lines.push('Broadcast IP: ' + (risk.broadcastIp ? 'At-risk' : 'No'));
        lines.push('Tor Node: ' + (risk.isTor ? torDesc : 'No'));

        const dbBaselines = [];
        for (const r of (Array.isArray(data.results) ? data.results : [])) {
            if (!r) continue;
            if (r.provider === 'StopForumSpam' && r.status === '200 OK') {
                if (r.blacklisted) lines.push('StopForumSpam: Blacklisted Toxic CIDR' + (r.toxicCidr ? ` (${r.toxicCidr})` : ''));
                else if (r.appears) lines.push(`StopForumSpam: Reported (${r.frequency || 0}x)`);
            }
            if (r.provider && typeof r.offlineDbUpdatedAt === 'string' && r.offlineDbUpdatedAt) {
                const d = formatOfflineDbDateShort(r.offlineDbUpdatedAt);
                if (d) dbBaselines.push(`${r.provider} ${d}`);
            }
        }
        if (dbBaselines.length > 0) lines.push('Offline DB Baseline: ' + dbBaselines.join(', '));
        const meta = getCacheMeta(data);
        const ageSec = getCacheAgeSeconds(data);
        if (ageSec !== null) {
            const ageText = formatRelativeCacheAge(ageSec);
            if (ageText) lines.push(meta && meta.isStale ? `${ageText} (stale >90d)` : ageText);
        }
        return lines.join('\n');
    }

    function applyRiskStylingToAnchorAndBadge(anchor, badge, data, fallbackIp, isRefresh) {
        ensureUserscriptStyles();
        const risk = evaluateRisk(data);
        const resolvedIp = (data && data.ip) || fallbackIp;
        const meta = getCacheMeta(data);
        const isStale = Boolean(!risk.isNonPublic && meta && meta.isStale === true);

        if (anchor.classList) {
            anchor.classList.remove('proxycheck-anchor-risk-high', 'proxycheck-anchor-risk-medium');
        }
        if (risk.riskTier === 'high' || risk.riskTier === 'medium') {
            if (anchor.classList) anchor.classList.add('proxycheck-anchor-risk-' + risk.riskTier);
            Object.assign(anchor.style, {
                backgroundColor: risk.riskTier === 'high' ? '#ffcccc' : '#fff3cd',
                color: risk.riskTier === 'high' ? '#990000' : '#856404',
                fontWeight: 'bold', padding: '1px 4px', borderRadius: '3px'
            });
        } else if (isRefresh && anchor.style && anchor.style.backgroundColor) {
            Object.assign(anchor.style, { backgroundColor: '', color: '', fontWeight: '', padding: '', borderRadius: '' });
        }

        const bcast = risk.broadcastIp ? '|BCASTIP' : '';
        const tor = risk.isTor ? '|' + (risk.torLabel ? risk.torLabel.toUpperCase() : 'TOR') : '';
        badge.href = TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp);
        badge.textContent = risk.isNonPublic
            ? `[${risk.nonPublicBadgeCode}]`
            : `[${risk.hasPrediction ? risk.predictionText + '%' : risk.badgePrimaryLabel}${bcast}${tor}]`;

        let stateClass = '';
        if (!risk.isNonPublic && !risk.hasPrediction) {
            if (risk.badgePrimaryLabel === 'QUOTA' || risk.badgePrimaryLabel === 'COOLDOWN') stateClass = ' proxycheck-badge-quota';
            else if (risk.badgePrimaryLabel === 'LIGHT') stateClass = ' proxycheck-badge-lite';
        }
        if (isStale) stateClass += ' proxycheck-badge-stale';
        badge.className = `${BADGE_CLASS} proxycheck-tier-${risk.riskTier}${stateClass}`;

        applyBaseBadgeStyle(badge);
        badge.style.fontWeight = risk.riskTier === 'low' ? '' : 'bold';
        badge.style.borderStyle = isStale ? 'dashed' : '';
        badge.title = buildBadgeTitleText(data, risk);
    }

    function isBadgeDetached(badge) {
        return !badge || badge.isConnected === false ||
            Boolean(typeof document !== 'undefined' && document.body && typeof document.body.contains === 'function' && !document.body.contains(badge));
    }

    function filterConnectedBadgeEntries(entries) {
        return (entries || []).filter((e) => e && e.anchor && e.badge && !isBadgeDetached(e.badge));
    }

    function registerRenderedBadge(cacheKey, anchor, badge, ip) {
        if (!cacheKey || !anchor || !badge) return;
        const active = filterConnectedBadgeEntries(renderedBadgeEntriesByIp.get(cacheKey));
        active.push({ anchor, badge, ip });
        renderedBadgeEntriesByIp.set(cacheKey, active);

        if (renderedBadgeEntriesByIp.size > RESULT_CACHE_MAX_ENTRIES) {
            for (const [gk, group] of renderedBadgeEntriesByIp.entries()) {
                if (gk === cacheKey) continue;
                const retained = filterConnectedBadgeEntries(group);
                if (retained.length > 0) renderedBadgeEntriesByIp.set(gk, retained);
                else renderedBadgeEntriesByIp.delete(gk);
            }
            while (renderedBadgeEntriesByIp.size > RESULT_CACHE_MAX_ENTRIES) {
                const oldestKey = renderedBadgeEntriesByIp.keys().next().value;
                if (!oldestKey || oldestKey === cacheKey) break;
                renderedBadgeEntriesByIp.delete(oldestKey);
            }
        }
    }

    function refreshRenderedBadgesForIp(ip, fullData) {
        const cacheKey = canonicalizeIpKey(ip);
        if (!cacheKey || !fullData || typeof fullData !== 'object') return;
        const active = filterConnectedBadgeEntries(renderedBadgeEntriesByIp.get(cacheKey));
        if (active.length === 0) { renderedBadgeEntriesByIp.delete(cacheKey); return; }
        active.forEach((e) => applyRiskStylingToAnchorAndBadge(e.anchor, e.badge, fullData, fullData.ip || e.ip, true));
        renderedBadgeEntriesByIp.set(cacheKey, active);
    }

    function requestFullIpUpgrade(targetIp, forceRefresh) {
        if (forceRefresh) return executeIpRefresh(targetIp).then((o) => (o && o.ok ? o.data : null));
        return fetchIpIntelligence(targetIp, 'full').then((fullData) => {
            if (!fullData || typeof fullData !== 'object') return null;
            refreshRenderedBadgesForIp(fullData.ip || targetIp, fullData);
            return fullData;
        });
    }

    function formatRefreshWarningText(outcome) {
        if (outcome && outcome.rateLimited) {
            const wait = typeof outcome.retryAfterSeconds === 'number' && outcome.retryAfterSeconds > 0 ? ` (retry in ${outcome.retryAfterSeconds}s)` : '';
            return `Refresh rate limit reached${wait}. Preserving cached intelligence.`;
        }
        return outcome && outcome.degradedFallback
            ? 'Upstream providers are temporarily degraded or quota-limited. Preserving cached intelligence.'
            : 'Refresh temporarily unavailable. Preserving cached intelligence.';
    }

    function showInfoDialog(data, ip) {
        if (infoDialogPromise) return infoDialogPromise;
        ensureUserscriptStyles();
        infoDialogPromise = mw.loader.using('oojs-ui-windows').then(() => {
            const targetIp = ip || (data && data.ip) || '';
            const cacheKey = canonicalizeIpKey(targetIp);
            let activeData = (cacheKey && latestResultByIp.get(cacheKey)) || data;
            const initialRisk = evaluateRisk(activeData);

            const $cacheAgeSpan = $('<span>', { 'class': 'proxycheck-cache-age' });
            const $refetchBtn = $('<button>', { type: 'button', 'class': 'proxycheck-refetch-btn', text: 'Refetch' });
            const $cacheBar = $('<div>', { 'class': 'proxycheck-dialog-cache-bar' }).append($cacheAgeSpan, $refetchBtn);
            const $warningNotice = $('<div>', { 'class': 'proxycheck-refresh-warning', style: 'display: none;' });
            const $panelContainer = $('<div>', { 'class': 'proxycheck-dialog-content' });
            let activeDetailsPanel = null, dialogClosed = false, refreshInFlight = false;

            const syncControls = (d, risk, isJustUpdated) => {
                if (risk.isNonPublic) { $cacheBar.css('display', 'none'); $warningNotice.css('display', 'none'); return; }
                $cacheBar.css('display', 'flex');
                const meta = getCacheMeta(d);
                const isStale = Boolean(!isJustUpdated && meta && meta.isStale === true);
                $cacheAgeSpan.text(formatCacheStatusLabel(d, Boolean(isJustUpdated)));
                if (isStale) $cacheAgeSpan.addClass('proxycheck-cache-age-stale');
                else $cacheAgeSpan.removeClass('proxycheck-cache-age-stale');
                if (!refreshInFlight) $refetchBtn.prop('disabled', false).text('Refetch');
            };

            const renderBody = (d, risk) => {
                disposeDetailsPanel(activeDetailsPanel);
                activeDetailsPanel = null;
                $panelContainer.empty();
                if (risk.isNonPublic) {
                    $panelContainer.append(
                        $('<p>').append($('<strong>').text('Address Type: '), document.createTextNode(`${risk.nonPublicReason} [${risk.nonPublicBadgeCode}]`)),
                        $('<p>').append($('<strong>').text('Status: '), document.createTextNode('External threat lookups skipped (non-public or reserved IP)'))
                    );
                } else {
                    activeDetailsPanel = buildResultDetailsPanel(d, risk, targetIp);
                    $panelContainer.append(activeDetailsPanel);
                }
            };

            const runDialogRefresh = (isAutoSwr) => {
                if (refreshInFlight || dialogClosed || accessBlocked || !isValidIp(targetIp)) return;
                if (isAutoSwr && !tryConsumeAutoSwrBudget()) return;
                refreshInFlight = true;
                $warningNotice.css('display', 'none').text('');
                $refetchBtn.prop('disabled', true).text('Updating...');
                executeIpRefresh(targetIp).then((outcome) => {
                    refreshInFlight = false;
                    if (dialogClosed) return;
                    if (!outcome || !outcome.ok || !outcome.data) {
                        $refetchBtn.prop('disabled', false).text('Refetch');
                        $warningNotice.text(formatRefreshWarningText(outcome)).css('display', 'block');
                        return;
                    }
                    activeData = outcome.data;
                    const freshRisk = evaluateRisk(activeData);
                    renderBody(activeData, freshRisk);
                    syncControls(activeData, freshRisk, true);
                    $warningNotice.css('display', 'none').text('');
                });
            };

            $refetchBtn.on('click', (e) => { e.preventDefault(); e.stopPropagation(); runDialogRefresh(false); });
            renderBody(activeData, initialRisk);
            syncControls(activeData, initialRisk, false);

            const $message = $('<div>').append(
                $cacheBar, $warningNotice, $panelContainer,
                $('<p>', { style: 'margin-top: 8px; margin-bottom: 0;' }).append(
                    $('<a>', { 'class': 'proxycheck-dialog-link', href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(targetIp), target: '_blank', rel: 'noopener noreferrer', text: 'Open full report ↗' })
                )
            );

            if (!initialRisk.isNonPublic && isPartialLightResult(activeData)) {
                let $upgradeNotice = $('<p>', { 'class': 'proxycheck-light-upgrade-notice', style: 'margin-top: 8px; margin-bottom: 0; font-size: 12px;' })
                    .text('Loading full commercial provider intelligence...');
                $message.append($upgradeNotice);
                requestFullIpUpgrade(targetIp, false).then((fullData) => {
                    if (!fullData) { if (!dialogClosed && $upgradeNotice) $upgradeNotice.text('Full commercial intelligence unavailable right now.'); return; }
                    activeData = fullData;
                    if (dialogClosed) return;
                    const updatedRisk = evaluateRisk(fullData);
                    renderBody(fullData, updatedRisk);
                    syncControls(fullData, updatedRisk, false);
                    if ($upgradeNotice) { $upgradeNotice.remove(); $upgradeNotice = null; }
                    if (shouldAutoRefreshPayload(fullData, cacheKey)) runDialogRefresh(true);
                }).catch(() => { if (!dialogClosed && $upgradeNotice) $upgradeNotice.text('Full commercial intelligence unavailable right now.'); });
            } else if (!initialRisk.isNonPublic && shouldAutoRefreshPayload(activeData, cacheKey)) {
                runDialogRefresh(true);
            }

            return Promise.resolve(OO.ui.alert($message, { title: targetIp, size: 'large' })).then(
                (r) => { dialogClosed = true; disposeDetailsPanel(activeDetailsPanel); activeDetailsPanel = null; return r; },
                (err) => { dialogClosed = true; disposeDetailsPanel(activeDetailsPanel); activeDetailsPanel = null; throw err; }
            );
        }).catch((err) => { warn('Info dialog failed:', err); })
          .then((r) => { infoDialogPromise = null; return r; });

        return infoDialogPromise;
    }

    function applyBaseBadgeStyle(badge) {
        Object.assign(badge.style, {
            marginLeft: '4px', fontSize: '0.85em',
            fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
            padding: '1px 5px', borderRadius: '3px', textDecoration: 'none', whiteSpace: 'nowrap'
        });
    }

    function createActionBadge(anchor, options) {
        if (accessBlocked || !anchor || !anchor.parentNode) return null;
        const nextEl = anchor.nextElementSibling;
        if (nextEl && nextEl.classList && nextEl.classList.contains(BADGE_CLASS)) return null;
        ensureUserscriptStyles();
        const badge = createEl('a', BADGE_CLASS + (options.extraClass ? ' ' + options.extraClass : ''), options.text, { href: '#', role: 'button', title: options.title });
        applyBaseBadgeStyle(badge);
        badge.style.cursor = 'pointer';
        badge.addEventListener('click', (e) => {
            e.preventDefault(); e.stopPropagation();
            if (!accessBlocked) options.onClick(badge);
        });
        anchor.parentNode.insertBefore(badge, anchor.nextSibling);
        return badge;
    }

    function createErrorRetryBadge(anchor, ip) {
        createActionBadge(anchor, {
            extraClass: 'proxycheck-ip-badge-error',
            text: '[Retry]',
            title: 'ProxyCheck lookup failed. Click to retry.',
            onClick: (badge) => {
                if (badge.parentNode) badge.parentNode.removeChild(badge);
                invalidateIpResultCache(ip);
                if (anchor.dataset) delete anchor.dataset.proxycheckProcessed;
                processAnchor(anchor);
            }
        });
    }

    function matchesSelector(el, sel) {
        return Boolean(el && el.nodeType === 1 && typeof el.matches === 'function' && el.matches(sel));
    }

    function closestElement(el, sel) {
        return el && el.nodeType === 1 && typeof el.closest === 'function' ? el.closest(sel) : null;
    }

    function isProxycheckInternalNode(node) {
        if (!node) return false;
        if (node.nodeType === 8) return true;
        if (node.nodeType === 3) return !node.parentNode || Boolean(closestElement(node.parentNode, INTERNAL_NODE_SELECTOR));
        return node.nodeType === 1 && Boolean(closestElement(node, INTERNAL_NODE_SELECTOR));
    }

    function shouldSkipRevealTarget(el) {
        return !el || el.nodeType !== 1 || Boolean(
            matchesSelector(el, REVEAL_CONTAINER_SELECTOR) && !matchesSelector(el, REVEAL_ANCHOR_SELECTOR) &&
            el.querySelector && el.querySelector(REVEAL_ANCHOR_SELECTOR)
        );
    }

    function extractIpFromRevealElement(el) {
        if (shouldSkipRevealTarget(el)) return '';
        let rawText = '';
        if (el.childNodes && el.childNodes.length > 0) {
            const chunks = [];
            for (const c of el.childNodes) {
                if (c && c.nodeType === 1 && matchesSelector(c, '.' + BADGE_CLASS)) continue;
                chunks.push(c.textContent || c.nodeValue || '');
            }
            rawText = chunks.join('');
        } else {
            rawText = el.textContent || '';
        }
        const trimmed = rawText.trim();
        if (isValidIp(trimmed)) return trimmed;
        if (/^\([^()]+\)$/.test(trimmed)) {
            const unwrapped = trimmed.slice(1, -1).trim();
            if (isValidIp(unwrapped)) return unwrapped;
        }
        return '';
    }

    function resumeAfterConsent() {
        if (accessBlocked || consentDeclined || !document.body) return;
        for (const anchor of document.body.querySelectorAll(TARGET_SELECTOR)) {
            if (!anchor || !anchor.dataset || anchor.dataset.proxycheckProcessed !== 'consent-declined') continue;
            const nextEl = anchor.nextElementSibling;
            if (nextEl && nextEl.classList && nextEl.classList.contains('proxycheck-ip-badge-consent') && nextEl.parentNode) {
                nextEl.parentNode.removeChild(nextEl);
            }
            delete anchor.dataset.proxycheckProcessed;
        }
        handleIPContributionsPage();
        scanSubtree(document.body);
    }

    function createConsentTriggerBadge(anchor) {
        createActionBadge(anchor, {
            extraClass: 'proxycheck-ip-badge-consent',
            text: '[ProxyCheck]',
            title: 'ProxyCheck consent required. Click to review policy and enable.',
            onClick: () => ensureConsent(true).then((agreed) => { if (agreed && !accessBlocked) resumeAfterConsent(); })
        });
    }

    function processAnchor(anchor) {
        if (accessBlocked || !anchor || !anchor.dataset || shouldSkipRevealTarget(anchor) ||
            (anchor.dataset.proxycheckProcessed && anchor.dataset.proxycheckProcessed !== 'observed')) return;
        const ip = extractIpFromRevealElement(anchor);
        if (!ip) return;
        anchor.dataset.proxycheckProcessed = 'pending';

        ensureConsent(false).then((agreed) => {
            if (!agreed) {
                if (!accessBlocked && anchor.dataset.proxycheckProcessed === 'pending') {
                    anchor.dataset.proxycheckProcessed = 'consent-declined';
                    createConsentTriggerBadge(anchor);
                } else delete anchor.dataset.proxycheckProcessed;
                return null;
            }
            return fetchIpIntelligence(ip, 'light');
        }).then((data) => {
            if (!data) {
                if (!accessBlocked && anchor.dataset.proxycheckProcessed === 'pending') {
                    anchor.dataset.proxycheckProcessed = 'error';
                    createErrorRetryBadge(anchor, ip);
                }
                return;
            }
            if (!anchor.parentNode || shouldSkipRevealTarget(anchor)) { delete anchor.dataset.proxycheckProcessed; return; }
            if (anchor.dataset.proxycheckProcessed === 'true') return;
            const nextEl = anchor.nextElementSibling;
            if (nextEl && nextEl.classList && nextEl.classList.contains(BADGE_CLASS)) { anchor.dataset.proxycheckProcessed = 'true'; return; }

            const resolvedIp = data.ip || ip;
            const badge = createEl('a', BADGE_CLASS, null, { target: '_blank', rel: 'noopener noreferrer' });
            badge.addEventListener('click', (e) => {
                e.preventDefault(); e.stopPropagation();
                const currentKey = canonicalizeIpKey(resolvedIp) || canonicalizeIpKey(ip);
                const activeData = (currentKey && latestResultByIp.get(currentKey)) || data;
                showInfoDialog(activeData, activeData.ip || resolvedIp);
            });
            applyRiskStylingToAnchorAndBadge(anchor, badge, data, resolvedIp, false);
            registerRenderedBadge(canonicalizeIpKey(resolvedIp) || canonicalizeIpKey(ip), anchor, badge, resolvedIp);
            anchor.parentNode.insertBefore(badge, anchor.nextSibling);
            anchor.dataset.proxycheckProcessed = 'true';
        });
    }

    function isIpInfoPanelMutation(target, addedNode) {
        if (closestElement(target, IPINFO_PANEL_SELECTOR)) return true;
        return Boolean(addedNode && addedNode.nodeType === 1 &&
            (matchesSelector(addedNode, IPINFO_PANEL_SELECTOR) || (addedNode.querySelector && addedNode.querySelector(IPINFO_PANEL_SELECTOR))));
    }

    function scheduleIpContributionsUpdate(shouldRefreshSpur) {
        pendingContributionsPageCheck = true;
        if (shouldRefreshSpur) pendingSpurRefresh = true;
        if (ipContributionsObserverTimer !== null) return;
        ipContributionsObserverTimer = window.setTimeout(() => {
            ipContributionsObserverTimer = null;
            const runPage = pendingContributionsPageCheck, runSpur = pendingSpurRefresh;
            pendingContributionsPageCheck = false;
            pendingSpurRefresh = false;
            if (accessBlocked || !isIpContributionsPage) return;
            if (runPage) handleIPContributionsPage();
            if (runSpur && typeof refreshPageInfoSpur === 'function') refreshPageInfoSpur();
        }, OBSERVER_THROTTLE_MS);
    }

    function scheduleAnchor(anchor) {
        if (accessBlocked || !anchor || !anchor.dataset || anchor.dataset.proxycheckProcessed || shouldSkipRevealTarget(anchor)) return;
        const ip = extractIpFromRevealElement(anchor);
        if (!ip) return;
        if (isIpContributionsPage && !ipContributionsInvalidTarget) handleIPContributionsPage(true);
        const cacheKey = canonicalizeIpKey(ip);
        if (ipPromiseCache.has(cacheKey) || readPersistedIpResult(cacheKey)) { processAnchor(anchor); return; }
        if (viewportObserver) { anchor.dataset.proxycheckProcessed = 'observed'; viewportObserver.observe(anchor); return; }
        processAnchor(anchor);
    }

    function scanSubtree(root) {
        if (accessBlocked || !root || root.nodeType !== 1 || isProxycheckInternalNode(root)) return;
        if (matchesSelector(root, TARGET_SELECTOR)) scheduleAnchor(root);
        for (const anchor of root.querySelectorAll(TARGET_SELECTOR)) scheduleAnchor(anchor);
    }

    function getTargetQueryParam() {
        if (mw.util && typeof mw.util.getParamValue === 'function') return mw.util.getParamValue('target');
        try {
            const q = typeof window !== 'undefined' && window.location && typeof window.location.search === 'string'
                ? window.location.search.replace(/^\?/, '') : '';
            if (!q) return null;
            for (const pair of q.split('&')) {
                const eq = pair.indexOf('=');
                const k = eq === -1 ? pair : pair.slice(0, eq);
                if (decodeURIComponent(k.replace(/\+/g, ' ')) === 'target') {
                    return decodeURIComponent((eq === -1 ? '' : pair.slice(eq + 1)).replace(/\+/g, ' '));
                }
            }
        } catch (err) { warn('Failed to parse query target:', err); }
        return null;
    }

    function extractContributionsTargetIp() {
        let target = mw.config.get('wgRelevantUserName');
        if (!target) {
            const parts = (mw.config.get('wgTitle') || '').split('/');
            if (parts.length > 1) target = parts.slice(1).join('/');
        }
        if (!target) target = getTargetQueryParam();
        return typeof target === 'string' ? target.trim() : '';
    }

    function isTemporaryAccountIdentifier(userText) {
        if (typeof userText !== 'string' || !userText.trim()) return false;
        const trimmed = userText.trim();
        return mw && mw.util && typeof mw.util.isTemporaryUser === 'function'
            ? Boolean(mw.util.isTemporaryUser(trimmed))
            : /^~\d{4}-/.test(trimmed);
    }

    function collectRevealedIpsInDom() {
        if (typeof document === 'undefined' || !document.body || typeof document.body.querySelectorAll !== 'function') return [];
        const discovered = [], seen = Object.create(null);
        for (const el of document.body.querySelectorAll(TARGET_SELECTOR)) {
            if (!el || isProxycheckInternalNode(el) || shouldSkipRevealTarget(el)) continue;
            const ip = extractIpFromRevealElement(el);
            const canonical = ip ? canonicalizeIpKey(ip) : '';
            if (canonical && !seen[canonical]) { seen[canonical] = true; discovered.push({ canonicalKey: canonical, displayIp: ip }); }
        }
        return discovered;
    }

    function resolveContributionsMountTarget(allowFallback) {
        const $panel = $('.ext-ipinfo-panel-layout');
        if ($panel.length > 0 && $panel.find('.ext-ipinfo-collapsible-layout-error, .oo-ui-flaggedElement-error, .oo-ui-icon-error').length === 0) {
            let $body = $panel.find('.oo-ui-fieldsetLayout-group.mw-collapsible-content').first();
            if ($body.length === 0) $body = $panel.find('.oo-ui-fieldsetLayout-group').first();
            if ($body.length === 0) $body = $panel.first();
            if ($body.length > 0) return { $element: $body, method: 'prepend' };
        }
        if (!allowFallback) return null;
        const candidates = [
            ['#mw-content-text .mw-contributions-header', 'before'],
            ['#mw-content-text .mw-contributions-list', 'before'],
            ['.mw-contributions-header', 'before'],
            ['.mw-contributions-list', 'before'],
            ['#mw-content-text .mw-contributions-form', 'after'],
            ['.mw-contributions-form', 'after'],
            ['#contentSub', 'after'],
            ['#mw-content-text', 'prepend'],
            ['#contentSub', 'prepend']
        ];
        for (const [sel, method] of candidates) {
            const $node = $(sel).first();
            if ($node.length === 0) continue;
            if ((method === 'before' || method === 'after') && $node.parent().length === 0) continue;
            return { $element: $node, method };
        }
        return typeof document !== 'undefined' && document.body ? { $element: $(document.body), method: 'prepend' } : null;
    }

    function isDocumentVisible() {
        return typeof document === 'undefined' || typeof document.visibilityState !== 'string' || document.visibilityState === 'visible';
    }

    function peekCachedIpState(ip) {
        const key = canonicalizeIpKey(ip);
        if (!key) return null;
        const latest = latestResultByIp.get(key);
        if (latest && !isPartialLightResult(latest) && isMemoryFullResultFresh(key, latest)) return { data: latest, isFull: true };
        const persisted = readPersistedIpResultEntry(key);
        if (persisted && persisted.data) return { data: persisted.data, isFull: !isPartialLightResult(persisted.data) };
        return latest ? { data: latest, isFull: false } : null;
    }

    function scheduleContributionsOnVisible(onVisible) {
        if (ipContributionsVisibilityHandler || typeof document === 'undefined' || typeof document.addEventListener !== 'function') return;
        ipContributionsVisibilityHandler = () => {
            if (accessBlocked || !isDocumentVisible()) return;
            clearContributionsSchedule();
            onVisible();
        };
        document.addEventListener('visibilitychange', ipContributionsVisibilityHandler);
    }

    function handleIPContributionsPage(allowFallback) {
        ensureUserscriptStyles();
        if (accessBlocked || consentDeclined || !isIpContributionsPage || ipContributionsInvalidTarget) return;

        const rawTarget = extractContributionsTargetIp();
        const isDirectIpTarget = isValidIp(rawTarget);
        const isTempAccountTarget = !isDirectIpTarget && isTemporaryAccountIdentifier(rawTarget);
        if (!isDirectIpTarget && !isTempAccountTarget) { ipContributionsInvalidTarget = true; return; }

        let discoveredTempIps = isTempAccountTarget ? collectRevealedIpsInDom() : [];
        if (isTempAccountTarget && discoveredTempIps.length === 0) return;

        if (document.getElementById('proxycheck-pageinfo')) {
            if (isTempAccountTarget && activeContributionsController) activeContributionsController.syncDiscoveredIps(discoveredTempIps);
            return;
        }
        if (ipContributionsPending) return;

        let initialTargetIp = isDirectIpTarget ? rawTarget : discoveredTempIps[0].displayIp;
        const effectiveAllowFallback = Boolean(allowFallback || isTempAccountTarget);
        if (!peekCachedIpState(initialTargetIp) && !isDocumentVisible()) {
            scheduleContributionsOnVisible(() => handleIPContributionsPage(effectiveAllowFallback));
            return;
        }

        const mountTarget = resolveContributionsMountTarget(effectiveAllowFallback);
        if (!mountTarget) {
            if (!effectiveAllowFallback && ipContributionsFallbackTimer === null) {
                ipContributionsFallbackTimer = window.setTimeout(() => {
                    ipContributionsFallbackTimer = null;
                    handleIPContributionsPage(true);
                }, IPINFO_FALLBACK_DELAY_MS);
            }
            return;
        }

        clearContributionsFallbackTimer();
        ipContributionsPending = true;
        let $box = null, $switcher = null, $result = null;

        const isNodeInDoc = (node) => Boolean(node) && (typeof document === 'undefined' || !document.body || typeof document.body.contains !== 'function' || document.body.contains(node));
        const mountBanner = (target) => {
            if (!$box || $box.length === 0 || !target || !target.$element || target.$element.length === 0) return false;
            const existing = document.getElementById('proxycheck-pageinfo');
            if (existing && existing !== $box[0] && existing.parentNode) existing.parentNode.removeChild(existing);
            target.$element[target.method]($box);
            return true;
        };
        const ensureBannerAttached = () => {
            if (!$box || $box.length === 0 || !$box[0]) return false;
            return isNodeInDoc($box[0]) || mountBanner(resolveContributionsMountTarget(effectiveAllowFallback) || resolveContributionsMountTarget(true));
        };
        const removeUnpopulatedBanner = () => {
            clearLoadingInterval();
            if ($box && $box.length > 0 && $box[0] && $box[0].parentNode) $box[0].parentNode.removeChild($box[0]);
            $box = $switcher = $result = activeContributionsController = null;
        };
        const registerResumeWhenVisible = () => scheduleContributionsOnVisible(() => handleIPContributionsPage(effectiveAllowFallback));

        ensureConsent().then((agreed) => {
            if (!agreed || accessBlocked || document.getElementById('proxycheck-pageinfo')) { ipContributionsPending = false; return null; }
            if (isTempAccountTarget) {
                discoveredTempIps = collectRevealedIpsInDom();
                if (discoveredTempIps.length === 0) { ipContributionsPending = false; return null; }
                initialTargetIp = discoveredTempIps[0].displayIp;
            }
            if (!peekCachedIpState(initialTargetIp) && !isDocumentVisible()) { ipContributionsPending = false; registerResumeWhenVisible(); return null; }

            let activeTarget = resolveContributionsMountTarget(effectiveAllowFallback) || mountTarget;
            if (!activeTarget || !activeTarget.$element || activeTarget.$element.length === 0 || (activeTarget.$element[0] && !isNodeInDoc(activeTarget.$element[0]))) {
                activeTarget = resolveContributionsMountTarget(true);
            }
            if (!activeTarget) { ipContributionsPending = false; return null; }

            $box = $('<div>', { id: 'proxycheck-pageinfo', 'class': 'proxycheck-pageinfo-banner' });
            $switcher = $('<div>', { 'class': 'proxycheck-temp-ip-switcher', style: 'display: none;' });
            $result = $('<span>', { id: 'proxycheck_result', text: '.' });
            $box.append($switcher, $result);
            mountBanner(activeTarget);

            let currentTargetIp = initialTargetIp, currentCanonicalKey = canonicalizeIpKey(currentTargetIp);
            let userPinnedKey = null, currentDiscoveredList = discoveredTempIps.slice(), currentDiscoveredSig = '';
            let isStatsExpanded = false, activeBannerDetailsPanel = null, bannerLoadSeq = 0, bannerRefreshInFlight = false;
            const fullUpgradeRequestedForKey = Object.create(null);
            const computeSig = (list) => list.map((e) => e.canonicalKey).join('|');

            const renderMultiIpSwitcher = () => {
                if (!$switcher) return;
                $switcher.empty();
                if (!isTempAccountTarget || currentDiscoveredList.length <= 1) { $switcher.css('display', 'none'); return; }
                $switcher.css('display', 'flex').append($('<span>', { 'class': 'proxycheck-temp-ip-subtitle', text: `${currentDiscoveredList.length} distinct revealed IPs on this page:` }));
                for (const entry of currentDiscoveredList) {
                    const selected = entry.canonicalKey === currentCanonicalKey;
                    const $pill = $('<button>', {
                        type: 'button',
                        'class': 'proxycheck-ip-pill' + (selected ? ' proxycheck-ip-pill-active' : ''),
                        'aria-pressed': selected ? 'true' : 'false',
                        text: entry.displayIp
                    }).on('click', (e) => {
                        e.preventDefault(); e.stopPropagation();
                        if (accessBlocked || entry.canonicalKey === currentCanonicalKey) return;
                        userPinnedKey = entry.canonicalKey;
                        switchInspectedBannerIp(entry.displayIp, true);
                    });
                    $switcher.append($pill);
                }
            };

            const renderBannerFailure = (failedIp) => {
                if (!$result || $result.length === 0) return;
                if (accessBlocked) { $result.text('[ProxyCheck] Access denied or disabled'); return; }
                const $retry = $('<a>', { href: '#', role: 'button', 'class': 'proxycheck-banner-retry', text: 'Retry ↻' }).on('click', (e) => {
                    e.preventDefault(); e.stopPropagation();
                    if (accessBlocked) return;
                    clearLoadingInterval(); clearContributionsSchedule();
                    invalidateIpResultCache(failedIp);
                    switchInspectedBannerIp(failedIp, true);
                });
                $result.empty().append(document.createTextNode('[ProxyCheck] Failed to acquire data '), $retry);
            };

            const renderBannerData = (bannerData, isJustUpdated) => {
                disposeDetailsPanel(activeBannerDetailsPanel);
                activeBannerDetailsPanel = null;
                const risk = evaluateRisk(bannerData);
                const resolvedIp = bannerData.ip || currentTargetIp;
                const resolvedKey = canonicalizeIpKey(resolvedIp) || currentCanonicalKey;
                const $activeBox = ($box && $box.length > 0) ? $box : $('#proxycheck-pageinfo');
                if ($activeBox && $activeBox.length > 0 && $activeBox[0] && $activeBox[0].classList) {
                    $activeBox[0].classList.remove('proxycheck-banner-tier-high', 'proxycheck-banner-tier-medium', 'proxycheck-banner-tier-nonpublic', 'proxycheck-banner-tier-low');
                    $activeBox[0].classList.add('proxycheck-banner-tier-' + risk.riskTier);
                }
                renderMultiIpSwitcher();
                const badgeClass = 'proxycheck-banner-badge proxycheck-tier-' + risk.riskTier;

                if (risk.isNonPublic) {
                    $result.empty().append(
                        $('<span>', { 'class': badgeClass, text: `ProxyCheck [${risk.nonPublicBadgeCode}]` }),
                        $('<span>').append(document.createTextNode(' \u00b7 '), $('<b>').text('Address Type:'), document.createTextNode(` ${risk.nonPublicReason} \u00b7 `), $('<b>').text('Status:'), document.createTextNode(' External threat lookups skipped (non-public or reserved IP) \u00b7 ')),
                        $('<a>', { href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp), target: '_blank', rel: 'noopener noreferrer', text: 'Full Report ↗' })
                    );
                    return;
                }

                const torDesc = formatTorDescription(risk), cloudDesc = formatCloudDescription(bannerData);
                const sharedEgress = getSharedPrivacyEgressLabel(bannerData);
                const verdictText = typeof bannerData.arbitrationVerdict === 'string' ? bannerData.arbitrationVerdict.trim() : '';
                const ptrHost = typeof bannerData.ptrHostname === 'string' ? bannerData.ptrHostname.trim() : '';
                const ptrLbl = typeof bannerData.ptrLabel === 'string' ? bannerData.ptrLabel.trim() : '';

                const $summary = $('<div>', { 'class': 'proxycheck-summary-line' }).append($('<span>', { 'class': badgeClass, text: 'ProxyCheck' }));
                const addItem = (lbl, valNode) => $summary.append(document.createTextNode(' \u00b7 '), $('<b>').text(lbl + ': '), valNode);

                if (isTempAccountTarget) addItem('IP', $('<code>').text(resolvedIp));
                addItem('Prediction', document.createTextNode(risk.predictionTooltip));
                if (verdictText) addItem('Verdict', document.createTextNode(verdictText));
                addItem('Recommended CIDR', document.createTextNode(bannerData.recommendedCidr || 'N/A'));
                addItem('BGP CIDR', document.createTextNode(bannerData.bgpPrefix || bannerData.mmdbCidr || 'N/A'));
                if (ptrHost || ptrLbl) {
                    const $ptr = $('<span>');
                    if (ptrHost) {
                        $ptr.append($('<code>').text(ptrHost));
                        if (ptrLbl) $ptr.append(document.createTextNode(' '), $('<span>', { 'class': bannerData.ptrIsHighRisk ? 'proxycheck-ptr-label-risk' : 'proxycheck-ptr-label-normal', text: `(${ptrLbl})` }));
                    } else $ptr.text(ptrLbl);
                    addItem('PTR', $ptr);
                }
                if (cloudDesc) addItem('Cloud', document.createTextNode(cloudDesc));
                if (sharedEgress) addItem('Shared Egress', $('<strong>', { 'class': 'proxycheck-banner-warning-text', text: `${sharedEgress} (soft block recommended)` }));
                if (isMobileOrCgnatPayload(bannerData)) addItem('Network', $('<strong>', { 'class': 'proxycheck-banner-warning-text', text: 'Mobile / CGNAT (/32 IPv4, /64 IPv6 lock)' }));
                addItem('Broadcast IP', risk.broadcastIp ? $('<strong>', { 'class': 'proxycheck-banner-warning-text', text: 'At-risk' }) : document.createTextNode('No'));
                addItem('Tor Node', risk.isTor ? $('<strong>', { 'class': 'proxycheck-banner-danger-text', text: torDesc }) : document.createTextNode('No'));

                let renderedSpur = getSpurProxyText();
                activeBannerDetailsPanel = buildResultDetailsPanel(bannerData, risk, resolvedIp);
                const $detailsWrapper = $('<div>', { 'class': 'proxycheck-pageinfo-details', style: isStatsExpanded ? 'display: block;' : 'display: none;' }).append(activeBannerDetailsPanel);

                refreshPageInfoSpur = () => {
                    const latestSpur = getSpurProxyText();
                    if (latestSpur === renderedSpur) return;
                    renderedSpur = latestSpur;
                    disposeDetailsPanel(activeBannerDetailsPanel);
                    activeBannerDetailsPanel = buildResultDetailsPanel(bannerData, risk, resolvedIp);
                    $detailsWrapper.empty().append(activeBannerDetailsPanel);
                };

                const $statsToggle = $('<a>', {
                    href: '#', role: 'button', 'class': 'proxycheck-stats-toggle',
                    'aria-expanded': isStatsExpanded ? 'true' : 'false',
                    text: isStatsExpanded ? 'Statistic ▾' : 'Statistic ▸'
                }).on('click', (e) => {
                    e.preventDefault(); e.stopPropagation();
                    isStatsExpanded = !isStatsExpanded;
                    $detailsWrapper.css('display', isStatsExpanded ? 'block' : 'none');
                    $statsToggle.attr('aria-expanded', isStatsExpanded ? 'true' : 'false').text(isStatsExpanded ? 'Statistic ▾' : 'Statistic ▸');
                    if (isStatsExpanded && isPartialLightResult(bannerData) && !fullUpgradeRequestedForKey[resolvedKey]) {
                        fullUpgradeRequestedForKey[resolvedKey] = true;
                        clearContributionsSchedule();
                        const $notice = $('<p>', { 'class': 'proxycheck-light-upgrade-notice', style: 'margin-top: 8px; margin-bottom: 0; font-size: 12px;' }).text('Loading full commercial provider intelligence...');
                        $detailsWrapper.append($notice);
                        requestFullIpUpgrade(resolvedIp, false).then((fullData) => {
                            if (!fullData) { $notice.text('Full commercial intelligence unavailable right now.'); return; }
                            if (ensureBannerAttached() && currentCanonicalKey === resolvedKey) renderBannerData(fullData, false);
                        });
                    }
                });

                const $bannerWarning = $('<div>', { 'class': 'proxycheck-refresh-warning', style: 'display: none;' });
                const meta = getCacheMeta(bannerData);
                const isStale = Boolean(!isJustUpdated && meta && meta.isStale === true);
                const $bannerAgeSpan = $('<span>', { 'class': 'proxycheck-cache-age' + (isStale ? ' proxycheck-cache-age-stale' : ''), text: formatCacheStatusLabel(bannerData, Boolean(isJustUpdated)) });
                const $bannerRefetchBtn = $('<button>', { type: 'button', 'class': 'proxycheck-refetch-btn', text: 'Refetch' });

                const runBannerRefresh = (isAutoSwr) => {
                    if (bannerRefreshInFlight || accessBlocked || !isValidIp(resolvedIp)) return;
                    if (isAutoSwr && !tryConsumeAutoSwrBudget()) return;
                    const seq = bannerLoadSeq;
                    bannerRefreshInFlight = true;
                    $bannerWarning.css('display', 'none').text('');
                    $bannerRefetchBtn.prop('disabled', true).text('Updating...');
                    executeIpRefresh(resolvedIp).then((outcome) => {
                        if (seq !== bannerLoadSeq || currentCanonicalKey !== resolvedKey) return;
                        bannerRefreshInFlight = false;
                        if (!ensureBannerAttached()) return;
                        if (!outcome || !outcome.ok || !outcome.data) {
                            $bannerRefetchBtn.prop('disabled', false).text('Refetch');
                            $bannerWarning.text(formatRefreshWarningText(outcome)).css('display', 'block');
                            return;
                        }
                        renderBannerData(outcome.data, true);
                    });
                };

                $bannerRefetchBtn.on('click', (e) => { e.preventDefault(); e.stopPropagation(); runBannerRefresh(false); });
                $summary.append(
                    document.createTextNode(' \u00b7 '),
                    $('<a>', { href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp), target: '_blank', rel: 'noopener noreferrer', text: 'Full Report ↗' }),
                    document.createTextNode(' \u00b7 '), $statsToggle,
                    document.createTextNode(' \u00b7 '), $('<span>', { 'class': 'proxycheck-cache-controls' }).append($bannerAgeSpan, $bannerRefetchBtn)
                );
                $result.empty().append($summary, $bannerWarning, $detailsWrapper);
                if (!isPartialLightResult(bannerData) && shouldAutoRefreshPayload(bannerData, resolvedKey)) runBannerRefresh(true);
            };

            const scheduleFullUpgradeAfterDelay = (ipForUpgrade, keyForUpgrade) => {
                clearContributionsSchedule();
                if (fullUpgradeRequestedForKey[keyForUpgrade] || accessBlocked) return;
                const armTimer = () => {
                    if (ipContributionsDelayTimer !== null || fullUpgradeRequestedForKey[keyForUpgrade] || accessBlocked) return;
                    ipContributionsDelayTimer = window.setTimeout(() => {
                        ipContributionsDelayTimer = null;
                        if (accessBlocked || fullUpgradeRequestedForKey[keyForUpgrade]) return;
                        if (!isDocumentVisible()) { scheduleContributionsOnVisible(armTimer); return; }
                        fullUpgradeRequestedForKey[keyForUpgrade] = true;
                        requestFullIpUpgrade(ipForUpgrade, false).then((fullData) => {
                            if (fullData && ensureBannerAttached() && currentCanonicalKey === keyForUpgrade) renderBannerData(fullData, false);
                        }).catch((err) => warn('Contributions upgrade failed:', err));
                    }, CONTRIB_FULL_TRIGGER_DELAY_MS);
                };
                if (isDocumentVisible()) armTimer(); else scheduleContributionsOnVisible(armTimer);
            };

            function switchInspectedBannerIp(nextIp, immediateFetch) {
                if (!isValidIp(nextIp)) return Promise.resolve(null);
                clearLoadingInterval(); clearContributionsSchedule();
                bannerRefreshInFlight = false;
                currentTargetIp = nextIp;
                currentCanonicalKey = canonicalizeIpKey(nextIp);
                bannerLoadSeq += 1;
                const activeSeq = bannerLoadSeq;
                renderMultiIpSwitcher();

                const cachedNow = peekCachedIpState(nextIp);
                if (cachedNow && cachedNow.isFull) {
                    return fetchIpIntelligence(nextIp, 'full').then((data) => {
                        if (activeSeq !== bannerLoadSeq || !ensureBannerAttached()) return null;
                        if (!data) { renderBannerFailure(nextIp); return null; }
                        renderBannerData(data, false);
                        return data;
                    });
                }
                if (cachedNow && cachedNow.data) {
                    if (ensureBannerAttached()) {
                        renderBannerData(cachedNow.data, false);
                        if (isPartialLightResult(cachedNow.data)) {
                            if (immediateFetch) {
                                fullUpgradeRequestedForKey[currentCanonicalKey] = true;
                                requestFullIpUpgrade(nextIp, false).then((fullData) => {
                                    if (fullData && activeSeq === bannerLoadSeq && ensureBannerAttached()) renderBannerData(fullData, false);
                                });
                            } else scheduleFullUpgradeAfterDelay(nextIp, currentCanonicalKey);
                        }
                    }
                    return Promise.resolve(cachedNow.data);
                }

                const frames = ['.\u00a0\u00a0', '\u00a0.\u00a0', '\u00a0\u00a0.'];
                let frameIdx = 0;
                $result.text(frames[0]);
                activeLoadingInterval = window.setInterval(() => {
                    $result.text(frames[frameIdx]);
                    frameIdx = (frameIdx + 1) % frames.length;
                }, 300);

                const runFullFetch = () => fetchIpIntelligence(nextIp, 'full').then((data) => {
                    if (activeSeq !== bannerLoadSeq) return null;
                    clearLoadingInterval();
                    if (!ensureBannerAttached()) return null;
                    if (!data) { renderBannerFailure(nextIp); return null; }
                    renderBannerData(data, false);
                    return data;
                }).catch((err) => {
                    if (activeSeq !== bannerLoadSeq) return null;
                    clearLoadingInterval();
                    warn('Contributions banner data failed:', err);
                    if (ensureBannerAttached()) renderBannerFailure(nextIp);
                    return null;
                });

                if (immediateFetch) return runFullFetch();
                return new Promise((resolve) => {
                    ipContributionsDelayTimer = window.setTimeout(() => {
                        ipContributionsDelayTimer = null;
                        if (activeSeq !== bannerLoadSeq) return resolve(null);
                        if (accessBlocked) { clearLoadingInterval(); return resolve(null); }
                        if (!isDocumentVisible()) { removeUnpopulatedBanner(); registerResumeWhenVisible(); return resolve(null); }
                        runFullFetch().then(resolve);
                    }, CONTRIB_FULL_TRIGGER_DELAY_MS);
                });
            }

            currentDiscoveredSig = computeSig(currentDiscoveredList);
            activeContributionsController = {
                syncDiscoveredIps: (nextList) => {
                    if (!Array.isArray(nextList) || nextList.length === 0) return;
                    const nextSig = computeSig(nextList);
                    if (nextSig === currentDiscoveredSig) return;
                    currentDiscoveredSig = nextSig;
                    currentDiscoveredList = nextList.slice();
                    if (!userPinnedKey && currentDiscoveredList[0].canonicalKey !== currentCanonicalKey) {
                        switchInspectedBannerIp(currentDiscoveredList[0].displayIp, true);
                        return;
                    }
                    renderMultiIpSwitcher();
                }
            };
            ipContributionsPending = false;
            return switchInspectedBannerIp(initialTargetIp, Boolean(isTempAccountTarget));
        }).catch((err) => {
            clearLoadingInterval();
            ipContributionsPending = false;
            warn('Contributions banner update failed:', err);
        });
    }

    $(() => {
        ensureUserscriptStyles();
        if (typeof window !== 'undefined' && typeof window.IntersectionObserver === 'function') {
            viewportObserver = new window.IntersectionObserver((entries) => {
                if (accessBlocked) return;
                for (const entry of entries) {
                    if (entry && entry.isIntersecting && entry.target) {
                        viewportObserver.unobserve(entry.target);
                        processAnchor(entry.target);
                    }
                }
            }, { rootMargin: '200px 0px' });
        }

        handleIPContributionsPage();
        scanSubtree(document.body);
        if (isIpContributionsPage && mw.hook) mw.hook('wikipage.content').add(() => handleIPContributionsPage());

        observer = new MutationObserver((mutations) => {
            if (accessBlocked) return;
            let hasExternal = false, hasIpInfo = false;
            for (const m of mutations) {
                if (!m.target || isProxycheckInternalNode(m.target)) continue;
                const targetEl = m.target.nodeType === 3 ? m.target.parentNode : m.target;
                if (!targetEl || targetEl.nodeType !== 1 || isProxycheckInternalNode(targetEl)) continue;
                const matched = matchesSelector(targetEl, TARGET_SELECTOR) ? targetEl : closestElement(targetEl, TARGET_SELECTOR);
                if (matched) { hasExternal = true; scheduleAnchor(matched); }
                if (m.addedNodes) {
                    for (const added of m.addedNodes) {
                        if (!added || added.nodeType !== 1 || isProxycheckInternalNode(added)) continue;
                        hasExternal = true;
                        if (!hasIpInfo && isIpInfoPanelMutation(targetEl, added)) hasIpInfo = true;
                        scanSubtree(added);
                    }
                }
            }
            if (isIpContributionsPage && hasExternal) scheduleIpContributionsUpdate(hasIpInfo);
        });
        observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    });
})(mediaWiki, jQuery);