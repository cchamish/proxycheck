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
    const INTERNAL_NODE_SELECTOR = '#proxycheck-pageinfo, #proxycheck_result, #proxycheck-userscript-styles, .proxycheck-ip-badge, .proxycheck-rb-badge, .proxycheck-details-panel, .proxycheck-light-upgrade-notice, .proxycheck-dialog-cache-bar, .proxycheck-cache-controls, .proxycheck-refetch-btn, .proxycheck-refresh-warning, .proxycheck-temp-ip-switcher, .proxycheck-quick-links';
    const IPINFO_PANEL_SELECTOR = '.ext-ipinfo-panel-layout';
    const OBSERVER_THROTTLE_MS = 100;
    const IPINFO_FALLBACK_DELAY_MS = 400;
    const MAX_CONCURRENT_REQUESTS = 4;
    const BATCH_DEBOUNCE_MS = 40;
    const MAX_BATCH_IPS = 10;
    const CONSENT_KEY = 'proxycheck-ip-policy-consent';
    const TOKEN_KEY = 'proxycheck-gadget-token';
    const TOKEN_USER_KEY = 'proxycheck-gadget-token-user';
    const TOKEN_EXPIRY_KEY = 'proxycheck-gadget-token-exp';
    const TOKEN_COOLDOWN_UNTIL_KEY = 'proxycheck-gadget-token-cooldown-until';
    const TOKEN_COOLDOWN_MIN_SECONDS = 5;
    const TOKEN_COOLDOWN_MAX_SECONDS = 120;
    const TOKEN_COOLDOWN_DEFAULT_SECONDS = 15;
    const TOKEN_COOLDOWN_JITTER_RATIO = 0.2;
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
    const COMMERCIAL_PROVIDERS = { AbuseIPDB: 1, IPData: 1, IPRegistry: 1, IP2Location: 1, GetIPIntel: 1, Proxycheck: 1, IPHub: 1, IPHunter: 1 };
    const PROVIDER_BADGE_PALETTES = {
        MaxMind: ['#e6f2ff', '#a3ccf5', '#0b4f8a', '#162a42', '#2f5a8a', '#8ec5ff'], IP2Location: ['#e3f8fc', '#99dfec', '#0b5d6b', '#133038', '#296878', '#7fd8e8'],
        IPData: ['#eaedff', '#b3bdf5', '#2c3e99', '#1d2345', '#3e4a8f', '#a3b3ff'], IPRegistry: ['#f0ebff', '#c5b6f2', '#4b2d8f', '#271e42', '#55418c', '#c3b0ff'],
        Proxycheck: ['#e4f7f2', '#9cd9cb', '#0d5e4e', '#13332b', '#296b5b', '#7be0c8'], 'Cloudflare Radar': ['#e8f0fe', '#a6c4f7', '#174ea6', '#182947', '#355794', '#94bfff'],
        AbuseIPDB: ['#e8eff5', '#aec2d4', '#294661', '#1d2936', '#3e5773', '#a3c2e0'], IPHub: ['#e5f5fa', '#9dd4e6', '#0d536b', '#142e3b', '#2b637d', '#84d0ed'],
        IPHunter: ['#ebf0f5', '#b8c6d6', '#324a63', '#1f2a36', '#425870', '#adc4db'], GetIPIntel: ['#eeeafd', '#bfb4f5', '#46328a', '#252045', '#4f458f', '#bdb2ff'],
        'Tor Onionoo': ['#f1ecf8', '#c9bce3', '#4e3475', '#29203d', '#574480', '#cbb8f2'], DShield: ['#e7f3f3', '#a7cfd1', '#1f5357', '#172e2f', '#316163', '#8cd4d6'],
        StopForumSpam: ['#e6f8f5', '#9fdcd2', '#125c51', '#13332e', '#286b60', '#7ee0d1'], 'Spamhaus ZEN': ['#eaedf7', '#b5c0de', '#2e3f6e', '#1e243b', '#404d7d', '#a8b8eb'],
        SpamCop: ['#eaf4fb', '#add2ec', '#1c537d', '#172c3d', '#315c80', '#91c6f2'], 'IPsum / DROP': ['#f4ecfb', '#ceb3ea', '#512b78', '#2a1d3b', '#5d4180', '#d4b8f8'],
        'OpenASN': ['#e6f4f8', '#9fd0df', '#0e5266', '#132d36', '#285f70', '#82d2e8'], 'Shodan InternetDB': ['#fbeee8', '#e8bca8', '#783416', '#361f16', '#734330', '#f5bba3'],
        'Privacy Relay': ['#eef0ff', '#b5bff7', '#2b3a94', '#1c2247', '#3f4d96', '#a8b5ff'], 'Shared CIDR': ['#e8f6ff', '#a8d8f8', '#0e527d', '#152c3d', '#2c5c80', '#8ac7f5'],
        'Multi-Source': ['#eef2f6', '#b9c6d4', '#3b4f66', '#222830', '#475466', '#b3c2d4'], 'Reverse DNS': ['#e8f7f7', '#a6dada', '#185b5e', '#153030', '#2c6666', '#87dbdb'],
        Spur: ['#e3f1f8', '#95cce6', '#0f4c6e', '#152b38', '#2c5973', '#8bc8eb']
    };
    const FALLBACK_COOL_PALETTES = [
        PROVIDER_BADGE_PALETTES.MaxMind, PROVIDER_BADGE_PALETTES.IP2Location, PROVIDER_BADGE_PALETTES.IPData,
        PROVIDER_BADGE_PALETTES.Proxycheck, PROVIDER_BADGE_PALETTES.IPRegistry, PROVIDER_BADGE_PALETTES.AbuseIPDB
    ];

    const ipStateMap = new Map();
    const renderedBadgeEntriesByIp = new Map();
    const autoSwrAttemptedKeys = new Set();
    const signalCache = typeof WeakMap === 'function' ? new WeakMap() : null;

    let activeContributionsController = null;
    let persistedCacheRaw = null;
    let persistedCacheStore = null;
    let storageFailureWarned = false;
    let stylesInjected = false;
    let observer = null;
    let accessBlocked = false;
    let consentGranted = false;
    let consentDeclined = false;
    let consentPromise = null;
    let authPromise = null;
    let memoryToken = null;
    let memoryTokenExpiry = null;
    let memoryTokenCooldownUntil = 0;
    let tokenExchangeVisibilityHandler = null;
    let tokenExchangeVisibilityResolve = null;
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
        if (id !== null) (isInterval ? window.clearInterval : window.clearTimeout)(id);
        return null;
    }

    function clearRequestQueue() {
        batchDebounceTimer = clearTimer(batchDebounceTimer, false);
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

    function clearTokenExchangeVisibilityWait() {
        if (tokenExchangeVisibilityHandler && typeof document !== 'undefined' && typeof document.removeEventListener === 'function') {
            document.removeEventListener('visibilitychange', tokenExchangeVisibilityHandler);
        }
        tokenExchangeVisibilityHandler = null;
        if (tokenExchangeVisibilityResolve) {
            const resolvePending = tokenExchangeVisibilityResolve;
            tokenExchangeVisibilityResolve = null;
            resolvePending(false);
        }
    }

    function blockAccess() {
        accessBlocked = true;
        activeLoadingInterval = clearTimer(activeLoadingInterval, true);
        clearTokenExchangeVisibilityWait();
        clearContributionsSchedule();
        ipContributionsObserverTimer = clearTimer(ipContributionsObserverTimer, false);
        ipContributionsFallbackTimer = clearTimer(ipContributionsFallbackTimer, false);
        pendingContributionsPageCheck = pendingSpurRefresh = false;
        clearRequestQueue();
        if (observer) observer.disconnect();
        if (typeof document !== 'undefined' && document.body && typeof document.body.querySelectorAll === 'function') {
            for (const el of document.body.querySelectorAll('.' + BADGE_CLASS + '.proxycheck-ip-badge-loading')) {
                const prev = el.previousElementSibling;
                if (prev && prev.dataset && prev.dataset.proxycheckProcessed === 'pending') delete prev.dataset.proxycheckProcessed;
                if (el.parentNode) el.parentNode.removeChild(el);
            }
        }
    }

    function warnPersistedCacheOnce(context, err) {
        if (storageFailureWarned) return;
        storageFailureWarned = true;
        warn('Persisted cache ' + context + ':', err);
    }

    function mwStoreOp(store, op, key, val) {
        try {
            if (store && typeof store[op] === 'function') return op === 'set' ? store.set(key, val) : store[op](key);
        } catch (err) {
            warnPersistedCacheOnce(op + ' failed', err);
        }
        return null;
    }

    function getSessionTokenStore() {
        return mw && mw.storage && mw.storage.session && typeof mw.storage.session.get === 'function' ? mw.storage.session : null;
    }

    function clearStoredToken() {
        memoryToken = memoryTokenExpiry = null;
        const store = getSessionTokenStore();
        [TOKEN_KEY, TOKEN_USER_KEY, TOKEN_EXPIRY_KEY].forEach((k) => mwStoreOp(store, 'remove', k));
    }

    function readStoredToken() {
        const store = getSessionTokenStore();
        const storedUser = mwStoreOp(store, 'get', TOKEN_USER_KEY), token = mwStoreOp(store, 'get', TOKEN_KEY), storedExpiry = mwStoreOp(store, 'get', TOKEN_EXPIRY_KEY);
        const hasExpiry = (typeof storedExpiry === 'string' && storedExpiry.trim() !== '') || (typeof storedExpiry === 'number' && isFinite(storedExpiry));
        if (hasExpiry && (!isFinite(Number(storedExpiry)) || Date.now() >= Number(storedExpiry))) { clearStoredToken(); return null; }
        if (typeof token === 'string' && token) {
            if (storedUser !== username) { clearStoredToken(); return null; }
            memoryToken = token;
            memoryTokenExpiry = hasExpiry ? Number(storedExpiry) : null;
            return token;
        }
        if (typeof storedUser === 'string' && storedUser && storedUser !== username) { clearStoredToken(); return null; }
        if (memoryToken && memoryTokenExpiry !== null && Date.now() >= memoryTokenExpiry) { clearStoredToken(); return null; }
        return memoryToken;
    }

    function storeToken(token, expiresInSeconds) {
        memoryToken = token;
        memoryTokenExpiry = null;
        const store = getSessionTokenStore();
        mwStoreOp(store, 'set', TOKEN_KEY, token);
        mwStoreOp(store, 'set', TOKEN_USER_KEY, username);
        if (typeof expiresInSeconds === 'number' && isFinite(expiresInSeconds) && expiresInSeconds > 0 && Math.floor(expiresInSeconds) === expiresInSeconds) {
            memoryTokenExpiry = Date.now() + Math.max(0, expiresInSeconds - 60) * 1000;
            mwStoreOp(store, 'set', TOKEN_EXPIRY_KEY, String(memoryTokenExpiry));
        } else {
            mwStoreOp(store, 'remove', TOKEN_EXPIRY_KEY);
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
            if (num < 0 || num > 255) return null;
            octets.push(num);
        }
        return octets;
    }

    function canonicalizeIpKey(rawIp) {
        if (rawIp === null || rawIp === undefined) return '';
        let norm = String(rawIp).trim().toLowerCase();
        if (!norm) return '';
        if (norm.includes(':')) {
            const z = norm.indexOf('%');
            if (z !== -1) norm = norm.slice(0, z);
            if (!norm) return '';
        }
        const v4 = parseIpv4Octets(norm);
        if (v4) return v4.join('.');
        if (!norm.includes(':')) return norm;
        const halves = norm.split('::');
        if (halves.length > 2) return norm;
        const hasComp = halves.length === 2, left = halves[0] ? halves[0].split(':') : [], right = hasComp && halves[1] ? halves[1].split(':') : [], tail = hasComp ? right : left;
        if (tail.length > 0 && tail[tail.length - 1].includes('.')) {
            const emb = parseIpv4Octets(tail[tail.length - 1]);
            if (!emb) return norm;
            tail.pop();
            tail.push(((emb[0] << 8) | emb[1]).toString(16), ((emb[2] << 8) | emb[3]).toString(16));
        }
        const total = left.length + right.length;
        if ((hasComp && total >= 8) || (!hasComp && total !== 8)) return norm;
        const expanded = [...left, ...(hasComp ? Array(8 - total).fill('0') : []), ...right];
        for (let i = 0; i < 8; i++) {
            if (!/^[0-9a-f]{1,4}$/.test(expanded[i])) return norm;
            expanded[i] = expanded[i].replace(/^0+/, '') || '0';
        }
        if (expanded.slice(0, 5).every((g) => g === '0') && expanded[5] === 'ffff') {
            const hi = parseInt(expanded[6], 16), lo = parseInt(expanded[7], 16);
            return `::ffff:${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
        }
        let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
        for (let i = 0; i < 8; i++) {
            if (expanded[i] === '0') { curStart = curStart === -1 ? i : curStart; curLen += 1; if (curLen > bestLen) { bestStart = curStart; bestLen = curLen; } }
            else { curStart = -1; curLen = 0; }
        }
        if (bestLen <= 1) return expanded.join(':');
        return bestLen === 8 ? '::' : expanded.slice(0, bestStart).join(':') + '::' + expanded.slice(bestStart + bestLen).join(':');
    }

    function tryConsumeAutoSwrBudget() {
        const now = Date.now(), hasStore = Boolean(mw && mw.storage && typeof mw.storage.get === 'function');
        const raw = hasStore ? mwStoreOp(mw.storage, 'get', AUTO_SWR_STORAGE_KEY) : null;
        let recent = memoryAutoSwrTimestamps;
        if (typeof raw === 'string' && raw) {
            try { recent = JSON.parse(raw); } catch (err) { warnPersistedCacheOnce('auto-refresh limiter parse failed', err); recent = []; }
        }
        recent = Array.isArray(recent) ? recent.filter((ts) => typeof ts === 'number' && isFinite(ts) && (now - ts) > -5000 && (now - ts) < AUTO_SWR_WINDOW_MS) : [];
        const persist = (list) => {
            memoryAutoSwrTimestamps = list.slice();
            if (mw && mw.storage && typeof mw.storage.set === 'function') mwStoreOp(mw.storage, 'set', AUTO_SWR_STORAGE_KEY, JSON.stringify(list));
        };
        if (recent.length >= AUTO_SWR_MAX_REQUESTS) { persist(recent); return false; }
        recent.push(now);
        persist(recent);
        return true;
    }

    function isRowQuotaGuarded(row) {
        return Boolean(row && typeof row === 'object' && (row.isQuotaGuarded || row.isQuotaGuard));
    }

    function hasDegradedQuotaOrCooldown(data) {
        return Boolean(data && Array.isArray(data.results) && data.results.some((r) => r && typeof r === 'object' &&
            (isRowQuotaGuarded(r) || (r.isCooldown && (!r.provider || Object.prototype.hasOwnProperty.call(COMMERCIAL_PROVIDERS, r.provider))))));
    }

    function getResultEntryTtlMs(entry) {
        if (entry && typeof entry.ttlMs === 'number' && isFinite(entry.ttlMs) && entry.ttlMs > 0) return Math.min(entry.ttlMs, RESULT_CACHE_TTL_MS);
        return entry && entry.data && hasDegradedQuotaOrCooldown(entry.data) ? DEGRADED_CACHE_TTL_MS : RESULT_CACHE_TTL_MS;
    }

    function isResultEntryValid(entry, now) {
        return Boolean(entry && typeof entry === 'object' && typeof entry.ts === 'number' && isFinite(entry.ts) &&
            (now - entry.ts < getResultEntryTtlMs(entry)) && entry.data && typeof entry.data === 'object');
    }

    function readPersistedResultStore() {
        if (!mw || !mw.storage || typeof mw.storage.get !== 'function') return null;
        const raw = mwStoreOp(mw.storage, 'get', RESULT_CACHE_STORAGE_KEY);
        if (typeof raw !== 'string' || !raw) { persistedCacheRaw = persistedCacheStore = null; return null; }
        if (raw === persistedCacheRaw && persistedCacheStore) return persistedCacheStore;
        try {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === 'object' && parsed.entries && typeof parsed.entries === 'object' && !Array.isArray(parsed.entries)) {
                persistedCacheRaw = raw;
                return (persistedCacheStore = parsed);
            }
        } catch (err) { warnPersistedCacheOnce('parse failed', err); }
        persistedCacheRaw = persistedCacheStore = null;
        mwStoreOp(mw.storage, 'remove', RESULT_CACHE_STORAGE_KEY);
        return null;
    }

    function writePersistedResultStore(store, protectedKey) {
        if (!mw || !mw.storage || typeof mw.storage.set !== 'function' || !store) return false;
        persistedCacheRaw = persistedCacheStore = null;
        const count = Object.keys(store.entries).length;
        const limits = count === 0 ? [0] : [count, Math.floor(RESULT_CACHE_MAX_ENTRIES / 2), 20, 1];
        const tried = Object.create(null);
        for (const limit of limits) {
            if (tried[limit]) continue;
            tried[limit] = true;
            const keys = Object.keys(store.entries);
            if (keys.length > limit) {
                const sortable = keys.map((key, order) => ({ key, ts: store.entries[key].ts, order, isProtected: Boolean(protectedKey && key === protectedKey) }))
                    .sort((a, b) => (a.isProtected !== b.isProtected ? (a.isProtected ? 1 : -1) : (a.ts !== b.ts ? a.ts - b.ts : a.order - b.order)));
                for (let i = 0; i < sortable.length - limit; i++) delete store.entries[sortable[i].key];
            }
            let serialized;
            try { serialized = JSON.stringify(store); } catch (err) { warnPersistedCacheOnce('serialization failed', err); return false; }
            const ok = mwStoreOp(mw.storage, 'set', RESULT_CACHE_STORAGE_KEY, serialized);
            if (ok !== false && ok !== null) { persistedCacheRaw = serialized; persistedCacheStore = store; return true; }
        }
        return false;
    }

    function normalizeQueryMode(mode) { return String(mode || 'light').trim().toLowerCase() === 'full' ? 'full' : 'light'; }
    function isPartialLightResult(data) { return Boolean(data && typeof data === 'object' && data.queryMode === 'light' && data.isPartialMode); }

    function getOrCreateIpState(key) {
        let entry = ipStateMap.get(key);
        if (!entry) ipStateMap.set(key, (entry = { lightPromise: null, fullPromise: null, inflightFull: null, inflightRefresh: null, data: null, fullTs: 0, fullTtlMs: 0 }));
        return entry;
    }

    function getIpData(key) { const entry = key ? ipStateMap.get(key) : null; return entry ? entry.data : null; }

    function isMemoryFullResultFresh(cacheKey, data) {
        if (!cacheKey || !data || typeof data !== 'object' || isPartialLightResult(data)) return false;
        const st = ipStateMap.get(cacheKey);
        return st && st.fullTs > 0 ? (Date.now() - st.fullTs) < st.fullTtlMs : !hasDegradedQuotaOrCooldown(data);
    }

    function recordIpResult(cacheKey, data, includeFullMeta, timestampMs) {
        if (!cacheKey || !data || typeof data !== 'object') return;
        const st = getOrCreateIpState(cacheKey);
        if (!(st.data && !isPartialLightResult(st.data) && isPartialLightResult(data))) st.data = data;
        if (includeFullMeta && !isPartialLightResult(data)) {
            st.fullTs = typeof timestampMs === 'number' && isFinite(timestampMs) ? timestampMs : Date.now();
            st.fullTtlMs = hasDegradedQuotaOrCooldown(data) ? DEGRADED_CACHE_TTL_MS : RESULT_CACHE_TTL_MS;
        }
    }

    function updatePersistedEntries(excludeKey, newEntryKey, newData) {
        if (!mw || !mw.storage || typeof mw.storage.set !== 'function') return;
        const store = readPersistedResultStore(), now = Date.now(), nextEntries = Object.create(null);
        if (newEntryKey && store && store.entries) {
            const cur = store.entries[newEntryKey];
            if (isPartialLightResult(newData) && isResultEntryValid(cur, now) && !isPartialLightResult(cur.data)) return;
        }
        if (store && store.entries) {
            for (const [k, v] of Object.entries(store.entries)) {
                if (k !== excludeKey && k !== newEntryKey && isResultEntryValid(v, now)) nextEntries[k] = v;
            }
        }
        if (newEntryKey && newData) {
            nextEntries[newEntryKey] = {
                ts: now, ttlMs: hasDegradedQuotaOrCooldown(newData) ? DEGRADED_CACHE_TTL_MS : RESULT_CACHE_TTL_MS, data: newData
            };
        }
        writePersistedResultStore({ entries: nextEntries }, newEntryKey || null);
    }

    function readPersistedIpResultEntry(cacheKey) {
        if (!cacheKey || typeof cacheKey !== 'string') return null;
        const store = readPersistedResultStore();
        if (!store || !Object.prototype.hasOwnProperty.call(store.entries, cacheKey)) return null;
        const entry = store.entries[cacheKey];
        if (!isResultEntryValid(entry, Date.now())) { updatePersistedEntries(cacheKey); return null; }
        return entry;
    }

    function invalidateIpResultCache(ip) {
        const cacheKey = canonicalizeIpKey(ip), rawLower = typeof ip === 'string' ? ip.trim().toLowerCase() : '';
        [cacheKey, rawLower].filter((k, i, arr) => k && arr.indexOf(k) === i).forEach((key) => {
            ipStateMap.delete(key);
            const store = readPersistedResultStore();
            if (store && Object.prototype.hasOwnProperty.call(store.entries, key)) updatePersistedEntries(key);
        });
    }

    function writePersistedIpResult(cacheKey, data) {
        if (cacheKey && typeof cacheKey === 'string' && data && typeof data === 'object') updatePersistedEntries(null, cacheKey, data);
    }

    function ensureConsent(forcePrompt) {
        if (accessBlocked) return Promise.resolve(false);
        if (consentGranted || mwStoreOp(mw.storage, 'get', CONSENT_KEY) === '1') {
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
            return OO.ui.confirm($msg, { title: 'Proxycheck on Temporary Account IP', size: 'medium' });
        }).then((agreed) => {
            consentPromise = null;
            if (agreed) {
                consentGranted = true;
                consentDeclined = false;
                mwStoreOp(mw.storage, 'set', CONSENT_KEY, '1');
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

    function readTokenExchangeCooldownUntil() {
        const now = Date.now();
        const maxAllowedUntil = now + (TOKEN_COOLDOWN_MAX_SECONDS * (1 + TOKEN_COOLDOWN_JITTER_RATIO) + 5) * 1000;
        let until = memoryTokenCooldownUntil;
        if (until > maxAllowedUntil) memoryTokenCooldownUntil = until = 0;
        if (mw && mw.storage && typeof mw.storage.get === 'function') {
            const raw = mwStoreOp(mw.storage, 'get', TOKEN_COOLDOWN_UNTIL_KEY);
            if (typeof raw === 'string' && raw.trim() !== '') {
                const parsed = Number(raw);
                if (!isFinite(parsed) || parsed <= now || parsed > maxAllowedUntil) {
                    mwStoreOp(mw.storage, 'remove', TOKEN_COOLDOWN_UNTIL_KEY);
                } else if (parsed > until) {
                    until = parsed;
                }
            }
        }
        if (until <= now) {
            memoryTokenCooldownUntil = 0;
            return 0;
        }
        memoryTokenCooldownUntil = until;
        return until;
    }

    function setTokenExchangeCooldown(retryAfterSeconds) {
        const rawSec = typeof retryAfterSeconds === 'number' && isFinite(retryAfterSeconds)
            ? retryAfterSeconds : TOKEN_COOLDOWN_DEFAULT_SECONDS;
        const clampedSec = Math.min(TOKEN_COOLDOWN_MAX_SECONDS, Math.max(TOKEN_COOLDOWN_MIN_SECONDS, rawSec));
        const jitterMs = Math.round(clampedSec * Math.random() * TOKEN_COOLDOWN_JITTER_RATIO * 1000);
        const until = Date.now() + clampedSec * 1000 + jitterMs;
        memoryTokenCooldownUntil = Math.max(memoryTokenCooldownUntil, until);
        if (mw && mw.storage && typeof mw.storage.set === 'function') {
            mwStoreOp(mw.storage, 'set', TOKEN_COOLDOWN_UNTIL_KEY, String(memoryTokenCooldownUntil));
        }
    }

    function waitForVisibleBeforeTokenExchange() {
        if (accessBlocked) return Promise.resolve(false);
        if (isDocumentVisible()) return Promise.resolve(true);
        if (typeof document === 'undefined' || typeof document.addEventListener !== 'function') return Promise.resolve(true);
        return new Promise((resolve) => {
            clearTokenExchangeVisibilityWait();
            tokenExchangeVisibilityResolve = resolve;
            tokenExchangeVisibilityHandler = () => {
                if (accessBlocked) { clearTokenExchangeVisibilityWait(); return; }
                if (!isDocumentVisible()) return;
                const finish = tokenExchangeVisibilityResolve;
                tokenExchangeVisibilityResolve = null;
                if (typeof document.removeEventListener === 'function') {
                    document.removeEventListener('visibilitychange', tokenExchangeVisibilityHandler);
                }
                tokenExchangeVisibilityHandler = null;
                if (finish) finish(true);
            };
            document.addEventListener('visibilitychange', tokenExchangeVisibilityHandler);
        });
    }

    function executeGadgetTokenExchange() {
        if (accessBlocked || readTokenExchangeCooldownUntil() > 0) return Promise.resolve(null);
        clearStoredToken();
        const wikiDomain = mw.config.get('wgServerName');
        return Promise.resolve(mw.loader.using('mediawiki.api')).then(() => {
            if (accessBlocked || readTokenExchangeCooldownUntil() > 0) return null;
            return new mw.Api().get({ action: 'centralauthtoken' }).then((d) => d, (code, details) => { warn('centralauthtoken request failed:', { code, details }); return null; });
        }).then((apiData) => {
            const cat = !accessBlocked && apiData && apiData.centralauthtoken && apiData.centralauthtoken.centralauthtoken;
            if (!cat || typeof cat !== 'string') { if (apiData && !accessBlocked) warn('Missing centralauthtoken:', apiData); return null; }
            return fetch(TOOL_BASE_URL + '/api/v1/auth/gadget-token', {
                method: 'POST', mode: 'cors', credentials: 'omit', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ centralauthtoken: cat, domain: wikiDomain })
            }).then((res) => {
                if (!res.ok) {
                    const readErrorText = typeof res.text === 'function'
                        ? res.text()
                        : (typeof res.json === 'function' ? res.json().then((obj) => JSON.stringify(obj)) : Promise.resolve(''));
                    if (res.status === 429) {
                        const headerRetry = res.headers && typeof res.headers.get === 'function' ? res.headers.get('Retry-After') : null;
                        return readErrorText.then((txt) => {
                            let bodyRetry = null;
                            if (txt) {
                                try {
                                    const parsed = JSON.parse(txt);
                                    if (parsed && typeof parsed.retryAfterSeconds === 'number' && isFinite(parsed.retryAfterSeconds)) {
                                        bodyRetry = parsed.retryAfterSeconds;
                                    }
                                } catch (_) {
                                    // Fall back to header or default cooldown when the 429 body is not JSON.
                                }
                            }
                            const parsedHeader = headerRetry !== null ? parseInt(headerRetry, 10) : NaN;
                            const resolvedRetry = bodyRetry !== null
                                ? bodyRetry
                                : (isFinite(parsedHeader) ? parsedHeader : TOKEN_COOLDOWN_DEFAULT_SECONDS);
                            setTokenExchangeCooldown(resolvedRetry);
                            warn('Gadget token HTTP 429:', txt);
                            return null;
                        });
                    }
                    return readErrorText.then((txt) => {
                        warn(`Gadget token HTTP ${res.status}:`, txt);
                        if (res.status === 403) { clearStoredToken(); blockAccess(); } else if (res.status === 401) clearStoredToken();
                        return null;
                    });
                }
                return res.json().then((payload) => {
                    const tok = payload && payload.token;
                    if (!tok || typeof tok !== 'string') { warn('Token missing in response:', payload); return null; }
                    storeToken(tok, payload.expires_in);
                    return tok;
                });
            });
        }).catch((err) => { warn('CentralAuth token exchange failed:', err); return null; });
    }

    function performGadgetTokenExchange(failedToken) {
        if (accessBlocked) return Promise.resolve(null);
        if (!isDocumentVisible()) {
            return waitForVisibleBeforeTokenExchange().then((canProceed) => {
                if (!canProceed || accessBlocked) return null;
                const latest = readStoredToken();
                if (latest && (!failedToken || latest !== failedToken)) return latest;
                return executeGadgetTokenExchange();
            });
        }
        return executeGadgetTokenExchange();
    }

    function refreshGadgetToken(failedToken) {
        if (accessBlocked) return Promise.resolve(null);
        if (authPromise) return authPromise;
        const latest = readStoredToken();
        if (latest && (!failedToken || latest !== failedToken)) return Promise.resolve(latest);
        const tracked = performGadgetTokenExchange(failedToken).then(
            (tok) => { if (authPromise === tracked) authPromise = null; return tok; },
            (err) => { if (authPromise === tracked) authPromise = null; throw err; }
        );
        return (authPromise = tracked);
    }

    function ensureGadgetToken() {
        if (accessBlocked) return Promise.resolve(null);
        const stored = readStoredToken();
        return stored ? Promise.resolve(stored) : refreshGadgetToken(null);
    }

    function apiFetchWithAuth(path, opts, token, hasRetried) {
        const headers = Object.assign({ Authorization: 'Bearer ' + token }, opts.headers || {});
        return fetch(TOOL_BASE_URL + path, Object.assign({ mode: 'cors', credentials: 'omit' }, opts, { headers })).then((res) => {
            if (res.status !== 401 && res.status !== 403) return res;
            if (res.status === 403 || hasRetried) { clearStoredToken(); blockAccess(); return null; }
            return refreshGadgetToken(token).then((fresh) => (!fresh || accessBlocked) ? null : apiFetchWithAuth(path, opts, fresh, true));
        });
    }

    function getCurrentWikiDbname() {
        const raw = mw && mw.config && typeof mw.config.get === 'function' ? mw.config.get('wgDBname') : '';
        return typeof raw === 'string' && raw.trim() ? raw.trim().toLowerCase() : '';
    }

    function fetchDetectWithToken(ip, token, hasRetried, mode) {
        if (!isValidIp(ip)) return Promise.resolve(null);
        const wikiDb = getCurrentWikiDbname();
        const wikiParam = wikiDb ? `&wiki=${encodeURIComponent(wikiDb)}` : '';
        return apiFetchWithAuth(`/api/v1/detect?ip=${encodeURIComponent(ip)}&compact=1&mode=${encodeURIComponent(normalizeQueryMode(mode))}${wikiParam}`,
            { method: 'GET' }, token, hasRetried).then((res) => (!res ? null : (!res.ok ? (warn(`Detection API HTTP ${res.status} for ${ip}`), null) : res.json())));
    }

    function fetchRefreshDetectWithToken(ip, token, hasRetried, mode) {
        if (!isValidIp(ip)) return Promise.resolve({ ok: false, status: 0, rateLimited: false, data: null });
        const wikiDb = getCurrentWikiDbname();
        const bodyPayload = { ip, mode: normalizeQueryMode(mode || 'full'), compact: true };
        if (wikiDb) bodyPayload.wiki = wikiDb;
        return apiFetchWithAuth('/api/v1/detect/refresh', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bodyPayload)
        }, token, hasRetried).then((res) => {
            if (!res) return { ok: false, status: 401, rateLimited: false, data: null };
            if (res.status === 429) return res.json().catch(() => ({})).then((b) => ({
                ok: false, status: 429, rateLimited: true,
                retryAfterSeconds: b && typeof b.retryAfterSeconds === 'number' ? b.retryAfterSeconds : null,
                message: b && typeof b.message === 'string' ? b.message : '', data: null
            }));
            if (!res.ok) { warn(`Refresh API HTTP ${res.status} for ${ip}`); return { ok: false, status: res.status, rateLimited: false, data: null }; }
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
        if (accessBlocked) { clearRequestQueue(); return resolve(null); }
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
        return enqueueNetworkTask(() => (accessBlocked ? null : ensureGadgetToken().then((token) => (!token || accessBlocked) ? null : fn(token))));
    }

    function enqueueSingleIpDetection(ip, mode) {
        const resolvedMode = normalizeQueryMode(mode);
        return runWithToken((token) => fetchDetectWithToken(ip, token, false, resolvedMode));
    }

    function fetchBatchDetectWithToken(ips, token, hasRetried) {
        const validIps = Array.isArray(ips) ? ips.filter(isValidIp) : [];
        if (validIps.length === 0) return Promise.resolve(null);
        const wikiDb = getCurrentWikiDbname();
        const bodyPayload = { ips: validIps, mode: 'light' };
        if (wikiDb) bodyPayload.wiki = wikiDb;
        return apiFetchWithAuth('/api/v1/detect/batch?compact=1', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bodyPayload)
        }, token, hasRetried).then((res) => {
            if (!res) return null;
            if (res.status === 404 || res.status === 405) { batchEndpointSupported = false; return { fallbackSingle: true }; }
            if (!res.ok) { warn(`Batch API HTTP ${res.status}`); return null; }
            return res.json();
        });
    }

    function extractIpResultFromBatch(batchPayload, rawIp) {
        const results = batchPayload && typeof batchPayload === 'object' ? batchPayload.results : null;
        if (!results || typeof results !== 'object') return null;
        const trimmed = String(rawIp || '').trim(), lower = trimmed.toLowerCase(), canonical = canonicalizeIpKey(trimmed);
        for (const k of [trimmed, lower, canonical]) {
            if (k && Object.prototype.hasOwnProperty.call(results, k) && results[k]) return results[k];
        }
        const inputMap = batchPayload.inputMap;
        if (inputMap && typeof inputMap === 'object') {
            const mapped = inputMap[rawIp] || inputMap[trimmed] || inputMap[lower] || (canonical ? inputMap[canonical] : '');
            if (mapped && Object.prototype.hasOwnProperty.call(results, mapped) && results[mapped]) return results[mapped];
        }
        for (const [k, entry] of Object.entries(results)) {
            if ((canonical && canonicalizeIpKey(k) === canonical) || (entry && typeof entry.ip === 'string' && canonical && canonicalizeIpKey(entry.ip) === canonical)) return entry;
        }
        return null;
    }

    function settleInflight(st, field, promise, aliasIp) {
        if (st[field] === promise) st[field] = null;
        const alias = typeof aliasIp === 'string' ? canonicalizeIpKey(aliasIp) : '';
        const aliasSt = alias ? ipStateMap.get(alias) : null;
        if (aliasSt && aliasSt[field] === promise) aliasSt[field] = null;
        return alias;
    }

    function dispatchBatchItems(batchItems) {
        if (!batchItems || batchItems.length === 0) return;
        if (accessBlocked) { batchItems.forEach((i) => i.resolve(null)); return; }
        if (!batchEndpointSupported) { batchItems.forEach((item) => enqueueSingleIpDetection(item.ip, 'light').then(item.resolve, item.reject)); return; }
        const uniqueIps = [], seen = Object.create(null);
        for (const item of batchItems) {
            const key = canonicalizeIpKey(item.ip) || item.ip.toLowerCase();
            if (!seen[key]) { seen[key] = true; uniqueIps.push(item.ip); }
        }
        runWithToken((token) => batchEndpointSupported ? fetchBatchDetectWithToken(uniqueIps, token, false) : { fallbackSingle: true })
            .then((batchPayload) => {
                if (batchPayload && batchPayload.fallbackSingle) {
                    batchDebounceTimer = clearTimer(batchDebounceTimer, false);
                    batchItems.concat(pendingBatchQueue.splice(0, pendingBatchQueue.length))
                        .forEach((item) => enqueueSingleIpDetection(item.ip, 'light').then(item.resolve, item.reject));
                    return;
                }
                batchItems.forEach((item) => item.resolve(extractIpResultFromBatch(batchPayload, item.ip)));
            }, (err) => batchItems.forEach((item) => item.reject(err)));
    }

    function flushPendingBatch() {
        batchDebounceTimer = clearTimer(batchDebounceTimer, false);
        if (accessBlocked) { clearRequestQueue(); return; }
        while (pendingBatchQueue.length > 0) dispatchBatchItems(pendingBatchQueue.splice(0, MAX_BATCH_IPS));
    }

    function enqueueBatchIpDetection(ip) {
        if (accessBlocked) return Promise.resolve(null);
        if (!batchEndpointSupported) return enqueueSingleIpDetection(ip, 'light');
        return new Promise((resolve, reject) => {
            pendingBatchQueue.push({ ip, resolve, reject });
            if (pendingBatchQueue.length >= MAX_BATCH_IPS) flushPendingBatch();
            else if (batchDebounceTimer === null) {
                batchDebounceTimer = window.setTimeout(() => { batchDebounceTimer = null; flushPendingBatch(); }, BATCH_DEBOUNCE_MS);
            }
        });
    }

    function syncResolvedIpAliases(cacheKey, data, promise, includeFullCache, recordedTs) {
        const resolvedTs = typeof recordedTs === 'number' && isFinite(recordedTs) ? recordedTs : Date.now();
        const writeAlias = (k) => {
            const st = getOrCreateIpState(k);
            recordIpResult(k, data, includeFullCache, resolvedTs);
            if (!st.lightPromise || includeFullCache) st.lightPromise = promise;
            if (includeFullCache && !st.fullPromise) st.fullPromise = promise;
            writePersistedIpResult(k, data);
        };
        writeAlias(cacheKey);
        if (typeof data.ip !== 'string') return;
        const resolvedKey = canonicalizeIpKey(data.ip);
        if (resolvedKey && resolvedKey !== cacheKey) writeAlias(resolvedKey);
    }

    function executeIpRefresh(ip) {
        const failOutcome = (extra) => Object.assign({ ok: false, rateLimited: false, retryAfterSeconds: null, degradedFallback: false, data: null }, extra);
        if (accessBlocked || !isValidIp(ip)) return Promise.resolve(failOutcome());
        const cacheKey = canonicalizeIpKey(ip);
        if (!cacheKey) return Promise.resolve(failOutcome());
        const st = getOrCreateIpState(cacheKey);
        if (st.inflightRefresh) return st.inflightRefresh;

        const refreshPromise = runWithToken((token) => fetchRefreshDetectWithToken(ip, token, false, 'full'))
            .then((res) => {
                const aliasKey = settleInflight(st, 'inflightRefresh', refreshPromise, res && res.data && res.data.ip);
                autoSwrAttemptedKeys.add(cacheKey);
                if (aliasKey) autoSwrAttemptedKeys.add(aliasKey);
                if (!res || !res.ok || !res.data || typeof res.data !== 'object') {
                    return failOutcome({ rateLimited: Boolean(res && res.rateLimited), retryAfterSeconds: res && typeof res.retryAfterSeconds === 'number' ? res.retryAfterSeconds : null });
                }
                const meta = res.data.cacheMeta && typeof res.data.cacheMeta === 'object' ? res.data.cacheMeta : null;
                if (meta && meta.degradedRefreshFallback === true) {
                    const persisted = readPersistedIpResultEntry(cacheKey);
                    const existingCached = st.data || (persisted && persisted.data);
                    if (!existingCached) {
                        st.fullPromise = st.lightPromise = Promise.resolve(res.data);
                        syncResolvedIpAliases(cacheKey, res.data, st.fullPromise, true, Date.now());
                    }
                    return failOutcome({ degradedFallback: true, data: existingCached || res.data });
                }
                const freshPromise = Promise.resolve(res.data);
                st.fullPromise = st.lightPromise = freshPromise;
                syncResolvedIpAliases(cacheKey, res.data, freshPromise, true, Date.now());
                refreshRenderedBadgesForIp(res.data.ip || ip, res.data);
                return { ok: true, rateLimited: false, retryAfterSeconds: null, degradedFallback: false, data: res.data };
            }).catch((err) => {
                settleInflight(st, 'inflightRefresh', refreshPromise);
                autoSwrAttemptedKeys.add(cacheKey);
                warn(`Refresh failed for ${ip}:`, err);
                return failOutcome();
            });
        return (st.inflightRefresh = refreshPromise);
    }

    function fetchIpIntelligence(ip, mode, options) {
        if (accessBlocked || !isValidIp(ip)) return Promise.resolve(null);
        const cacheKey = canonicalizeIpKey(ip);
        if (!cacheKey) return Promise.resolve(null);
        const st = getOrCreateIpState(cacheKey), resolvedMode = normalizeQueryMode(mode);
        if (resolvedMode === 'full' && options && options.forceRefresh) return executeIpRefresh(ip).then((o) => (o && o.ok ? o.data : null));
        if (st.inflightFull) return st.inflightFull;
        if (st.fullPromise && st.data && st.fullTs > 0 && !isMemoryFullResultFresh(cacheKey, st.data)) {
            if (st.lightPromise === st.fullPromise) st.lightPromise = null;
            st.fullPromise = null; st.fullTs = st.fullTtlMs = 0;
        }
        if (st.fullPromise) return st.fullPromise;

        if (resolvedMode === 'full') {
            if (st.data && !isPartialLightResult(st.data) && isMemoryFullResultFresh(cacheKey, st.data)) return (st.fullPromise = Promise.resolve(st.data));
            const persisted = readPersistedIpResultEntry(cacheKey);
            if (persisted && persisted.data && !isPartialLightResult(persisted.data)) {
                recordIpResult(cacheKey, persisted.data, true, persisted.ts);
                return (st.fullPromise = st.lightPromise = Promise.resolve(persisted.data));
            }
            const fullPromise = enqueueSingleIpDetection(ip, 'full').then((data) => {
                settleInflight(st, 'inflightFull', fullPromise, data && data.ip);
                if (!data || typeof data !== 'object') return null;
                st.fullPromise = st.lightPromise = fullPromise;
                syncResolvedIpAliases(cacheKey, data, fullPromise, true, Date.now());
                return data;
            }).catch((err) => { settleInflight(st, 'inflightFull', fullPromise); warn(`Full detection failed for ${ip}:`, err); return null; });
            return (st.inflightFull = fullPromise);
        }

        if (st.lightPromise) return st.lightPromise;
        const persisted = readPersistedIpResultEntry(cacheKey);
        if (persisted && persisted.data) {
            const isFull = !isPartialLightResult(persisted.data);
            recordIpResult(cacheKey, persisted.data, isFull, persisted.ts);
            const p = Promise.resolve(persisted.data);
            st.lightPromise = p;
            if (isFull) st.fullPromise = p;
            return p;
        }
        const promise = enqueueBatchIpDetection(ip).then((data) => {
            if (!data || typeof data !== 'object') { if (st.lightPromise === promise) st.lightPromise = null; return null; }
            const isFullReady = !isPartialLightResult(data);
            if (isFullReady && !st.fullPromise) st.fullPromise = promise;
            syncResolvedIpAliases(cacheKey, data, promise, isFullReady, Date.now());
            return data;
        }).catch((err) => { warn(`Detection failed for ${ip}:`, err); if (st.lightPromise === promise) st.lightPromise = null; return null; });
        return (st.lightPromise = promise);
    }

    function extractNonEmptyStrings(list) {
        if (!Array.isArray(list)) return [];
        return list.map((item) => (typeof item === 'string' ? item.trim() : '')).filter(Boolean);
    }

    function collectNumericPorts(target, list) {
        if (!Array.isArray(list)) return;
        for (const item of list) {
            const n = Number(item);
            if (isFinite(n) && n > 0 && target.indexOf(n) === -1) target.push(n);
        }
    }

    function isValidProviderRow(row) {
        return Boolean(row && typeof row === 'object' && !row.isCooldown && !isRowQuotaGuarded(row) &&
            (row.status === '200 OK' || row.statusCode === 200));
    }

    function formatOfflineDbDateShort(iso) {
        if (typeof iso !== 'string' || !iso.trim()) return '';
        const ms = Date.parse(iso.trim());
        return isNaN(ms) ? iso.trim() : new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    }

    function analyzeProviderSignals(data) {
        if (data && typeof data === 'object' && signalCache && signalCache.has(data)) return signalCache.get(data);
        const rows = Array.isArray(data && data.results) ? data.results : [];
        const maxmindRows = [], ip2locRows = [], otherRows = [];
        const openProxyPorts = [], shodanOpenPorts = [], dbBaselines = [], dbUpdatedAtMap = {};
        const rowRiskItems = [], lightProviderLabels = [];
        const addLightLbl = (lbl) => { const c = typeof lbl === 'string' ? lbl.trim() : ''; if (c && lightProviderLabels.indexOf(c) === -1) lightProviderLabels.push(c); };
        if (data) collectNumericPorts(openProxyPorts, data.openProxyPorts);

        let getipintelRow = null, stopforumspamRow = null, sfsTitleLine = '', dropRow = null, shodanOpenPortRow = null;
        let hasQuotaGuardedProvider = false, hasCooldownProvider = false;
        let validCommercialCount = 0, positiveCommercialVotes = 0, validTotalSourceCount = 0;
        let hasSpamhausNonPbl = false, hasSpamhausPolicy = false, hasDshieldSignal = false;
        let hasSpamcopSignal = false, hasIpsumDropSignal = false;
        let hasOpenAsnVpn = false, hasOpenAsnHosting = false, openAsnSharedProvider = '', openAsnSharedCategory = '';
        let hasMaxmindHosting = false, hasMaxmindRiskFlag = false, hasShodanOpenPortsSignal = false;
        let hasOtherNonCommercialRiskFlag = false, hasLightCommercialRiskFlag = false;

        for (const r of rows) {
            if (!r || typeof r !== 'object') continue;
            if (r.provider === 'GetIPIntel') getipintelRow = r;
            else if (r.provider === 'StopForumSpam') {
                stopforumspamRow = r;
                if (r.status === '200 OK') {
                    if (r.blacklisted) sfsTitleLine = 'StopForumSpam: Blacklisted Toxic CIDR' + (r.toxicCidr ? ` (${r.toxicCidr})` : '');
                    else if (r.appears) sfsTitleLine = `StopForumSpam: Reported (${r.frequency || 0}x)`;
                }
            }
            if (r.provider === 'Shodan InternetDB') collectNumericPorts(openProxyPorts, r.openProxyPorts);
            if (r.provider && typeof r.offlineDbUpdatedAt === 'string' && r.offlineDbUpdatedAt.trim()) {
                const iso = r.offlineDbUpdatedAt.trim(), d = formatOfflineDbDateShort(iso);
                dbUpdatedAtMap[r.provider] = iso;
                if (d) dbBaselines.push(`${r.provider} ${d}`);
            }
            if (isRowQuotaGuarded(r)) hasQuotaGuardedProvider = true;
            else if (r.isCooldown) hasCooldownProvider = true;
            if (!isValidProviderRow(r)) continue;

            if (r.provider === 'MaxMind') maxmindRows.push(r);
            else if (r.provider === 'IP2Location') ip2locRows.push(r);
            else otherRows.push(r);

            validTotalSourceCount += 1;
            const provider = r.provider || 'Provider';
            const highRiskFlags = Array.isArray(r.securityFlags)
                ? r.securityFlags.filter((f) => f && f.isHighRisk && typeof f.label === 'string' && f.label.trim()).map((f) => f.label.trim())
                : [];
            const hasHighRiskFlag = highRiskFlags.length > 0;
            if (r.provider !== 'GetIPIntel') {
                highRiskFlags.forEach((lbl) => {
                    rowRiskItems.push([lbl.toLowerCase() === 'tor exit node' ? 'Tor Exit' : lbl, provider]);
                    addLightLbl(`${provider}:${lbl}`);
                });
            }

            if (Object.prototype.hasOwnProperty.call(COMMERCIAL_PROVIDERS, r.provider)) {
                validCommercialCount += 1;
                if (hasHighRiskFlag || (typeof r.usageType === 'string' && /datacenter|data center|hosting|cloud|transit|cdn/i.test(r.usageType))) positiveCommercialVotes += 1;
                if (r.provider !== 'GetIPIntel' && hasHighRiskFlag) hasLightCommercialRiskFlag = true;
                continue;
            }
            if (r.provider === 'StopForumSpam') {
                if (r.blacklisted || r.appears) addLightLbl(r.blacklisted ? 'StopForumSpam:Blacklisted' : 'StopForumSpam:Listed');
            } else if (r.provider === 'Spamhaus ZEN') {
                const codes = extractNonEmptyStrings(r.listedCodes), isListed = Boolean(r.isListed || codes.length > 0);
                const isNonPbl = isListed && (codes.length > 0 ? codes.some((c) => c !== '127.0.0.10' && c !== '127.0.0.11') : (!r.isPolicyRange || hasHighRiskFlag));
                if (isListed || r.isPolicyRange) addLightLbl('Spamhaus:Listed');
                if (isNonPbl) hasSpamhausNonPbl = true;
                else if (isListed || r.isPolicyRange) hasSpamhausPolicy = true;
            } else if (r.provider === 'DShield') {
                if ((Number(r.attacks) || 0) > 0 || (Number(r.count) || 0) > 0 || extractNonEmptyStrings(r.threatfeeds).length > 0 || hasHighRiskFlag) {
                    hasDshieldSignal = true;
                    if (!hasHighRiskFlag) {
                        const attacks = Number(r.attacks) || 0;
                        rowRiskItems.push(['Malicious Activity', provider]);
                        addLightLbl(attacks > 0 ? `DShield:Attack Activity (${attacks} attacks)` : 'DShield:Threat Feed');
                    }
                }
            } else if (r.provider === 'SpamCop') {
                if (r.isListed || extractNonEmptyStrings(r.listedCodes).length > 0 || hasHighRiskFlag) {
                    hasSpamcopSignal = true;
                    if (!hasHighRiskFlag) { rowRiskItems.push(['SpamCop Listed', provider]); addLightLbl('SpamCop:Listed'); }
                }
            } else if (r.provider === 'IPsum / DROP') {
                const ipsumScore = Number(r.ipsumScore) || 0;
                if (r.inSpamhausDrop) { dropRow = r; addLightLbl('IPsum:DROP'); }
                else if (r.isIpsumListed || r.isListed || ipsumScore >= 2) addLightLbl(ipsumScore > 0 ? `IPsum:${ipsumScore} lists` : 'IPsum:Listed');
                if (r.inSpamhausDrop || r.isIpsumListed || r.isListed || ipsumScore >= 2 || hasHighRiskFlag) hasIpsumDropSignal = true;
                if (!hasHighRiskFlag && !r.inSpamhausDrop && (r.isIpsumListed || ipsumScore === 2)) rowRiskItems.push([`IPsum Moderate (${ipsumScore || 2} lists)`, provider]);
            } else if (r.provider === 'OpenASN') {
                const verdict = typeof r.coreVerdict === 'string' ? r.coreVerdict.trim().toLowerCase() : '';
                const isCdn = Boolean(r.isCdn), isDc = Boolean(r.isDatacenter);
                const fallbackName = (fallback) => [r.sharedProvider, r.organisation, r.isp].map((v) => (typeof v === 'string' ? v.trim() : '')).find((v) => v && v !== '-') || fallback;
                if (verdict === 'vpn') {
                    hasOpenAsnVpn = true; addLightLbl('OpenASN:VPN');
                    if (!hasHighRiskFlag) rowRiskItems.push(['VPN', provider]);
                } else if (verdict === 'enterprise_gateway' || r.isEnterpriseGateway) {
                    if (!openAsnSharedProvider) { openAsnSharedProvider = fallbackName('Enterprise Gateway'); openAsnSharedCategory = 'enterprise_gateway'; }
                } else if (verdict === 'hosting' && isCdn && !isDc) {
                    if (!openAsnSharedProvider) { openAsnSharedProvider = fallbackName('CDN'); openAsnSharedCategory = 'cdn'; }
                } else if (verdict === 'hosting') {
                    hasOpenAsnHosting = true; addLightLbl('OpenASN:Hosting');
                    if (!hasHighRiskFlag) rowRiskItems.push(['Hosting / Datacentre', provider]);
                }
                if (hasHighRiskFlag && verdict !== 'vpn') hasOtherNonCommercialRiskFlag = true;
            } else if (r.provider === 'MaxMind') {
                const usage = typeof r.usageType === 'string' ? r.usageType.trim().toLowerCase() : '';
                const sharedHosting = Boolean(typeof r.sharedProvider === 'string' && r.sharedProvider.trim() && (r.sharedCategory === 'cloud' || r.sharedCategory === 'vpn'));
                const isHosting = Boolean((typeof r.hostingProvider === 'string' && r.hostingProvider.trim()) || sharedHosting ||
                    (typeof r.cloudProvider === 'string' && r.cloudProvider.trim()) || usage === 'hosting' || usage === 'datacenter' || usage === 'data center');
                if (isHosting) { hasMaxmindHosting = true; if (!hasHighRiskFlag) { rowRiskItems.push(['Hosting', provider]); addLightLbl('MaxMind:Hosting'); } }
                if (hasHighRiskFlag) hasMaxmindRiskFlag = true;
            } else if (r.provider === 'Shodan InternetDB') {
                collectNumericPorts(shodanOpenPorts, r.ports);
                if ((Array.isArray(r.ports) && r.ports.length > 0) || (Array.isArray(r.securityFlags) && r.securityFlags.some((f) => f && f.label === 'Open Ports'))) {
                    hasShodanOpenPortsSignal = true; shodanOpenPortRow = r;
                }
                if (hasHighRiskFlag) hasOtherNonCommercialRiskFlag = true;
            } else if (hasHighRiskFlag) {
                hasOtherNonCommercialRiskFlag = true;
            }
        }

        const sig = {
            orderedRows: maxmindRows.concat(ip2locRows, otherRows),
            rowRiskItems, lightProviderLabels, shodanOpenPortRow,
            openProxyPorts, shodanOpenPorts, dbBaselines, dbUpdatedAtMap, sfsTitleLine, dropRow,
            getipintelRow, stopforumspamRow, hasQuotaGuardedProvider, hasCooldownProvider,
            validCommercialCount, positiveCommercialVotes, validTotalSourceCount,
            hasSpamhausNonPbl, hasSpamhausPolicy, hasDshieldSignal, hasSpamcopSignal,
            hasIpsumDropSignal, hasOpenAsnVpn, hasOpenAsnHosting, openAsnSharedProvider, openAsnSharedCategory, hasMaxmindHosting, hasMaxmindRiskFlag,
            hasShodanOpenPortsSignal, hasOtherNonCommercialRiskFlag, hasLightCommercialRiskFlag
        };
        if (data && typeof data === 'object' && signalCache) signalCache.set(data, sig);
        return sig;
    }

    function evaluateRisk(data) {
        const sig = analyzeProviderSignals(data);
        const isNonPublic = Boolean(data.isNonPublic);
        const nonPublicCategory = typeof data.nonPublicCategory === 'string' ? data.nonPublicCategory.trim().toLowerCase() : '';
        const nonPublicReason = typeof data.nonPublicReason === 'string' && data.nonPublicReason.trim() ? data.nonPublicReason.trim() : 'Non-Public / Reserved IP';
        const nonPublicBadgeCode = (nonPublicCategory === 'private' || nonPublicCategory === 'loopback' || nonPublicCategory === 'link_local') ? 'LOCAL' : 'RESERVED';
        const prediction = Number(data.prediction_score) || 0;
        const hasPrediction = data.getipintel_chance !== null && data.getipintel_chance !== undefined && !isNaN(Number(data.getipintel_chance));
        const broadcastIp = Boolean(data.is_broadcast_ip), isTor = Boolean(data.isTor), isMajorityProxyVpn = Boolean(data.isMajorityProxyVpn);
        const arbitrationTier = typeof data.arbitrationTier === 'string' ? data.arbitrationTier.trim().toLowerCase() : '';
        const ptrIsHighRisk = Boolean(data.ptrIsHighRisk);
        const arbitrationVerdict = typeof data.arbitrationVerdict === 'string' ? data.arbitrationVerdict.trim() : '';
        const torLabel = typeof data.torLabel === 'string' && data.torLabel.trim() ? data.torLabel.trim() : (isTor ? 'Tor Node' : '');
        const torSummary = typeof data.torSummary === 'string' && data.torSummary.trim() ? data.torSummary.trim() : '';
        const torFlags = extractNonEmptyStrings(data.torFlags);

        const sfsRow = sig.stopforumspamRow;
        const isSfsBlacklisted = Boolean(sfsRow && (sfsRow.blacklisted || sfsRow.toxicCidr));
        const isSfsListed = Boolean(sfsRow && (sfsRow.appears || (sfsRow.frequency && Number(sfsRow.frequency) > 0) ||
            (Array.isArray(sfsRow.securityFlags) && sfsRow.securityFlags.some((f) => f && f.isHighRisk))));
        const suspectedResidentialProxy = Boolean(data.suspectedResidentialProxy), highlySuspectedResidentialProxy = Boolean(data.highlySuspectedResidentialProxy);
        const sharedPrivacyEgress = typeof data.sharedPrivacyEgress === 'string' && data.sharedPrivacyEgress.trim() ? data.sharedPrivacyEgress.trim().toLowerCase() : '';
        const sharedProvider = resolveSharedProvider(data, sig), hasSharedProvider = Boolean(sharedProvider);
        const isPartialLight = Boolean(data.isPartialMode || String(data.queryMode || '').trim().toLowerCase() === 'light');
        const giiRow = sig.getipintelRow, isGetIpIntelDeferred = Boolean(giiRow && (giiRow.isDeferred || giiRow.status === 'Deferred (Light Mode)'));
        // Spamhaus PBL flags dynamic consumer ISP ranges, so only elevate it to yellow before commercial scoring runs.
        const isLightScreeningMode = Boolean(!hasPrediction && (isPartialLight || isGetIpIntelDeferred));
        const hasActiveSpamhausSignal = sig.hasSpamhausNonPbl || (isLightScreeningMode && sig.hasSpamhausPolicy);
        const hasProviderRiskSignal = Boolean(
            hasActiveSpamhausSignal || sig.hasDshieldSignal || sig.hasSpamcopSignal || sig.hasIpsumDropSignal ||
            sig.hasOpenAsnVpn || sig.hasOpenAsnHosting || sig.hasMaxmindHosting || sig.hasMaxmindRiskFlag || sig.hasShodanOpenPortsSignal ||
            sig.shodanOpenPorts.length > 0 || sig.hasOtherNonCommercialRiskFlag || (isLightScreeningMode && sig.hasLightCommercialRiskFlag)
        );
        const hasHighOrMediumSignals = Boolean(
            isTor || isMajorityProxyVpn || highlySuspectedResidentialProxy || suspectedResidentialProxy ||
            sig.openProxyPorts.length > 0 || hasSharedProvider || arbitrationTier === 'destructive' ||
            ptrIsHighRisk || arbitrationTier === 'warning' || broadcastIp ||
            isSfsBlacklisted || isSfsListed || hasProviderRiskSignal
        );
        const isLightDeferredClean = Boolean(!hasPrediction && !hasHighOrMediumSignals && !sig.hasQuotaGuardedProvider && !sig.hasCooldownProvider && (isPartialLight || isGetIpIntelDeferred));
        const hasValidNonPredictionClean = Boolean(!hasPrediction && !hasHighOrMediumSignals && !isLightDeferredClean &&
            (sig.validCommercialCount > 0 || (!sig.hasQuotaGuardedProvider && !sig.hasCooldownProvider && (sig.validTotalSourceCount > 0 || arbitrationTier === 'success'))));

        const riskTier = isNonPublic ? 'nonpublic'
            : ((hasPrediction && prediction > 80) || isTor || isMajorityProxyVpn || highlySuspectedResidentialProxy || arbitrationTier === 'destructive' || isSfsBlacklisted || hasSharedProvider || sig.hasOpenAsnVpn) ? 'high'
                : ((hasPrediction && prediction >= 30) || broadcastIp || suspectedResidentialProxy || sig.openProxyPorts.length > 0 || arbitrationTier === 'warning' || ptrIsHighRisk || isSfsListed || hasProviderRiskSignal) ? 'medium'
                    : 'low';

        const predictionText = hasPrediction ? String(Number(prediction.toFixed(2))) : '';
        const giiStatus = giiRow && giiRow.status ? ` (${giiRow.status})` : '';
        const commSuffix = sig.validCommercialCount > 0 ? `; ${sig.validCommercialCount} commercial sources OK` : '';
        const predictionTooltip = hasPrediction ? predictionText + '%'
            : isLightDeferredClean ? 'Light screening passed (no local/free-tier flags). Click to run full commercial check.'
                : (isPartialLight || isGetIpIntelDeferred) ? 'Light Mode (commercial sources deferred; click for full check)'
                    : sig.hasQuotaGuardedProvider ? 'Quota Guard Active' + giiStatus + commSuffix
                        : sig.hasCooldownProvider ? 'Provider Cooldown' + giiStatus + commSuffix
                            : sig.validCommercialCount > 0 ? `Unavailable (${sig.positiveCommercialVotes}/${sig.validCommercialCount} commercial sources flagged)`
                                : 'Unavailable' + (data.predictionLabel ? ` (${data.predictionLabel})` : '');

        const primaryRules = [
            [highlySuspectedResidentialProxy || suspectedResidentialProxy, 'RES-PROXY'],
            [isMajorityProxyVpn || arbitrationTier === 'destructive', /datacenter|hosting/i.test(arbitrationVerdict) ? 'HOSTING' : 'PROXY'],
            [isSfsBlacklisted, 'BLACKLIST'],
            [sig.openProxyPorts.length > 0, 'PROXY-PORT'],
            [hasSharedProvider, 'SHARED/' + sharedProvider],
            [sig.hasOpenAsnVpn, 'OpenASN:VPN'],
            [ptrIsHighRisk, 'PTR-RISK'],
            [isSfsListed, 'SPAM'],
            [arbitrationTier === 'warning', 'REVIEW'],
            [sig.hasDshieldSignal, 'DSHIELD'],
            [sig.hasSpamcopSignal, 'SPAMCOP'],
            [hasActiveSpamhausSignal, 'SPAMHAUS'],
            [sig.hasIpsumDropSignal, 'IPSUM'],
            [sig.hasMaxmindHosting || sig.hasOpenAsnHosting, 'HOSTING'],
            [sig.hasShodanOpenPortsSignal || sig.shodanOpenPorts.length > 0, 'OPEN-PORTS'],
            [sig.hasMaxmindRiskFlag || sig.hasOtherNonCommercialRiskFlag || (isLightScreeningMode && sig.hasLightCommercialRiskFlag), 'FLAGGED'],
            [isLightDeferredClean, 'LIGHT'],
            [hasValidNonPredictionClean, sig.validCommercialCount > 0 ? `OK ${sig.positiveCommercialVotes}/${sig.validCommercialCount}` : 'CLEAN'],
            [sig.hasQuotaGuardedProvider, 'QUOTA'],
            [sig.hasCooldownProvider, 'COOLDOWN']
        ];
        const matchedRule = primaryRules.find(([cond]) => cond);
        const badgePrimaryLabel = matchedRule ? matchedRule[1] : 'N/A';

        return {
            sig, isNonPublic, nonPublicCategory, nonPublicReason, nonPublicBadgeCode,
            prediction, hasPrediction, broadcastIp, isTor, isMajorityProxyVpn,
            suspectedResidentialProxy, highlySuspectedResidentialProxy, sharedPrivacyEgress,
            isMobileOrCgnat: isMobileOrCgnatPayload(data), openProxyPorts: sig.openProxyPorts, shodanOpenPorts: sig.shodanOpenPorts,
            arbitrationTier, ptrIsHighRisk, sharedProvider, hasSharedProvider, isSfsBlacklisted, isSfsListed,
            hasQuotaGuardedProvider: sig.hasQuotaGuardedProvider, hasCooldownProvider: sig.hasCooldownProvider,
            isLightScreeningMode, isLightDeferredClean, validCommercialCount: sig.validCommercialCount,
            positiveCommercialVotes: sig.positiveCommercialVotes, validTotalSourceCount: sig.validTotalSourceCount,
            torLabel, torFlags, torSummary, riskTier, predictionText, predictionTooltip, badgePrimaryLabel
        };
    }

    function formatTorDescription(risk) {
        if (!risk.isTor) return '';
        const lbl = risk.torLabel || 'Tor Node';
        return risk.torFlags.length > 0 ? `${lbl} (Flags: ${risk.torFlags.join(', ')})`
            : (risk.torSummary && risk.torSummary !== lbl ? `${lbl} (${risk.torSummary})` : lbl);
    }

    function formatSharedDescription(data, risk) {
        const p = risk && risk.sharedProvider ? risk.sharedProvider : '';
        if (!p) return '';
        const cidr = [data && data.sharedCidr, data && data.cloudCidr].find((v) => typeof v === 'string' && v.trim());
        return cidr ? `${p} (${cidr.trim()})` : p;
    }

    function getCacheMeta(data) { return data && typeof data === 'object' && data.cacheMeta && typeof data.cacheMeta === 'object' ? data.cacheMeta : null; }

    function getCacheAgeSeconds(data) {
        const meta = getCacheMeta(data);
        if (meta && typeof meta.ageSeconds === 'number' && isFinite(meta.ageSeconds) && meta.ageSeconds >= 0) return Math.floor(meta.ageSeconds);
        const tsRaw = (meta && (meta.fetchedAt || meta.cachedAt)) || (data && data.fetchedAt), ms = tsRaw ? Date.parse(tsRaw) : NaN;
        return isNaN(ms) ? null : Math.max(0, Math.floor((Date.now() - ms) / 1000));
    }

    function formatRelativeCacheAge(ageSeconds) {
        if (typeof ageSeconds !== 'number' || !isFinite(ageSeconds) || ageSeconds < 0) return '';
        const mins = Math.floor(ageSeconds / 60);
        if (mins < 1) return 'Cached just now';
        const d = Math.floor(mins / 1440), h = Math.floor((mins % 1440) / 60), m = mins % 60, parts = [];
        if (d > 0) parts.push(`${d}d`);
        if (h > 0) parts.push(`${h}h`);
        if (m > 0 || parts.length === 0) parts.push(`${m}m`);
        return `Cached ${parts.join('')} ago`;
    }

    function formatCacheStatusLabel(data, isJustUpdated) {
        if (isJustUpdated || (getCacheMeta(data) && getCacheMeta(data).status === 'miss')) return 'Just updated';
        const ageSec = getCacheAgeSeconds(data);
        return ageSec !== null ? formatRelativeCacheAge(ageSec) : (data && data.isCached ? 'Cached' : 'Just updated');
    }

    function shouldAutoRefreshPayload(data, cacheKey) {
        const meta = getCacheMeta(data), key = cacheKey || canonicalizeIpKey(data && data.ip);
        return Boolean(meta && meta.shouldAutoRefresh === true && !(key && autoSwrAttemptedKeys.has(key)));
    }

    function isMobileOrCgnatPayload(data) {
        return Boolean(data && (data.isMobileOrCgnat === true || (typeof data.ptrCategory === 'string' && data.ptrCategory.trim().toLowerCase() === 'mobile_or_cgnat')));
    }

    function getSharedPrivacyEgressLabel(data) {
        const val = data && typeof data.sharedPrivacyEgress === 'string' ? data.sharedPrivacyEgress.trim().toLowerCase() : '';
        return val === 'icloud_private_relay' ? 'Apple iCloud Private Relay' : (val === 'cloudflare_warp' ? 'Cloudflare WARP' : (val ? data.sharedPrivacyEgress.trim() : ''));
    }

    function resolveSharedProvider(data, sig) {
        const text = (v) => (typeof v === 'string' ? v.trim() : '');
        return text(data && data.sharedProvider) || getSharedPrivacyEgressLabel(data) || (sig && sig.openAsnSharedProvider) || text(data && data.cloudProvider);
    }

    function shouldRecommendFreshResidentialRecheck(data) {
        const meta = getCacheMeta(data), age = getCacheAgeSeconds(data);
        return Boolean((meta && meta.recommendFreshRecheck === true) || (data && data.suspectedResidentialProxy && age !== null && age > RESIDENTIAL_RECHECK_THRESHOLD_SECONDS));
    }

    function resolveRangeBlockTarget(cidr) {
        const trimmed = typeof cidr === 'string' ? cidr.trim() : '';
        if (!trimmed || trimmed === 'N/A' || !trimmed.includes('/') || trimmed.includes('%')) return '';
        const parts = trimmed.split('/');
        if (parts.length !== 2) return '';
        const addr = parts[0].trim(), prefixStr = parts[1].trim();
        if (!/^\d{1,3}$/.test(prefixStr) || !isValidIp(addr)) return '';
        const prefix = Number(prefixStr), maxPrefix = addr.includes(':') ? 128 : 32;
        return (prefix >= 1 && prefix < maxPrefix) ? `${canonicalizeIpKey(addr)}/${prefix}` : '';
    }

    function buildWikiPageUrl(pageTitle, queryParams) {
        let baseUrl = (mw && mw.util && typeof mw.util.getUrl === 'function') ? mw.util.getUrl(pageTitle) : '';
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

    function buildDesensitisedWikitextSummary(data, rows, fallbackIp, sig) {
        const targetIp = sanitizeWikitextFragment((data && data.ip) || fallbackIp || '');
        const cidr = sanitizeWikitextFragment((data && data.recommendedCidr) || targetIp);
        const esc = data && !data.highlySuspectedResidentialProxy && typeof data.escalationCidr === 'string' && data.escalationCidr.trim()
            ? sanitizeWikitextFragment(data.escalationCidr) : '';
        const asn = sanitizeWikitextFragment((data && data.primaryAsn) || (collectAsnEntries(rows)[0] && collectAsnEntries(rows)[0].value) || '');
        const isp = sanitizeWikitextFragment((collectIspEntries(rows)[0] && collectIspEntries(rows)[0].value) || '');
        const verdict = sanitizeWikitextFragment((data && data.arbitrationVerdict) || 'IP Intelligence Summary');
        const signals = [];
        if (data && data.isTor) signals.push(sanitizeWikitextFragment(data.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node')));
        const shared = resolveSharedProvider(data, sig);
        if (shared) signals.push('Shared egress: ' + sanitizeWikitextFragment(shared));
        if (isMobileOrCgnatPayload(data)) signals.push('Mobile/CGNAT');
        const ports = sig.openProxyPorts;
        if (ports.length > 0) signals.push(`Open proxy ports: ${ports.join(', ')}`);
        if (sig.dropRow) {
            signals.push(sig.dropRow.dropSblId ? `Spamhaus DROP (${sanitizeWikitextFragment(sig.dropRow.dropSblId)})` : 'Spamhaus DROP');
        }
        const net = [asn, isp].filter(Boolean).join(' / ');
        const parts = [`<code>${targetIp}</code>`, `CIDR <code>${cidr}</code>${esc ? ` (escalation: <code>${esc}</code>)` : ''}`];
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
        const text = String(value).trim(), lower = text.toLowerCase();
        return Boolean(text) && text !== '-' && lower !== 'n/a' && lower !== 'unknown';
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

    function collectAsnEntries(rows) {
        const byAsn = new Map(), entries = [];
        rows.forEach((row, idx) => {
            if (!isUsableProviderValue(row && row.asn)) return;
            const text = String(row.asn).trim(), m = text.match(/^(?:as\s*)?(\d+)$/i);
            const asn = m ? 'AS' + m[1] : text.toUpperCase();
            const provider = (row && row.provider) || 'Provider';
            let entry = byAsn.get(asn);
            if (!entry) { entry = { value: asn, providers: [], voteCount: 0, firstIndex: idx }; byAsn.set(asn, entry); entries.push(entry); }
            entry.voteCount += 1;
            if (entry.providers.indexOf(provider) === -1) entry.providers.push(provider);
        });
        entries.sort((a, b) => b.voteCount !== a.voteCount ? b.voteCount - a.voteCount : a.firstIndex - b.firstIndex);
        return entries.map((e, i) => ({ value: e.value, providers: e.providers, showProviders: i > 0, defaultChecked: i === 0 }));
    }

    function upsertProviderEntry(byKey, entries, key, value, provider) {
        let entry = byKey.get(key);
        if (!entry) { entry = { value, providers: [], showProviders: true, defaultChecked: false }; byKey.set(key, entry); entries.push(entry); }
        if (provider && entry.providers.indexOf(provider) === -1) entry.providers.push(provider);
    }

    function collectGroupedProviderValues(rows, extractItem) {
        const byKey = new Map(), entries = [];
        for (const row of rows) {
            const ext = row ? extractItem(row) : null;
            if (ext && ext.key && ext.value) upsertProviderEntry(byKey, entries, ext.key, ext.value, row.provider || 'Provider');
        }
        return entries;
    }

    function collectIspEntries(rows) {
        return collectGroupedProviderValues(rows, (row) => {
            const raw = isUsableProviderValue(row.isp) ? row.isp : (isUsableProviderValue(row.organisation) ? row.organisation : '');
            const cleaned = raw ? stripTrailingMetadataParens(raw, true) : '';
            return isUsableProviderValue(cleaned)
                ? { key: cleaned.toLowerCase().replace(/\./g, '').replace(/[,;:]+/g, ' ').replace(/\s+/g, ' ').trim(), value: cleaned }
                : null;
        });
    }

    function collectLocationEntries(rows) {
        return collectGroupedProviderValues(rows, (row) => {
            if (!isUsableProviderValue(row.location)) return null;
            const parts = stripTrailingMetadataParens(row.location, false).split(',').map((p) => p.trim()).filter(Boolean);
            const norm = parts.filter((p, i) => i === 0 || parts[i - 1].toLowerCase() !== p.toLowerCase()).join(', ');
            return isUsableProviderValue(norm)
                ? { key: norm.toLowerCase().replace(/\s*,\s*/g, ', ').replace(/\s+/g, ' ').trim(), value: norm }
                : null;
        });
    }

    function collectPredictionEntries(data, risk) {
        if (data.getipintel_chance === null || data.getipintel_chance === undefined) return [];
        return [{
            value: `Prediction ${risk.predictionText}%`, copyValue: `${risk.predictionText}% Prediction`,
            providers: ['GetIPIntel'], showProviders: true, defaultChecked: true
        }];
    }

    function collectRiskEntries(data, rows, risk) {
        const sig = risk.sig, byKey = new Map(), entries = [];
        const addEntry = (val, provider) => {
            const text = typeof val === 'string' ? val.trim() : '';
            if (text) upsertProviderEntry(byKey, entries, text.toLowerCase(), text, provider);
        };
        if (risk.isTor) addEntry(risk.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node'), 'Tor Onionoo');
        sig.rowRiskItems.forEach(([lbl, provider]) => addEntry(lbl, provider));
        if (risk.isLightScreeningMode && sig.hasSpamhausPolicy) addEntry('Policy/Dynamic ISP Range (PBL)', 'Spamhaus ZEN');
        if (risk.hasSharedProvider) {
            const matchRow = rows.find((r) => r && r.provider && (r.sharedProvider || r.cloudProvider) === risk.sharedProvider);
            const viaRelay = Boolean((typeof data.sharedCategory === 'string' && data.sharedCategory.trim().toLowerCase() === 'relay') || getSharedPrivacyEgressLabel(data) === risk.sharedProvider);
            addEntry(`Shared (${risk.sharedProvider})`, matchRow ? matchRow.provider : (viaRelay ? 'Privacy Relay' : 'Shared CIDR'));
        }
        if (risk.broadcastIp) addEntry('Broadcast IP', 'Multi-Source');
        if (data.ptrIsHighRisk && typeof data.ptrLabel === 'string' && data.ptrLabel.trim()) addEntry(`PTR (${data.ptrLabel.trim()})`, 'Reverse DNS');
        if (data.suspectedResidentialProxy) addEntry('Suspected Residential Proxy / Compromised Host', 'Multi-Source');
        if (data.highlySuspectedResidentialProxy) addEntry('Highly Suspected Residential Proxy', 'GetIPIntel ResidentialProxy');
        if (sig.openProxyPorts.length > 0) addEntry(`Open Proxy Ports (${sig.openProxyPorts.join(', ')})`, 'Shodan InternetDB');
        else if (sig.shodanOpenPorts.length > 0) addEntry(`Open Ports (${sig.shodanOpenPorts.join(', ')})`, 'Shodan InternetDB');
        else if (sig.hasShodanOpenPortsSignal) addEntry('Open Ports', 'Shodan InternetDB');
        return entries;
    }

    function collectLightBadgeInfo(data, risk) {
        const sig = risk.sig, rows = sig.orderedRows;
        const asnEntry = collectAsnEntries(rows)[0], ispEntry = collectIspEntries(rows)[0];
        const riskLabels = [], providerRiskLabels = sig.lightProviderLabels.slice();
        const addLabelTo = (target, label) => {
            const cleaned = typeof label === 'string' ? label.trim() : '';
            if (cleaned && target.indexOf(cleaned) === -1) target.push(cleaned);
        };
        if (sig.shodanOpenPortRow && !(risk.openProxyPorts && risk.openProxyPorts.length > 0)) {
            const rowPorts = [];
            collectNumericPorts(rowPorts, sig.shodanOpenPortRow.ports);
            addLabelTo(providerRiskLabels, rowPorts.length > 0 ? `Shodan:Open Ports (${rowPorts.length > 4 ? rowPorts.slice(0, 4).join(',') + '...' : rowPorts.join(',')})` : 'Shodan:Open Ports');
        }
        const redundant = ['SPAMHAUS', 'DSHIELD', 'SPAMCOP', 'IPSUM', 'HOSTING', 'OPEN-PORTS', 'FLAGGED'];
        if (risk.badgePrimaryLabel && !['LIGHT', 'CLEAN', 'N/A'].includes(risk.badgePrimaryLabel) &&
            !(providerRiskLabels.length > 0 && redundant.includes(risk.badgePrimaryLabel))) addLabelTo(riskLabels, risk.badgePrimaryLabel);
        if (risk.isTor) addLabelTo(riskLabels, formatTorDescription(risk) || 'Tor');
        if (risk.ptrIsHighRisk) addLabelTo(riskLabels, 'PTR-Risk');
        if (risk.openProxyPorts && risk.openProxyPorts.length > 0) addLabelTo(riskLabels, `Shodan:${risk.openProxyPorts.join(',')}`);
        providerRiskLabels.forEach((lbl) => addLabelTo(riskLabels, lbl));
        return { asn: asnEntry ? asnEntry.value : '', isp: ispEntry ? ispEntry.value : '', riskLabels };
    }

    function getSpurProxyText() {
        if (!isContributionsSpecialPage()) return '';
        const $panel = $('.ext-ipinfo-panel-layout').first();
        if ($panel.length === 0) return '';
        const $nodes = $panel.find('.ext-ipinfo-widget-property[data-property="proxies"]:not(.ext-ipinfo-widget-property-no-data) .ext-ipinfo-widget-property-value');
        if ($nodes.length === 0) return '';
        const seen = Object.create(null), lines = [];
        $nodes.each(function () {
            if ($(this).closest('.ext-ipinfo-widget-error, .ext-ipinfo-contains-error').length > 0) return;
            const raw = (this.innerText || this.textContent || '');
            for (const line of raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)) {
                if (!seen[line]) { seen[line] = true; lines.push(line); }
            }
        });
        return lines.join(', ');
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
            'a.proxycheck-anchor-risk-high, a.proxycheck-anchor-risk-high:visited, .proxycheck-anchor-risk-high { background-color: #ffcccc; color: #990000; font-weight: bold; padding: 1px 4px; border-radius: 3px; }',
            'a.proxycheck-anchor-risk-medium, a.proxycheck-anchor-risk-medium:visited, .proxycheck-anchor-risk-medium { background-color: #fff3cd; color: #856404; font-weight: bold; padding: 1px 4px; border-radius: 3px; }',
            'a.proxycheck-ip-badge, a.proxycheck-ip-badge:visited { margin-left: 4px; font-size: 0.85em; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; padding: 1px 5px; border-radius: 3px; text-decoration: none; white-space: nowrap; cursor: pointer; }',
            ...boldTiers.map((t) => `a.proxycheck-ip-badge.proxycheck-tier-${t}, a.proxycheck-ip-badge.proxycheck-tier-${t}:visited { background-color: var(--proxycheck-${t}-bg); color: var(--proxycheck-${t}-color) !important; border: 1px solid var(--proxycheck-${t}-border); font-weight: bold; }`),
            'a.proxycheck-ip-badge.proxycheck-tier-low, a.proxycheck-ip-badge.proxycheck-tier-low:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-low-color) !important; border: 1px solid var(--proxycheck-low-border); font-weight: normal; }',
            'a.proxycheck-ip-badge.proxycheck-badge-lite, a.proxycheck-ip-badge.proxycheck-badge-lite:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-subtle-color) !important; border: 1px solid var(--proxycheck-low-border); opacity: 0.9; }',
            'a.proxycheck-ip-badge.proxycheck-badge-quota, a.proxycheck-ip-badge.proxycheck-badge-quota:visited { background-color: var(--proxycheck-medium-bg); color: var(--proxycheck-medium-color) !important; border: 1px dashed var(--proxycheck-medium-border); }',
            'a.proxycheck-ip-badge.proxycheck-ip-badge-loading, a.proxycheck-ip-badge.proxycheck-ip-badge-loading:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-muted-color) !important; border: 1px solid var(--proxycheck-low-border); cursor: default; opacity: 0.8; }',
            'a.proxycheck-ip-badge.proxycheck-ip-badge-error, a.proxycheck-ip-badge.proxycheck-ip-badge-error:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-muted-color) !important; border: 1px dashed var(--proxycheck-error-border); }',
            'a.proxycheck-ip-badge.proxycheck-ip-badge-consent, a.proxycheck-ip-badge.proxycheck-ip-badge-consent:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-low-color) !important; border: 1px solid var(--proxycheck-low-border); }',
            'a.proxycheck-ip-badge.proxycheck-badge-stale, a.proxycheck-ip-badge.proxycheck-badge-stale:visited { border-style: dashed; }',
            'a.proxycheck-rb-badge, a.proxycheck-rb-badge:visited { margin-left: 4px; font-size: 0.85em; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; padding: 1px 5px; border-radius: 3px; text-decoration: none; white-space: nowrap; }',
            'a.proxycheck-rb-badge.proxycheck-rb-badge-active, a.proxycheck-rb-badge.proxycheck-rb-badge-active:visited { background-color: var(--proxycheck-high-bg); color: var(--proxycheck-high-color) !important; border: 1px solid var(--proxycheck-high-border); font-weight: bold; }',
            'a.proxycheck-rb-badge.proxycheck-rb-badge-neutral, a.proxycheck-rb-badge.proxycheck-rb-badge-neutral:visited { background-color: var(--proxycheck-low-bg); color: var(--proxycheck-low-color) !important; border: 1px solid var(--proxycheck-low-border); font-weight: normal; }',
            '.proxycheck-rb-active-label { color: var(--proxycheck-high-color); font-weight: bold; }',
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
        if (attrs) {
            for (const [k, v] of Object.entries(attrs)) {
                if (v !== undefined && v !== null && !/^on/i.test(k)) el.setAttribute(k, String(v));
            }
        }
        return el;
    }

    function ensureUserscriptStyles() {
        if (stylesInjected || typeof document === 'undefined') return;
        if (document.getElementById(STYLE_ELEMENT_ID)) { stylesInjected = true; return; }
        const cssText = buildUserscriptCss();
        const parent = document.head || document.body || document.documentElement;
        if (parent) { parent.appendChild(createEl('style', '', cssText, { id: STYLE_ELEMENT_ID, type: 'text/css' })); stylesInjected = true; }
    }

    function getProviderBadgePalette(provider) {
        if (Object.prototype.hasOwnProperty.call(PROVIDER_BADGE_PALETTES, provider)) return PROVIDER_BADGE_PALETTES[provider];
        let hash = 0;
        const text = String(provider || '');
        for (let i = 0; i < text.length; i++) hash = ((hash * 31) + text.charCodeAt(i)) | 0;
        return FALLBACK_COOL_PALETTES[Math.abs(hash) % FALLBACK_COOL_PALETTES.length];
    }

    function createSourceBadge(provider, providerUpdatedAtMap) {
        const [bg, border, color, darkBg, darkBorder, darkColor] = getProviderBadgePalette(provider);
        const updatedIso = providerUpdatedAtMap && providerUpdatedAtMap[provider];
        const formatted = updatedIso ? formatOfflineDbDateShort(updatedIso) : '';
        const attrs = {
            class: 'proxycheck-source-tag',
            style: `--proxycheck-tag-bg: ${bg}; --proxycheck-tag-border: ${border}; --proxycheck-tag-color: ${color}; --proxycheck-tag-dark-bg: ${darkBg}; --proxycheck-tag-dark-border: ${darkBorder}; --proxycheck-tag-dark-color: ${darkColor};`,
            text: provider
        };
        if (formatted) attrs.title = 'Offline DB updated: ' + formatted;
        return $('<span>', attrs);
    }

    function buildResultDetailsPanel(data, risk, fallbackIp) {
        ensureUserscriptStyles();
        const sig = risk.sig, rows = sig.orderedRows;
        const resolvedIp = isValidIp(data && data.ip) ? String(data.ip).trim() : (isValidIp(fallbackIp) ? String(fallbackIp).trim() : '');
        const spurText = getSpurProxyText();
        const spurEntries = spurText ? [{ value: spurText, providers: ['Spur'], showProviders: true, defaultChecked: true }] : [];

        const sections = [
            { label: 'Prediction', entries: collectPredictionEntries(data, risk), isRisk: false, emptyText: 'Unavailable', copyable: false },
            { label: 'ASN', entries: collectAsnEntries(rows), isRisk: false, emptyText: '-', copyable: true },
            { label: 'ISP', entries: collectIspEntries(rows), isRisk: false, emptyText: '-', copyable: true },
            { label: 'Location', entries: collectLocationEntries(rows), isRisk: false, emptyText: '-', copyable: false },
            { label: 'Risk', entries: collectRiskEntries(data, rows, risk).concat(spurEntries), isRisk: true, emptyText: 'No high-risk signals detected', copyable: false }
        ];

        const $panel = $('<div>', { class: 'proxycheck-details-panel' });
        const sharedEgressLabel = risk.sharedProvider;
        const highlySuspectedResidentialProxy = Boolean(data && data.highlySuspectedResidentialProxy);
        const bannerPills = [];
        if (sharedEgressLabel) bannerPills.push(['proxycheck-signal-privacy', `Shared Egress: ${sharedEgressLabel} \u2014 many unrelated users may share this address; check collateral damage before blocking.`]);
        if (isMobileOrCgnatPayload(data)) bannerPills.push(['proxycheck-signal-cgnat', 'Mobile / CGNAT Network: Collateral-damage warning \u2014 recommended block locked to /32 (IPv4) or /64 (IPv6).']);
        if (data && data.suspectedResidentialProxy) bannerPills.push(['proxycheck-signal-danger', 'Suspected Residential Proxy / Compromised Host' + (shouldRecommendFreshResidentialRecheck(data) ? ' \u2014 Cached signal is older than 7 days; click Refetch to verify current DHCP assignment before issuing a long-term block.' : '')]);
        if (highlySuspectedResidentialProxy) bannerPills.push(['proxycheck-signal-danger', 'Highly Suspected Residential Proxy']);
        if (sig.openProxyPorts.length > 0) bannerPills.push(['proxycheck-signal-danger', `Shodan Open Proxy Ports: ${sig.openProxyPorts.join(', ')}`]);
        if (bannerPills.length > 0) {
            const $banners = $('<div>', { class: 'proxycheck-signal-banners' });
            bannerPills.forEach(([cls, text]) => $banners.append($('<div>', { class: 'proxycheck-signal-pill ' + cls, text })));
            $panel.append($banners);
        }

        const $table = $('<table>', { style: 'width: 100%; border-collapse: collapse;' });
        const appendRow = (label, $cell) => {
            $('<tr>').append(
                $('<th>', { class: 'proxycheck-details-label', style: 'text-align: left; vertical-align: top; padding: 4px 12px 4px 0; width: 78px; font-weight: 600; white-space: nowrap;' }).text(label),
                $('<td>', { style: 'padding: 4px 0; vertical-align: top;' }).append($cell)
            ).appendTo($table);
        };

        const checkboxItems = [];
        for (const section of sections) {
            const $content = $('<div>', { style: 'display: flex; flex-direction: column; gap: 3px;' });
            if (section.entries.length === 0) {
                $content.append($('<span>', { class: 'proxycheck-details-empty', text: section.emptyText }));
            } else {
                for (const entry of section.entries) {
                    const $body = $('<span>', { style: 'display: block; flex: 1; min-width: 0; line-height: 1.5;' })
                        .append($('<span>', { class: 'proxycheck-result-value' + (section.isRisk ? ' proxycheck-result-value-risk' : ''), text: entry.value }));
                    if (entry.showProviders && entry.providers.length > 0) {
                        entry.providers.forEach((p) => $body.append(createSourceBadge(p, sig.dbUpdatedAtMap)));
                    }
                    if (section.copyable) {
                        const $checkbox = $('<input>', {
                            type: 'checkbox', class: 'proxycheck-result-checkbox',
                            checked: Boolean(entry.defaultChecked), style: 'margin: 3px 0 0 0; flex-shrink: 0; cursor: pointer;'
                        });
                        $content.append($('<label>', { style: 'display: flex; align-items: flex-start; gap: 6px; margin: 0; cursor: pointer; font-weight: normal;' }).append($checkbox, $body));
                        checkboxItems.push({ checkbox: $checkbox, copyValue: entry.copyValue || entry.value });
                    } else {
                        $content.append($('<div>', { style: 'display: flex; align-items: flex-start; margin: 0;' }).append($body));
                    }
                }
            }
            appendRow(section.label, $content);
        }

        const verdictText = data && typeof data.arbitrationVerdict === 'string' ? data.arbitrationVerdict.trim() : '';
        if (verdictText) appendRow('Verdict', $('<span>', { class: 'proxycheck-result-value', text: verdictText }));

        const recCidr = data && typeof data.recommendedCidr === 'string' && data.recommendedCidr.trim() ? data.recommendedCidr.trim() : 'N/A';
        const escCidr = data && typeof data.escalationCidr === 'string' ? data.escalationCidr.trim() : '';
        const bgpCidr = (data && typeof data.bgpPrefix === 'string' && data.bgpPrefix.trim()) || (data && typeof data.mmdbCidr === 'string' && data.mmdbCidr.trim()) || '';
        const cidrRationale = (data && typeof data.cidrRationale === 'string' && data.cidrRationale.trim()) || (data && typeof data.cidrNote === 'string' && data.cidrNote.trim()) || '';

        const $cidrLine = $('<div>').append($('<code>').text(recCidr));
        if (!highlySuspectedResidentialProxy) {
            if (escCidr) $cidrLine.append($('<span>', { class: 'proxycheck-inline-pill', text: 'Escalation: ' + escCidr }));
            if (bgpCidr) $cidrLine.append($('<span>', { class: 'proxycheck-inline-pill', text: 'BGP: ' + bgpCidr }));
        }
        const $cidrCell = $('<div>').append($cidrLine);
        if (highlySuspectedResidentialProxy) {
            $cidrCell.append($('<div>', {
                class: 'proxycheck-cidr-rationale proxycheck-residential-proxy-warning',
                text: 'Highly Suspected Residential Proxy: this IP is highly likely to use residential proxy infrastructure. Restrict CIDR blocking to this single IP and proceed with discretion on CIDR.'
            }));
        } else if (cidrRationale) {
            $cidrCell.append($('<div>', { class: 'proxycheck-cidr-rationale', text: cidrRationale }));
        }
        appendRow('CIDR', $cidrCell);

        const rb = data && data.rangeblock && typeof data.rangeblock === 'object' ? data.rangeblock : null;
        if (rb && resolvedIp) {
            const rbWikis = Array.isArray(rb.wikis) ? rb.wikis : [];
            const $rbCell = $('<div>', { class: 'proxycheck-rb-distribution' });
            if (rbWikis.length === 0) {
                $rbCell.append($('<span>', { class: 'proxycheck-details-empty', text: 'No hits (0/0)' }));
            } else {
                rbWikis.forEach((entry, idx) => {
                    if (!entry || !entry.wiki) return;
                    if (idx > 0) $rbCell.append(document.createTextNode(', '));
                    $rbCell.append(document.createTextNode(`${Number(entry.count) || 0} on `));
                    $rbCell.append($('<a>', {
                        class: 'proxycheck-rb-wiki-link',
                        href: `${TOOL_BASE_URL}/?ip=${encodeURIComponent(resolvedIp)}&tab=rb&wiki=${encodeURIComponent(entry.wiki)}`,
                        target: '_blank',
                        rel: 'noopener noreferrer',
                        text: entry.wiki
                    }));
                    if (entry.hasActive) {
                        $rbCell.append(document.createTextNode(' '));
                        $rbCell.append($('<span>', { class: 'proxycheck-rb-active-label', text: '(active)' }));
                    }
                });
            }
            appendRow('Rangeblock', $rbCell);
        }

        const $copyLink = $('<a>', { href: '#', role: 'button', class: 'proxycheck-copy-result', text: 'Copy result' });
        const $copyWikitextBtn = $('<a>', { href: '#', role: 'button', class: 'proxycheck-copy-wikitext', text: 'Copy Wikitext' });
        let panelDisposed = false;
        const copyTimers = { res: null, wiki: null };
        const getSelectedCommentValues = () => checkboxItems.filter((item) => item.checkbox.prop('checked'))
            .map((item) => sanitizeHtmlCommentContent(item.copyValue)).filter(Boolean);
        const buildAttributionComment = (vals) => `<!-- ${(vals.length ? sanitizeHtmlCommentContent(vals.join(', ')) + ' ' : '') + BLOCK_REASON_ATTRIBUTION} -->`;
        const bindCopy = ($btn, key, baseLabel, copiedLabel, getPayload) => {
            const scheduleReset = (delayMs) => {
                copyTimers[key] = clearTimer(copyTimers[key], false);
                if (!panelDisposed) copyTimers[key] = window.setTimeout(() => { copyTimers[key] = null; if (!panelDisposed) $btn.text(baseLabel); }, delayMs);
            };
            $btn.on('click', (e) => {
                e.preventDefault(); e.stopPropagation();
                if (panelDisposed) return;
                const payload = getPayload();
                if (!payload) { $btn.text('Select at least one item'); return scheduleReset(1500); }
                copyText(payload).then(
                    () => { if (!panelDisposed) { $btn.text(copiedLabel); scheduleReset(1500); } },
                    (err) => { warn(baseLabel + ' failed:', err); if (!panelDisposed) { $btn.text('Copy failed'); scheduleReset(2000); } }
                );
            });
        };
        bindCopy($copyLink, 'res', 'Copy result', 'Copied', () => {
            const selected = getSelectedCommentValues();
            return selected.length ? buildAttributionComment(selected) : '';
        });
        bindCopy($copyWikitextBtn, 'wiki', 'Copy Wikitext', 'Copied Wikitext', () => buildDesensitisedWikitextSummary(data, rows, resolvedIp, sig));
        $panel.append($table, $('<div>', { style: 'margin-top: 8px; display: flex; align-items: center; flex-wrap: wrap; gap: 12px;' }).append($copyLink, $copyWikitextBtn));

        if (resolvedIp) {
            const rangeTarget = resolveRangeBlockTarget(recCidr);
            const buildBlockParams = () => {
                // Omit wpReason so Codex Special:Block does not prepend "other:" to wpReason-other.
                return { wpExpiry: '3 months', wpHardBlock: '1', 'wpReason-other': '{{blocked proxy}}' + buildAttributionComment(getSelectedCommentValues()) };
            };
            const mkLink = (cls, href, text) => $('<a>', { class: cls, href, target: '_blank', rel: 'noopener noreferrer', text });
            const $singleBlockLink = mkLink('proxycheck-link-block', buildWikiPageUrl('Special:Block/' + resolvedIp, buildBlockParams()), 'Special:Block ↗');
            const blockLinks = [{ el: $singleBlockLink, target: resolvedIp }];
            const $rangeBlockLink = rangeTarget
                ? mkLink('proxycheck-link-block-range', buildWikiPageUrl('Special:Block/' + rangeTarget, buildBlockParams()), 'Special:Block (range) ↗')
                : null;
            if ($rangeBlockLink) blockLinks.push({ el: $rangeBlockLink, target: rangeTarget });
            const syncBlockLinkHrefs = () => {
                if (panelDisposed) return;
                const params = buildBlockParams();
                blockLinks.forEach((entry) => entry.el.attr('href', buildWikiPageUrl('Special:Block/' + entry.target, params)));
            };
            checkboxItems.forEach((item) => item.checkbox.on('change', syncBlockLinkHrefs).on('click', syncBlockLinkHrefs));
            blockLinks.forEach((entry) => entry.el.on('click', syncBlockLinkHrefs));

            const $quickLinks = $('<div>', { class: 'proxycheck-quick-links' }).append(
                mkLink('proxycheck-link-globalcontribs', buildWikiPageUrl('Special:GlobalContributions/' + resolvedIp, null), 'GlobalContributions ↗'),
                mkLink('proxycheck-link-rangeblock', TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp) + '&tab=rb', 'Rangeblock Finder ↗'),
                mkLink('proxycheck-link-whois', 'https://whois.toolforge.org/gateway.py?lookup=true&ip=' + encodeURIComponent(resolvedIp), 'WHOIS ↗'),
                $singleBlockLink
            );
            if ($rangeBlockLink) $quickLinks.append($rangeBlockLink);
            $panel.append($quickLinks);
        }

        $panel._proxycheckDispose = () => {
            panelDisposed = true;
            copyTimers.res = clearTimer(copyTimers.res, false);
            copyTimers.wiki = clearTimer(copyTimers.wiki, false);
        };
        return $panel;
    }

    function disposeDetailsPanel($panel) {
        if ($panel && typeof $panel._proxycheckDispose === 'function') $panel._proxycheckDispose();
    }

    function copyText(text) {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') return navigator.clipboard.writeText(text);
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
        const sig = risk.sig, torDesc = formatTorDescription(risk), sharedDesc = formatSharedDescription(data, risk);
        const lines = [];
        if (!risk.hasPrediction && isPartialLightResult(data)) {
            const lightInfo = collectLightBadgeInfo(data, risk);
            if (lightInfo.asn) lines.push('ASN: ' + lightInfo.asn);
            if (lightInfo.isp) lines.push('ISP: ' + lightInfo.isp);
            if (lightInfo.riskLabels.length > 0) lines.push('Light risk: ' + lightInfo.riskLabels.join(', '));
        }
        lines.push(risk.isLightDeferredClean
            ? 'Light screening passed (no local/free-tier flags). Click to run full commercial check.'
            : 'Prediction: ' + risk.predictionTooltip);
        if (typeof data.arbitrationVerdict === 'string' && data.arbitrationVerdict.trim()) lines.push('Verdict: ' + data.arbitrationVerdict.trim());
        lines.push('Recommended CIDR: ' + (data.recommendedCidr || 'N/A'));
        lines.push('BGP CIDR: ' + (data.bgpPrefix || data.mmdbCidr || 'N/A'));
        if (sharedDesc) lines.push('Shared egress: ' + sharedDesc);
        lines.push('Broadcast IP: ' + (risk.broadcastIp ? 'At-risk' : 'No'));
        lines.push('Tor Node: ' + (risk.isTor ? torDesc : 'No'));
        if (sig.sfsTitleLine) lines.push(sig.sfsTitleLine);
        if (sig.dbBaselines.length > 0) lines.push('Offline DB Baseline: ' + sig.dbBaselines.join(', '));
        const meta = getCacheMeta(data), ageSec = getCacheAgeSeconds(data);
        if (ageSec !== null) {
            const ageText = formatRelativeCacheAge(ageSec);
            if (ageText) lines.push(meta && meta.isStale ? `${ageText} (stale >90d)` : ageText);
        }
        return lines.join('\n');
    }

    function applyRiskStylingToAnchorAndBadge(anchor, badge, data, fallbackIp) {
        ensureUserscriptStyles();
        const risk = evaluateRisk(data);
        const resolvedIp = (data && data.ip) || fallbackIp;
        const meta = getCacheMeta(data);
        const isStale = Boolean(!risk.isNonPublic && meta && meta.isStale === true);

        if (anchor.classList) {
            anchor.classList.remove('proxycheck-anchor-risk-high', 'proxycheck-anchor-risk-medium');
            if (risk.riskTier === 'high' || risk.riskTier === 'medium') anchor.classList.add('proxycheck-anchor-risk-' + risk.riskTier);
        }

        const bcast = risk.broadcastIp ? '|BCASTIP' : '';
        const tor = risk.isTor ? '|' + (risk.torLabel ? risk.torLabel.toUpperCase() : 'TOR') : '';
        badge.href = TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp);
        if (risk.isNonPublic) {
            badge.textContent = `[${risk.nonPublicBadgeCode}]`;
        } else if (!risk.hasPrediction && isPartialLightResult(data)) {
            const lightInfo = collectLightBadgeInfo(data, risk), lightParts = [];
            if (lightInfo.asn) lightParts.push(lightInfo.asn);
            if (lightInfo.isp) lightParts.push(lightInfo.isp);
            if (lightInfo.riskLabels.length > 0) lightParts.push(lightInfo.riskLabels.join(','));
            if (bcast) lightParts.push(bcast.slice(1));
            if (tor) lightParts.push(tor.slice(1));
            badge.textContent = '[' + (lightParts.length > 0 ? lightParts.join('|') : 'LIGHT') + ']';
        } else {
            badge.textContent = `[${risk.hasPrediction ? risk.predictionText + '%' : risk.badgePrimaryLabel}${bcast}${tor}]`;
        }

        let stateClass = '';
        if (!risk.isNonPublic && !risk.hasPrediction) {
            if (risk.badgePrimaryLabel === 'QUOTA' || risk.badgePrimaryLabel === 'COOLDOWN') stateClass = ' proxycheck-badge-quota';
            else if (risk.badgePrimaryLabel === 'LIGHT') stateClass = ' proxycheck-badge-lite';
        }
        if (isStale) stateClass += ' proxycheck-badge-stale';
        badge.className = `${BADGE_CLASS} proxycheck-tier-${risk.riskTier}${stateClass}`;
        badge.title = buildBadgeTitleText(data, risk);

        const rb = !risk.isNonPublic && data && data.rangeblock && typeof data.rangeblock === 'object' ? data.rangeblock : null;
        const localTotal = rb ? Math.max(0, Number(rb.localTotal) || 0) : 0;
        const globalTotal = rb ? Math.max(0, Number(rb.globalTotal) || 0) : 0;
        const existingRbBadge = badge.nextElementSibling && badge.nextElementSibling.classList &&
            badge.nextElementSibling.classList.contains('proxycheck-rb-badge')
            ? badge.nextElementSibling : null;

        if (localTotal > 0 || globalTotal > 0) {
            const rbBadge = existingRbBadge || createEl('a', 'proxycheck-rb-badge', '');
            rbBadge.textContent = `rangeblock: ${localTotal}/${globalTotal}`;
            rbBadge.className = `proxycheck-rb-badge ${rb.hasActive ? 'proxycheck-rb-badge-active' : 'proxycheck-rb-badge-neutral'}`;
            rbBadge.href = `${TOOL_BASE_URL}/?ip=${encodeURIComponent(resolvedIp)}&tab=rb`;
            rbBadge.target = '_blank';
            rbBadge.rel = 'noopener noreferrer';
            rbBadge.title = rb.hasActive ? 'Cross-wiki rangeblock (active)' : 'Cross-wiki rangeblock (historical)';
            if (!existingRbBadge && badge.parentNode) {
                badge.parentNode.insertBefore(rbBadge, badge.nextSibling);
            }
        } else if (existingRbBadge && existingRbBadge.parentNode) {
            existingRbBadge.parentNode.removeChild(existingRbBadge);
        }
    }

    function isBadgeDetached(badge) {
        return !badge || badge.isConnected === false ||
            Boolean(typeof document !== 'undefined' && document.body && !document.body.contains(badge));
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
        active.forEach((e) => applyRiskStylingToAnchorAndBadge(e.anchor, e.badge, fullData, fullData.ip || e.ip));
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

    function createRefreshControl(opts) {
        const $ageSpan = $('<span>', { class: 'proxycheck-cache-age' });
        const $btn = $('<button>', { type: 'button', class: 'proxycheck-refetch-btn', text: 'Refetch' });
        const $warning = $('<div>', { class: 'proxycheck-refresh-warning', style: 'display: none;' });
        let inFlight = false;

        const sync = (data, isJustUpdated) => {
            const meta = getCacheMeta(data);
            const isStale = Boolean(!isJustUpdated && meta && meta.isStale === true);
            $ageSpan.text(formatCacheStatusLabel(data, Boolean(isJustUpdated)))
            [isStale ? 'addClass' : 'removeClass']('proxycheck-cache-age-stale');
            if (!inFlight) $btn.prop('disabled', false).text('Refetch');
        };

        const run = (isAutoSwr) => {
            const ip = opts.getIp();
            if (inFlight || !opts.isActive() || accessBlocked || !isValidIp(ip)) return;
            if (isAutoSwr && !tryConsumeAutoSwrBudget()) return;
            const guardToken = opts.getGuard ? opts.getGuard() : null;
            inFlight = true;
            $warning.css('display', 'none').text('');
            $btn.prop('disabled', true).text('Updating...');
            executeIpRefresh(ip).then((outcome) => {
                if (opts.getGuard && opts.getGuard() !== guardToken) return;
                inFlight = false;
                if (!opts.isActive()) return;
                if (!outcome || !outcome.ok || !outcome.data) {
                    $btn.prop('disabled', false).text('Refetch');
                    $warning.text(formatRefreshWarningText(outcome)).css('display', 'block');
                    return;
                }
                $warning.css('display', 'none').text('');
                opts.onSuccess(outcome.data);
            });
        };

        $btn.on('click', (e) => { e.preventDefault(); e.stopPropagation(); run(false); });
        return {
            $ageSpan, $btn, $warning, sync, run,
            resetFlight: () => { inFlight = false; }
        };
    }

    function attachLightUpgrade($container, targetIp, isActive, onUpgraded) {
        let $notice = $('<p>', { class: 'proxycheck-light-upgrade-notice', style: 'margin-top: 8px; margin-bottom: 0; font-size: 12px;' })
            .text('Loading full commercial provider intelligence...');
        $container.append($notice);
        return requestFullIpUpgrade(targetIp, false).then((fullData) => {
            if (!isActive()) return null;
            if (!fullData) { if ($notice) $notice.text('Full commercial intelligence unavailable right now.'); return null; }
            if ($notice) { $notice.remove(); $notice = null; }
            onUpgraded(fullData);
            return fullData;
        }).catch(() => { if (isActive() && $notice) $notice.text('Full commercial intelligence unavailable right now.'); return null; });
    }

    function showInfoDialog(data, ip) {
        if (infoDialogPromise) return infoDialogPromise;
        ensureUserscriptStyles();
        infoDialogPromise = mw.loader.using('oojs-ui-windows').then(() => {
            const targetIp = ip || (data && data.ip) || '', cacheKey = canonicalizeIpKey(targetIp);
            let activeData = (cacheKey && getIpData(cacheKey)) || data, activeDetailsPanel = null, dialogClosed = false;
            const initialRisk = evaluateRisk(activeData);
            const $panelContainer = $('<div>', { class: 'proxycheck-dialog-content' });

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

            const refreshCtrl = createRefreshControl({
                getIp: () => targetIp, isActive: () => !dialogClosed,
                onSuccess: (freshData) => { activeData = freshData; const r = evaluateRisk(activeData); renderBody(activeData, r); syncBar(activeData, r, true); }
            });
            const $cacheBar = $('<div>', { class: 'proxycheck-dialog-cache-bar' }).append(refreshCtrl.$ageSpan, refreshCtrl.$btn);
            const syncBar = (d, risk, isJustUpdated) => {
                if (risk.isNonPublic) { $cacheBar.css('display', 'none'); refreshCtrl.$warning.css('display', 'none'); return; }
                $cacheBar.css('display', 'flex');
                refreshCtrl.sync(d, isJustUpdated);
            };

            renderBody(activeData, initialRisk);
            syncBar(activeData, initialRisk, false);
            const $message = $('<div>').append($cacheBar, refreshCtrl.$warning, $panelContainer,
                $('<p>', { style: 'margin-top: 8px; margin-bottom: 0;' }).append(
                    $('<a>', { class: 'proxycheck-dialog-link', href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(targetIp), target: '_blank', rel: 'noopener noreferrer', text: 'Open full report ↗' })
                ));

            if (!initialRisk.isNonPublic && isPartialLightResult(activeData)) {
                attachLightUpgrade($message, targetIp, () => !dialogClosed, (fullData) => {
                    activeData = fullData;
                    const r = evaluateRisk(fullData);
                    renderBody(fullData, r);
                    syncBar(fullData, r, false);
                    if (shouldAutoRefreshPayload(fullData, cacheKey)) refreshCtrl.run(true);
                });
            } else if (!initialRisk.isNonPublic && shouldAutoRefreshPayload(activeData, cacheKey)) {
                refreshCtrl.run(true);
            }

            return Promise.resolve(OO.ui.alert($message, { title: targetIp, size: 'large' })).then(
                (r) => { dialogClosed = true; disposeDetailsPanel(activeDetailsPanel); activeDetailsPanel = null; return r; },
                (err) => { dialogClosed = true; disposeDetailsPanel(activeDetailsPanel); activeDetailsPanel = null; throw err; }
            );
        }).catch((err) => { warn('Info dialog failed:', err); })
            .then((r) => { infoDialogPromise = null; return r; });

        return infoDialogPromise;
    }

    function attachBadgeClick(badge, fn) {
        if (!badge._pcBound) {
            badge._pcBound = true;
            badge.addEventListener('click', (e) => {
                e.preventDefault(); e.stopPropagation();
                if (!accessBlocked && typeof badge._pcClick === 'function') badge._pcClick(badge);
            });
        }
        badge._pcClick = fn || null;
    }

    function updateActionBadge(badge, options) {
        badge.className = BADGE_CLASS + (options.extraClass ? ' ' + options.extraClass : '');
        badge.textContent = options.text;
        badge.title = options.title || '';
        badge.href = '#';
        badge.setAttribute('role', 'button');
        badge.removeAttribute('aria-busy');
        badge.removeAttribute('target');
        badge.removeAttribute('rel');
        attachBadgeClick(badge, options.onClick);
    }

    function isProxycheckInternalNode(node) {
        if (!node) return false;
        if (node.nodeType === 8) return true;
        if (node.nodeType === 3) return !node.parentNode || Boolean(node.parentNode.closest && node.parentNode.closest(INTERNAL_NODE_SELECTOR));
        return node.nodeType === 1 && Boolean(node.closest && node.closest(INTERNAL_NODE_SELECTOR));
    }

    function shouldSkipRevealTarget(el) {
        return !el || el.nodeType !== 1 || Boolean(
            el.matches && el.matches(REVEAL_CONTAINER_SELECTOR) && !el.matches(REVEAL_ANCHOR_SELECTOR) &&
            el.querySelector && el.querySelector(REVEAL_ANCHOR_SELECTOR)
        );
    }

    function extractIpFromRevealElement(el) {
        if (shouldSkipRevealTarget(el)) return '';
        let rawText = '';
        if (el.childNodes && el.childNodes.length > 0) {
            const chunks = [];
            for (const c of el.childNodes) {
                if (c && c.nodeType === 1 && c.matches && c.matches('.' + BADGE_CLASS)) continue;
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

    function processAnchor(anchor) {
        if (accessBlocked || !anchor || !anchor.dataset || !anchor.parentNode || shouldSkipRevealTarget(anchor) || anchor.dataset.proxycheckProcessed) return;
        const ip = extractIpFromRevealElement(anchor);
        if (!ip) return;
        const existingNext = anchor.nextElementSibling;
        if (existingNext && existingNext.classList && existingNext.classList.contains(BADGE_CLASS)) { anchor.dataset.proxycheckProcessed = 'true'; return; }

        ensureUserscriptStyles();
        anchor.dataset.proxycheckProcessed = 'pending';
        const badge = createEl('a', `${BADGE_CLASS} proxycheck-ip-badge-loading`, '[…]', { title: 'Checking IP intelligence...', 'aria-busy': 'true' });
        attachBadgeClick(badge, null);
        anchor.parentNode.insertBefore(badge, anchor.nextSibling);
        const removePlaceholder = () => { if (badge.parentNode) badge.parentNode.removeChild(badge); delete anchor.dataset.proxycheckProcessed; };

        ensureConsent(false).then((agreed) => {
            if (agreed) return fetchIpIntelligence(ip, 'light');
            if (accessBlocked || anchor.dataset.proxycheckProcessed !== 'pending') { removePlaceholder(); return null; }
            anchor.dataset.proxycheckProcessed = 'consent-declined';
            updateActionBadge(badge, {
                extraClass: 'proxycheck-ip-badge-consent', text: '[ProxyCheck]',
                title: 'ProxyCheck consent required. Click to review policy and enable.',
                onClick: () => ensureConsent(true).then((ok) => { if (ok && !accessBlocked) resumeAfterConsent(); })
            });
            return null;
        }).then((data) => {
            if (!data) {
                if (anchor.dataset.proxycheckProcessed === 'consent-declined') return;
                if (accessBlocked || !anchor.parentNode || anchor.dataset.proxycheckProcessed !== 'pending') { removePlaceholder(); return; }
                anchor.dataset.proxycheckProcessed = 'error';
                updateActionBadge(badge, {
                    extraClass: 'proxycheck-ip-badge-error', text: '[Retry]', title: 'ProxyCheck lookup failed. Click to retry.',
                    onClick: (el) => { if (el.parentNode) el.parentNode.removeChild(el); invalidateIpResultCache(ip); delete anchor.dataset.proxycheckProcessed; processAnchor(anchor); }
                });
                return;
            }
            if (!anchor.parentNode || shouldSkipRevealTarget(anchor)) { removePlaceholder(); return; }
            if (anchor.dataset.proxycheckProcessed === 'true') return;
            const resolvedIp = data.ip || ip;
            badge.removeAttribute('aria-busy');
            badge.removeAttribute('role');
            badge.target = '_blank';
            badge.rel = 'noopener noreferrer';
            attachBadgeClick(badge, () => {
                const k = canonicalizeIpKey(resolvedIp) || canonicalizeIpKey(ip), cur = (k && getIpData(k)) || data;
                showInfoDialog(cur, cur.ip || resolvedIp);
            });
            applyRiskStylingToAnchorAndBadge(anchor, badge, data, resolvedIp);
            registerRenderedBadge(canonicalizeIpKey(resolvedIp) || canonicalizeIpKey(ip), anchor, badge, resolvedIp);
            if (badge.parentNode !== anchor.parentNode || anchor.nextElementSibling !== badge) anchor.parentNode.insertBefore(badge, anchor.nextSibling);
            anchor.dataset.proxycheckProcessed = 'true';
        });
    }

    function isIpInfoPanelMutation(target, addedNode) {
        if (target && target.closest && target.closest(IPINFO_PANEL_SELECTOR)) return true;
        return Boolean(addedNode && addedNode.nodeType === 1 &&
            ((addedNode.matches && addedNode.matches(IPINFO_PANEL_SELECTOR)) || (addedNode.querySelector && addedNode.querySelector(IPINFO_PANEL_SELECTOR))));
    }

    function scheduleIpContributionsUpdate(shouldRefreshSpur) {
        pendingContributionsPageCheck = true;
        if (shouldRefreshSpur) pendingSpurRefresh = true;
        if (ipContributionsObserverTimer !== null) return;
        ipContributionsObserverTimer = window.setTimeout(() => {
            ipContributionsObserverTimer = null;
            const runPage = pendingContributionsPageCheck, runSpur = pendingSpurRefresh;
            pendingContributionsPageCheck = pendingSpurRefresh = false;
            if (accessBlocked || !isIpContributionsPage) return;
            if (runPage) handleIPContributionsPage();
            if (runSpur && typeof refreshPageInfoSpur === 'function') refreshPageInfoSpur();
        }, OBSERVER_THROTTLE_MS);
    }

    function scheduleAnchor(anchor) {
        if (accessBlocked || !anchor || !anchor.dataset || anchor.dataset.proxycheckProcessed || shouldSkipRevealTarget(anchor)) return;
        if (isIpContributionsPage && !ipContributionsInvalidTarget) handleIPContributionsPage(true);
        processAnchor(anchor);
    }

    function scanSubtree(root) {
        if (accessBlocked || !root || root.nodeType !== 1 || isProxycheckInternalNode(root)) return;
        if (root.matches && root.matches(TARGET_SELECTOR)) scheduleAnchor(root);
        for (const anchor of root.querySelectorAll(TARGET_SELECTOR)) scheduleAnchor(anchor);
    }

    function extractContributionsTargetIp() {
        let target = mw.config.get('wgRelevantUserName');
        if (!target) {
            const parts = (mw.config.get('wgTitle') || '').split('/');
            if (parts.length > 1) target = parts.slice(1).join('/');
        }
        if (!target) {
            target = (mw.util && typeof mw.util.getParamValue === 'function')
                ? mw.util.getParamValue('target')
                : new URLSearchParams(typeof window !== 'undefined' && window.location ? window.location.search : '').get('target');
        }
        return typeof target === 'string' ? target.trim() : '';
    }

    function isTemporaryAccountIdentifier(userText) {
        if (typeof userText !== 'string' || !userText.trim()) return false;
        const trimmed = userText.trim();
        return mw && mw.util && typeof mw.util.isTemporaryUser === 'function'
            ? Boolean(mw.util.isTemporaryUser(trimmed)) : /^~\d{4}-/.test(trimmed);
    }

    function collectRevealedIpsInDom() {
        if (typeof document === 'undefined' || !document.body) return [];
        const discovered = [], seen = Object.create(null);
        for (const el of document.body.querySelectorAll(TARGET_SELECTOR)) {
            if (!el || isProxycheckInternalNode(el) || shouldSkipRevealTarget(el)) continue;
            const ip = extractIpFromRevealElement(el), canonical = ip ? canonicalizeIpKey(ip) : '';
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
            ['#mw-content-text .mw-contributions-header, .mw-contributions-header', 'before'],
            ['#mw-content-text .mw-contributions-list, .mw-contributions-list', 'before'],
            ['#mw-content-text .mw-contributions-form, .mw-contributions-form', 'after'],
            ['#contentSub', 'after'],
            ['#mw-content-text, #contentSub', 'prepend']
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
        const latest = getIpData(key);
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

        ipContributionsFallbackTimer = clearTimer(ipContributionsFallbackTimer, false);
        ipContributionsPending = true;
        let $box = null, $switcher = null, $result = null;
        const stopLoading = () => { activeLoadingInterval = clearTimer(activeLoadingInterval, true); };
        const isNodeInDoc = (node) => Boolean(node) && (typeof document === 'undefined' || !document.body || document.body.contains(node));
        const mountBanner = (target) => {
            if (!$box || $box.length === 0 || !target || !target.$element || target.$element.length === 0) return false;
            const existing = document.getElementById('proxycheck-pageinfo');
            if (existing && existing !== $box[0] && existing.parentNode) existing.parentNode.removeChild(existing);
            target.$element[target.method]($box);
            return true;
        };
        const ensureBannerAttached = () => Boolean($box && $box.length > 0 && $box[0] &&
            (isNodeInDoc($box[0]) || mountBanner(resolveContributionsMountTarget(effectiveAllowFallback) || resolveContributionsMountTarget(true))));
        const removeUnpopulatedBanner = () => {
            stopLoading();
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

            $box = $('<div>', { id: 'proxycheck-pageinfo', class: 'proxycheck-pageinfo-banner' });
            $switcher = $('<div>', { class: 'proxycheck-temp-ip-switcher', style: 'display: none;' });
            $result = $('<span>', { id: 'proxycheck_result', text: '.' });
            $box.append($switcher, $result);
            mountBanner(activeTarget);

            let currentTargetIp = initialTargetIp, currentCanonicalKey = canonicalizeIpKey(currentTargetIp);
            let userPinnedKey = null, currentDiscoveredList = discoveredTempIps.slice(), currentDiscoveredSig = '';
            let isStatsExpanded = false, activeBannerDetailsPanel = null, bannerLoadSeq = 0;
            const fullUpgradeRequestedForKey = Object.create(null);
            const computeSig = (list) => list.map((e) => e.canonicalKey).join('|');

            const renderMultiIpSwitcher = () => {
                if (!$switcher) return;
                $switcher.empty();
                if (!isTempAccountTarget || currentDiscoveredList.length <= 1) { $switcher.css('display', 'none'); return; }
                $switcher.css('display', 'flex').append($('<span>', { class: 'proxycheck-temp-ip-subtitle', text: `${currentDiscoveredList.length} distinct revealed IPs on this page:` }));
                for (const entry of currentDiscoveredList) {
                    const selected = entry.canonicalKey === currentCanonicalKey;
                    $switcher.append($('<button>', {
                        type: 'button', class: 'proxycheck-ip-pill' + (selected ? ' proxycheck-ip-pill-active' : ''),
                        'aria-pressed': selected ? 'true' : 'false', text: entry.displayIp
                    }).on('click', (e) => {
                        e.preventDefault(); e.stopPropagation();
                        if (!accessBlocked && entry.canonicalKey !== currentCanonicalKey) { userPinnedKey = entry.canonicalKey; switchInspectedBannerIp(entry.displayIp, true); }
                    }));
                }
            };

            const renderBannerFailure = (failedIp) => {
                if (!$result || $result.length === 0) return;
                if (accessBlocked) { $result.text('[ProxyCheck] Access denied or disabled'); return; }
                const $retry = $('<a>', { href: '#', role: 'button', class: 'proxycheck-banner-retry', text: 'Retry ↻' }).on('click', (e) => {
                    e.preventDefault(); e.stopPropagation();
                    if (accessBlocked) return;
                    stopLoading(); clearContributionsSchedule();
                    invalidateIpResultCache(failedIp);
                    switchInspectedBannerIp(failedIp, true);
                });
                $result.empty().append(document.createTextNode('[ProxyCheck] Failed to acquire data '), $retry);
            };

            const renderBannerData = (bannerData, isJustUpdated) => {
                disposeDetailsPanel(activeBannerDetailsPanel);
                activeBannerDetailsPanel = null;
                const risk = evaluateRisk(bannerData), resolvedIp = bannerData.ip || currentTargetIp, resolvedKey = canonicalizeIpKey(resolvedIp) || currentCanonicalKey;
                const $activeBox = ($box && $box.length > 0) ? $box : $('#proxycheck-pageinfo');
                if ($activeBox && $activeBox.length > 0 && $activeBox[0] && $activeBox[0].classList) {
                    $activeBox[0].classList.remove('proxycheck-banner-tier-high', 'proxycheck-banner-tier-medium', 'proxycheck-banner-tier-nonpublic', 'proxycheck-banner-tier-low');
                    $activeBox[0].classList.add('proxycheck-banner-tier-' + risk.riskTier);
                }
                renderMultiIpSwitcher();
                const badgeClass = 'proxycheck-banner-badge proxycheck-tier-' + risk.riskTier;
                if (risk.isNonPublic) {
                    $result.empty().append(
                        $('<span>', { class: badgeClass, text: `ProxyCheck [${risk.nonPublicBadgeCode}]` }),
                        $('<span>').append(document.createTextNode(' \u00b7 '), $('<b>').text('Address Type:'), document.createTextNode(` ${risk.nonPublicReason} \u00b7 `), $('<b>').text('Status:'), document.createTextNode(' External threat lookups skipped (non-public or reserved IP) \u00b7 ')),
                        $('<a>', { href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp), target: '_blank', rel: 'noopener noreferrer', text: 'Full Report ↗' })
                    );
                    return;
                }

                const torDesc = formatTorDescription(risk), sharedDesc = formatSharedDescription(bannerData, risk);
                const verdictText = typeof bannerData.arbitrationVerdict === 'string' ? bannerData.arbitrationVerdict.trim() : '';
                const ptrHost = typeof bannerData.ptrHostname === 'string' ? bannerData.ptrHostname.trim() : '';
                const ptrLbl = typeof bannerData.ptrLabel === 'string' ? bannerData.ptrLabel.trim() : '';
                const $summary = $('<div>', { class: 'proxycheck-summary-line' }).append($('<span>', { class: badgeClass, text: 'ProxyCheck' }));
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
                        if (ptrLbl) $ptr.append(document.createTextNode(' '), $('<span>', { class: bannerData.ptrIsHighRisk ? 'proxycheck-ptr-label-risk' : 'proxycheck-ptr-label-normal', text: `(${ptrLbl})` }));
                    } else $ptr.text(ptrLbl);
                    addItem('PTR', $ptr);
                }
                if (sharedDesc) addItem('Shared Egress', $('<strong>', { class: 'proxycheck-banner-danger-text', text: sharedDesc }));
                if (isMobileOrCgnatPayload(bannerData)) addItem('Network', $('<strong>', { class: 'proxycheck-banner-warning-text', text: 'Mobile / CGNAT (/32 IPv4, /64 IPv6 lock)' }));
                addItem('Broadcast IP', risk.broadcastIp ? $('<strong>', { class: 'proxycheck-banner-warning-text', text: 'At-risk' }) : document.createTextNode('No'));
                addItem('Tor Node', risk.isTor ? $('<strong>', { class: 'proxycheck-banner-danger-text', text: torDesc }) : document.createTextNode('No'));

                let renderedSpur = getSpurProxyText();
                activeBannerDetailsPanel = buildResultDetailsPanel(bannerData, risk, resolvedIp);
                const $detailsWrapper = $('<div>', { class: 'proxycheck-pageinfo-details', style: isStatsExpanded ? 'display: block;' : 'display: none;' }).append(activeBannerDetailsPanel);
                refreshPageInfoSpur = () => {
                    const latestSpur = getSpurProxyText();
                    if (latestSpur === renderedSpur) return;
                    renderedSpur = latestSpur;
                    disposeDetailsPanel(activeBannerDetailsPanel);
                    $detailsWrapper.empty().append((activeBannerDetailsPanel = buildResultDetailsPanel(bannerData, risk, resolvedIp)));
                };

                const $statsToggle = $('<a>', {
                    href: '#', role: 'button', class: 'proxycheck-stats-toggle',
                    'aria-expanded': isStatsExpanded ? 'true' : 'false', text: isStatsExpanded ? 'Statistic ▾' : 'Statistic ▸'
                }).on('click', (e) => {
                    e.preventDefault(); e.stopPropagation();
                    isStatsExpanded = !isStatsExpanded;
                    $detailsWrapper.css('display', isStatsExpanded ? 'block' : 'none');
                    $statsToggle.attr('aria-expanded', isStatsExpanded ? 'true' : 'false').text(isStatsExpanded ? 'Statistic ▾' : 'Statistic ▸');
                    if (isStatsExpanded && isPartialLightResult(bannerData) && !fullUpgradeRequestedForKey[resolvedKey]) {
                        fullUpgradeRequestedForKey[resolvedKey] = true;
                        clearContributionsSchedule();
                        attachLightUpgrade($detailsWrapper, resolvedIp, () => ensureBannerAttached() && currentCanonicalKey === resolvedKey, (fullData) => renderBannerData(fullData, false));
                    }
                });

                const refreshCtrl = createRefreshControl({
                    getIp: () => resolvedIp, isActive: ensureBannerAttached,
                    getGuard: () => `${bannerLoadSeq}:${currentCanonicalKey}`, onSuccess: (freshData) => renderBannerData(freshData, true)
                });
                refreshCtrl.sync(bannerData, isJustUpdated);
                $summary.append(
                    document.createTextNode(' \u00b7 '),
                    $('<a>', { href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp), target: '_blank', rel: 'noopener noreferrer', text: 'Full Report ↗' }),
                    document.createTextNode(' \u00b7 '), $statsToggle,
                    document.createTextNode(' \u00b7 '), $('<span>', { class: 'proxycheck-cache-controls' }).append(refreshCtrl.$ageSpan, refreshCtrl.$btn)
                );
                $result.empty().append($summary, refreshCtrl.$warning, $detailsWrapper);
                if (!isPartialLightResult(bannerData) && shouldAutoRefreshPayload(bannerData, resolvedKey)) refreshCtrl.run(true);
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
                stopLoading(); clearContributionsSchedule();
                currentTargetIp = nextIp;
                currentCanonicalKey = canonicalizeIpKey(nextIp);
                const activeSeq = ++bannerLoadSeq;
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
                activeLoadingInterval = window.setInterval(() => { $result.text(frames[(frameIdx = (frameIdx + 1) % frames.length)]); }, 300);

                const runFullFetch = () => fetchIpIntelligence(nextIp, 'full').then((data) => {
                    if (activeSeq !== bannerLoadSeq) return null;
                    stopLoading();
                    if (!ensureBannerAttached()) return null;
                    if (!data) { renderBannerFailure(nextIp); return null; }
                    renderBannerData(data, false);
                    return data;
                }).catch((err) => {
                    if (activeSeq !== bannerLoadSeq) return null;
                    stopLoading();
                    warn('Contributions banner data failed:', err);
                    if (ensureBannerAttached()) renderBannerFailure(nextIp);
                    return null;
                });

                if (immediateFetch) return runFullFetch();
                return new Promise((resolve) => {
                    ipContributionsDelayTimer = window.setTimeout(() => {
                        ipContributionsDelayTimer = null;
                        if (activeSeq !== bannerLoadSeq) return resolve(null);
                        if (accessBlocked) { stopLoading(); return resolve(null); }
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
        }).catch((err) => { stopLoading(); ipContributionsPending = false; warn('Contributions banner update failed:', err); });
    }

    $(() => {
        ensureUserscriptStyles();
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
                const matched = (targetEl.matches && targetEl.matches(TARGET_SELECTOR))
                    ? targetEl : (targetEl.closest ? targetEl.closest(TARGET_SELECTOR) : null);
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
