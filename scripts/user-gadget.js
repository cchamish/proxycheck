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
    const WIKI_DBNAME = String(mw.config.get('wgDBname') || '').trim().toLowerCase();
    const isIpContributionsPage = (() => {
        const specialName = mw.config.get('wgCanonicalSpecialPageName');
        if (specialName) return specialName === 'IPContributions' || specialName === 'Contributions' || specialName === 'IContributions';
        return /^[^:]+:(IPContributions|IContributions|Contributions)(\/|$)/i.test(mw.config.get('wgPageName') || '');
    })();

    const ipStateMap = new Map();
    const renderedBadgeEntriesByIp = new Map();
    const autoSwrAttemptedKeys = new Set();
    const riskCache = new WeakMap();
    const requestQueue = [];
    const pendingBatchQueue = [];

    let accessBlocked = false;
    let observer = null;
    let storageFailureWarned = false;
    let persistedCacheRaw = null;
    let persistedCacheStore = null;
    let memoryAutoSwrTimestamps = [];
    let consentGranted = false;
    let consentDeclined = false;
    let consentPromise = null;
    let authPromise = null;
    let memoryToken = null;
    let memoryTokenExpiry = null;
    let memoryTokenCooldownUntil = 0;
    let cancelTokenVisibilityWait = null;
    let activeRequestCount = 0;
    let batchEndpointSupported = true;
    let batchDebounceTimer = null;
    let infoDialoguePromise = null;
    let contributionsBanner = null;
    let contributionsPending = false;
    let contributionsInvalidTarget = false;
    let contributionsObserverTimer = null;
    let contributionsFallbackTimer = null;
    let contributionsDelayTimer = null;
    let contributionsVisibilityHandler = null;
    let pendingSpurRefresh = false;

    const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);

    function warn(msg, err) {
        console.warn('[proxycheck] ' + msg, err !== undefined ? err : '');
    }

    function warnStorageOnce(context, err) {
        if (storageFailureWarned) return;
        storageFailureWarned = true;
        warn('Storage ' + context + ':', err);
    }

    function storageGet(store, key) {
        try {
            return store ? store.get(key) : null;
        } catch (err) {
            warnStorageOnce('read failed', err);
            return null;
        }
    }

    function storageSet(store, key, value) {
        try {
            return store ? store.set(key, value) : false;
        } catch (err) {
            warnStorageOnce('write failed', err);
            return false;
        }
    }

    function storageRemove(store, key) {
        try {
            if (store) store.remove(key);
        } catch (err) {
            warnStorageOnce('remove failed', err);
        }
    }

    function sessionStore() {
        return mw.storage && mw.storage.session;
    }

    function isDocumentVisible() {
        return typeof document.visibilityState !== 'string' || document.visibilityState === 'visible';
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

    function canonicaliseIpKey(rawIp) {
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

    function blockAccess() {
        accessBlocked = true;
        if (cancelTokenVisibilityWait) cancelTokenVisibilityWait();
        clearContributionsSchedule();
        window.clearTimeout(contributionsObserverTimer);
        window.clearTimeout(contributionsFallbackTimer);
        window.clearTimeout(batchDebounceTimer);
        contributionsObserverTimer = contributionsFallbackTimer = batchDebounceTimer = null;
        pendingSpurRefresh = false;
        pendingBatchQueue.splice(0).forEach((item) => item.resolve(null));
        requestQueue.splice(0).forEach((item) => item.resolve(null));
        if (observer) observer.disconnect();
        for (const el of document.body.querySelectorAll(`.${BADGE_CLASS}.proxycheck-ip-badge-loading`)) {
            const prev = el.previousElementSibling;
            if (prev && prev.dataset && prev.dataset.proxycheckProcessed === 'pending') delete prev.dataset.proxycheckProcessed;
            el.remove();
        }
    }

    function isRowQuotaGuarded(row) {
        return Boolean(row && typeof row === 'object' && (row.isQuotaGuarded || row.isQuotaGuard));
    }

    function hasDegradedQuotaOrCooldown(data) {
        return Boolean(data && Array.isArray(data.results) && data.results.some((r) => r && typeof r === 'object' &&
            (isRowQuotaGuarded(r) || (r.isCooldown && (!r.provider || hasOwn(COMMERCIAL_PROVIDERS, r.provider))))));
    }

    function resultTtlMs(data) {
        return hasDegradedQuotaOrCooldown(data) ? DEGRADED_CACHE_TTL_MS : RESULT_CACHE_TTL_MS;
    }

    function isPartialLightResult(data) {
        return Boolean(data && typeof data === 'object' && data.queryMode === 'light' && data.isPartialMode);
    }

    function isResultEntryValid(entry, now) {
        if (!entry || typeof entry !== 'object' || typeof entry.ts !== 'number' || !isFinite(entry.ts) || !entry.data || typeof entry.data !== 'object') return false;
        const ttlMs = typeof entry.ttlMs === 'number' && isFinite(entry.ttlMs) && entry.ttlMs > 0
            ? Math.min(entry.ttlMs, RESULT_CACHE_TTL_MS) : resultTtlMs(entry.data);
        return now - entry.ts < ttlMs;
    }

    function readPersistedResultStore() {
        const raw = storageGet(mw.storage, RESULT_CACHE_STORAGE_KEY);
        if (typeof raw !== 'string' || !raw) {
            persistedCacheRaw = persistedCacheStore = null;
            return null;
        }
        if (raw === persistedCacheRaw && persistedCacheStore) return persistedCacheStore;
        try {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === 'object' && parsed.entries && typeof parsed.entries === 'object' && !Array.isArray(parsed.entries)) {
                persistedCacheRaw = raw;
                persistedCacheStore = parsed;
                return parsed;
            }
        } catch (err) {
            warnStorageOnce('result cache parse failed', err);
        }
        persistedCacheRaw = persistedCacheStore = null;
        storageRemove(mw.storage, RESULT_CACHE_STORAGE_KEY);
        return null;
    }

    function savePersistedEntries(entries, protectedKey) {
        persistedCacheRaw = persistedCacheStore = null;
        const count = Object.keys(entries).length;
        const limits = count === 0 ? [0] : Array.from(new Set([count, Math.floor(RESULT_CACHE_MAX_ENTRIES / 2), 20, 1]));
        for (const limit of limits) {
            const keys = Object.keys(entries);
            if (keys.length > limit) {
                keys.map((key, order) => ({ key, ts: entries[key].ts, order, isProtected: key === protectedKey }))
                    .sort((a, b) => (a.isProtected !== b.isProtected ? (a.isProtected ? 1 : -1) : (a.ts !== b.ts ? a.ts - b.ts : a.order - b.order)))
                    .slice(0, keys.length - limit)
                    .forEach(({ key }) => delete entries[key]);
            }
            const store = { entries };
            const serialised = JSON.stringify(store);
            if (storageSet(mw.storage, RESULT_CACHE_STORAGE_KEY, serialised) !== false) {
                persistedCacheRaw = serialised;
                persistedCacheStore = store;
                return;
            }
        }
    }

    function removePersistedEntry(key) {
        const store = readPersistedResultStore();
        if (!store || !hasOwn(store.entries, key)) return;
        const now = Date.now(), entries = Object.create(null);
        for (const [k, v] of Object.entries(store.entries)) {
            if (k !== key && isResultEntryValid(v, now)) entries[k] = v;
        }
        savePersistedEntries(entries, null);
    }

    function writePersistedEntry(key, data) {
        const store = readPersistedResultStore(), now = Date.now(), entries = Object.create(null);
        const current = store && store.entries[key];
        if (isPartialLightResult(data) && isResultEntryValid(current, now) && !isPartialLightResult(current.data)) return;
        if (store) {
            for (const [k, v] of Object.entries(store.entries)) {
                if (k !== key && isResultEntryValid(v, now)) entries[k] = v;
            }
        }
        entries[key] = { ts: now, ttlMs: resultTtlMs(data), data };
        savePersistedEntries(entries, key);
    }

    function readPersistedIpResultEntry(cacheKey) {
        const store = readPersistedResultStore();
        if (!store || !hasOwn(store.entries, cacheKey)) return null;
        const entry = store.entries[cacheKey];
        if (isResultEntryValid(entry, Date.now())) return entry;
        removePersistedEntry(cacheKey);
        return null;
    }

    function invalidateIpResultCache(ip) {
        for (const key of new Set([canonicaliseIpKey(ip), String(ip).trim().toLowerCase()])) {
            if (!key) continue;
            ipStateMap.delete(key);
            removePersistedEntry(key);
        }
    }

    function getOrCreateIpState(key) {
        let entry = ipStateMap.get(key);
        if (!entry) ipStateMap.set(key, (entry = { lightPromise: null, fullPromise: null, inflightFull: null, inflightRefresh: null, data: null, fullTs: 0, fullTtlMs: 0 }));
        return entry;
    }

    function getIpData(key) {
        const entry = key ? ipStateMap.get(key) : null;
        return entry ? entry.data : null;
    }

    function isMemoryFullResultFresh(cacheKey, data) {
        if (!data || typeof data !== 'object' || isPartialLightResult(data)) return false;
        const st = ipStateMap.get(cacheKey);
        return st && st.fullTs > 0 ? (Date.now() - st.fullTs) < st.fullTtlMs : !hasDegradedQuotaOrCooldown(data);
    }

    function recordIpResult(cacheKey, data, timestampMs) {
        const st = getOrCreateIpState(cacheKey);
        if (isPartialLightResult(data)) {
            if (!st.data || isPartialLightResult(st.data)) st.data = data;
            return;
        }
        st.data = data;
        st.fullTs = timestampMs;
        st.fullTtlMs = resultTtlMs(data);
    }

    function storeResolvedResult(cacheKey, data, promise) {
        const isFull = !isPartialLightResult(data), now = Date.now();
        const resolvedKey = typeof data.ip === 'string' ? canonicaliseIpKey(data.ip) : '';
        const keys = resolvedKey && resolvedKey !== cacheKey ? [cacheKey, resolvedKey] : [cacheKey];
        for (const key of keys) {
            const st = getOrCreateIpState(key);
            recordIpResult(key, data, now);
            if (!st.lightPromise || isFull) st.lightPromise = promise;
            if (isFull && !st.fullPromise) st.fullPromise = promise;
            writePersistedEntry(key, data);
        }
    }

    function peekCachedIpState(ip) {
        const key = canonicaliseIpKey(ip);
        if (!key) return null;
        const latest = getIpData(key);
        if (isMemoryFullResultFresh(key, latest)) return { data: latest, isFull: true };
        const persisted = readPersistedIpResultEntry(key);
        if (persisted) return { data: persisted.data, isFull: !isPartialLightResult(persisted.data) };
        return latest ? { data: latest, isFull: false } : null;
    }

    function tryConsumeAutoSwrBudget() {
        const now = Date.now();
        const raw = storageGet(mw.storage, AUTO_SWR_STORAGE_KEY);
        let recent = memoryAutoSwrTimestamps;
        if (typeof raw === 'string' && raw) {
            try {
                recent = JSON.parse(raw);
            } catch (err) {
                warnStorageOnce('auto-refresh limiter parse failed', err);
                recent = [];
            }
        }
        recent = Array.isArray(recent) ? recent.filter((ts) => typeof ts === 'number' && isFinite(ts) && (now - ts) > -5000 && (now - ts) < AUTO_SWR_WINDOW_MS) : [];
        const allowed = recent.length < AUTO_SWR_MAX_REQUESTS;
        if (allowed) recent.push(now);
        memoryAutoSwrTimestamps = recent.slice();
        storageSet(mw.storage, AUTO_SWR_STORAGE_KEY, JSON.stringify(recent));
        return allowed;
    }

    function ensureConsent(forcePrompt) {
        if (accessBlocked) return Promise.resolve(false);
        if (consentGranted || storageGet(mw.storage, CONSENT_KEY) === '1') {
            consentGranted = true;
            consentDeclined = false;
            return Promise.resolve(true);
        }
        if (consentDeclined && !forcePrompt) return Promise.resolve(false);
        if (consentPromise) return consentPromise;

        consentDeclined = false;
        consentPromise = mw.loader.using('oojs-ui-windows').then(() => {
            const policyLink = (href, text) => $('<li>').append($('<a>', { href, target: '_blank', rel: 'noopener noreferrer', text }));
            const $msg = $('<div>').append(
                $('<p>').text('By using this script, you acknowledge that you fully understand and agree to comply with:'),
                $('<ul>').append(
                    policyLink('https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_Access_to_Nonpublic_Personal_Data_Policy', 'Wikimedia Foundation Access to Nonpublic Personal Data Policy'),
                    policyLink('https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy', 'Wikimedia Foundation Privacy Policy')
                ),
                $('<p>').text('and all other applicable policies and guidelines regarding Temporary Account IP reveal.'),
                $('<p>').text('Do you agree and wish to proceed?')
            );
            return OO.ui.confirm($msg, { title: 'Proxycheck on Temporary Account IP', size: 'medium' });
        }).catch((err) => {
            warn('Consent dialogue failed:', err);
            return false;
        }).then((agreed) => {
            consentPromise = null;
            consentGranted = Boolean(agreed);
            consentDeclined = !agreed;
            if (agreed) storageSet(mw.storage, CONSENT_KEY, '1');
            return Boolean(agreed);
        });
        return consentPromise;
    }

    function clearStoredToken() {
        memoryToken = memoryTokenExpiry = null;
        [TOKEN_KEY, TOKEN_USER_KEY, TOKEN_EXPIRY_KEY].forEach((key) => storageRemove(sessionStore(), key));
    }

    function readStoredToken() {
        const store = sessionStore();
        const storedUser = storageGet(store, TOKEN_USER_KEY), token = storageGet(store, TOKEN_KEY), storedExpiry = storageGet(store, TOKEN_EXPIRY_KEY);
        const hasExpiry = (typeof storedExpiry === 'string' && storedExpiry.trim() !== '') || (typeof storedExpiry === 'number' && isFinite(storedExpiry));
        if (hasExpiry && (!isFinite(Number(storedExpiry)) || Date.now() >= Number(storedExpiry))) {
            clearStoredToken();
            return null;
        }
        if (typeof token === 'string' && token) {
            if (storedUser !== username) {
                clearStoredToken();
                return null;
            }
            memoryToken = token;
            memoryTokenExpiry = hasExpiry ? Number(storedExpiry) : null;
            return token;
        }
        const isForeignUser = typeof storedUser === 'string' && storedUser !== '' && storedUser !== username;
        const isMemoryTokenExpired = Boolean(memoryToken && memoryTokenExpiry !== null && Date.now() >= memoryTokenExpiry);
        if (isForeignUser || isMemoryTokenExpired) {
            clearStoredToken();
            return null;
        }
        return memoryToken;
    }

    function isTokenExchangeCoolingDown() {
        const now = Date.now();
        const maxAllowedUntil = now + (TOKEN_COOLDOWN_MAX_SECONDS * (1 + TOKEN_COOLDOWN_JITTER_RATIO) + 5) * 1000;
        let until = memoryTokenCooldownUntil > maxAllowedUntil ? 0 : memoryTokenCooldownUntil;
        const raw = storageGet(mw.storage, TOKEN_COOLDOWN_UNTIL_KEY);
        if (typeof raw === 'string' && raw.trim() !== '') {
            const stored = Number(raw);
            if (!isFinite(stored) || stored <= now || stored > maxAllowedUntil) storageRemove(mw.storage, TOKEN_COOLDOWN_UNTIL_KEY);
            else until = Math.max(until, stored);
        }
        memoryTokenCooldownUntil = until > now ? until : 0;
        return memoryTokenCooldownUntil > 0;
    }

    function exchangeGadgetToken(failedToken) {
        const visible = isDocumentVisible() ? Promise.resolve(true) : new Promise((resolve) => {
            const finish = (canProceed) => {
                document.removeEventListener('visibilitychange', onVisibilityChange);
                cancelTokenVisibilityWait = null;
                resolve(canProceed);
            };
            const onVisibilityChange = () => {
                if (accessBlocked) finish(false);
                else if (isDocumentVisible()) finish(true);
            };
            document.addEventListener('visibilitychange', onVisibilityChange);
            cancelTokenVisibilityWait = () => finish(false);
        });

        return visible.then((canProceed) => {
            if (!canProceed || accessBlocked) return null;
            const latest = readStoredToken();
            if (latest && latest !== failedToken) return latest;
            if (isTokenExchangeCoolingDown()) return null;
            clearStoredToken();

            return Promise.resolve(mw.loader.using('mediawiki.api')).then(() => {
                if (accessBlocked || isTokenExchangeCoolingDown()) return null;
                return new mw.Api().get({ action: 'centralauthtoken' }).then((d) => d, (code, details) => {
                    warn('centralauthtoken request failed:', { code, details });
                    return null;
                });
            }).then((apiData) => {
                if (accessBlocked) return null;
                const centralAuthToken = apiData && apiData.centralauthtoken && apiData.centralauthtoken.centralauthtoken;
                if (!centralAuthToken || typeof centralAuthToken !== 'string') {
                    if (apiData) warn('Missing centralauthtoken:', apiData);
                    return null;
                }
                return fetch(TOOL_BASE_URL + '/api/v1/auth/gadget-token', {
                    method: 'POST', mode: 'cors', credentials: 'omit', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ centralauthtoken: centralAuthToken, domain: mw.config.get('wgServerName') })
                });
            }).then((res) => {
                if (!res) return null;
                if (res.status === 429) {
                    return res.json().catch(() => null).then((body) => {
                        warn('Gadget token HTTP 429:', body);
                        const headerRetry = parseInt(res.headers.get('Retry-After'), 10);
                        const retryAfter = body && typeof body.retryAfterSeconds === 'number' && isFinite(body.retryAfterSeconds)
                            ? body.retryAfterSeconds
                            : (isFinite(headerRetry) ? headerRetry : TOKEN_COOLDOWN_DEFAULT_SECONDS);
                        const seconds = Math.min(TOKEN_COOLDOWN_MAX_SECONDS, Math.max(TOKEN_COOLDOWN_MIN_SECONDS, retryAfter));
                        const jitterMs = Math.round(seconds * Math.random() * TOKEN_COOLDOWN_JITTER_RATIO * 1000);
                        memoryTokenCooldownUntil = Math.max(memoryTokenCooldownUntil, Date.now() + seconds * 1000 + jitterMs);
                        storageSet(mw.storage, TOKEN_COOLDOWN_UNTIL_KEY, String(memoryTokenCooldownUntil));
                        return null;
                    });
                }
                if (!res.ok) {
                    return res.text().then((text) => {
                        warn(`Gadget token HTTP ${res.status}:`, text);
                        if (res.status === 401 || res.status === 403) clearStoredToken();
                        if (res.status === 403) blockAccess();
                        return null;
                    });
                }
                return res.json().then((payload) => {
                    const token = payload && payload.token;
                    if (!token || typeof token !== 'string') {
                        warn('Token missing in response:', payload);
                        return null;
                    }
                    const expiresIn = payload.expires_in;
                    const store = sessionStore();
                    memoryToken = token;
                    memoryTokenExpiry = Number.isInteger(expiresIn) && expiresIn > 0 ? Date.now() + Math.max(0, expiresIn - 60) * 1000 : null;
                    storageSet(store, TOKEN_KEY, token);
                    storageSet(store, TOKEN_USER_KEY, username);
                    if (memoryTokenExpiry !== null) storageSet(store, TOKEN_EXPIRY_KEY, String(memoryTokenExpiry));
                    else storageRemove(store, TOKEN_EXPIRY_KEY);
                    return token;
                });
            });
        }).catch((err) => {
            warn('CentralAuth token exchange failed:', err);
            return null;
        });
    }

    function getGadgetToken(failedToken) {
        if (accessBlocked) return Promise.resolve(null);
        const stored = readStoredToken();
        if (stored && stored !== failedToken) return Promise.resolve(stored);
        if (!authPromise) {
            authPromise = exchangeGadgetToken(failedToken).then((token) => {
                authPromise = null;
                return token;
            });
        }
        return authPromise;
    }

    function drainRequestQueue() {
        while (!accessBlocked && activeRequestCount < MAX_CONCURRENT_REQUESTS && requestQueue.length > 0) {
            const { taskFn, resolve, reject } = requestQueue.shift();
            activeRequestCount += 1;
            const release = () => {
                activeRequestCount -= 1;
                drainRequestQueue();
            };
            new Promise((run) => run(taskFn())).then(
                (value) => { release(); resolve(value); },
                (err) => { release(); reject(err); }
            );
        }
    }

    function enqueueNetworkTask(taskFn) {
        if (accessBlocked) return Promise.resolve(null);
        return new Promise((resolve, reject) => {
            requestQueue.push({ taskFn, resolve, reject });
            drainRequestQueue();
        });
    }

    function authorisedFetch(path, init) {
        const attempt = (token, isRetry) => {
            if (!token || accessBlocked) return null;
            const headers = Object.assign({ Authorization: 'Bearer ' + token }, init.headers);
            return fetch(TOOL_BASE_URL + path, Object.assign({ mode: 'cors', credentials: 'omit' }, init, { headers })).then((res) => {
                if (res.status !== 401 && res.status !== 403) return res;
                if (res.status === 403 || isRetry) {
                    clearStoredToken();
                    blockAccess();
                    return null;
                }
                return getGadgetToken(token).then((freshToken) => attempt(freshToken, true));
            });
        };
        return getGadgetToken(null).then((token) => attempt(token, false));
    }

    function fetchDetect(ip, mode) {
        const wikiParam = WIKI_DBNAME ? `&wiki=${encodeURIComponent(WIKI_DBNAME)}` : '';
        const path = `/api/v1/detect?ip=${encodeURIComponent(ip)}&compact=1&mode=${mode}${wikiParam}`;
        return enqueueNetworkTask(() => authorisedFetch(path, { method: 'GET' }).then((res) => {
            if (!res) return null;
            if (!res.ok) {
                warn(`Detection API HTTP ${res.status} for ${ip}`);
                return null;
            }
            return res.json();
        }));
    }

    function flushPendingBatch() {
        window.clearTimeout(batchDebounceTimer);
        batchDebounceTimer = null;
        const fetchEachSingly = (items) => items.forEach((item) => fetchDetect(item.ip, 'light').then(item.resolve, item.reject));

        while (pendingBatchQueue.length > 0) {
            const items = pendingBatchQueue.splice(0, MAX_BATCH_IPS);
            if (!batchEndpointSupported) {
                fetchEachSingly(items);
                continue;
            }
            const uniqueIps = [], seen = Object.create(null);
            for (const item of items) {
                const key = canonicaliseIpKey(item.ip) || item.ip.toLowerCase();
                if (!seen[key]) { seen[key] = true; uniqueIps.push(item.ip); }
            }
            const body = { ips: uniqueIps, mode: 'light' };
            if (WIKI_DBNAME) body.wiki = WIKI_DBNAME;

            enqueueNetworkTask(() => {
                if (!batchEndpointSupported) return { fallbackSingle: true };
                return authorisedFetch('/api/v1/detect/batch?compact=1', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
                }).then((res) => {
                    if (!res) return null;
                    if (res.status === 404 || res.status === 405) {
                        batchEndpointSupported = false;
                        return { fallbackSingle: true };
                    }
                    if (!res.ok) {
                        warn(`Batch API HTTP ${res.status}`);
                        return null;
                    }
                    return res.json();
                });
            }).then((payload) => {
                if (payload && payload.fallbackSingle) {
                    window.clearTimeout(batchDebounceTimer);
                    batchDebounceTimer = null;
                    fetchEachSingly(items.concat(pendingBatchQueue.splice(0)));
                    return;
                }
                const results = payload && typeof payload === 'object' && payload.results && typeof payload.results === 'object' ? payload.results : null;
                const inputMap = payload && typeof payload === 'object' && payload.inputMap && typeof payload.inputMap === 'object' ? payload.inputMap : null;
                items.forEach((item) => {
                    if (!results) return item.resolve(null);
                    const trimmed = String(item.ip || '').trim(), lower = trimmed.toLowerCase(), canonical = canonicaliseIpKey(trimmed);
                    let match = null;
                    for (const k of [trimmed, lower, canonical]) {
                        if (k && hasOwn(results, k) && results[k]) { match = results[k]; break; }
                    }
                    if (!match && inputMap) {
                        const mapped = inputMap[item.ip] || inputMap[trimmed] || inputMap[lower] || (canonical ? inputMap[canonical] : '');
                        if (mapped && hasOwn(results, mapped) && results[mapped]) match = results[mapped];
                    }
                    if (!match && canonical) {
                        for (const [k, entry] of Object.entries(results)) {
                            if (canonicaliseIpKey(k) === canonical || (entry && typeof entry.ip === 'string' && canonicaliseIpKey(entry.ip) === canonical)) {
                                match = entry;
                                break;
                            }
                        }
                    }
                    item.resolve(match);
                });
            }, (err) => items.forEach((item) => item.reject(err)));
        }
    }

    function requestLightDetection(ip) {
        if (!batchEndpointSupported) return fetchDetect(ip, 'light');
        return new Promise((resolve, reject) => {
            pendingBatchQueue.push({ ip, resolve, reject });
            if (pendingBatchQueue.length >= MAX_BATCH_IPS) flushPendingBatch();
            else if (batchDebounceTimer === null) batchDebounceTimer = window.setTimeout(flushPendingBatch, BATCH_DEBOUNCE_MS);
        });
    }

    function fetchIpIntelligence(ip, mode) {
        if (accessBlocked || !isValidIp(ip)) return Promise.resolve(null);
        const cacheKey = canonicaliseIpKey(ip);
        if (!cacheKey) return Promise.resolve(null);
        const st = getOrCreateIpState(cacheKey);
        if (st.inflightFull) return st.inflightFull;
        if (st.fullPromise && st.data && st.fullTs > 0 && !isMemoryFullResultFresh(cacheKey, st.data)) {
            if (st.lightPromise === st.fullPromise) st.lightPromise = null;
            st.fullPromise = null;
            st.fullTs = st.fullTtlMs = 0;
        }
        if (st.fullPromise) return st.fullPromise;

        if (mode === 'full') {
            if (isMemoryFullResultFresh(cacheKey, st.data)) return (st.fullPromise = Promise.resolve(st.data));
            const persisted = readPersistedIpResultEntry(cacheKey);
            if (persisted && !isPartialLightResult(persisted.data)) {
                recordIpResult(cacheKey, persisted.data, persisted.ts);
                return (st.fullPromise = st.lightPromise = Promise.resolve(persisted.data));
            }
            const fullPromise = fetchDetect(ip, 'full').then((data) => {
                st.inflightFull = null;
                if (!data || typeof data !== 'object') return null;
                st.fullPromise = st.lightPromise = fullPromise;
                storeResolvedResult(cacheKey, data, fullPromise);
                return data;
            }).catch((err) => {
                st.inflightFull = null;
                warn(`Full detection failed for ${ip}:`, err);
                return null;
            });
            return (st.inflightFull = fullPromise);
        }

        if (st.lightPromise) return st.lightPromise;
        const persisted = readPersistedIpResultEntry(cacheKey);
        if (persisted) {
            recordIpResult(cacheKey, persisted.data, persisted.ts);
            st.lightPromise = Promise.resolve(persisted.data);
            if (!isPartialLightResult(persisted.data)) st.fullPromise = st.lightPromise;
            return st.lightPromise;
        }
        const lightPromise = requestLightDetection(ip).then((data) => {
            if (!data || typeof data !== 'object') {
                if (st.lightPromise === lightPromise) st.lightPromise = null;
                return null;
            }
            if (!isPartialLightResult(data) && !st.fullPromise) st.fullPromise = lightPromise;
            storeResolvedResult(cacheKey, data, lightPromise);
            return data;
        }).catch((err) => {
            warn(`Detection failed for ${ip}:`, err);
            if (st.lightPromise === lightPromise) st.lightPromise = null;
            return null;
        });
        return (st.lightPromise = lightPromise);
    }

    function refreshIpResult(ip) {
        const failure = (extra) => Object.assign({ ok: false, rateLimited: false, retryAfterSeconds: null, degradedFallback: false, data: null }, extra);
        const cacheKey = accessBlocked || !isValidIp(ip) ? '' : canonicaliseIpKey(ip);
        if (!cacheKey) return Promise.resolve(failure());
        const st = getOrCreateIpState(cacheKey);
        if (st.inflightRefresh) return st.inflightRefresh;

        const body = { ip, mode: 'full', compact: true };
        if (WIKI_DBNAME) body.wiki = WIKI_DBNAME;
        const refreshPromise = enqueueNetworkTask(() => authorisedFetch('/api/v1/detect/refresh', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        }).then((res) => {
            if (!res) return null;
            if (res.status === 429) {
                return res.json().catch(() => null).then((b) => ({
                    rateLimited: true, retryAfterSeconds: b && typeof b.retryAfterSeconds === 'number' ? b.retryAfterSeconds : null
                }));
            }
            if (!res.ok) {
                warn(`Refresh API HTTP ${res.status} for ${ip}`);
                return null;
            }
            return res.json().then((data) => ({ data }));
        })).then((res) => {
            st.inflightRefresh = null;
            autoSwrAttemptedKeys.add(cacheKey);
            const data = res && res.data;
            if (!data || typeof data !== 'object') {
                return failure({ rateLimited: Boolean(res && res.rateLimited), retryAfterSeconds: res && typeof res.retryAfterSeconds === 'number' ? res.retryAfterSeconds : null });
            }
            const resolvedKey = typeof data.ip === 'string' ? canonicaliseIpKey(data.ip) : '';
            if (resolvedKey) autoSwrAttemptedKeys.add(resolvedKey);

            const meta = getCacheMeta(data);
            if (meta && meta.degradedRefreshFallback === true) {
                const persisted = readPersistedIpResultEntry(cacheKey);
                const existing = st.data || (persisted && persisted.data);
                if (!existing) {
                    st.fullPromise = st.lightPromise = Promise.resolve(data);
                    storeResolvedResult(cacheKey, data, st.fullPromise);
                }
                return failure({ degradedFallback: true, data: existing || data });
            }
            st.fullPromise = st.lightPromise = Promise.resolve(data);
            storeResolvedResult(cacheKey, data, st.fullPromise);
            return { ok: true, rateLimited: false, retryAfterSeconds: null, degradedFallback: false, data };
        }).catch((err) => {
            st.inflightRefresh = null;
            autoSwrAttemptedKeys.add(cacheKey);
            warn(`Refresh failed for ${ip}:`, err);
            return failure();
        });
        return (st.inflightRefresh = refreshPromise);
    }

    function collectNumericPorts(target, list) {
        if (!Array.isArray(list)) return;
        for (const item of list) {
            const n = Number(item);
            if (isFinite(n) && n > 0 && target.indexOf(n) === -1) target.push(n);
        }
    }

    function formatOfflineDbDateShort(iso) {
        if (typeof iso !== 'string' || !iso.trim()) return '';
        const ms = Date.parse(iso.trim());
        return isNaN(ms) ? iso.trim() : new Date(ms).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    }

    function evaluateRisk(data) {
        if (data && typeof data === 'object' && riskCache.has(data)) return riskCache.get(data);
        const nonEmptyStrings = (list) => Array.isArray(list) ? list.map((item) => (typeof item === 'string' ? item.trim() : '')).filter(Boolean) : [];
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
        let hasOpenAsnVpn = false, hasOpenAsnHosting = false, openAsnSharedProvider = '';
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
            if (r.isCooldown || isRowQuotaGuarded(r) || (r.status !== '200 OK' && r.statusCode !== 200)) continue;

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

            if (hasOwn(COMMERCIAL_PROVIDERS, r.provider)) {
                validCommercialCount += 1;
                if (hasHighRiskFlag || (typeof r.usageType === 'string' && /datacenter|data center|hosting|cloud|transit|cdn/i.test(r.usageType))) positiveCommercialVotes += 1;
                if (r.provider !== 'GetIPIntel' && hasHighRiskFlag) hasLightCommercialRiskFlag = true;
                continue;
            }
            if (r.provider === 'StopForumSpam') {
                if (r.blacklisted || r.appears) addLightLbl(r.blacklisted ? 'StopForumSpam:Blacklisted' : 'StopForumSpam:Listed');
            } else if (r.provider === 'Spamhaus ZEN') {
                const codes = nonEmptyStrings(r.listedCodes), isListed = Boolean(r.isListed || codes.length > 0);
                const isNonPbl = isListed && (codes.length > 0 ? codes.some((c) => c !== '127.0.0.10' && c !== '127.0.0.11') : (!r.isPolicyRange || hasHighRiskFlag));
                if (isListed || r.isPolicyRange) addLightLbl('Spamhaus:Listed');
                if (isNonPbl) hasSpamhausNonPbl = true;
                else if (isListed || r.isPolicyRange) hasSpamhausPolicy = true;
            } else if (r.provider === 'DShield') {
                if ((Number(r.attacks) || 0) > 0 || (Number(r.count) || 0) > 0 || nonEmptyStrings(r.threatfeeds).length > 0 || hasHighRiskFlag) {
                    hasDshieldSignal = true;
                    if (!hasHighRiskFlag) {
                        const attacks = Number(r.attacks) || 0;
                        rowRiskItems.push(['Malicious Activity', provider]);
                        addLightLbl(attacks > 0 ? `DShield:Attack Activity (${attacks} attacks)` : 'DShield:Threat Feed');
                    }
                }
            } else if (r.provider === 'SpamCop') {
                if (r.isListed || nonEmptyStrings(r.listedCodes).length > 0 || hasHighRiskFlag) {
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
                const isCdn = Boolean(r.isCdn), isDatacentre = Boolean(r.isDatacenter);
                const fallbackName = (fallback) => [r.sharedProvider, r.organisation, r.isp].map((v) => (typeof v === 'string' ? v.trim() : '')).find((v) => v && v !== '-') || fallback;
                if (verdict === 'vpn') {
                    hasOpenAsnVpn = true; addLightLbl('OpenASN:VPN');
                    if (!hasHighRiskFlag) rowRiskItems.push(['VPN', provider]);
                } else if (verdict === 'enterprise_gateway' || r.isEnterpriseGateway) {
                    if (!openAsnSharedProvider) openAsnSharedProvider = fallbackName('Enterprise Gateway');
                } else if (verdict === 'hosting' && isCdn && !isDatacentre) {
                    if (!openAsnSharedProvider) openAsnSharedProvider = fallbackName('CDN');
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
            hasSpamhausPolicy, hasShodanOpenPortsSignal, openAsnSharedProvider
        };

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
        const torFlags = nonEmptyStrings(data.torFlags);

        const isSfsBlacklisted = Boolean(stopforumspamRow && (stopforumspamRow.blacklisted || stopforumspamRow.toxicCidr));
        const isSfsListed = Boolean(stopforumspamRow && (stopforumspamRow.appears || (stopforumspamRow.frequency && Number(stopforumspamRow.frequency) > 0) ||
            (Array.isArray(stopforumspamRow.securityFlags) && stopforumspamRow.securityFlags.some((f) => f && f.isHighRisk))));
        const suspectedResidentialProxy = Boolean(data.suspectedResidentialProxy), highlySuspectedResidentialProxy = Boolean(data.highlySuspectedResidentialProxy);
        const sharedInfo = resolveSharedProvider(data, sig);
        const sharedProvider = sharedInfo.label, hasSharedProvider = Boolean(sharedProvider);
        const isPartialLight = Boolean(data.isPartialMode || String(data.queryMode || '').trim().toLowerCase() === 'light');
        const isGetIpIntelDeferred = Boolean(getipintelRow && (getipintelRow.isDeferred || getipintelRow.status === 'Deferred (Light Mode)'));
        // Spamhaus PBL flags dynamic consumer ISP ranges, so only elevate it to yellow before commercial scoring runs.
        const isLightScreeningMode = Boolean(!hasPrediction && (isPartialLight || isGetIpIntelDeferred));
        const hasActiveSpamhausSignal = hasSpamhausNonPbl || (isLightScreeningMode && hasSpamhausPolicy);
        const hasProviderRiskSignal = Boolean(
            hasActiveSpamhausSignal || hasDshieldSignal || hasSpamcopSignal || hasIpsumDropSignal ||
            hasOpenAsnVpn || hasOpenAsnHosting || hasMaxmindHosting || hasMaxmindRiskFlag || hasShodanOpenPortsSignal ||
            shodanOpenPorts.length > 0 || hasOtherNonCommercialRiskFlag || (isLightScreeningMode && hasLightCommercialRiskFlag)
        );
        const hasHighOrMediumSignals = Boolean(
            isTor || isMajorityProxyVpn || highlySuspectedResidentialProxy || suspectedResidentialProxy ||
            openProxyPorts.length > 0 || hasSharedProvider || arbitrationTier === 'destructive' ||
            ptrIsHighRisk || arbitrationTier === 'warning' || broadcastIp ||
            isSfsBlacklisted || isSfsListed || hasProviderRiskSignal
        );
        const isLightDeferredClean = Boolean(!hasPrediction && !hasHighOrMediumSignals && !hasQuotaGuardedProvider && !hasCooldownProvider && (isPartialLight || isGetIpIntelDeferred));
        const hasValidNonPredictionClean = Boolean(!hasPrediction && !hasHighOrMediumSignals && !isLightDeferredClean &&
            (validCommercialCount > 0 || (!hasQuotaGuardedProvider && !hasCooldownProvider && (validTotalSourceCount > 0 || arbitrationTier === 'success'))));

        const riskTier = isNonPublic ? 'nonpublic'
            : ((hasPrediction && prediction > 80) || isTor || isMajorityProxyVpn || highlySuspectedResidentialProxy || arbitrationTier === 'destructive' || isSfsBlacklisted || hasSharedProvider || hasOpenAsnVpn) ? 'high'
                : ((hasPrediction && prediction >= 30) || broadcastIp || suspectedResidentialProxy || openProxyPorts.length > 0 || arbitrationTier === 'warning' || ptrIsHighRisk || isSfsListed || hasProviderRiskSignal) ? 'medium'
                    : 'low';

        const predictionText = hasPrediction ? String(Number(prediction.toFixed(2))) : '';
        const giiStatus = getipintelRow && getipintelRow.status ? ` (${getipintelRow.status})` : '';
        const commSuffix = validCommercialCount > 0 ? `; ${validCommercialCount} commercial sources OK` : '';
        const predictionTooltip = hasPrediction ? predictionText + '%'
            : isLightDeferredClean ? 'Light screening passed (no local/free-tier flags). Click to run full commercial check.'
                : (isPartialLight || isGetIpIntelDeferred) ? 'Light Mode (commercial sources deferred; click for full check)'
                    : hasQuotaGuardedProvider ? 'Quota Guard Active' + giiStatus + commSuffix
                        : hasCooldownProvider ? 'Provider Cooldown' + giiStatus + commSuffix
                            : validCommercialCount > 0 ? `Unavailable (${positiveCommercialVotes}/${validCommercialCount} commercial sources flagged)`
                                : 'Unavailable' + (data.predictionLabel ? ` (${data.predictionLabel})` : '');

        const primaryRules = [
            [highlySuspectedResidentialProxy || suspectedResidentialProxy, 'RES-PROXY'],
            [isMajorityProxyVpn || arbitrationTier === 'destructive', /datacenter|hosting/i.test(arbitrationVerdict) ? 'HOSTING' : 'PROXY'],
            [isSfsBlacklisted, 'BLACKLIST'],
            [openProxyPorts.length > 0, 'PROXY-PORT'],
            [hasSharedProvider, 'SHARED/' + sharedProvider],
            [hasOpenAsnVpn, 'OpenASN:VPN'],
            [ptrIsHighRisk, 'PTR-RISK'],
            [isSfsListed, 'SPAM'],
            [arbitrationTier === 'warning', 'REVIEW'],
            [hasDshieldSignal, 'DSHIELD'],
            [hasSpamcopSignal, 'SPAMCOP'],
            [hasActiveSpamhausSignal, 'SPAMHAUS'],
            [hasIpsumDropSignal, 'IPSUM'],
            [hasMaxmindHosting || hasOpenAsnHosting, 'HOSTING'],
            [hasShodanOpenPortsSignal || shodanOpenPorts.length > 0, 'OPEN-PORTS'],
            [hasMaxmindRiskFlag || hasOtherNonCommercialRiskFlag || (isLightScreeningMode && hasLightCommercialRiskFlag), 'FLAGGED'],
            [isLightDeferredClean, 'LIGHT'],
            [hasValidNonPredictionClean, validCommercialCount > 0 ? `OK ${positiveCommercialVotes}/${validCommercialCount}` : 'CLEAN'],
            [hasQuotaGuardedProvider, 'QUOTA'],
            [hasCooldownProvider, 'COOLDOWN']
        ];
        const matchedRule = primaryRules.find(([cond]) => cond);
        const badgePrimaryLabel = matchedRule ? matchedRule[1] : 'N/A';

        const evaluated = {
            sig, isNonPublic, nonPublicReason, nonPublicBadgeCode,
            hasPrediction, broadcastIp, isTor, openProxyPorts, ptrIsHighRisk,
            sharedProvider, hasSharedProvider, sharedViaRelay: sharedInfo.viaRelay,
            isLightScreeningMode, isLightDeferredClean,
            torLabel, torFlags, torSummary, riskTier, predictionText, predictionTooltip, badgePrimaryLabel
        };
        if (data && typeof data === 'object') riskCache.set(data, evaluated);
        return evaluated;
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

    function shouldAutoRefreshPayload(data, cacheKey) {
        const meta = getCacheMeta(data), key = cacheKey || canonicaliseIpKey(data && data.ip);
        return Boolean(meta && meta.shouldAutoRefresh === true && !(key && autoSwrAttemptedKeys.has(key)));
    }

    function isMobileOrCgnatPayload(data) {
        return Boolean(data && (data.isMobileOrCgnat === true || (typeof data.ptrCategory === 'string' && data.ptrCategory.trim().toLowerCase() === 'mobile_or_cgnat')));
    }

    function resolveSharedProvider(data, sig) {
        const text = (v) => (typeof v === 'string' ? v.trim() : '');
        const rawEgress = text(data && data.sharedPrivacyEgress);
        const lowerEgress = rawEgress.toLowerCase();
        const egressLabel = lowerEgress === 'icloud_private_relay' ? 'Apple iCloud Private Relay'
            : (lowerEgress === 'cloudflare_warp' ? 'Cloudflare WARP' : rawEgress);
        const label = text(data && data.sharedProvider) || egressLabel || (sig && sig.openAsnSharedProvider) || text(data && data.cloudProvider);
        const viaRelay = Boolean(label && (text(data && data.sharedCategory).toLowerCase() === 'relay' || egressLabel === label));
        return { label, viaRelay };
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

    function isUsableProviderValue(value) {
        if (value === null || value === undefined) return false;
        const text = String(value).trim(), lower = text.toLowerCase();
        return Boolean(text) && text !== '-' && lower !== 'n/a' && lower !== 'unknown';
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

    function collectIspEntries(rows) {
        const byKey = new Map(), entries = [];
        const trailingMetaRe = /\s*\(\s*(?:[+-]?\d+(?:\.\d+)?\s*,\s*[+-]?\d+(?:\.\d+)?|AS\s*\d+)\s*\)\s*$/i;
        for (const row of rows) {
            const raw = row && (isUsableProviderValue(row.isp) ? row.isp : (isUsableProviderValue(row.organisation) ? row.organisation : ''));
            let cleaned = String(raw || '').trim();
            while (cleaned && trailingMetaRe.test(cleaned)) cleaned = cleaned.replace(trailingMetaRe, '').trim();
            cleaned = cleaned.replace(/,\s*$/, '').trim();
            if (!isUsableProviderValue(cleaned)) continue;
            const key = cleaned.toLowerCase().replace(/\./g, '').replace(/[,;:]+/g, ' ').replace(/\s+/g, ' ').trim();
            upsertProviderEntry(byKey, entries, key, cleaned, row.provider || 'Provider');
        }
        return entries;
    }

    function getSpurProxyText() {
        if (!isIpContributionsPage) return '';
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
        if (document.getElementById(STYLE_ELEMENT_ID)) return;
        const darkThemeRules = (scope) => [
            `${scope} { --proxycheck-surface-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-surface-color: var(--color-base, #eaecf0); --proxycheck-subtle-color: var(--color-subtle, #a2a9b1); --proxycheck-muted-color: var(--color-subtle, #a2a9b1); --proxycheck-border-color: var(--border-color-subtle, #54595d); --proxycheck-divider-color: var(--border-color-subtle, #3a3f47); --proxycheck-link-color: var(--color-progressive, #88a3e8); --proxycheck-high-bg: #3d1414; --proxycheck-high-color: #ff9999; --proxycheck-high-border: #7a2929; --proxycheck-medium-bg: #382b0c; --proxycheck-medium-color: #ffd966; --proxycheck-medium-border: #755918; --proxycheck-nonpublic-bg: #222b36; --proxycheck-nonpublic-color: #c2d4e8; --proxycheck-nonpublic-border: #4a5d73; --proxycheck-low-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-low-color: var(--color-base, #eaecf0); --proxycheck-low-border: var(--border-color-subtle, #54595d); --proxycheck-error-border: var(--border-color-subtle, #6c737c); --proxycheck-banner-high-bg: #2c1414; --proxycheck-banner-high-accent: #ff6666; --proxycheck-banner-medium-bg: #2b220d; --proxycheck-banner-medium-accent: #f0b144; --proxycheck-banner-nonpublic-bg: #1e242c; --proxycheck-banner-nonpublic-accent: #8c959f; --proxycheck-banner-low-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-banner-low-accent: var(--color-progressive, #6d9cff); --proxycheck-banner-low-badge-bg: var(--background-color-interactive-subtle, #27292d); --proxycheck-code-bg: var(--background-color-neutral-subtle, rgba(255, 255, 255, 0.08)); }`,
            `${scope} a.proxycheck-anchor-risk-high, ${scope} a.proxycheck-anchor-risk-high:visited, ${scope} .proxycheck-anchor-risk-high { background-color: #3d1414 !important; color: #ff9999 !important; }`,
            `${scope} a.proxycheck-anchor-risk-medium, ${scope} a.proxycheck-anchor-risk-medium:visited, ${scope} .proxycheck-anchor-risk-medium { background-color: #382b0c !important; color: #ffd966 !important; }`,
            `${scope} .proxycheck-source-tag { background-color: var(--proxycheck-tag-dark-bg, #1c2a3a); border-color: var(--proxycheck-tag-dark-border, #3a5778); color: var(--proxycheck-tag-dark-color, #9cc9ff); }`,
            `${scope} .proxycheck-signal-privacy { background-color: #1c2345; color: #b0bfff; border-color: #3d4b8f; }`
        ].join('\n');
        const boldTiers = ['high', 'medium', 'nonpublic'];
        const allTiers = ['high', 'medium', 'nonpublic', 'low'];
        const cssText = [
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
            darkThemeRules('html.skin-theme-clientpref-night'),
            `@media (prefers-color-scheme: dark) {\n${darkThemeRules('html.skin-theme-clientpref-os')}\n}`
        ].join('\n');
        const parent = document.head || document.body || document.documentElement;
        if (parent) parent.appendChild(createEl('style', '', cssText, { id: STYLE_ELEMENT_ID, type: 'text/css' }));
    }

    function buildResultDetailsPanel(data, risk, fallbackIp) {
        const sig = risk.sig, rows = sig.orderedRows;
        const resolvedIp = isValidIp(data && data.ip) ? String(data.ip).trim() : (isValidIp(fallbackIp) ? String(fallbackIp).trim() : '');
        const asnEntries = collectAsnEntries(rows);
        const ispEntries = collectIspEntries(rows);

        const predictionEntries = data.getipintel_chance !== null && data.getipintel_chance !== undefined ? [{
            value: `Prediction ${risk.predictionText}%`, copyValue: `${risk.predictionText}% Prediction`,
            providers: ['GetIPIntel'], showProviders: true, defaultChecked: true
        }] : [];

        const locationEntries = [], locByKey = new Map();
        const trailingCoordRe = /\s*\(\s*[+-]?\d+(?:\.\d+)?\s*,\s*[+-]?\d+(?:\.\d+)?\s*\)\s*$/;
        for (const row of rows) {
            if (!row || !isUsableProviderValue(row.location)) continue;
            let cleaned = String(row.location).trim();
            while (cleaned && trailingCoordRe.test(cleaned)) cleaned = cleaned.replace(trailingCoordRe, '').trim();
            const parts = cleaned.replace(/,\s*$/, '').split(',').map((p) => p.trim()).filter(Boolean);
            const norm = parts.filter((p, i) => i === 0 || parts[i - 1].toLowerCase() !== p.toLowerCase()).join(', ');
            if (!isUsableProviderValue(norm)) continue;
            upsertProviderEntry(locByKey, locationEntries, norm.toLowerCase().replace(/\s*,\s*/g, ', ').replace(/\s+/g, ' ').trim(), norm, row.provider || 'Provider');
        }

        const riskEntries = [], riskByKey = new Map();
        const addRisk = (val, provider) => {
            const text = typeof val === 'string' ? val.trim() : '';
            if (text) upsertProviderEntry(riskByKey, riskEntries, text.toLowerCase(), text, provider);
        };
        if (risk.isTor) addRisk(risk.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node'), 'Tor Onionoo');
        sig.rowRiskItems.forEach(([lbl, provider]) => addRisk(lbl, provider));
        if (risk.isLightScreeningMode && sig.hasSpamhausPolicy) addRisk('Policy/Dynamic ISP Range (PBL)', 'Spamhaus ZEN');
        if (risk.hasSharedProvider) {
            const matchRow = rows.find((r) => r && r.provider && (r.sharedProvider || r.cloudProvider) === risk.sharedProvider);
            addRisk(`Shared (${risk.sharedProvider})`, matchRow ? matchRow.provider : (risk.sharedViaRelay ? 'Privacy Relay' : 'Shared CIDR'));
        }
        if (risk.broadcastIp) addRisk('Broadcast IP', 'Multi-Source');
        if (data.ptrIsHighRisk && typeof data.ptrLabel === 'string' && data.ptrLabel.trim()) addRisk(`PTR (${data.ptrLabel.trim()})`, 'Reverse DNS');
        if (data.suspectedResidentialProxy) addRisk('Suspected Residential Proxy / Compromised Host', 'Multi-Source');
        if (data.highlySuspectedResidentialProxy) addRisk('Highly Suspected Residential Proxy', 'GetIPIntel ResidentialProxy');
        if (sig.openProxyPorts.length > 0) addRisk(`Open Proxy Ports (${sig.openProxyPorts.join(', ')})`, 'Shodan InternetDB');
        else if (sig.shodanOpenPorts.length > 0) addRisk(`Open Ports (${sig.shodanOpenPorts.join(', ')})`, 'Shodan InternetDB');
        else if (sig.hasShodanOpenPortsSignal) addRisk('Open Ports', 'Shodan InternetDB');
        const spurText = getSpurProxyText();
        if (spurText) riskEntries.push({ value: spurText, providers: ['Spur'], showProviders: true, defaultChecked: true });

        const sections = [
            { label: 'Prediction', entries: predictionEntries, isRisk: false, emptyText: 'Unavailable', copyable: false },
            { label: 'ASN', entries: asnEntries, isRisk: false, emptyText: '-', copyable: true },
            { label: 'ISP', entries: ispEntries, isRisk: false, emptyText: '-', copyable: true },
            { label: 'Location', entries: locationEntries, isRisk: false, emptyText: '-', copyable: false },
            { label: 'Risk', entries: riskEntries, isRisk: true, emptyText: 'No high-risk signals detected', copyable: false }
        ];

        const createSourceBadge = (provider) => {
            let palette = hasOwn(PROVIDER_BADGE_PALETTES, provider) ? PROVIDER_BADGE_PALETTES[provider] : null;
            if (!palette) {
                let hash = 0;
                for (let i = 0; i < provider.length; i++) hash = ((hash * 31) + provider.charCodeAt(i)) | 0;
                palette = FALLBACK_COOL_PALETTES[Math.abs(hash) % FALLBACK_COOL_PALETTES.length];
            }
            const [bg, border, color, darkBg, darkBorder, darkColor] = palette;
            const formatted = sig.dbUpdatedAtMap[provider] ? formatOfflineDbDateShort(sig.dbUpdatedAtMap[provider]) : '';
            const attrs = {
                class: 'proxycheck-source-tag',
                style: `--proxycheck-tag-bg: ${bg}; --proxycheck-tag-border: ${border}; --proxycheck-tag-color: ${color}; --proxycheck-tag-dark-bg: ${darkBg}; --proxycheck-tag-dark-border: ${darkBorder}; --proxycheck-tag-dark-color: ${darkColor};`,
                text: provider
            };
            if (formatted) attrs.title = 'Offline DB updated: ' + formatted;
            return $('<span>', attrs);
        };

        const $panel = $('<div>', { class: 'proxycheck-details-panel' });
        const highlySuspectedResidentialProxy = Boolean(data && data.highlySuspectedResidentialProxy);
        const cacheMeta = getCacheMeta(data), cacheAge = getCacheAgeSeconds(data);
        const recommendFreshRecheck = Boolean((cacheMeta && cacheMeta.recommendFreshRecheck === true) ||
            (data && data.suspectedResidentialProxy && cacheAge !== null && cacheAge > RESIDENTIAL_RECHECK_THRESHOLD_SECONDS));
        const bannerPills = [];
        if (risk.sharedProvider) bannerPills.push(['proxycheck-signal-privacy', `Shared Egress: ${risk.sharedProvider} \u2014 many unrelated users may share this address; check collateral damage before blocking.`]);
        if (isMobileOrCgnatPayload(data)) bannerPills.push(['proxycheck-signal-cgnat', 'Mobile / CGNAT Network: Collateral-damage warning \u2014 recommended block locked to /32 (IPv4) or /64 (IPv6).']);
        if (data && data.suspectedResidentialProxy) bannerPills.push(['proxycheck-signal-danger', 'Suspected Residential Proxy / Compromised Host' + (recommendFreshRecheck ? ' \u2014 Cached signal is older than 7 days; click Refetch to verify current DHCP assignment before issuing a long-term block.' : '')]);
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
                    if (entry.showProviders && entry.providers.length > 0) entry.providers.forEach((p) => $body.append(createSourceBadge(p)));
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
                        target: '_blank', rel: 'noopener noreferrer', text: entry.wiki
                    }));
                    if (entry.hasActive) {
                        $rbCell.append(document.createTextNode(' '), $('<span>', { class: 'proxycheck-rb-active-label', text: '(active)' }));
                    }
                });
            }
            appendRow('Rangeblock', $rbCell);
        }

        const sanitiseHtmlComment = (text) => {
            let s = String(text || '');
            while (s.includes('<!--') || s.includes('-->')) s = s.replace(/<!--|-->/g, '');
            return s.replace(/--!?>/g, '').replace(/--+$/g, '').trim();
        };
        const getSelectedCommentValues = () => checkboxItems.filter((item) => item.checkbox.prop('checked'))
            .map((item) => sanitiseHtmlComment(item.copyValue)).filter(Boolean);
        const buildAttributionComment = (vals) => `<!-- ${(vals.length ? sanitiseHtmlComment(vals.join(', ')) + ' ' : '') + BLOCK_REASON_ATTRIBUTION} -->`;

        const copyToClipboard = (text) => {
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
                } catch (err) { reject(err); } finally { ta.remove(); }
            });
        };

        const bindCopy = ($btn, baseLabel, copiedLabel, getPayload) => {
            let resetTimer = null;
            const scheduleReset = (delayMs) => {
                window.clearTimeout(resetTimer);
                resetTimer = window.setTimeout(() => {
                    resetTimer = null;
                    if (document.body.contains($btn[0])) $btn.text(baseLabel);
                }, delayMs);
            };
            $btn.on('click', (e) => {
                e.preventDefault(); e.stopPropagation();
                const payload = getPayload();
                if (!payload) { $btn.text('Select at least one item'); return scheduleReset(1500); }
                copyToClipboard(payload).then(
                    () => { if (document.body.contains($btn[0])) { $btn.text(copiedLabel); scheduleReset(1500); } },
                    (err) => { warn(baseLabel + ' failed:', err); if (document.body.contains($btn[0])) { $btn.text('Copy failed'); scheduleReset(2000); } }
                );
            });
        };

        const $copyLink = $('<a>', { href: '#', role: 'button', class: 'proxycheck-copy-result', text: 'Copy result' });
        const $copyWikitextBtn = $('<a>', { href: '#', role: 'button', class: 'proxycheck-copy-wikitext', text: 'Copy Wikitext' });
        bindCopy($copyLink, 'Copy result', 'Copied', () => {
            const selected = getSelectedCommentValues();
            return selected.length ? buildAttributionComment(selected) : '';
        });
        bindCopy($copyWikitextBtn, 'Copy Wikitext', 'Copied Wikitext', () => {
            const sanitise = (value) => String(value || '').replace(/[\r\n]+/g, ' ').replace(/<!--|-->|\{\{|\}\}|\[\[|\]\]/g, '').trim();
            const targetIp = sanitise((data && data.ip) || resolvedIp);
            const cidr = sanitise((data && data.recommendedCidr) || targetIp);
            const esc = !highlySuspectedResidentialProxy && escCidr ? sanitise(escCidr) : '';
            const asn = sanitise((data && data.primaryAsn) || (asnEntries[0] && asnEntries[0].value) || '');
            const isp = sanitise((ispEntries[0] && ispEntries[0].value) || '');
            const signals = [];
            if (data && data.isTor) signals.push(sanitise(data.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node')));
            if (risk.sharedProvider) signals.push('Shared egress: ' + sanitise(risk.sharedProvider));
            if (isMobileOrCgnatPayload(data)) signals.push('Mobile/CGNAT');
            if (sig.openProxyPorts.length > 0) signals.push(`Open proxy ports: ${sig.openProxyPorts.join(', ')}`);
            if (sig.dropRow) signals.push(sig.dropRow.dropSblId ? `Spamhaus DROP (${sanitise(sig.dropRow.dropSblId)})` : 'Spamhaus DROP');
            const rawTs = (data && data.fetchedAt) || (cacheMeta && (cacheMeta.fetchedAt || cacheMeta.cachedAt)) || '';
            const parsedMs = rawTs ? Date.parse(rawTs) : NaN;
            const fetchDate = new Date(isNaN(parsedMs) ? Date.now() : parsedMs).toISOString().slice(0, 10) + ' UTC';
            const net = [asn, isp].filter(Boolean).join(' / ');
            const parts = [`<code>${targetIp}</code>`, `CIDR <code>${cidr}</code>${esc ? ` (escalation: <code>${esc}</code>)` : ''}`];
            if (net) parts.push(net);
            parts.push(sanitise(verdictText || 'IP Intelligence Summary'));
            if (signals.length > 0) parts.push(signals.join('; '));
            parts.push(`fetched ${fetchDate}`);
            return `* ${parts.join(' \u00b7 ')}`;
        });
        $panel.append($table, $('<div>', { style: 'margin-top: 8px; display: flex; align-items: center; flex-wrap: wrap; gap: 12px;' }).append($copyLink, $copyWikitextBtn));

        if (resolvedIp) {
            let rangeTarget = '';
            if (recCidr !== 'N/A' && recCidr.includes('/') && !recCidr.includes('%')) {
                const cidrParts = recCidr.split('/');
                if (cidrParts.length === 2 && /^\d{1,3}$/.test(cidrParts[1].trim()) && isValidIp(cidrParts[0].trim())) {
                    const addr = cidrParts[0].trim(), prefix = Number(cidrParts[1].trim()), maxPrefix = addr.includes(':') ? 128 : 32;
                    if (prefix >= 1 && prefix < maxPrefix) rangeTarget = `${canonicaliseIpKey(addr)}/${prefix}`;
                }
            }
            const buildBlockParams = () => ({
                // Omit wpReason so Codex Special:Block does not prepend "other:" to wpReason-other.
                wpExpiry: '3 months', wpHardBlock: '1', 'wpReason-other': '{{blocked proxy}}' + buildAttributionComment(getSelectedCommentValues())
            });
            const mkLink = (cls, href, text) => $('<a>', { class: cls, href, target: '_blank', rel: 'noopener noreferrer', text });
            const $singleBlockLink = mkLink('proxycheck-link-block', buildWikiPageUrl('Special:Block/' + resolvedIp, buildBlockParams()), 'Special:Block ↗');
            const blockLinks = [{ el: $singleBlockLink, target: resolvedIp }];
            const $rangeBlockLink = rangeTarget
                ? mkLink('proxycheck-link-block-range', buildWikiPageUrl('Special:Block/' + rangeTarget, buildBlockParams()), 'Special:Block (range) ↗')
                : null;
            if ($rangeBlockLink) blockLinks.push({ el: $rangeBlockLink, target: rangeTarget });
            const syncBlockLinkHrefs = () => {
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

        return $panel;
    }

    function renderBadge(anchor, badge, data, fallbackIp) {
        const risk = evaluateRisk(data), sig = risk.sig;
        const resolvedIp = (data && data.ip) || fallbackIp;
        const meta = getCacheMeta(data);
        const isStale = Boolean(!risk.isNonPublic && meta && meta.isStale === true);

        if (anchor.classList) {
            anchor.classList.remove('proxycheck-anchor-risk-high', 'proxycheck-anchor-risk-medium');
            if (risk.riskTier === 'high' || risk.riskTier === 'medium') anchor.classList.add('proxycheck-anchor-risk-' + risk.riskTier);
        }

        let lightInfo = null;
        if (!risk.isNonPublic && !risk.hasPrediction && isPartialLightResult(data)) {
            const rows = sig.orderedRows;
            const asnEntry = collectAsnEntries(rows)[0], ispEntry = collectIspEntries(rows)[0];
            const riskLabels = [], providerRiskLabels = sig.lightProviderLabels.slice();
            const addUnique = (target, label) => {
                const cleaned = typeof label === 'string' ? label.trim() : '';
                if (cleaned && target.indexOf(cleaned) === -1) target.push(cleaned);
            };
            if (sig.shodanOpenPortRow && risk.openProxyPorts.length === 0) {
                const rowPorts = [];
                collectNumericPorts(rowPorts, sig.shodanOpenPortRow.ports);
                addUnique(providerRiskLabels, rowPorts.length > 0 ? `Shodan:Open Ports (${rowPorts.length > 4 ? rowPorts.slice(0, 4).join(',') + '...' : rowPorts.join(',')})` : 'Shodan:Open Ports');
            }
            const redundant = ['SPAMHAUS', 'DSHIELD', 'SPAMCOP', 'IPSUM', 'HOSTING', 'OPEN-PORTS', 'FLAGGED'];
            if (risk.badgePrimaryLabel && !['LIGHT', 'CLEAN', 'N/A'].includes(risk.badgePrimaryLabel) &&
                !(providerRiskLabels.length > 0 && redundant.includes(risk.badgePrimaryLabel))) addUnique(riskLabels, risk.badgePrimaryLabel);
            if (risk.isTor) addUnique(riskLabels, formatTorDescription(risk) || 'Tor');
            if (risk.ptrIsHighRisk) addUnique(riskLabels, 'PTR-Risk');
            if (risk.openProxyPorts.length > 0) addUnique(riskLabels, `Shodan:${risk.openProxyPorts.join(',')}`);
            providerRiskLabels.forEach((lbl) => addUnique(riskLabels, lbl));
            lightInfo = { asn: asnEntry ? asnEntry.value : '', isp: ispEntry ? ispEntry.value : '', riskLabels };
        }

        const bcast = risk.broadcastIp ? '|BCASTIP' : '';
        const tor = risk.isTor ? '|' + (risk.torLabel ? risk.torLabel.toUpperCase() : 'TOR') : '';
        badge.href = TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp);
        if (risk.isNonPublic) {
            badge.textContent = `[${risk.nonPublicBadgeCode}]`;
        } else if (lightInfo) {
            const lightParts = [];
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

        if (risk.isNonPublic) {
            badge.title = `Address Type: ${risk.nonPublicReason} [${risk.nonPublicBadgeCode}]\nStatus: External threat lookups skipped (non-public or reserved IP)`;
        } else {
            const lines = [];
            if (lightInfo) {
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
            const sharedDesc = formatSharedDescription(data, risk);
            if (sharedDesc) lines.push('Shared egress: ' + sharedDesc);
            lines.push('Broadcast IP: ' + (risk.broadcastIp ? 'At-risk' : 'No'));
            lines.push('Tor Node: ' + (risk.isTor ? formatTorDescription(risk) : 'No'));
            if (sig.sfsTitleLine) lines.push(sig.sfsTitleLine);
            if (sig.dbBaselines.length > 0) lines.push('Offline DB Baseline: ' + sig.dbBaselines.join(', '));
            const ageSec = getCacheAgeSeconds(data);
            if (ageSec !== null) {
                const ageText = formatRelativeCacheAge(ageSec);
                if (ageText) lines.push(meta && meta.isStale ? `${ageText} (stale >90d)` : ageText);
            }
            badge.title = lines.join('\n');
        }

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
            if (!existingRbBadge && badge.parentNode) badge.parentNode.insertBefore(rbBadge, badge.nextSibling);
        } else if (existingRbBadge) {
            existingRbBadge.remove();
        }
    }

    function filterConnectedBadgeEntries(entries) {
        return (entries || []).filter((e) => e && e.anchor && e.badge && e.badge.isConnected !== false && document.body.contains(e.badge));
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
        const cacheKey = canonicaliseIpKey(ip);
        if (!cacheKey || !fullData || typeof fullData !== 'object') return;
        const active = filterConnectedBadgeEntries(renderedBadgeEntriesByIp.get(cacheKey));
        if (active.length === 0) { renderedBadgeEntriesByIp.delete(cacheKey); return; }
        active.forEach((e) => renderBadge(e.anchor, e.badge, fullData, fullData.ip || e.ip));
        renderedBadgeEntriesByIp.set(cacheKey, active);
    }

    function upgradeToFullResult(ip) {
        return fetchIpIntelligence(ip, 'full').then((fullData) => {
            if (fullData) refreshRenderedBadgesForIp(fullData.ip || ip, fullData);
            return fullData;
        });
    }

    function createRefreshControl(ip, isActive, onSuccess) {
        const $ageSpan = $('<span>', { class: 'proxycheck-cache-age' });
        const $btn = $('<button>', { type: 'button', class: 'proxycheck-refetch-btn', text: 'Refetch' });
        const $warning = $('<div>', { class: 'proxycheck-refresh-warning', style: 'display: none;' });
        let inFlight = false;

        const sync = (data, isJustUpdated) => {
            const meta = getCacheMeta(data), ageSeconds = getCacheAgeSeconds(data);
            let label;
            if (isJustUpdated || (meta && meta.status === 'miss')) label = 'Just updated';
            else if (ageSeconds !== null) label = formatRelativeCacheAge(ageSeconds);
            else label = data && data.isCached ? 'Cached' : 'Just updated';
            $ageSpan.text(label).toggleClass('proxycheck-cache-age-stale', Boolean(!isJustUpdated && meta && meta.isStale === true));
            if (!inFlight) $btn.prop('disabled', false).text('Refetch');
        };

        const run = (isAutoSwr) => {
            if (inFlight || !isActive() || accessBlocked || !isValidIp(ip)) return;
            if (isAutoSwr && !tryConsumeAutoSwrBudget()) return;
            inFlight = true;
            $warning.css('display', 'none').text('');
            $btn.prop('disabled', true).text('Updating...');
            refreshIpResult(ip).then((outcome) => {
                if (outcome.ok) refreshRenderedBadgesForIp(outcome.data.ip || ip, outcome.data);
                inFlight = false;
                if (!isActive()) return;
                if (!outcome.ok) {
                    let warningText = 'Refresh temporarily unavailable. Preserving cached intelligence.';
                    if (outcome.rateLimited) {
                        const wait = typeof outcome.retryAfterSeconds === 'number' && outcome.retryAfterSeconds > 0 ? ` (retry in ${outcome.retryAfterSeconds}s)` : '';
                        warningText = `Refresh rate limit reached${wait}. Preserving cached intelligence.`;
                    } else if (outcome.degradedFallback) {
                        warningText = 'Upstream providers are temporarily degraded or quota-limited. Preserving cached intelligence.';
                    }
                    $btn.prop('disabled', false).text('Refetch');
                    $warning.text(warningText).css('display', 'block');
                    return;
                }
                $warning.css('display', 'none').text('');
                onSuccess(outcome.data);
            });
        };

        $btn.on('click', (e) => { e.preventDefault(); e.stopPropagation(); run(false); });
        return { $ageSpan, $btn, $warning, sync, run };
    }

    function attachLightUpgrade($container, ip, isActive, onUpgraded) {
        const $notice = $('<p>', { class: 'proxycheck-light-upgrade-notice', style: 'margin-top: 8px; margin-bottom: 0; font-size: 12px;' })
            .text('Loading full commercial provider intelligence...');
        $container.append($notice);
        upgradeToFullResult(ip).then((fullData) => {
            if (!isActive()) return;
            if (!fullData) {
                $notice.text('Full commercial intelligence unavailable right now.');
                return;
            }
            $notice.remove();
            onUpgraded(fullData);
        });
    }

    function showInfoDialogue(data, ip) {
        if (infoDialoguePromise) return;
        infoDialoguePromise = mw.loader.using('oojs-ui-windows').then(() => {
            const targetIp = ip || data.ip || '', cacheKey = canonicaliseIpKey(targetIp);
            let dialogueClosed = false;
            const isOpen = () => !dialogueClosed;
            const $body = $('<div>', { class: 'proxycheck-dialog-content' });
            const refreshCtrl = createRefreshControl(targetIp, isOpen, (freshData) => render(freshData, true));
            const $cacheBar = $('<div>', { class: 'proxycheck-dialog-cache-bar' }).append(refreshCtrl.$ageSpan, refreshCtrl.$btn);

            const render = (d, isJustUpdated) => {
                const risk = evaluateRisk(d);
                $body.empty();
                if (risk.isNonPublic) {
                    $body.append(
                        $('<p>').append($('<strong>').text('Address Type: '), document.createTextNode(`${risk.nonPublicReason} [${risk.nonPublicBadgeCode}]`)),
                        $('<p>').append($('<strong>').text('Status: '), document.createTextNode('External threat lookups skipped (non-public or reserved IP)'))
                    );
                    $cacheBar.css('display', 'none');
                    refreshCtrl.$warning.css('display', 'none');
                } else {
                    $body.append(buildResultDetailsPanel(d, risk, targetIp));
                    $cacheBar.css('display', 'flex');
                    refreshCtrl.sync(d, isJustUpdated);
                }
                return risk;
            };

            const initialData = (cacheKey && getIpData(cacheKey)) || data;
            const initialRisk = render(initialData, false);
            const $message = $('<div>').append($cacheBar, refreshCtrl.$warning, $body,
                $('<p>', { style: 'margin-top: 8px; margin-bottom: 0;' }).append(
                    $('<a>', { class: 'proxycheck-dialog-link', href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(targetIp), target: '_blank', rel: 'noopener noreferrer', text: 'Open full report ↗' })
                ));

            if (!initialRisk.isNonPublic && isPartialLightResult(initialData)) {
                attachLightUpgrade($message, targetIp, isOpen, (fullData) => {
                    render(fullData, false);
                    if (shouldAutoRefreshPayload(fullData, cacheKey)) refreshCtrl.run(true);
                });
            } else if (!initialRisk.isNonPublic && shouldAutoRefreshPayload(initialData, cacheKey)) {
                refreshCtrl.run(true);
            }

            const close = () => { dialogueClosed = true; };
            return Promise.resolve(OO.ui.alert($message, { title: targetIp, size: 'large' })).then(close, (err) => { close(); throw err; });
        }).catch((err) => warn('Info dialogue failed:', err)).then(() => { infoDialoguePromise = null; });
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

    function processAnchor(anchor) {
        if (accessBlocked || !anchor.dataset || !anchor.parentNode || shouldSkipRevealTarget(anchor) || anchor.dataset.proxycheckProcessed) return;
        const ip = extractIpFromRevealElement(anchor);
        if (!ip) return;
        const existingNext = anchor.nextElementSibling;
        if (existingNext && existingNext.classList.contains(BADGE_CLASS)) {
            anchor.dataset.proxycheckProcessed = 'true';
            return;
        }

        anchor.dataset.proxycheckProcessed = 'pending';
        const badge = createEl('a', `${BADGE_CLASS} proxycheck-ip-badge-loading`, '[…]', { title: 'Checking IP intelligence...', 'aria-busy': 'true' });
        let onBadgeClick = null;
        badge.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!accessBlocked && onBadgeClick) onBadgeClick();
        });
        anchor.parentNode.insertBefore(badge, anchor.nextSibling);

        const removePlaceholder = () => {
            badge.remove();
            delete anchor.dataset.proxycheckProcessed;
        };
        const showActionBadge = (stateClass, text, title, action) => {
            badge.className = `${BADGE_CLASS} ${stateClass}`;
            badge.textContent = text;
            badge.title = title;
            badge.href = '#';
            badge.setAttribute('role', 'button');
            badge.removeAttribute('aria-busy');
            badge.removeAttribute('target');
            badge.removeAttribute('rel');
            onBadgeClick = action;
        };

        ensureConsent(false).then((agreed) => {
            if (agreed) return fetchIpIntelligence(ip, 'light');
            if (accessBlocked || anchor.dataset.proxycheckProcessed !== 'pending') {
                removePlaceholder();
                return null;
            }
            anchor.dataset.proxycheckProcessed = 'consent-declined';
            showActionBadge('proxycheck-ip-badge-consent', '[ProxyCheck]', 'ProxyCheck consent required. Click to review policy and enable.', () => {
                ensureConsent(true).then((granted) => {
                    if (!granted || accessBlocked) return;
                    for (const el of document.body.querySelectorAll(TARGET_SELECTOR)) {
                        if (!el.dataset || el.dataset.proxycheckProcessed !== 'consent-declined') continue;
                        const next = el.nextElementSibling;
                        if (next && next.classList.contains('proxycheck-ip-badge-consent')) next.remove();
                        delete el.dataset.proxycheckProcessed;
                    }
                    handleIPContributionsPage();
                    scanSubtree(document.body);
                });
            });
            return null;
        }).then((data) => {
            if (!data) {
                if (anchor.dataset.proxycheckProcessed === 'consent-declined') return;
                if (accessBlocked || !anchor.parentNode || anchor.dataset.proxycheckProcessed !== 'pending') {
                    removePlaceholder();
                    return;
                }
                anchor.dataset.proxycheckProcessed = 'error';
                showActionBadge('proxycheck-ip-badge-error', '[Retry]', 'ProxyCheck lookup failed. Click to retry.', () => {
                    badge.remove();
                    invalidateIpResultCache(ip);
                    delete anchor.dataset.proxycheckProcessed;
                    processAnchor(anchor);
                });
                return;
            }
            if (!anchor.parentNode || shouldSkipRevealTarget(anchor)) {
                removePlaceholder();
                return;
            }
            if (anchor.dataset.proxycheckProcessed === 'true') return;
            const resolvedIp = data.ip || ip;
            const cacheKey = canonicaliseIpKey(resolvedIp) || canonicaliseIpKey(ip);
            badge.removeAttribute('aria-busy');
            badge.removeAttribute('role');
            badge.target = '_blank';
            badge.rel = 'noopener noreferrer';
            onBadgeClick = () => {
                const current = (cacheKey && getIpData(cacheKey)) || data;
                showInfoDialogue(current, current.ip || resolvedIp);
            };
            renderBadge(anchor, badge, data, resolvedIp);
            registerRenderedBadge(cacheKey, anchor, badge, resolvedIp);
            if (badge.parentNode !== anchor.parentNode || anchor.nextElementSibling !== badge) anchor.parentNode.insertBefore(badge, anchor.nextSibling);
            anchor.dataset.proxycheckProcessed = 'true';
        });
    }

    function scanSubtree(root) {
        if (accessBlocked || !root || root.nodeType !== 1 || isProxycheckInternalNode(root)) return;
        const candidates = root.matches(TARGET_SELECTOR) ? [root] : [];
        candidates.push(...root.querySelectorAll(TARGET_SELECTOR));
        const anchors = candidates.filter((el) => el.dataset && !el.dataset.proxycheckProcessed && !shouldSkipRevealTarget(el));
        if (anchors.length === 0) return;
        if (isIpContributionsPage && !contributionsInvalidTarget) handleIPContributionsPage(true);
        anchors.forEach(processAnchor);
    }

    function collectRevealedIpsInDom() {
        if (typeof document === 'undefined' || !document.body) return [];
        const discovered = [], seen = Object.create(null);
        for (const el of document.body.querySelectorAll(TARGET_SELECTOR)) {
            if (!el || isProxycheckInternalNode(el) || shouldSkipRevealTarget(el)) continue;
            const ip = extractIpFromRevealElement(el), canonical = ip ? canonicaliseIpKey(ip) : '';
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

    function clearContributionsSchedule() {
        window.clearTimeout(contributionsDelayTimer);
        contributionsDelayTimer = null;
        if (contributionsVisibilityHandler) {
            document.removeEventListener('visibilitychange', contributionsVisibilityHandler);
            contributionsVisibilityHandler = null;
        }
    }

    function scheduleContributionsOnVisible(onVisible) {
        if (contributionsVisibilityHandler) return;
        contributionsVisibilityHandler = () => {
            if (accessBlocked || !isDocumentVisible()) return;
            clearContributionsSchedule();
            onVisible();
        };
        document.addEventListener('visibilitychange', contributionsVisibilityHandler);
    }

    function handleIPContributionsPage(allowFallback) {
        if (accessBlocked || consentDeclined || !isIpContributionsPage || contributionsInvalidTarget) return;

        let target = mw.config.get('wgRelevantUserName');
        if (!target) {
            const parts = (mw.config.get('wgTitle') || '').split('/');
            if (parts.length > 1) target = parts.slice(1).join('/');
        }
        if (!target) {
            target = mw.util && typeof mw.util.getParamValue === 'function'
                ? mw.util.getParamValue('target') : new URLSearchParams(window.location.search).get('target');
        }
        target = typeof target === 'string' ? target.trim() : '';
        const isDirectIpTarget = isValidIp(target);
        const isTempAccountTarget = !isDirectIpTarget && Boolean(target) && (mw.util && typeof mw.util.isTemporaryUser === 'function'
            ? Boolean(mw.util.isTemporaryUser(target)) : /^~\d{4}-/.test(target));
        if (!isDirectIpTarget && !isTempAccountTarget) {
            contributionsInvalidTarget = true;
            return;
        }

        let discoveredIps = isTempAccountTarget ? collectRevealedIpsInDom() : [];
        if (isTempAccountTarget && discoveredIps.length === 0) return;
        if (document.getElementById('proxycheck-pageinfo')) {
            if (isTempAccountTarget && contributionsBanner) contributionsBanner.syncDiscoveredIps(discoveredIps);
            return;
        }
        if (contributionsPending) return;

        const fallbackAllowed = Boolean(allowFallback || isTempAccountTarget);
        const resumeWhenVisible = () => scheduleContributionsOnVisible(() => handleIPContributionsPage(fallbackAllowed));
        let initialIp = isDirectIpTarget ? target : discoveredIps[0].displayIp;
        if (!peekCachedIpState(initialIp) && !isDocumentVisible()) {
            resumeWhenVisible();
            return;
        }

        const mountTarget = resolveContributionsMountTarget(fallbackAllowed);
        if (!mountTarget) {
            if (!fallbackAllowed && contributionsFallbackTimer === null) {
                contributionsFallbackTimer = window.setTimeout(() => {
                    contributionsFallbackTimer = null;
                    handleIPContributionsPage(true);
                }, IPINFO_FALLBACK_DELAY_MS);
            }
            return;
        }
        window.clearTimeout(contributionsFallbackTimer);
        contributionsFallbackTimer = null;

        contributionsPending = true;
        ensureConsent().then((agreed) => {
            if (!agreed || accessBlocked || document.getElementById('proxycheck-pageinfo')) return;
            if (isTempAccountTarget) {
                discoveredIps = collectRevealedIpsInDom();
                if (discoveredIps.length === 0) return;
                initialIp = discoveredIps[0].displayIp;
            }
            if (!peekCachedIpState(initialIp) && !isDocumentVisible()) {
                resumeWhenVisible();
                return;
            }
            let activeTarget = resolveContributionsMountTarget(fallbackAllowed) || mountTarget;
            if (!document.body.contains(activeTarget.$element[0])) activeTarget = resolveContributionsMountTarget(true);
            if (!activeTarget) return;
            contributionsBanner = mountContributionsBanner(activeTarget, fallbackAllowed, isTempAccountTarget, discoveredIps, initialIp, resumeWhenVisible);
        }).catch((err) => warn('Contributions banner update failed:', err)).then(() => { contributionsPending = false; });
    }

    function mountContributionsBanner(initialMountTarget, fallbackAllowed, isTempAccountTarget, discoveredIps, initialIp, resumeWhenVisible) {
        const $box = $('<div>', { id: 'proxycheck-pageinfo', class: 'proxycheck-pageinfo-banner' });
        const $switcher = $('<div>', { class: 'proxycheck-temp-ip-switcher', style: 'display: none;' });
        const $result = $('<span>', { id: 'proxycheck_result', text: '.' });
        $box.append($switcher, $result);

        let isRemoved = false, loadingInterval = null, rebuildDetailsForSpur = null;
        let currentIp = initialIp, currentKey = canonicaliseIpKey(initialIp);
        let pinnedKey = null, discoveredList = discoveredIps.slice(), isStatsExpanded = false, loadSeq = 0;
        const fullUpgradeRequestedForKey = Object.create(null);
        const listSignature = (list) => list.map((e) => e.canonicalKey).join('|');
        let discoveredSignature = listSignature(discoveredList);

        const stopLoading = () => {
            window.clearInterval(loadingInterval);
            loadingInterval = null;
        };
        const mountInto = (target) => {
            if (!target) return false;
            const existing = document.getElementById('proxycheck-pageinfo');
            if (existing && existing !== $box[0]) existing.remove();
            target.$element[target.method]($box);
            return true;
        };
        const ensureBannerAttached = () => !isRemoved && (document.body.contains($box[0]) ||
            mountInto(resolveContributionsMountTarget(fallbackAllowed) || resolveContributionsMountTarget(true)));
        const removeUnpopulatedBanner = () => {
            stopLoading();
            isRemoved = true;
            $box.remove();
        };

        const renderSwitcher = () => {
            $switcher.empty();
            if (!isTempAccountTarget || discoveredList.length <= 1) {
                $switcher.css('display', 'none');
                return;
            }
            $switcher.css('display', 'flex').append($('<span>', { class: 'proxycheck-temp-ip-subtitle', text: `${discoveredList.length} distinct revealed IPs on this page:` }));
            for (const entry of discoveredList) {
                const selected = entry.canonicalKey === currentKey;
                $switcher.append($('<button>', {
                    type: 'button', class: 'proxycheck-ip-pill' + (selected ? ' proxycheck-ip-pill-active' : ''),
                    'aria-pressed': selected ? 'true' : 'false', text: entry.displayIp
                }).on('click', (e) => {
                    e.preventDefault(); e.stopPropagation();
                    if (accessBlocked || entry.canonicalKey === currentKey) return;
                    pinnedKey = entry.canonicalKey;
                    switchToIp(entry.displayIp, true);
                }));
            }
        };

        const renderFailure = (failedIp) => {
            if (accessBlocked) {
                $result.text('[ProxyCheck] Access denied or disabled');
                return;
            }
            const $retry = $('<a>', { href: '#', role: 'button', class: 'proxycheck-banner-retry', text: 'Retry ↻' }).on('click', (e) => {
                e.preventDefault(); e.stopPropagation();
                if (accessBlocked) return;
                stopLoading();
                clearContributionsSchedule();
                invalidateIpResultCache(failedIp);
                switchToIp(failedIp, true);
            });
            $result.empty().append(document.createTextNode('[ProxyCheck] Failed to acquire data '), $retry);
        };

        const renderData = (bannerData, isJustUpdated) => {
            const risk = evaluateRisk(bannerData), resolvedIp = bannerData.ip || currentIp, resolvedKey = canonicaliseIpKey(resolvedIp) || currentKey;
            const renderedSeq = loadSeq, renderedKey = currentKey;
            rebuildDetailsForSpur = null;
            $box.removeClass('proxycheck-banner-tier-high proxycheck-banner-tier-medium proxycheck-banner-tier-nonpublic proxycheck-banner-tier-low')
                .addClass('proxycheck-banner-tier-' + risk.riskTier);
            renderSwitcher();
            const badgeClass = 'proxycheck-banner-badge proxycheck-tier-' + risk.riskTier;
            const fullReportLink = () => $('<a>', { href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp), target: '_blank', rel: 'noopener noreferrer', text: 'Full Report ↗' });
            if (risk.isNonPublic) {
                $result.empty().append(
                    $('<span>', { class: badgeClass, text: `ProxyCheck [${risk.nonPublicBadgeCode}]` }),
                    $('<span>').append(document.createTextNode(' \u00b7 '), $('<b>').text('Address Type:'), document.createTextNode(` ${risk.nonPublicReason} \u00b7 `), $('<b>').text('Status:'), document.createTextNode(' External threat lookups skipped (non-public or reserved IP) \u00b7 ')),
                    fullReportLink()
                );
                return;
            }

            const verdictText = typeof bannerData.arbitrationVerdict === 'string' ? bannerData.arbitrationVerdict.trim() : '';
            const ptrHost = typeof bannerData.ptrHostname === 'string' ? bannerData.ptrHostname.trim() : '';
            const ptrLbl = typeof bannerData.ptrLabel === 'string' ? bannerData.ptrLabel.trim() : '';
            const sharedDesc = formatSharedDescription(bannerData, risk);
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
            addItem('Tor Node', risk.isTor ? $('<strong>', { class: 'proxycheck-banner-danger-text', text: formatTorDescription(risk) }) : document.createTextNode('No'));

            let renderedSpur = getSpurProxyText();
            const $details = $('<div>', { class: 'proxycheck-pageinfo-details', style: isStatsExpanded ? 'display: block;' : 'display: none;' })
                .append(buildResultDetailsPanel(bannerData, risk, resolvedIp));
            rebuildDetailsForSpur = () => {
                const latestSpur = getSpurProxyText();
                if (latestSpur === renderedSpur) return;
                renderedSpur = latestSpur;
                $details.empty().append(buildResultDetailsPanel(bannerData, risk, resolvedIp));
            };

            const statsLabel = () => (isStatsExpanded ? 'Statistic ▾' : 'Statistic ▸');
            const $statsToggle = $('<a>', {
                href: '#', role: 'button', class: 'proxycheck-stats-toggle', 'aria-expanded': String(isStatsExpanded), text: statsLabel()
            }).on('click', (e) => {
                e.preventDefault(); e.stopPropagation();
                isStatsExpanded = !isStatsExpanded;
                $details.css('display', isStatsExpanded ? 'block' : 'none');
                $statsToggle.attr('aria-expanded', String(isStatsExpanded)).text(statsLabel());
                if (isStatsExpanded && isPartialLightResult(bannerData) && !fullUpgradeRequestedForKey[resolvedKey]) {
                    fullUpgradeRequestedForKey[resolvedKey] = true;
                    clearContributionsSchedule();
                    attachLightUpgrade($details, resolvedIp, () => ensureBannerAttached() && currentKey === resolvedKey, (fullData) => renderData(fullData, false));
                }
            });

            const refreshCtrl = createRefreshControl(resolvedIp,
                () => ensureBannerAttached() && loadSeq === renderedSeq && currentKey === renderedKey,
                (freshData) => renderData(freshData, true));
            refreshCtrl.sync(bannerData, isJustUpdated);
            $summary.append(
                document.createTextNode(' \u00b7 '), fullReportLink(),
                document.createTextNode(' \u00b7 '), $statsToggle,
                document.createTextNode(' \u00b7 '), $('<span>', { class: 'proxycheck-cache-controls' }).append(refreshCtrl.$ageSpan, refreshCtrl.$btn)
            );
            $result.empty().append($summary, refreshCtrl.$warning, $details);
            if (!isPartialLightResult(bannerData) && shouldAutoRefreshPayload(bannerData, resolvedKey)) refreshCtrl.run(true);
        };

        const scheduleFullUpgradeAfterDelay = (upgradeIp, upgradeKey) => {
            clearContributionsSchedule();
            if (fullUpgradeRequestedForKey[upgradeKey] || accessBlocked) return;
            const armTimer = () => {
                if (contributionsDelayTimer !== null || fullUpgradeRequestedForKey[upgradeKey] || accessBlocked) return;
                contributionsDelayTimer = window.setTimeout(() => {
                    contributionsDelayTimer = null;
                    if (accessBlocked || fullUpgradeRequestedForKey[upgradeKey]) return;
                    if (!isDocumentVisible()) {
                        scheduleContributionsOnVisible(armTimer);
                        return;
                    }
                    fullUpgradeRequestedForKey[upgradeKey] = true;
                    upgradeToFullResult(upgradeIp).then((fullData) => {
                        if (fullData && ensureBannerAttached() && currentKey === upgradeKey) renderData(fullData, false);
                    });
                }, CONTRIB_FULL_TRIGGER_DELAY_MS);
            };
            if (isDocumentVisible()) armTimer();
            else scheduleContributionsOnVisible(armTimer);
        };

        const switchToIp = (nextIp, immediateFetch) => {
            if (!isValidIp(nextIp)) return;
            stopLoading();
            clearContributionsSchedule();
            currentIp = nextIp;
            currentKey = canonicaliseIpKey(nextIp);
            const seq = ++loadSeq;
            renderSwitcher();

            const cached = peekCachedIpState(nextIp);
            if (cached && cached.isFull) {
                fetchIpIntelligence(nextIp, 'full').then((data) => {
                    if (seq !== loadSeq || !ensureBannerAttached()) return;
                    if (data) renderData(data, false);
                    else renderFailure(nextIp);
                });
                return;
            }
            if (cached) {
                if (!ensureBannerAttached()) return;
                renderData(cached.data, false);
                if (!isPartialLightResult(cached.data)) return;
                if (!immediateFetch) {
                    scheduleFullUpgradeAfterDelay(nextIp, currentKey);
                    return;
                }
                fullUpgradeRequestedForKey[currentKey] = true;
                upgradeToFullResult(nextIp).then((fullData) => {
                    if (fullData && seq === loadSeq && ensureBannerAttached()) renderData(fullData, false);
                });
                return;
            }

            const frames = ['.\u00a0\u00a0', '\u00a0.\u00a0', '\u00a0\u00a0.'];
            let frameIdx = 0;
            $result.text(frames[0]);
            loadingInterval = window.setInterval(() => {
                if (accessBlocked) stopLoading();
                else $result.text(frames[(frameIdx = (frameIdx + 1) % frames.length)]);
            }, 300);

            const runFullFetch = () => fetchIpIntelligence(nextIp, 'full').then((data) => {
                if (seq !== loadSeq) return;
                stopLoading();
                if (!ensureBannerAttached()) return;
                if (data) renderData(data, false);
                else renderFailure(nextIp);
            });
            if (immediateFetch) {
                runFullFetch();
                return;
            }
            contributionsDelayTimer = window.setTimeout(() => {
                contributionsDelayTimer = null;
                if (seq !== loadSeq) return;
                if (accessBlocked) {
                    stopLoading();
                    return;
                }
                if (!isDocumentVisible()) {
                    removeUnpopulatedBanner();
                    resumeWhenVisible();
                    return;
                }
                runFullFetch();
            }, CONTRIB_FULL_TRIGGER_DELAY_MS);
        };

        mountInto(initialMountTarget);
        switchToIp(initialIp, isTempAccountTarget);
        return {
            syncDiscoveredIps: (nextList) => {
                if (isRemoved || nextList.length === 0) return;
                const nextSignature = listSignature(nextList);
                if (nextSignature === discoveredSignature) return;
                discoveredSignature = nextSignature;
                discoveredList = nextList.slice();
                if (!pinnedKey && discoveredList[0].canonicalKey !== currentKey) switchToIp(discoveredList[0].displayIp, true);
                else renderSwitcher();
            },
            refreshSpur: () => {
                if (!isRemoved && rebuildDetailsForSpur) rebuildDetailsForSpur();
            }
        };
    }

    $(() => {
        ensureUserscriptStyles();
        handleIPContributionsPage();
        scanSubtree(document.body);
        if (isIpContributionsPage) mw.hook('wikipage.content').add(() => handleIPContributionsPage());

        observer = new MutationObserver((mutations) => {
            if (accessBlocked) return;
            let hasExternal = false, touchesIpInfo = false;
            for (const m of mutations) {
                if (!m.target || isProxycheckInternalNode(m.target)) continue;
                const targetEl = m.target.nodeType === 3 ? m.target.parentNode : m.target;
                if (!targetEl || targetEl.nodeType !== 1 || isProxycheckInternalNode(targetEl)) continue;
                const matched = targetEl.closest(TARGET_SELECTOR);
                if (matched) {
                    hasExternal = true;
                    scanSubtree(matched);
                }
                for (const added of m.addedNodes) {
                    if (!added || added.nodeType !== 1 || isProxycheckInternalNode(added)) continue;
                    hasExternal = true;
                    if (!touchesIpInfo) {
                        touchesIpInfo = Boolean(targetEl.closest(IPINFO_PANEL_SELECTOR) || added.matches(IPINFO_PANEL_SELECTOR) || added.querySelector(IPINFO_PANEL_SELECTOR));
                    }
                    scanSubtree(added);
                }
            }
            if (!isIpContributionsPage || !hasExternal) return;
            if (touchesIpInfo) pendingSpurRefresh = true;
            if (contributionsObserverTimer !== null) return;
            contributionsObserverTimer = window.setTimeout(() => {
                contributionsObserverTimer = null;
                const runSpur = pendingSpurRefresh;
                pendingSpurRefresh = false;
                if (accessBlocked) return;
                handleIPContributionsPage();
                if (runSpur && contributionsBanner) contributionsBanner.refreshSpur();
            }, OBSERVER_THROTTLE_MS);
        });
        observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    });
})(mediaWiki, jQuery);
