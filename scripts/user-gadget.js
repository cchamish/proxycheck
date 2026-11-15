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

    var username = mw.config.get('wgUserName');
    if (!username || mw.config.get('wgUserIsTemp') || username.charAt(0) === '~') {
        return;
    }

    var TOOL_BASE_URL = 'https://proxycheck.toolforge.org';
    var TARGET_SELECTOR = 'a.ext-checkuser-tempaccount-reveal-ip-anchor';
    var BADGE_CLASS = 'proxycheck-ip-badge';
    var STYLE_ELEMENT_ID = 'proxycheck-userscript-styles';
    var INTERNAL_NODE_SELECTOR = '#proxycheck-pageinfo, #proxycheck_result, #proxycheck-userscript-styles, .proxycheck-ip-badge, .proxycheck-details-panel, .proxycheck-light-upgrade-notice';
    var IPINFO_PANEL_SELECTOR = '.ext-ipinfo-panel-layout';
    var OBSERVER_THROTTLE_MS = 100;
    var IPINFO_FALLBACK_DELAY_MS = 400;
    var MAX_CONCURRENT_REQUESTS = 4;
    var BATCH_DEBOUNCE_MS = 40;
    var MAX_BATCH_IPS = 25;
    var CONSENT_KEY = 'proxycheck-ip-policy-consent';
    var TOKEN_KEY = 'proxycheck-gadget-token';
    var TOKEN_USER_KEY = 'proxycheck-gadget-token-user';
    var TOKEN_EXPIRY_KEY = 'proxycheck-gadget-token-exp';
    var TOKEN_REFRESH_LOCK_KEY = 'proxycheck-gadget-token-refresh-lock';
    var TOKEN_REFRESH_LOCK_TTL_MS = 8000;
    var TOKEN_REFRESH_POLL_INTERVAL_MS = 250;
    var TOKEN_REFRESH_WAIT_TIMEOUT_MS = 4000;
    var RESULT_CACHE_STORAGE_KEY = 'proxycheck-ip-result-cache-v1';
    var RESULT_CACHE_TTL_MS = 30 * 60 * 1000;
    var RESULT_CACHE_MAX_ENTRIES = 200;

    var IPV4_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
    var IPV6_PATTERN = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

    var ipPromiseCache = new Map();
    var ipFullPromiseCache = new Map();
    var latestResultByIp = new Map();
    var renderedBadgeEntriesByIp = new Map();
    var persistedCacheRaw = null;
    var persistedCacheStore = null;
    var storageFailureWarned = false;
    var stylesInjected = false;
    var observer = null;
    var viewportObserver = null;
    var accessBlocked = false;
    var consentGranted = false;
    var consentDeclined = false;
    var consentPromise = null;
    var authPromise = null;
    var tokenRefreshWaitTimer = null;
    var tokenRefreshWaitCancel = null;
    var memoryToken = null;
    var memoryTokenExpiry = null;
    function isContributionsSpecialPage() {
        var specialName = mw.config.get('wgCanonicalSpecialPageName');
        if (specialName === 'IPContributions' || specialName === 'Contributions' || specialName === 'IContributions') {
            return true;
        }
        if (specialName) {
            return false;
        }
        var pageName = mw.config.get('wgPageName') || '';
        return /^[^:]+:(IPContributions|IContributions|Contributions)(\/|$)/i.test(pageName);
    }

    var ipContributionsPending = false;
    var ipContributionsInvalidTarget = false;
    var isIpContributionsPage = isContributionsSpecialPage();
    var infoDialogPromise = null;
    var refreshPageInfoSpur = null;
    var activeLoadingInterval = null;
    var ipContributionsObserverTimer = null;
    var ipContributionsFallbackTimer = null;
    var pendingContributionsPageCheck = false;
    var pendingSpurRefresh = false;
    var activeRequestCount = 0;
    var requestQueue = [];
    var batchEndpointSupported = true;
    var pendingBatchQueue = [];
    var batchDebounceTimer = null;

    function clearLoadingInterval() {
        if (activeLoadingInterval !== null) {
            window.clearInterval(activeLoadingInterval);
            activeLoadingInterval = null;
        }
    }

    function clearTokenRefreshWait() {
        if (tokenRefreshWaitTimer !== null) {
            window.clearTimeout(tokenRefreshWaitTimer);
            tokenRefreshWaitTimer = null;
        }
        if (typeof tokenRefreshWaitCancel === 'function') {
            var cancelFn = tokenRefreshWaitCancel;
            tokenRefreshWaitCancel = null;
            cancelFn();
        }
    }

    function clearRequestQueue() {
        if (batchDebounceTimer !== null) {
            window.clearTimeout(batchDebounceTimer);
            batchDebounceTimer = null;
        }
        while (pendingBatchQueue.length > 0) {
            var pending = pendingBatchQueue.shift();
            pending.resolve(null);
        }
        while (requestQueue.length > 0) {
            var queued = requestQueue.shift();
            queued.resolve(null);
        }
    }

    function blockAccess() {
        accessBlocked = true;
        clearLoadingInterval();
        clearTokenRefreshWait();
        if (ipContributionsObserverTimer !== null) {
            window.clearTimeout(ipContributionsObserverTimer);
            ipContributionsObserverTimer = null;
        }
        if (ipContributionsFallbackTimer !== null) {
            window.clearTimeout(ipContributionsFallbackTimer);
            ipContributionsFallbackTimer = null;
        }
        pendingContributionsPageCheck = false;
        pendingSpurRefresh = false;
        clearRequestQueue();
        if (observer) {
            observer.disconnect();
        }
        if (viewportObserver) {
            viewportObserver.disconnect();
        }
    }

    function clearStoredToken() {
        memoryToken = null;
        memoryTokenExpiry = null;
        mw.storage.remove(TOKEN_KEY);
        mw.storage.remove(TOKEN_USER_KEY);
        mw.storage.remove(TOKEN_EXPIRY_KEY);
    }

    function readStoredToken() {
        var storedUser = mw.storage.get(TOKEN_USER_KEY);
        var token = mw.storage.get(TOKEN_KEY);
        var storedExpiry = mw.storage.get(TOKEN_EXPIRY_KEY);
        var hasStoredExpiry = (typeof storedExpiry === 'string' && storedExpiry.trim() !== '') ||
            (typeof storedExpiry === 'number' && isFinite(storedExpiry));
        if (hasStoredExpiry) {
            var expiryMs = Number(storedExpiry);
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
        if (
            typeof expiresInSeconds === 'number' &&
            isFinite(expiresInSeconds) &&
            expiresInSeconds > 0 &&
            Math.floor(expiresInSeconds) === expiresInSeconds
        ) {
            var expiryMs = Date.now() + Math.max(0, expiresInSeconds - 60) * 1000;
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
        if (!text || text.indexOf('.') === -1 || text.indexOf(':') !== -1) {
            return null;
        }
        var parts = text.split('.');
        if (parts.length !== 4) {
            return null;
        }
        var octets = [];
        for (var i = 0; i < 4; i++) {
            if (!/^\d{1,3}$/.test(parts[i])) {
                return null;
            }
            var num = parseInt(parts[i], 10);
            if (isNaN(num) || num < 0 || num > 255) {
                return null;
            }
            octets.push(num);
        }
        return octets;
    }

    // Normalize IPv4 and IPv6 addresses into a canonical RFC 5952 cache key
    function canonicalizeIpKey(rawIp) {
        if (rawIp === null || rawIp === undefined) {
            return '';
        }
        var normalized = String(rawIp).trim().toLowerCase();
        if (!normalized) {
            return '';
        }

        if (normalized.indexOf(':') !== -1) {
            var zoneIndex = normalized.indexOf('%');
            if (zoneIndex !== -1) {
                normalized = normalized.slice(0, zoneIndex);
            }
            if (!normalized) {
                return '';
            }
        }

        var v4Octets = parseIpv4Octets(normalized);
        if (v4Octets) {
            return v4Octets.join('.');
        }

        if (normalized.indexOf(':') === -1) {
            return normalized;
        }

        var halves = normalized.split('::');
        if (halves.length > 2) {
            return normalized;
        }

        var hasCompression = halves.length === 2;
        var leftGroups = halves[0] ? halves[0].split(':') : [];
        var rightGroups = hasCompression && halves[1] ? halves[1].split(':') : [];

        // Convert an optional trailing dotted-quad IPv4 segment into two 16-bit hex groups
        var tailTarget = hasCompression ? rightGroups : leftGroups;
        if (tailTarget.length > 0 && tailTarget[tailTarget.length - 1].indexOf('.') !== -1) {
            var embeddedOctets = parseIpv4Octets(tailTarget[tailTarget.length - 1]);
            if (!embeddedOctets) {
                return normalized;
            }
            tailTarget.pop();
            tailTarget.push(((embeddedOctets[0] << 8) | embeddedOctets[1]).toString(16));
            tailTarget.push(((embeddedOctets[2] << 8) | embeddedOctets[3]).toString(16));
        }

        var totalExplicit = leftGroups.length + rightGroups.length;
        if (hasCompression) {
            if (totalExplicit >= 8) {
                return normalized;
            }
        } else if (totalExplicit !== 8) {
            return normalized;
        }

        var expanded = [];
        var i;
        for (i = 0; i < leftGroups.length; i++) {
            expanded.push(leftGroups[i]);
        }
        if (hasCompression) {
            var zeroCount = 8 - totalExplicit;
            for (i = 0; i < zeroCount; i++) {
                expanded.push('0');
            }
        }
        for (i = 0; i < rightGroups.length; i++) {
            expanded.push(rightGroups[i]);
        }

        for (i = 0; i < 8; i++) {
            var group = expanded[i];
            if (!/^[0-9a-f]{1,4}$/.test(group)) {
                return normalized;
            }
            expanded[i] = group.replace(/^0+/, '') || '0';
        }

        // Format IPv4-mapped IPv6 addresses per RFC 5952 section 5
        if (
            expanded[0] === '0' &&
            expanded[1] === '0' &&
            expanded[2] === '0' &&
            expanded[3] === '0' &&
            expanded[4] === '0' &&
            expanded[5] === 'ffff'
        ) {
            var hi = parseInt(expanded[6], 16);
            var lo = parseInt(expanded[7], 16);
            return '::ffff:' +
                ((hi >> 8) & 255) + '.' +
                (hi & 255) + '.' +
                ((lo >> 8) & 255) + '.' +
                (lo & 255);
        }

        var bestStart = -1;
        var bestLen = 0;
        var curStart = -1;
        var curLen = 0;
        for (i = 0; i < 8; i++) {
            if (expanded[i] === '0') {
                if (curStart === -1) {
                    curStart = i;
                    curLen = 1;
                } else {
                    curLen += 1;
                }
                if (curLen > bestLen) {
                    bestStart = curStart;
                    bestLen = curLen;
                }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }

        if (bestLen <= 1) {
            return expanded.join(':');
        }
        if (bestLen === 8) {
            return '::';
        }
        var prefix = expanded.slice(0, bestStart).join(':');
        var suffix = expanded.slice(bestStart + bestLen).join(':');
        return prefix + '::' + suffix;
    }

    function warnPersistedCacheOnce(context, err) {
        if (storageFailureWarned || typeof console === 'undefined' || typeof console.warn !== 'function') {
            return;
        }
        storageFailureWarned = true;
        console.warn('[proxycheck] Persisted cache ' + context + ':', err);
    }

    function wrapWebStorage(storageName) {
        try {
            if (typeof window === 'undefined') {
                return null;
            }
            var store = window[storageName];
            if (
                !store ||
                typeof store.getItem !== 'function' ||
                typeof store.setItem !== 'function'
            ) {
                return null;
            }
            return {
                get: function (key) {
                    return store.getItem(key);
                },
                set: function (key, value) {
                    store.setItem(key, value);
                    return true;
                },
                remove: function (key) {
                    if (typeof store.removeItem === 'function') {
                        store.removeItem(key);
                    }
                }
            };
        } catch (err) {
            warnPersistedCacheOnce('storage access failed for ' + storageName, err);
            return null;
        }
    }

    function getResultStorageBackend() {
        var local = wrapWebStorage('localStorage');
        if (local) {
            return local;
        }
        try {
            if (
                mw &&
                mw.storage &&
                typeof mw.storage.get === 'function' &&
                typeof mw.storage.set === 'function'
            ) {
                return {
                    get: function (key) {
                        return mw.storage.get(key);
                    },
                    set: function (key, value) {
                        return mw.storage.set(key, value) !== false;
                    },
                    remove: function (key) {
                        if (typeof mw.storage.remove === 'function') {
                            mw.storage.remove(key);
                        }
                    }
                };
            }
        } catch (err) {
            warnPersistedCacheOnce('storage access failed for mw.storage', err);
        }
        return wrapWebStorage('sessionStorage');
    }

    // Clone payload without provider rawJson fields to keep persisted storage compact
    function compactIpResultForStorage(data) {
        if (!data || typeof data !== 'object') {
            return null;
        }
        var copy = {};
        var keys = Object.keys(data);
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            if (key === 'results' && Array.isArray(data.results)) {
                var compactResults = [];
                for (var j = 0; j < data.results.length; j++) {
                    var row = data.results[j];
                    if (!row || typeof row !== 'object') {
                        compactResults.push(row);
                        continue;
                    }
                    var compactRow = {};
                    var rowKeys = Object.keys(row);
                    for (var k = 0; k < rowKeys.length; k++) {
                        var rowKey = rowKeys[k];
                        if (rowKey !== 'rawJson') {
                            compactRow[rowKey] = row[rowKey];
                        }
                    }
                    compactResults.push(compactRow);
                }
                copy.results = compactResults;
            } else {
                copy[key] = data[key];
            }
        }
        return copy;
    }

    function clearCorruptPersistedStore(backend) {
        persistedCacheRaw = null;
        persistedCacheStore = null;
        try {
            backend.remove(RESULT_CACHE_STORAGE_KEY);
        } catch (err) {
            warnPersistedCacheOnce('cleanup failed', err);
        }
    }

    function readPersistedResultStore(backend) {
        if (!backend) {
            return null;
        }
        var raw = null;
        try {
            raw = backend.get(RESULT_CACHE_STORAGE_KEY);
        } catch (err) {
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
        if (raw === persistedCacheRaw && persistedCacheStore) {
            return persistedCacheStore;
        }
        var parsed = null;
        try {
            parsed = JSON.parse(raw);
        } catch (err) {
            warnPersistedCacheOnce('parse failed', err);
            clearCorruptPersistedStore(backend);
            return null;
        }
        if (
            !parsed ||
            typeof parsed !== 'object' ||
            !parsed.entries ||
            typeof parsed.entries !== 'object' ||
            Array.isArray(parsed.entries)
        ) {
            clearCorruptPersistedStore(backend);
            return null;
        }
        persistedCacheRaw = raw;
        persistedCacheStore = parsed;
        return parsed;
    }

    function isResultEntryValid(entry, now) {
        return Boolean(
            entry &&
            typeof entry === 'object' &&
            typeof entry.ts === 'number' &&
            isFinite(entry.ts) &&
            (now - entry.ts < RESULT_CACHE_TTL_MS) &&
            entry.data &&
            typeof entry.data === 'object'
        );
    }

    function cloneEntriesExcluding(sourceEntries, excludedKey) {
        var nextEntries = Object.create(null);
        if (!sourceEntries) {
            return nextEntries;
        }
        var keys = Object.keys(sourceEntries);
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            if (key !== excludedKey) {
                nextEntries[key] = sourceEntries[key];
            }
        }
        return nextEntries;
    }

    function pruneExpiredResultEntries(entries, now) {
        var keys = Object.keys(entries);
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            if (!isResultEntryValid(entries[key], now)) {
                delete entries[key];
            }
        }
    }

    function evictOldestResultEntries(entries, maxEntries, protectedKey) {
        var keys = Object.keys(entries);
        if (keys.length <= maxEntries) {
            return;
        }
        var sortable = [];
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            sortable.push({
                key: key,
                ts: entries[key].ts,
                order: i,
                isProtected: Boolean(protectedKey && key === protectedKey)
            });
        }
        sortable.sort(function (a, b) {
            if (a.isProtected !== b.isProtected) {
                return a.isProtected ? 1 : -1;
            }
            if (a.ts !== b.ts) {
                return a.ts - b.ts;
            }
            return a.order - b.order;
        });
        var excessCount = sortable.length - maxEntries;
        for (var j = 0; j < excessCount; j++) {
            delete entries[sortable[j].key];
        }
    }

    function writePersistedResultStore(backend, store, protectedKey) {
        if (!backend || !store) {
            return false;
        }
        persistedCacheRaw = null;
        persistedCacheStore = null;

        var currentCount = Object.keys(store.entries).length;
        var attemptLimits = currentCount === 0
            ? [0]
            : [currentCount, Math.floor(RESULT_CACHE_MAX_ENTRIES / 2), 20, 1];
        var triedLimits = Object.create(null);
        var lastWriteErr = null;

        for (var i = 0; i < attemptLimits.length; i++) {
            var limit = attemptLimits[i];
            if (triedLimits[limit]) {
                continue;
            }
            triedLimits[limit] = true;
            evictOldestResultEntries(store.entries, limit, protectedKey);

            var serialized = null;
            try {
                serialized = JSON.stringify(store);
            } catch (err) {
                warnPersistedCacheOnce('serialization failed', err);
                return false;
            }
            try {
                if (backend.set(RESULT_CACHE_STORAGE_KEY, serialized)) {
                    persistedCacheRaw = serialized;
                    persistedCacheStore = store;
                    return true;
                }
            } catch (err) {
                lastWriteErr = err;
            }
        }
        if (lastWriteErr) {
            warnPersistedCacheOnce('write failed', lastWriteErr);
        }
        return false;
    }

    function normalizeQueryMode(mode) {
        return String(mode || 'light').trim().toLowerCase() === 'full' ? 'full' : 'light';
    }

    function isPartialLightResult(data) {
        return Boolean(
            data &&
            typeof data === 'object' &&
            data.queryMode === 'light' &&
            Boolean(data.isPartialMode)
        );
    }

    function recordLatestIpResult(cacheKey, data) {
        if (!cacheKey || !data || typeof data !== 'object') {
            return;
        }
        var existing = latestResultByIp.get(cacheKey);
        if (existing && !isPartialLightResult(existing) && isPartialLightResult(data)) {
            return;
        }
        latestResultByIp.set(cacheKey, data);
    }

    function readPersistedIpResult(cacheKey) {
        if (!cacheKey || typeof cacheKey !== 'string') {
            return null;
        }
        var backend = getResultStorageBackend();
        var store = readPersistedResultStore(backend);
        if (!store || !Object.prototype.hasOwnProperty.call(store.entries, cacheKey)) {
            return null;
        }

        var now = Date.now();
        var entry = store.entries[cacheKey];
        if (!isResultEntryValid(entry, now)) {
            var nextEntries = cloneEntriesExcluding(store.entries, cacheKey);
            pruneExpiredResultEntries(nextEntries, now);
            writePersistedResultStore(backend, { entries: nextEntries }, null);
            return null;
        }

        return entry.data;
    }

    function writePersistedIpResult(cacheKey, data) {
        if (!cacheKey || typeof cacheKey !== 'string' || !data || typeof data !== 'object') {
            return;
        }
        var compactData = compactIpResultForStorage(data);
        if (!compactData) {
            return;
        }
        var backend = getResultStorageBackend();
        if (!backend) {
            return;
        }

        var now = Date.now();
        var existingStore = readPersistedResultStore(backend);
        var existingEntry = existingStore && existingStore.entries
            ? existingStore.entries[cacheKey]
            : null;
        if (
            isPartialLightResult(compactData) &&
            isResultEntryValid(existingEntry, now) &&
            !isPartialLightResult(existingEntry.data)
        ) {
            return;
        }
        var nextEntries = cloneEntriesExcluding(existingStore && existingStore.entries, cacheKey);

        pruneExpiredResultEntries(nextEntries, now);
        nextEntries[cacheKey] = {
            ts: now,
            data: compactData
        };
        evictOldestResultEntries(nextEntries, RESULT_CACHE_MAX_ENTRIES, cacheKey);
        writePersistedResultStore(backend, { entries: nextEntries }, cacheKey);
    }

    function ensureConsent(forcePrompt) {
        if (accessBlocked) {
            return Promise.resolve(false);
        }
        if (consentGranted || mw.storage.get(CONSENT_KEY) === '1') {
            consentGranted = true;
            consentDeclined = false;
            return Promise.resolve(true);
        }
        if (consentDeclined && !forcePrompt) {
            return Promise.resolve(false);
        }
        if (consentPromise) {
            return consentPromise;
        }

        consentDeclined = false;
        consentPromise = mw.loader.using('oojs-ui-windows').then(function () {
            var $message = $('<div>').append(
                $('<p>').text('By using this script, you acknowledge that you fully understand and agree to comply with:'),
                $('<ul>').append(
                    $('<li>').append($('<a>', {
                        href: 'https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_Access_to_Nonpublic_Personal_Data_Policy',
                        target: '_blank',
                        rel: 'noopener noreferrer',
                        text: 'Wikimedia Foundation Access to Nonpublic Personal Data Policy'
                    })),
                    $('<li>').append($('<a>', {
                        href: 'https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy',
                        target: '_blank',
                        rel: 'noopener noreferrer',
                        text: 'Wikimedia Foundation Privacy Policy'
                    }))
                ),
                $('<p>').text('and all other applicable policies and guidelines regarding Temporary Account IP reveal.'),
                $('<p>').text('Do you agree and wish to proceed?')
            );

            return OO.ui.confirm($message, {
                title: 'Proxy Detector on Temporary Account IP',
                size: 'medium'
            });
        }).then(function (agreed) {
            consentPromise = null;
            if (agreed) {
                consentGranted = true;
                consentDeclined = false;
                mw.storage.set(CONSENT_KEY, '1');
                return true;
            }
            consentDeclined = true;
            return false;
        }).catch(function (err) {
            console.warn('[proxycheck] Failed to load consent dialog:', err);
            consentPromise = null;
            consentDeclined = true;
            return false;
        });

        return consentPromise;
    }

    function isTokenRefreshLockActive() {
        var rawLock = mw.storage.get(TOKEN_REFRESH_LOCK_KEY);
        if (rawLock === false || rawLock === null || rawLock === undefined || rawLock === '') {
            return false;
        }
        var lockTs = Number(rawLock);
        if (!isFinite(lockTs) || lockTs <= 0) {
            return false;
        }
        var ageMs = Date.now() - lockTs;
        return ageMs >= -5000 && ageMs < TOKEN_REFRESH_LOCK_TTL_MS;
    }

    function acquireTokenRefreshLock() {
        var lockValue = String(Date.now());
        mw.storage.set(TOKEN_REFRESH_LOCK_KEY, lockValue);
        return lockValue;
    }

    function releaseTokenRefreshLock(lockValue) {
        if (!lockValue) {
            mw.storage.remove(TOKEN_REFRESH_LOCK_KEY);
            return;
        }
        var currentLock = mw.storage.get(TOKEN_REFRESH_LOCK_KEY);
        if (currentLock === null || currentLock === undefined || currentLock === false) {
            return;
        }
        if (String(currentLock) === String(lockValue)) {
            mw.storage.remove(TOKEN_REFRESH_LOCK_KEY);
        }
    }

    function waitForCrossTabTokenRefresh(failedToken) {
        return new Promise(function (resolve) {
            var startedAt = Date.now();
            var settled = false;

            function finish(token) {
                if (settled) {
                    return;
                }
                settled = true;
                if (tokenRefreshWaitTimer !== null) {
                    window.clearTimeout(tokenRefreshWaitTimer);
                    tokenRefreshWaitTimer = null;
                }
                if (tokenRefreshWaitCancel === cancelWait) {
                    tokenRefreshWaitCancel = null;
                }
                resolve(token || null);
            }

            function cancelWait() {
                finish(null);
            }

            tokenRefreshWaitCancel = cancelWait;

            function poll() {
                if (accessBlocked) {
                    finish(null);
                    return;
                }
                var storedToken = readStoredToken();
                if (storedToken && (!failedToken || storedToken !== failedToken)) {
                    finish(storedToken);
                    return;
                }
                if (!isTokenRefreshLockActive()) {
                    finish(null);
                    return;
                }
                if (Date.now() - startedAt >= TOKEN_REFRESH_WAIT_TIMEOUT_MS) {
                    finish(null);
                    return;
                }
                tokenRefreshWaitTimer = window.setTimeout(poll, TOKEN_REFRESH_POLL_INTERVAL_MS);
            }

            tokenRefreshWaitTimer = window.setTimeout(poll, TOKEN_REFRESH_POLL_INTERVAL_MS);
        });
    }

    function performGadgetTokenExchange() {
        if (accessBlocked) {
            return Promise.resolve(null);
        }

        var lockValue = acquireTokenRefreshLock();
        clearStoredToken();

        var wikiDomain = mw.config.get('wgServerName');

        return Promise.resolve(mw.loader.using('mediawiki.api')).then(function () {
            if (accessBlocked) {
                return null;
            }
            return new mw.Api().get({ action: 'centralauthtoken' }).then(function (apiData) {
                return apiData;
            }, function (code, details) {
                console.warn('[proxycheck] MediaWiki centralauthtoken request failed:', code, details);
                return null;
            });
        }).then(function (apiData) {
            if (!apiData || accessBlocked) {
                return null;
            }
            var centralAuthToken = apiData &&
                apiData.centralauthtoken &&
                apiData.centralauthtoken.centralauthtoken;
            if (!centralAuthToken || typeof centralAuthToken !== 'string') {
                console.warn('[proxycheck] MediaWiki did not return a centralauthtoken:', apiData);
                return null;
            }

            return fetch(TOOL_BASE_URL + '/api/v1/auth/gadget-token', {
                method: 'POST',
                mode: 'cors',
                credentials: 'omit',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    centralauthtoken: centralAuthToken,
                    domain: wikiDomain
                })
            }).then(function (response) {
                if (!response.ok) {
                    return response.text().then(function (bodyText) {
                        console.warn('[proxycheck] Gadget token exchange HTTP ' + response.status + ':', bodyText);
                        if (response.status === 403) {
                            clearStoredToken();
                            blockAccess();
                        } else if (response.status === 401) {
                            clearStoredToken();
                        }
                        return null;
                    });
                }
                return response.json().then(function (payload) {
                    var signedToken = payload && payload.token;
                    if (!signedToken || typeof signedToken !== 'string') {
                        console.warn('[proxycheck] Gadget token response did not contain a token:', payload);
                        return null;
                    }
                    storeToken(signedToken, payload && payload.expires_in);
                    return signedToken;
                });
            });
        }).catch(function (err) {
            console.warn('[proxycheck] CentralAuth token exchange failed:', err);
            return null;
        }).then(function (token) {
            releaseTokenRefreshLock(lockValue);
            return token;
        });
    }

    // Deduplicate concurrent CentralAuth token exchanges across intra-tab callers and browser tabs
    function refreshGadgetToken(failedToken) {
        if (accessBlocked) {
            return Promise.resolve(null);
        }
        if (authPromise) {
            return authPromise;
        }
        var latestToken = readStoredToken();
        if (latestToken && (!failedToken || latestToken !== failedToken)) {
            return Promise.resolve(latestToken);
        }

        var pendingExchange;
        if (isTokenRefreshLockActive()) {
            pendingExchange = waitForCrossTabTokenRefresh(failedToken).then(function (sharedToken) {
                if (accessBlocked) {
                    return null;
                }
                if (sharedToken && (!failedToken || sharedToken !== failedToken)) {
                    return sharedToken;
                }
                var currentStored = readStoredToken();
                if (currentStored && (!failedToken || currentStored !== failedToken)) {
                    return currentStored;
                }
                return performGadgetTokenExchange();
            });
        } else {
            pendingExchange = performGadgetTokenExchange();
        }

        var trackedPromise = pendingExchange.then(function (token) {
            if (authPromise === trackedPromise) {
                authPromise = null;
            }
            return token;
        }, function (err) {
            if (authPromise === trackedPromise) {
                authPromise = null;
            }
            throw err;
        });
        authPromise = trackedPromise;
        return trackedPromise;
    }

    function ensureGadgetToken() {
        if (accessBlocked) {
            return Promise.resolve(null);
        }
        var storedToken = readStoredToken();
        if (storedToken) {
            return Promise.resolve(storedToken);
        }
        return refreshGadgetToken(null);
    }

    function fetchDetectWithToken(ip, token, hasRetried, mode) {
        var resolvedMode = normalizeQueryMode(mode);
        return fetch(
            TOOL_BASE_URL +
                '/api/v1/detect?ip=' +
                encodeURIComponent(ip) +
                '&compact=1&mode=' +
                encodeURIComponent(resolvedMode),
            {
                method: 'GET',
                mode: 'cors',
                credentials: 'omit',
                headers: { 'Authorization': 'Bearer ' + token }
            }
        ).then(function (response) {
            if (response.status === 403) {
                clearStoredToken();
                blockAccess();
                return null;
            }
            if (response.status === 401) {
                if (hasRetried) {
                    clearStoredToken();
                    blockAccess();
                    return null;
                }
                return refreshGadgetToken(token).then(function (freshToken) {
                    if (!freshToken || accessBlocked) {
                        return null;
                    }
                    return fetchDetectWithToken(ip, freshToken, true, resolvedMode);
                });
            }
            if (!response.ok) {
                console.warn('[proxycheck] Detection API returned HTTP ' + response.status + ' for ' + ip);
                return null;
            }
            return response.json();
        });
    }

    function pumpRequestQueue() {
        if (accessBlocked) {
            clearRequestQueue();
            return;
        }
        while (activeRequestCount < MAX_CONCURRENT_REQUESTS && requestQueue.length > 0) {
            var item = requestQueue.shift();
            runQueuedNetworkTask(item.taskFn, item.resolve, item.reject);
        }
    }

    function runQueuedNetworkTask(taskFn, resolve, reject) {
        if (accessBlocked) {
            clearRequestQueue();
            resolve(null);
            return;
        }
        activeRequestCount += 1;
        var taskPromise;
        try {
            taskPromise = Promise.resolve(taskFn());
        } catch (err) {
            taskPromise = Promise.reject(err);
        }
        taskPromise.then(function (result) {
            activeRequestCount -= 1;
            pumpRequestQueue();
            resolve(result);
        }, function (err) {
            activeRequestCount -= 1;
            pumpRequestQueue();
            reject(err);
        });
    }

    // Bound concurrent API detection requests to avoid exhausting browser connections
    function enqueueNetworkTask(taskFn) {
        if (accessBlocked) {
            clearRequestQueue();
            return Promise.resolve(null);
        }
        return new Promise(function (resolve, reject) {
            if (activeRequestCount < MAX_CONCURRENT_REQUESTS) {
                runQueuedNetworkTask(taskFn, resolve, reject);
            } else {
                requestQueue.push({
                    taskFn: taskFn,
                    resolve: resolve,
                    reject: reject
                });
            }
        });
    }

    function enqueueSingleIpDetection(ip, mode) {
        var resolvedMode = normalizeQueryMode(mode);
        return enqueueNetworkTask(function () {
            if (accessBlocked) {
                return null;
            }
            return ensureGadgetToken().then(function (token) {
                if (!token || accessBlocked) {
                    return null;
                }
                return fetchDetectWithToken(ip, token, false, resolvedMode);
            });
        });
    }

    function fetchBatchDetectWithToken(ips, token, hasRetried, mode) {
        var resolvedMode = normalizeQueryMode(mode);
        return fetch(TOOL_BASE_URL + '/api/v1/detect/batch?compact=1', {
            method: 'POST',
            mode: 'cors',
            credentials: 'omit',
            headers: {
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ips: ips, mode: resolvedMode })
        }).then(function (response) {
            if (response.status === 404 || response.status === 405) {
                batchEndpointSupported = false;
                return { fallbackSingle: true };
            }
            if (response.status === 403) {
                clearStoredToken();
                blockAccess();
                return null;
            }
            if (response.status === 401) {
                if (hasRetried) {
                    clearStoredToken();
                    blockAccess();
                    return null;
                }
                return refreshGadgetToken(token).then(function (freshToken) {
                    if (!freshToken || accessBlocked) {
                        return null;
                    }
                    return fetchBatchDetectWithToken(ips, freshToken, true, resolvedMode);
                });
            }
            if (!response.ok) {
                console.warn('[proxycheck] Batch detection API returned HTTP ' + response.status);
                return null;
            }
            return response.json();
        });
    }

    function extractIpResultFromBatch(batchPayload, rawIp) {
        if (!batchPayload || typeof batchPayload !== 'object') {
            return null;
        }
        var results = batchPayload.results;
        if (!results || typeof results !== 'object') {
            return null;
        }
        var trimmedIp = String(rawIp || '').trim();
        var lowerIp = trimmedIp.toLowerCase();
        var canonicalKey = canonicalizeIpKey(trimmedIp);
        if (Object.prototype.hasOwnProperty.call(results, trimmedIp) && results[trimmedIp]) {
            return results[trimmedIp];
        }
        if (Object.prototype.hasOwnProperty.call(results, lowerIp) && results[lowerIp]) {
            return results[lowerIp];
        }
        if (canonicalKey && Object.prototype.hasOwnProperty.call(results, canonicalKey) && results[canonicalKey]) {
            return results[canonicalKey];
        }
        var inputMap = batchPayload.inputMap;
        if (inputMap && typeof inputMap === 'object') {
            var mappedKey = inputMap[rawIp] || inputMap[trimmedIp] || inputMap[lowerIp] ||
                (canonicalKey ? inputMap[canonicalKey] : '');
            if (mappedKey && Object.prototype.hasOwnProperty.call(results, mappedKey) && results[mappedKey]) {
                return results[mappedKey];
            }
        }
        var keys = Object.keys(results);
        for (var i = 0; i < keys.length; i++) {
            var entry = results[keys[i]];
            if (keys[i].toLowerCase() === lowerIp ||
                (canonicalKey && canonicalizeIpKey(keys[i]) === canonicalKey)) {
                return entry;
            }
            if (entry && typeof entry.ip === 'string' &&
                (entry.ip.toLowerCase() === lowerIp ||
                 (canonicalKey && canonicalizeIpKey(entry.ip) === canonicalKey))) {
                return entry;
            }
        }
        return null;
    }

    function fallbackBatchItemsToSingle(batchItems) {
        for (var i = 0; i < batchItems.length; i++) {
            (function (item) {
                enqueueSingleIpDetection(item.ip, item.mode).then(item.resolve, item.reject);
            })(batchItems[i]);
        }
    }

    function dispatchBatchBucket(bucketItems, bucketMode) {
        if (!bucketItems || bucketItems.length === 0) {
            return;
        }
        var uniqueIps = [];
        var seenIps = Object.create(null);
        for (var i = 0; i < bucketItems.length; i++) {
            var candidateIp = bucketItems[i].ip;
            var candidateKey = canonicalizeIpKey(candidateIp) || candidateIp.toLowerCase();
            if (!seenIps[candidateKey]) {
                seenIps[candidateKey] = true;
                uniqueIps.push(candidateIp);
            }
        }

        enqueueNetworkTask(function () {
            if (accessBlocked) {
                return null;
            }
            if (!batchEndpointSupported) {
                return { fallbackSingle: true };
            }
            return ensureGadgetToken().then(function (token) {
                if (!token || accessBlocked) {
                    return null;
                }
                if (!batchEndpointSupported) {
                    return { fallbackSingle: true };
                }
                return fetchBatchDetectWithToken(uniqueIps, token, false, bucketMode);
            });
        }).then(function (batchPayload) {
            if (batchPayload && batchPayload.fallbackSingle) {
                if (batchDebounceTimer !== null) {
                    window.clearTimeout(batchDebounceTimer);
                    batchDebounceTimer = null;
                }
                var remainingItems = pendingBatchQueue.splice(0, pendingBatchQueue.length);
                fallbackBatchItemsToSingle(bucketItems.concat(remainingItems));
                return;
            }
            for (var j = 0; j < bucketItems.length; j++) {
                var item = bucketItems[j];
                var ipResult = extractIpResultFromBatch(batchPayload, item.ip);
                item.resolve(ipResult);
            }
        }, function (err) {
            for (var j = 0; j < bucketItems.length; j++) {
                bucketItems[j].reject(err);
            }
        });
    }

    function dispatchBatchItems(batchItems) {
        if (!batchItems || batchItems.length === 0) {
            return;
        }
        if (accessBlocked) {
            for (var k = 0; k < batchItems.length; k++) {
                batchItems[k].resolve(null);
            }
            return;
        }
        if (!batchEndpointSupported) {
            fallbackBatchItemsToSingle(batchItems);
            return;
        }

        var lightItems = [];
        var fullItems = [];
        for (var i = 0; i < batchItems.length; i++) {
            if (normalizeQueryMode(batchItems[i].mode) === 'full') {
                fullItems.push(batchItems[i]);
            } else {
                lightItems.push(batchItems[i]);
            }
        }
        dispatchBatchBucket(lightItems, 'light');
        dispatchBatchBucket(fullItems, 'full');
    }

    function flushPendingBatch() {
        if (batchDebounceTimer !== null) {
            window.clearTimeout(batchDebounceTimer);
            batchDebounceTimer = null;
        }
        if (accessBlocked) {
            clearRequestQueue();
            return;
        }
        while (pendingBatchQueue.length > 0) {
            var batchItems = pendingBatchQueue.splice(0, MAX_BATCH_IPS);
            dispatchBatchItems(batchItems);
        }
    }

    function enqueueBatchIpDetection(ip, mode) {
        var resolvedMode = normalizeQueryMode(mode);
        if (accessBlocked) {
            return Promise.resolve(null);
        }
        if (!batchEndpointSupported) {
            return enqueueSingleIpDetection(ip, resolvedMode);
        }
        return new Promise(function (resolve, reject) {
            pendingBatchQueue.push({
                ip: ip,
                mode: resolvedMode,
                resolve: resolve,
                reject: reject
            });
            if (pendingBatchQueue.length >= MAX_BATCH_IPS) {
                flushPendingBatch();
            } else if (batchDebounceTimer === null) {
                batchDebounceTimer = window.setTimeout(function () {
                    batchDebounceTimer = null;
                    flushPendingBatch();
                }, BATCH_DEBOUNCE_MS);
            }
        });
    }

    function syncResolvedIpAliases(cacheKey, data, promise, includeFullCache) {
        recordLatestIpResult(cacheKey, data);
        writePersistedIpResult(cacheKey, data);
        if (typeof data.ip !== 'string') {
            return;
        }
        var resolvedKey = canonicalizeIpKey(data.ip);
        if (!resolvedKey || resolvedKey === cacheKey) {
            return;
        }
        recordLatestIpResult(resolvedKey, data);
        writePersistedIpResult(resolvedKey, data);
        if (!ipPromiseCache.has(resolvedKey) || includeFullCache) {
            ipPromiseCache.set(resolvedKey, promise);
        }
        if (includeFullCache && !ipFullPromiseCache.has(resolvedKey)) {
            ipFullPromiseCache.set(resolvedKey, promise);
        }
    }

    function fetchIpIntelligence(ip, mode) {
        if (accessBlocked) {
            return Promise.resolve(null);
        }
        var cacheKey = canonicalizeIpKey(ip);
        if (!cacheKey) {
            return Promise.resolve(null);
        }

        var resolvedMode = normalizeQueryMode(mode);
        if (resolvedMode === 'full') {
            if (ipFullPromiseCache.has(cacheKey)) {
                return ipFullPromiseCache.get(cacheKey);
            }

            var cachedLatestFull = latestResultByIp.get(cacheKey);
            if (cachedLatestFull && !isPartialLightResult(cachedLatestFull)) {
                var promotedPromise = Promise.resolve(cachedLatestFull);
                ipFullPromiseCache.set(cacheKey, promotedPromise);
                return promotedPromise;
            }

            var persistedFullData = readPersistedIpResult(cacheKey);
            if (persistedFullData && !isPartialLightResult(persistedFullData)) {
                recordLatestIpResult(cacheKey, persistedFullData);
                var cachedFullPromise = Promise.resolve(persistedFullData);
                ipFullPromiseCache.set(cacheKey, cachedFullPromise);
                ipPromiseCache.set(cacheKey, cachedFullPromise);
                return cachedFullPromise;
            }

            var fullPromise = enqueueSingleIpDetection(ip, 'full').then(function (data) {
                if (!data || typeof data !== 'object') {
                    if (ipFullPromiseCache.get(cacheKey) === fullPromise) {
                        ipFullPromiseCache.delete(cacheKey);
                    }
                    return null;
                }
                ipPromiseCache.set(cacheKey, fullPromise);
                syncResolvedIpAliases(cacheKey, data, fullPromise, true);
                return data;
            }).catch(function (err) {
                console.warn('[proxycheck] Full detection request failed for ' + ip + ':', err);
                if (ipFullPromiseCache.get(cacheKey) === fullPromise) {
                    ipFullPromiseCache.delete(cacheKey);
                }
                return null;
            });

            ipFullPromiseCache.set(cacheKey, fullPromise);
            return fullPromise;
        }

        if (ipFullPromiseCache.has(cacheKey)) {
            return ipFullPromiseCache.get(cacheKey);
        }
        if (ipPromiseCache.has(cacheKey)) {
            return ipPromiseCache.get(cacheKey);
        }

        var persistedData = readPersistedIpResult(cacheKey);
        if (persistedData) {
            recordLatestIpResult(cacheKey, persistedData);
            var cachedPromise = Promise.resolve(persistedData);
            ipPromiseCache.set(cacheKey, cachedPromise);
            if (!isPartialLightResult(persistedData)) {
                ipFullPromiseCache.set(cacheKey, cachedPromise);
            }
            return cachedPromise;
        }

        var promise = enqueueBatchIpDetection(ip, 'light').then(function (data) {
            if (!data || typeof data !== 'object') {
                if (ipPromiseCache.get(cacheKey) === promise) {
                    ipPromiseCache.delete(cacheKey);
                }
                return null;
            }
            var isFullReady = !isPartialLightResult(data);
            if (isFullReady && !ipFullPromiseCache.has(cacheKey)) {
                ipFullPromiseCache.set(cacheKey, promise);
            }
            syncResolvedIpAliases(cacheKey, data, promise, isFullReady);
            return data;
        }).catch(function (err) {
            console.warn('[proxycheck] Detection request failed for ' + ip + ':', err);
            if (ipPromiseCache.get(cacheKey) === promise) {
                ipPromiseCache.delete(cacheKey);
            }
            return null;
        });

        ipPromiseCache.set(cacheKey, promise);
        return promise;
    }

    function evaluateRisk(data) {
        var isNonPublic = Boolean(data.isNonPublic);
        var nonPublicCategory = typeof data.nonPublicCategory === 'string'
            ? data.nonPublicCategory.trim().toLowerCase()
            : '';
        var nonPublicReason = typeof data.nonPublicReason === 'string' && data.nonPublicReason.trim()
            ? data.nonPublicReason.trim()
            : 'Non-Public / Reserved IP';
        var isLocalNonPublic = nonPublicCategory === 'private' ||
            nonPublicCategory === 'loopback' ||
            nonPublicCategory === 'link_local';
        var nonPublicBadgeCode = isLocalNonPublic ? 'LOCAL' : 'RESERVED';

        var prediction = Number(data.prediction_score) || 0;
        var hasPrediction = data.getipintel_chance !== null &&
            data.getipintel_chance !== undefined &&
            !isNaN(Number(data.getipintel_chance));
        var broadcastIp = Boolean(data.is_broadcast_ip);
        var isTor = Boolean(data.isTor);
        var isMajorityProxyVpn = Boolean(data.isMajorityProxyVpn);
        var arbitrationTier = typeof data.arbitrationTier === 'string'
            ? data.arbitrationTier.trim().toLowerCase()
            : '';
        var ptrIsHighRisk = Boolean(data.ptrIsHighRisk);
        var hasCloudProvider = Boolean(
            typeof data.cloudProvider === 'string' && data.cloudProvider.trim()
        );
        var arbitrationVerdict = typeof data.arbitrationVerdict === 'string'
            ? data.arbitrationVerdict.trim()
            : '';
        var torLabel = typeof data.torLabel === 'string' && data.torLabel.trim()
            ? data.torLabel.trim()
            : (isTor ? 'Tor Node' : '');
        var torSummary = typeof data.torSummary === 'string' && data.torSummary.trim()
            ? data.torSummary.trim()
            : '';
        var torFlags = Array.isArray(data.torFlags)
            ? data.torFlags.map(function (flag) {
                  return typeof flag === 'string' ? flag.trim() : '';
              }).filter(Boolean)
            : [];

        var riskTier = 'low';
        if (isNonPublic) {
            riskTier = 'nonpublic';
        } else if ((hasPrediction && prediction > 80) || isTor || isMajorityProxyVpn ||
            arbitrationTier === 'destructive') {
            riskTier = 'high';
        } else if ((hasPrediction && prediction >= 30) || broadcastIp ||
            arbitrationTier === 'warning' || ptrIsHighRisk || hasCloudProvider) {
            riskTier = 'medium';
        }

        var predictionText = hasPrediction
            ? String(Number(prediction.toFixed(2)))
            : '';
        var predictionTooltip = hasPrediction
            ? predictionText + '%'
            : 'Unavailable' + (data.predictionLabel ? ' (' + data.predictionLabel + ')' : '');
        var badgePrimaryLabel = 'N/A';
        if (isMajorityProxyVpn || arbitrationTier === 'destructive') {
            badgePrimaryLabel = /datacenter|hosting/i.test(arbitrationVerdict)
                ? 'HOSTING'
                : 'PROXY';
        } else if (hasCloudProvider) {
            badgePrimaryLabel = 'CLOUD';
        } else if (ptrIsHighRisk) {
            badgePrimaryLabel = 'PTR-RISK';
        } else if (arbitrationTier === 'warning') {
            badgePrimaryLabel = 'REVIEW';
        }

        return {
            isNonPublic: isNonPublic,
            nonPublicCategory: nonPublicCategory,
            nonPublicReason: nonPublicReason,
            nonPublicBadgeCode: nonPublicBadgeCode,
            prediction: prediction,
            hasPrediction: hasPrediction,
            broadcastIp: broadcastIp,
            isTor: isTor,
            isMajorityProxyVpn: isMajorityProxyVpn,
            arbitrationTier: arbitrationTier,
            ptrIsHighRisk: ptrIsHighRisk,
            hasCloudProvider: hasCloudProvider,
            torLabel: torLabel,
            torFlags: torFlags,
            torSummary: torSummary,
            riskTier: riskTier,
            predictionText: predictionText,
            predictionTooltip: predictionTooltip,
            badgePrimaryLabel: badgePrimaryLabel
        };
    }

    function formatTorDescription(risk) {
        if (!risk.isTor) {
            return '';
        }
        var label = risk.torLabel || 'Tor Node';
        if (risk.torFlags.length > 0) {
            return label + ' (' + risk.torFlags.join(', ') + ')';
        }
        if (risk.torSummary) {
            return risk.torSummary;
        }
        return label;
    }

    function formatCloudDescription(data) {
        var provider = typeof data.cloudProvider === 'string' ? data.cloudProvider.trim() : '';
        var cidr = typeof data.cloudCidr === 'string' ? data.cloudCidr.trim() : '';
        if (provider && cidr) {
            return provider + ' (' + cidr + ')';
        }
        return provider || cidr;
    }

    var BLOCK_REASON_ATTRIBUTION = '([[:m:User:Hamish/proxycheck.js|proxycheck]])';

    function sanitizeHtmlCommentContent(text) {
        if (text === null || text === undefined) {
            return '';
        }
        return String(text)
            .replace(/<!-+/g, '<! -')
            .replace(/-+!>/g, '- !>')
            .replace(/-+>/g, '- >')
            .replace(/--+/g, '- -')
            .replace(/^[\s-]+|[\s-]+$/g, '');
    }

    function isUsableProviderValue(value) {
        if (value === null || value === undefined) {
            return false;
        }
        var text = String(value).trim();
        var lower = text.toLowerCase();
        return Boolean(text) && text !== '-' && lower !== 'n/a' && lower !== 'unknown';
    }

    function isValidProviderRow(row) {
        return Boolean(
            row &&
            typeof row === 'object' &&
            !row.isCooldown &&
            !row.isQuotaGuarded &&
            (row.status === '200 OK' || row.statusCode === 200)
        );
    }

    function getProviderRows(data) {
        var results = Array.isArray(data && data.results) ? data.results : [];
        var preferredNames = ['MaxMind', 'IP2Location'];
        var ordered = [];

        preferredNames.forEach(function (providerName) {
            results.forEach(function (row) {
                if (isValidProviderRow(row) && row.provider === providerName && ordered.indexOf(row) === -1) {
                    ordered.push(row);
                }
            });
        });
        results.forEach(function (row) {
            if (isValidProviderRow(row) && ordered.indexOf(row) === -1) {
                ordered.push(row);
            }
        });
        return ordered;
    }

    function stripTrailingMetadataParens(value, stripTrailingAsn) {
        var text = typeof value === 'string' ? value.trim() : String(value || '').trim();
        var coordPattern = /\s*\(\s*[+-]?\d+(?:\.\d+)?\s*,\s*[+-]?\d+(?:\.\d+)?\s*\)\s*$/;
        var asnPattern = /\s*\(\s*AS\s*\d+\s*\)\s*$/i;
        var changed = true;

        while (text && changed) {
            changed = false;
            if (coordPattern.test(text)) {
                text = text.replace(coordPattern, '').trim();
                changed = true;
            }
            if (stripTrailingAsn && asnPattern.test(text)) {
                text = text.replace(asnPattern, '').trim();
                changed = true;
            }
        }
        return text.replace(/,\s*$/, '').trim();
    }

    function normalizeAsnValue(value) {
        if (!isUsableProviderValue(value)) {
            return '';
        }
        var text = String(value).trim();
        var match = text.match(/^(?:as\s*)?(\d+)$/i);
        if (match) {
            return 'AS' + match[1];
        }
        return text.toUpperCase();
    }

    function collectAsnEntries(rows) {
        var byAsn = new Map();
        var entries = [];

        rows.forEach(function (row, index) {
            var asn = normalizeAsnValue(row && row.asn);
            var provider = (row && row.provider) || 'Provider';
            if (!asn) {
                return;
            }
            var entry = byAsn.get(asn);
            if (!entry) {
                entry = {
                    value: asn,
                    providers: [],
                    voteCount: 0,
                    firstIndex: index
                };
                byAsn.set(asn, entry);
                entries.push(entry);
            }
            entry.voteCount += 1;
            if (entry.providers.indexOf(provider) === -1) {
                entry.providers.push(provider);
            }
        });

        entries.sort(function (a, b) {
            if (b.voteCount !== a.voteCount) {
                return b.voteCount - a.voteCount;
            }
            return a.firstIndex - b.firstIndex;
        });

        return entries.map(function (entry, index) {
            return {
                value: entry.value,
                providers: entry.providers,
                showProviders: index > 0,
                defaultChecked: index === 0
            };
        });
    }

    function normalizeIspKey(value) {
        return value
            .toLowerCase()
            .replace(/\./g, '')
            .replace(/[,;:]+/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function collectIspEntries(rows) {
        var byKey = new Map();
        var entries = [];

        rows.forEach(function (row) {
            var raw = '';
            if (row && isUsableProviderValue(row.isp)) {
                raw = row.isp;
            } else if (row && isUsableProviderValue(row.organisation)) {
                raw = row.organisation;
            }
            if (!raw) {
                return;
            }
            var cleaned = stripTrailingMetadataParens(raw, true);
            if (!isUsableProviderValue(cleaned)) {
                return;
            }
            var key = normalizeIspKey(cleaned);
            if (!key) {
                return;
            }
            var provider = (row && row.provider) || 'Provider';
            var entry = byKey.get(key);
            if (!entry) {
                entry = {
                    value: cleaned,
                    providers: [],
                    showProviders: true,
                    defaultChecked: false
                };
                byKey.set(key, entry);
                entries.push(entry);
            }
            if (entry.providers.indexOf(provider) === -1) {
                entry.providers.push(provider);
            }
        });

        return entries;
    }

    function collapseLocationDuplicates(value) {
        var parts = value.split(',').map(function (part) {
            return part.trim();
        }).filter(Boolean);
        var collapsed = [];

        parts.forEach(function (part) {
            if (
                collapsed.length === 0 ||
                collapsed[collapsed.length - 1].toLowerCase() !== part.toLowerCase()
            ) {
                collapsed.push(part);
            }
        });

        var joined = collapsed.join(', ');
        return isUsableProviderValue(joined) ? joined : '';
    }

    function collectLocationEntries(rows) {
        var byKey = new Map();
        var entries = [];

        rows.forEach(function (row) {
            if (!row || !isUsableProviderValue(row.location)) {
                return;
            }
            var stripped = stripTrailingMetadataParens(row.location, false);
            var normalized = collapseLocationDuplicates(stripped);
            if (!normalized) {
                return;
            }
            var key = normalized.toLowerCase().replace(/\s*,\s*/g, ', ').replace(/\s+/g, ' ').trim();
            var provider = row.provider || 'Provider';
            var entry = byKey.get(key);
            if (!entry) {
                entry = {
                    value: normalized,
                    providers: [],
                    showProviders: true,
                    defaultChecked: false
                };
                byKey.set(key, entry);
                entries.push(entry);
            }
            if (entry.providers.indexOf(provider) === -1) {
                entry.providers.push(provider);
            }
        });

        return entries;
    }

    function normalizeRiskFlagLabel(label) {
        var text = typeof label === 'string' ? label.trim() : '';
        if (!text) {
            return '';
        }
        if (text.toLowerCase() === 'tor exit node') {
            return 'Tor Exit';
        }
        return text;
    }

    function collectPredictionEntries(data, risk) {
        if (data.getipintel_chance === null || data.getipintel_chance === undefined) {
            return [];
        }
        return [
            {
                value: 'Prediction ' + risk.predictionText + '%',
                copyValue: risk.predictionText + '% Prediction',
                providers: ['GetIPIntel'],
                showProviders: true,
                defaultChecked: true
            }
        ];
    }

    function collectRiskEntries(data, rows, risk) {
        var byKey = new Map();
        var entries = [];

        function addEntry(value, provider) {
            var text = typeof value === 'string' ? value.trim() : '';
            if (!text) {
                return;
            }
            var key = text.toLowerCase();
            var entry = byKey.get(key);
            if (!entry) {
                entry = {
                    value: text,
                    providers: [],
                    showProviders: true,
                    defaultChecked: false
                };
                byKey.set(key, entry);
                entries.push(entry);
            }
            if (provider && entry.providers.indexOf(provider) === -1) {
                entry.providers.push(provider);
            }
        }

        if (risk.isTor) {
            var torEntryLabel = risk.torLabel || (data.torIsExit ? 'Tor Exit' : 'Tor Node');
            addEntry(torEntryLabel, 'Tor Onionoo');
        }

        rows.forEach(function (row) {
            if (!row || !Array.isArray(row.securityFlags)) {
                return;
            }
            var provider = row.provider || 'Provider';
            if (provider === 'GetIPIntel') {
                return;
            }
            row.securityFlags.forEach(function (flag) {
                if (!flag || !flag.isHighRisk || typeof flag.label !== 'string') {
                    return;
                }
                var normalized = normalizeRiskFlagLabel(flag.label);
                if (normalized) {
                    addEntry(normalized, provider);
                }
            });
        });

        var cloudProvider = typeof data.cloudProvider === 'string' ? data.cloudProvider.trim() : '';
        if (cloudProvider) {
            var cloudSource = 'Cloud CIDR';
            for (var i = 0; i < rows.length; i++) {
                if (rows[i] && rows[i].cloudProvider === cloudProvider && rows[i].provider) {
                    cloudSource = rows[i].provider;
                    break;
                }
            }
            addEntry('Cloud (' + cloudProvider + ')', cloudSource);
        }

        if (risk.broadcastIp) {
            addEntry('Broadcast IP', 'Multi-Source');
        }

        if (data.ptrIsHighRisk && typeof data.ptrLabel === 'string' && data.ptrLabel.trim()) {
            addEntry('PTR (' + data.ptrLabel.trim() + ')', 'Reverse DNS');
        }

        return entries;
    }

    function isSpurIpInfoPage() {
        return isContributionsSpecialPage();
    }

    function extractDomLines(element) {
        if (!element) {
            return [];
        }
        var chunks = [];
        function walk(node) {
            if (!node) {
                return;
            }
            if (node.nodeType === 3) {
                chunks.push(node.nodeValue || '');
                return;
            }
            if (node.nodeType !== 1) {
                return;
            }
            var tagName = (node.tagName || '').toUpperCase();
            if (tagName === 'BR') {
                chunks.push('\n');
                return;
            }
            var isBlock = tagName === 'DIV' || tagName === 'P' || tagName === 'LI';
            if (isBlock) {
                chunks.push('\n');
            }
            var childNodes = node.childNodes || [];
            for (var i = 0; i < childNodes.length; i++) {
                walk(childNodes[i]);
            }
            if (isBlock) {
                chunks.push('\n');
            }
        }
        walk(element);
        return chunks.join('').split(/\r?\n/).map(function (line) {
            return line.trim();
        }).filter(function (line) {
            return Boolean(line);
        });
    }

    // Read Spur proxy types from MediaWiki IPInfo when rendered on contributions special pages
    function getSpurProxyText() {
        if (!isSpurIpInfoPage()) {
            return '';
        }
        var $panel = $('.ext-ipinfo-panel-layout').first();
        if ($panel.length === 0) {
            return '';
        }
        var $valueNodes = $panel.find(
            '.ext-ipinfo-widget-property[data-property="proxies"]:not(.ext-ipinfo-widget-property-no-data) .ext-ipinfo-widget-property-value'
        );
        if ($valueNodes.length === 0) {
            return '';
        }
        var seen = Object.create(null);
        var uniqueLines = [];
        $valueNodes.each(function () {
            if ($(this).closest('.ext-ipinfo-widget-error, .ext-ipinfo-contains-error').length > 0) {
                return;
            }
            extractDomLines(this).forEach(function (line) {
                if (!seen[line]) {
                    seen[line] = true;
                    uniqueLines.push(line);
                }
            });
        });
        return uniqueLines.join(', ');
    }

    function collectSpurEntriesFromDom() {
        var spurText = getSpurProxyText();
        if (!spurText) {
            return [];
        }
        return [
            {
                value: spurText,
                providers: ['Spur'],
                showProviders: true,
                defaultChecked: true
            }
        ];
    }

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
        'Cloud CIDR': { bg: '#e8f6ff', border: '#a8d8f8', color: '#0e527d', darkBg: '#152c3d', darkBorder: '#2c5c80', darkColor: '#8ac7f5' },
        'Multi-Source': { bg: '#eef2f6', border: '#b9c6d4', color: '#3b4f66', darkBg: '#222830', darkBorder: '#475466', darkColor: '#b3c2d4' },
        'Reverse DNS': { bg: '#e8f7f7', border: '#a6dada', color: '#185b5e', darkBg: '#153030', darkBorder: '#2c6666', darkColor: '#87dbdb' },
        'Spur': { bg: '#e3f1f8', border: '#95cce6', color: '#0f4c6e', darkBg: '#152b38', darkBorder: '#2c5973', darkColor: '#8bc8eb' }
    };

    var FALLBACK_COOL_PALETTES = [
        { bg: '#e6f2ff', border: '#a3ccf5', color: '#0b4f8a', darkBg: '#162a42', darkBorder: '#2f5a8a', darkColor: '#8ec5ff' },
        { bg: '#e3f8fc', border: '#99dfec', color: '#0b5d6b', darkBg: '#133038', darkBorder: '#296878', darkColor: '#7fd8e8' },
        { bg: '#eaedff', border: '#b3bdf5', color: '#2c3e99', darkBg: '#1d2345', darkBorder: '#3e4a8f', darkColor: '#a3b3ff' },
        { bg: '#e4f7f2', border: '#9cd9cb', color: '#0d5e4e', darkBg: '#13332b', darkBorder: '#296b5b', darkColor: '#7be0c8' },
        { bg: '#f0ebff', border: '#c5b6f2', color: '#4b2d8f', darkBg: '#271e42', darkBorder: '#55418c', darkColor: '#c3b0ff' },
        { bg: '#e8eff5', border: '#aec2d4', color: '#294661', darkBg: '#1d2936', darkBorder: '#3e5773', darkColor: '#a3c2e0' }
    ];

    function buildDarkThemeRuleBlock(scopeSelector) {
        return [
            scopeSelector + ' {',
            '  --proxycheck-surface-bg: var(--background-color-interactive-subtle, #27292d);',
            '  --proxycheck-surface-color: var(--color-base, #eaecf0);',
            '  --proxycheck-subtle-color: var(--color-subtle, #a2a9b1);',
            '  --proxycheck-muted-color: var(--color-subtle, #a2a9b1);',
            '  --proxycheck-border-color: var(--border-color-subtle, #54595d);',
            '  --proxycheck-divider-color: var(--border-color-subtle, #3a3f47);',
            '  --proxycheck-link-color: var(--color-progressive, #88a3e8);',
            '  --proxycheck-high-bg: #3d1414;',
            '  --proxycheck-high-color: #ff9999;',
            '  --proxycheck-high-border: #7a2929;',
            '  --proxycheck-medium-bg: #382b0c;',
            '  --proxycheck-medium-color: #ffd966;',
            '  --proxycheck-medium-border: #755918;',
            '  --proxycheck-nonpublic-bg: #222b36;',
            '  --proxycheck-nonpublic-color: #c2d4e8;',
            '  --proxycheck-nonpublic-border: #4a5d73;',
            '  --proxycheck-low-bg: var(--background-color-interactive-subtle, #27292d);',
            '  --proxycheck-low-color: var(--color-base, #eaecf0);',
            '  --proxycheck-low-border: var(--border-color-subtle, #54595d);',
            '  --proxycheck-error-border: var(--border-color-subtle, #6c737c);',
            '  --proxycheck-banner-high-bg: #2c1414;',
            '  --proxycheck-banner-high-accent: #ff6666;',
            '  --proxycheck-banner-medium-bg: #2b220d;',
            '  --proxycheck-banner-medium-accent: #f0b144;',
            '  --proxycheck-banner-nonpublic-bg: #1e242c;',
            '  --proxycheck-banner-nonpublic-accent: #8c959f;',
            '  --proxycheck-banner-low-bg: var(--background-color-interactive-subtle, #27292d);',
            '  --proxycheck-banner-low-accent: var(--color-progressive, #6d9cff);',
            '  --proxycheck-banner-low-badge-bg: var(--background-color-interactive-subtle, #27292d);',
            '  --proxycheck-code-bg: var(--background-color-neutral-subtle, rgba(255, 255, 255, 0.08));',
            '}',
            scopeSelector + ' a.proxycheck-anchor-risk-high,',
            scopeSelector + ' a.proxycheck-anchor-risk-high:visited,',
            scopeSelector + ' .proxycheck-anchor-risk-high {',
            '  background-color: #3d1414 !important;',
            '  color: #ff9999 !important;',
            '}',
            scopeSelector + ' a.proxycheck-anchor-risk-medium,',
            scopeSelector + ' a.proxycheck-anchor-risk-medium:visited,',
            scopeSelector + ' .proxycheck-anchor-risk-medium {',
            '  background-color: #382b0c !important;',
            '  color: #ffd966 !important;',
            '}',
            scopeSelector + ' .proxycheck-source-tag {',
            '  background-color: var(--proxycheck-tag-dark-bg, #1c2a3a);',
            '  border-color: var(--proxycheck-tag-dark-border, #3a5778);',
            '  color: var(--proxycheck-tag-dark-color, #9cc9ff);',
            '}'
        ].join('\n');
    }

    function buildUserscriptCss() {
        return [
            ':root {',
            '  --proxycheck-surface-bg: var(--background-color-interactive-subtle, #f8f9fa);',
            '  --proxycheck-surface-color: var(--color-base, #202122);',
            '  --proxycheck-subtle-color: var(--color-subtle, #54595d);',
            '  --proxycheck-muted-color: var(--color-placeholder, #72777d);',
            '  --proxycheck-border-color: var(--border-color-subtle, #c8ccd1);',
            '  --proxycheck-divider-color: var(--border-color-subtle, #eaecf0);',
            '  --proxycheck-link-color: var(--color-progressive, #3366cc);',
            '  --proxycheck-high-bg: #ffe6e6;',
            '  --proxycheck-high-color: #990000;',
            '  --proxycheck-high-border: #f5b7b1;',
            '  --proxycheck-medium-bg: #fff8e1;',
            '  --proxycheck-medium-color: #856404;',
            '  --proxycheck-medium-border: #ffe082;',
            '  --proxycheck-nonpublic-bg: #eef2f6;',
            '  --proxycheck-nonpublic-color: #3b4f66;',
            '  --proxycheck-nonpublic-border: #b9c6d4;',
            '  --proxycheck-low-bg: var(--background-color-interactive-subtle, #f8f9fa);',
            '  --proxycheck-low-color: var(--color-subtle, #54595d);',
            '  --proxycheck-low-border: var(--border-color-subtle, #c8ccd1);',
            '  --proxycheck-error-border: #a2a9b1;',
            '  --proxycheck-banner-high-bg: #fffafa;',
            '  --proxycheck-banner-high-accent: #d33;',
            '  --proxycheck-banner-medium-bg: #fffdf5;',
            '  --proxycheck-banner-medium-accent: #fc3;',
            '  --proxycheck-banner-nonpublic-bg: #f4f6f8;',
            '  --proxycheck-banner-nonpublic-accent: #72777d;',
            '  --proxycheck-banner-low-bg: var(--background-color-interactive-subtle, #f8f9fa);',
            '  --proxycheck-banner-low-accent: var(--color-progressive, #36c);',
            '  --proxycheck-banner-low-badge-bg: var(--background-color-base, #ffffff);',
            '  --proxycheck-code-bg: var(--background-color-neutral-subtle, rgba(0, 0, 0, 0.04));',
            '}',
            'a.proxycheck-ip-badge, a.proxycheck-ip-badge:visited {',
            '  margin-left: 4px;',
            '  font-size: 0.85em;',
            '  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;',
            '  padding: 1px 5px;',
            '  border-radius: 3px;',
            '  text-decoration: none;',
            '  white-space: nowrap;',
            '}',
            'a.proxycheck-ip-badge.proxycheck-tier-high, a.proxycheck-ip-badge.proxycheck-tier-high:visited {',
            '  background-color: var(--proxycheck-high-bg);',
            '  color: var(--proxycheck-high-color) !important;',
            '  border: 1px solid var(--proxycheck-high-border);',
            '  font-weight: bold;',
            '}',
            'a.proxycheck-ip-badge.proxycheck-tier-medium, a.proxycheck-ip-badge.proxycheck-tier-medium:visited {',
            '  background-color: var(--proxycheck-medium-bg);',
            '  color: var(--proxycheck-medium-color) !important;',
            '  border: 1px solid var(--proxycheck-medium-border);',
            '  font-weight: bold;',
            '}',
            'a.proxycheck-ip-badge.proxycheck-tier-nonpublic, a.proxycheck-ip-badge.proxycheck-tier-nonpublic:visited {',
            '  background-color: var(--proxycheck-nonpublic-bg);',
            '  color: var(--proxycheck-nonpublic-color) !important;',
            '  border: 1px solid var(--proxycheck-nonpublic-border);',
            '  font-weight: bold;',
            '}',
            'a.proxycheck-ip-badge.proxycheck-tier-low, a.proxycheck-ip-badge.proxycheck-tier-low:visited {',
            '  background-color: var(--proxycheck-low-bg);',
            '  color: var(--proxycheck-low-color) !important;',
            '  border: 1px solid var(--proxycheck-low-border);',
            '  font-weight: normal;',
            '}',
            'a.proxycheck-ip-badge.proxycheck-ip-badge-error, a.proxycheck-ip-badge.proxycheck-ip-badge-error:visited {',
            '  background-color: var(--proxycheck-low-bg);',
            '  color: var(--proxycheck-muted-color) !important;',
            '  border: 1px dashed var(--proxycheck-error-border);',
            '}',
            'a.proxycheck-ip-badge.proxycheck-ip-badge-consent, a.proxycheck-ip-badge.proxycheck-ip-badge-consent:visited {',
            '  background-color: var(--proxycheck-low-bg);',
            '  color: var(--proxycheck-low-color) !important;',
            '  border: 1px solid var(--proxycheck-low-border);',
            '}',
            '#proxycheck-pageinfo {',
            '  font-size: 92%;',
            '  line-height: 1.5em;',
            '  padding: 8px 12px;',
            '  margin-bottom: 12px;',
            '  background-color: var(--proxycheck-surface-bg);',
            '  color: var(--proxycheck-surface-color);',
            '  border: 1px solid var(--proxycheck-divider-color);',
            '  border-left: 4px solid var(--proxycheck-border-color);',
            '  border-radius: 2px;',
            '}',
            '#proxycheck-pageinfo.proxycheck-banner-tier-high {',
            '  border-left-color: var(--proxycheck-banner-high-accent);',
            '  background-color: var(--proxycheck-banner-high-bg);',
            '}',
            '#proxycheck-pageinfo.proxycheck-banner-tier-medium {',
            '  border-left-color: var(--proxycheck-banner-medium-accent);',
            '  background-color: var(--proxycheck-banner-medium-bg);',
            '}',
            '#proxycheck-pageinfo.proxycheck-banner-tier-nonpublic {',
            '  border-left-color: var(--proxycheck-banner-nonpublic-accent);',
            '  background-color: var(--proxycheck-banner-nonpublic-bg);',
            '}',
            '#proxycheck-pageinfo.proxycheck-banner-tier-low {',
            '  border-left-color: var(--proxycheck-banner-low-accent);',
            '  background-color: var(--proxycheck-banner-low-bg);',
            '}',
            '#proxycheck-pageinfo code {',
            '  background-color: var(--proxycheck-code-bg);',
            '  color: inherit;',
            '  border-color: var(--proxycheck-border-color);',
            '}',
            '.proxycheck-banner-badge {',
            '  padding: 1px 6px;',
            '  border-radius: 3px;',
            '  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;',
            '}',
            '.proxycheck-banner-badge.proxycheck-tier-high {',
            '  background-color: var(--proxycheck-high-bg);',
            '  color: var(--proxycheck-high-color);',
            '  border: 1px solid var(--proxycheck-high-border);',
            '  font-weight: bold;',
            '}',
            '.proxycheck-banner-badge.proxycheck-tier-medium {',
            '  background-color: var(--proxycheck-medium-bg);',
            '  color: var(--proxycheck-medium-color);',
            '  border: 1px solid var(--proxycheck-medium-border);',
            '  font-weight: bold;',
            '}',
            '.proxycheck-banner-badge.proxycheck-tier-nonpublic {',
            '  background-color: var(--proxycheck-nonpublic-bg);',
            '  color: var(--proxycheck-nonpublic-color);',
            '  border: 1px solid var(--proxycheck-nonpublic-border);',
            '  font-weight: bold;',
            '}',
            '.proxycheck-banner-badge.proxycheck-tier-low {',
            '  background-color: var(--proxycheck-banner-low-badge-bg);',
            '  color: var(--proxycheck-low-color);',
            '  border: 1px solid var(--proxycheck-low-border);',
            '}',
            '.proxycheck-ptr-label-risk, .proxycheck-banner-danger-text {',
            '  color: var(--proxycheck-high-color);',
            '}',
            '.proxycheck-ptr-label-risk {',
            '  font-weight: bold;',
            '}',
            '.proxycheck-ptr-label-normal {',
            '  color: var(--proxycheck-subtle-color);',
            '}',
            '.proxycheck-banner-warning-text {',
            '  color: var(--proxycheck-medium-color);',
            '}',
            '.proxycheck-pageinfo-details {',
            '  margin-top: 8px;',
            '  padding-top: 8px;',
            '  border-top: 1px solid var(--proxycheck-divider-color);',
            '}',
            '.proxycheck-details-panel, .proxycheck-dialog-content {',
            '  color: var(--proxycheck-surface-color);',
            '}',
            '.proxycheck-details-label {',
            '  color: var(--proxycheck-subtle-color);',
            '}',
            '.proxycheck-details-empty {',
            '  color: var(--proxycheck-muted-color);',
            '}',
            '.proxycheck-result-value {',
            '  color: var(--proxycheck-surface-color);',
            '}',
            '.proxycheck-result-value-risk {',
            '  color: var(--proxycheck-high-color);',
            '  font-weight: 500;',
            '}',
            '.proxycheck-result-checkbox {',
            '  accent-color: var(--proxycheck-link-color);',
            '}',
            '.proxycheck-source-tag {',
            '  display: inline-block;',
            '  font-size: 0.82em;',
            '  color: var(--proxycheck-tag-color, #0b4f8a);',
            '  background-color: var(--proxycheck-tag-bg, #e6f2ff);',
            '  border: 1px solid var(--proxycheck-tag-border, #a3ccf5);',
            '  border-radius: 3px;',
            '  padding: 0 5px;',
            '  line-height: 1.4;',
            '  margin-left: 5px;',
            '  vertical-align: middle;',
            '}',
            '.proxycheck-light-upgrade-notice {',
            '  color: var(--proxycheck-subtle-color);',
            '}',
            '#proxycheck-pageinfo a, .proxycheck-details-panel a, .proxycheck-dialog-link {',
            '  color: var(--proxycheck-link-color);',
            '}',
            buildDarkThemeRuleBlock('html.skin-theme-clientpref-night'),
            '@media (prefers-color-scheme: dark) {',
            buildDarkThemeRuleBlock('html.skin-theme-clientpref-os'),
            '}'
        ].join('\n');
    }

    function ensureUserscriptStyles() {
        if (stylesInjected || typeof document === 'undefined') {
            return;
        }
        if (typeof document.getElementById === 'function' && document.getElementById(STYLE_ELEMENT_ID)) {
            stylesInjected = true;
            return;
        }
        var cssText = buildUserscriptCss();
        var styleParent = document.head || document.body || document.documentElement;
        if (
            styleParent &&
            typeof document.createElement === 'function' &&
            typeof styleParent.appendChild === 'function'
        ) {
            var styleElement = document.createElement('style');
            styleElement.id = STYLE_ELEMENT_ID;
            styleElement.type = 'text/css';
            if ('textContent' in styleElement) {
                styleElement.textContent = cssText;
            } else {
                styleElement.appendChild(document.createTextNode(cssText));
            }
            styleParent.appendChild(styleElement);
            stylesInjected = true;
            return;
        }
        if (mw && mw.util && typeof mw.util.addCSS === 'function') {
            mw.util.addCSS(cssText);
            stylesInjected = true;
        }
    }

    function addElementClass(element, className) {
        if (!element || !className) {
            return;
        }
        if (element.classList && typeof element.classList.add === 'function') {
            element.classList.add(className);
            return;
        }
        var existing = typeof element.className === 'string' ? element.className : '';
        var parts = existing ? existing.split(/\s+/) : [];
        if (parts.indexOf(className) === -1) {
            parts.push(className);
            element.className = parts.join(' ').trim();
        }
    }

    function removeElementClass(element, className) {
        if (!element || !className) {
            return;
        }
        if (element.classList && typeof element.classList.remove === 'function') {
            element.classList.remove(className);
            return;
        }
        if (typeof element.className !== 'string' || !element.className) {
            return;
        }
        var parts = element.className.split(/\s+/);
        var nextParts = [];
        for (var i = 0; i < parts.length; i++) {
            if (parts[i] && parts[i] !== className) {
                nextParts.push(parts[i]);
            }
        }
        element.className = nextParts.join(' ');
    }

    function getProviderBadgePalette(provider) {
        if (Object.prototype.hasOwnProperty.call(PROVIDER_BADGE_PALETTES, provider)) {
            return PROVIDER_BADGE_PALETTES[provider];
        }
        var hash = 0;
        var text = String(provider || '');
        for (var i = 0; i < text.length; i++) {
            hash = ((hash * 31) + text.charCodeAt(i)) | 0;
        }
        var index = Math.abs(hash) % FALLBACK_COOL_PALETTES.length;
        return FALLBACK_COOL_PALETTES[index];
    }

    function createSourceBadge(provider) {
        var palette = getProviderBadgePalette(provider);
        return $('<span>', {
            'class': 'proxycheck-source-tag',
            style: '--proxycheck-tag-bg: ' + palette.bg + '; ' +
                '--proxycheck-tag-border: ' + palette.border + '; ' +
                '--proxycheck-tag-color: ' + palette.color + '; ' +
                '--proxycheck-tag-dark-bg: ' + palette.darkBg + '; ' +
                '--proxycheck-tag-dark-border: ' + palette.darkBorder + '; ' +
                '--proxycheck-tag-dark-color: ' + palette.darkColor + ';',
            text: provider
        });
    }

    function buildResultDetailsPanel(data, risk) {
        ensureUserscriptStyles();
        var rows = getProviderRows(data);
        var riskEntries = collectRiskEntries(data, rows, risk).concat(collectSpurEntriesFromDom());
        var sections = [
            { label: 'Prediction', entries: collectPredictionEntries(data, risk), isRisk: false, emptyText: 'Unavailable', copyWithSource: true },
            { label: 'ASN', entries: collectAsnEntries(rows), isRisk: false, emptyText: '-', copyWithSource: false },
            { label: 'ISP', entries: collectIspEntries(rows), isRisk: false, emptyText: '-', copyWithSource: true },
            { label: 'Location', entries: collectLocationEntries(rows), isRisk: false, emptyText: '-', copyWithSource: true },
            { label: 'Risk', entries: riskEntries, isRisk: true, emptyText: 'No high-risk signals detected', copyWithSource: true }
        ];

        var $panel = $('<div>', {
            'class': 'proxycheck-details-panel'
        });
        var $table = $('<table>', {
            style: 'width: 100%; border-collapse: collapse;'
        });
        var checkboxItems = [];

        sections.forEach(function (section) {
            var $content = $('<div>', {
                style: 'display: flex; flex-direction: column; gap: 3px;'
            });

            if (section.entries.length === 0) {
                $content.append(
                    $('<span>', {
                        'class': 'proxycheck-details-empty',
                        text: section.emptyText
                    })
                );
            } else {
                section.entries.forEach(function (entry) {
                    var $checkbox = $('<input>', {
                        type: 'checkbox',
                        'class': 'proxycheck-result-checkbox',
                        checked: Boolean(entry.defaultChecked),
                        style: 'margin: 3px 0 0 0; flex-shrink: 0; cursor: pointer;'
                    });
                    var $text = $('<span>', {
                        'class': 'proxycheck-result-value' + (section.isRisk ? ' proxycheck-result-value-risk' : ''),
                        text: entry.value
                    });
                    var $body = $('<span>', {
                        style: 'display: block; flex: 1; min-width: 0; line-height: 1.5;'
                    }).append($text);

                    if (entry.showProviders && entry.providers.length > 0) {
                        entry.providers.forEach(function (provider) {
                            $body.append(createSourceBadge(provider));
                        });
                    }

                    var $line = $('<label>', {
                        style: 'display: flex; align-items: flex-start; gap: 6px; ' +
                            'margin: 0; cursor: pointer; font-weight: normal;'
                    }).append($checkbox, $body);

                    checkboxItems.push({
                        checkbox: $checkbox,
                        copyValue: entry.copyValue || entry.value,
                        providers: entry.providers || [],
                        copyWithSource: section.copyWithSource
                    });
                    $content.append($line);
                });
            }

            $('<tr>').append(
                $('<th>', {
                    'class': 'proxycheck-details-label',
                    style: 'text-align: left; vertical-align: top; padding: 4px 12px 4px 0; ' +
                        'width: 78px; font-weight: 600; white-space: nowrap;'
                }).text(section.label),
                $('<td>', {
                    style: 'padding: 4px 0; vertical-align: top;'
                }).append($content)
            ).appendTo($table);
        });

        var $copyLink = $('<a>', {
            href: '#',
            role: 'button',
            'class': 'proxycheck-copy-result',
            text: 'Copy result'
        });
        var resetTimerId = null;

        function scheduleCopyLabelReset(delayMs) {
            if (resetTimerId !== null) {
                window.clearTimeout(resetTimerId);
            }
            resetTimerId = window.setTimeout(function () {
                resetTimerId = null;
                $copyLink.text('Copy result');
            }, delayMs);
        }

        $copyLink.on('click', function (event) {
            event.preventDefault();
            event.stopPropagation();

            var selectedValues = [];
            checkboxItems.forEach(function (item) {
                if (item.checkbox.prop('checked')) {
                    var rawEntry = (item.copyWithSource && item.providers.length > 0)
                        ? (item.providers.join(', ') + ': ' + item.copyValue)
                        : item.copyValue;
                    var safeEntry = sanitizeHtmlCommentContent(rawEntry);
                    if (safeEntry) {
                        selectedValues.push(safeEntry);
                    }
                }
            });

            if (selectedValues.length === 0) {
                $copyLink.text('Select at least one item');
                scheduleCopyLabelReset(1500);
                return;
            }

            var commentBody = sanitizeHtmlCommentContent(selectedValues.join(', ')) + ' ' + BLOCK_REASON_ATTRIBUTION;
            var formattedResult = '<!-- ' + commentBody.trim() + ' -->';
            copyText(formattedResult).then(function () {
                $copyLink.text('Copied');
                scheduleCopyLabelReset(1500);
            }).catch(function (err) {
                console.warn('[proxycheck] Failed to copy result:', err);
                $copyLink.text('Copy failed');
                scheduleCopyLabelReset(2000);
            });
        });

        var $actions = $('<div>', {
            style: 'margin-top: 8px; display: flex; align-items: center; gap: 12px;'
        }).append($copyLink);

        $panel.append($table, $actions);
        return $panel;
    }

    function copyText(text) {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            return navigator.clipboard.writeText(text);
        }

        return new Promise(function (resolve, reject) {
            var textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                if (!document.execCommand('copy')) {
                    throw new Error('document.execCommand("copy") returned false');
                }
                resolve();
            } catch (err) {
                reject(err);
            } finally {
                document.body.removeChild(textarea);
            }
        });
    }

    function buildBadgeTitleText(data, risk) {
        if (risk.isNonPublic) {
            return [
                'Address Type: ' + risk.nonPublicReason + ' [' + risk.nonPublicBadgeCode + ']',
                'Status: External threat lookups skipped (non-public or reserved IP)'
            ].join('\n');
        }
        var torDesc = formatTorDescription(risk);
        var cloudDesc = formatCloudDescription(data);
        var titleLines = [
            'Prediction: ' + risk.predictionTooltip
        ];
        if (typeof data.arbitrationVerdict === 'string' && data.arbitrationVerdict.trim()) {
            titleLines.push('Verdict: ' + data.arbitrationVerdict.trim());
        }
        titleLines.push('Recommended CIDR: ' + (data.recommendedCidr || 'N/A'));
        titleLines.push('BGP CIDR: ' + (data.mmdbCidr || 'N/A'));
        if (cloudDesc) {
            titleLines.push('Cloud: ' + cloudDesc);
        }
        titleLines.push('Broadcast IP: ' + (risk.broadcastIp ? 'At-risk' : 'No'));
        titleLines.push('Tor Node: ' + (risk.isTor ? torDesc : 'No'));
        return titleLines.join('\n');
    }

    function applyRiskStylingToAnchorAndBadge(anchor, badge, data, fallbackIp, isRefresh) {
        ensureUserscriptStyles();
        var risk = evaluateRisk(data);
        var resolvedIp = (data && data.ip) || fallbackIp;

        removeElementClass(anchor, 'proxycheck-anchor-risk-high');
        removeElementClass(anchor, 'proxycheck-anchor-risk-medium');
        if (risk.riskTier === 'high' || risk.riskTier === 'medium') {
            addElementClass(
                anchor,
                risk.riskTier === 'high' ? 'proxycheck-anchor-risk-high' : 'proxycheck-anchor-risk-medium'
            );
            anchor.style.backgroundColor = risk.riskTier === 'high' ? '#ffcccc' : '#fff3cd';
            anchor.style.color = risk.riskTier === 'high' ? '#990000' : '#856404';
            anchor.style.fontWeight = 'bold';
            anchor.style.padding = '1px 4px';
            anchor.style.borderRadius = '3px';
        } else if (isRefresh && anchor.style && anchor.style.backgroundColor) {
            anchor.style.backgroundColor = '';
            anchor.style.color = '';
            anchor.style.fontWeight = '';
            anchor.style.padding = '';
            anchor.style.borderRadius = '';
        }

        var broadcastLabel = risk.broadcastIp ? '|BCASTIP' : '';
        var torBadgeSuffix = risk.isTor
            ? '|' + (risk.torLabel ? risk.torLabel.toUpperCase() : 'TOR')
            : '';

        badge.href = TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp);
        badge.textContent = risk.isNonPublic
            ? '[' + risk.nonPublicBadgeCode + ']'
            : '[' + (risk.hasPrediction ? risk.predictionText + '%' : risk.badgePrimaryLabel) +
                broadcastLabel + torBadgeSuffix + ']';
        badge.className = BADGE_CLASS + ' proxycheck-tier-' + risk.riskTier;

        applyBaseBadgeStyle(badge);
        badge.style.fontWeight = risk.riskTier === 'low' ? '' : 'bold';
        badge.title = buildBadgeTitleText(data, risk);
    }

    function registerRenderedBadge(cacheKey, anchor, badge, ip) {
        if (!cacheKey || !anchor || !badge) {
            return;
        }
        var existingEntries = renderedBadgeEntriesByIp.get(cacheKey);
        if (!existingEntries) {
            existingEntries = [];
            renderedBadgeEntriesByIp.set(cacheKey, existingEntries);
        }
        existingEntries.push({ anchor: anchor, badge: badge, ip: ip });
    }

    function refreshRenderedBadgesForIp(ip, fullData) {
        var cacheKey = canonicalizeIpKey(ip);
        if (!cacheKey || !fullData || typeof fullData !== 'object') {
            return;
        }
        var entries = renderedBadgeEntriesByIp.get(cacheKey);
        if (!entries || entries.length === 0) {
            return;
        }
        var activeEntries = [];
        for (var i = 0; i < entries.length; i++) {
            var entry = entries[i];
            if (!entry || !entry.anchor || !entry.badge) {
                continue;
            }
            // Drop detached DOM entries when a real browser document has updated the page
            if (typeof document !== 'undefined' && document.body && typeof document.body.contains === 'function' &&
                !document.body.contains(entry.badge)) {
                continue;
            }
            applyRiskStylingToAnchorAndBadge(entry.anchor, entry.badge, fullData, fullData.ip || entry.ip, true);
            activeEntries.push(entry);
        }
        if (activeEntries.length > 0) {
            renderedBadgeEntriesByIp.set(cacheKey, activeEntries);
        } else {
            renderedBadgeEntriesByIp.delete(cacheKey);
        }
    }

    function showInfoDialog(data, ip) {
        if (infoDialogPromise) {
            return infoDialogPromise;
        }

        ensureUserscriptStyles();
        infoDialogPromise = mw.loader.using('oojs-ui-windows').then(function () {
            var targetIp = ip || (data && data.ip) || '';
            var cacheKey = canonicalizeIpKey(targetIp);
            var initialData = (cacheKey && latestResultByIp.get(cacheKey)) || data;
            var initialRisk = evaluateRisk(initialData);
            var $message = $('<div>');
            var $panelContainer = $('<div>', { 'class': 'proxycheck-dialog-content' });

            function renderDialogBody(dialogData, dialogRisk) {
                $panelContainer.empty();
                if (dialogRisk.isNonPublic) {
                    $panelContainer.append(
                        $('<p>').append(
                            $('<strong>').text('Address Type: '),
                            document.createTextNode(dialogRisk.nonPublicReason + ' [' + dialogRisk.nonPublicBadgeCode + ']')
                        ),
                        $('<p>').append(
                            $('<strong>').text('Status: '),
                            document.createTextNode('External threat lookups skipped (non-public or reserved IP)')
                        )
                    );
                } else {
                    $panelContainer.append(buildResultDetailsPanel(dialogData, dialogRisk));
                }
            }

            renderDialogBody(initialData, initialRisk);
            $message.append($panelContainer);
            $message.append(
                $('<p>', { style: 'margin-top: 8px; margin-bottom: 0;' }).append(
                    $('<a>', {
                        'class': 'proxycheck-dialog-link',
                        href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(targetIp),
                        target: '_blank',
                        rel: 'noopener noreferrer',
                        text: 'Open full report ↗'
                    })
                )
            );

            var dialogClosed = false;
            var $upgradeNotice = null;
            if (!initialRisk.isNonPublic && isPartialLightResult(initialData)) {
                $upgradeNotice = $('<p>', {
                    'class': 'proxycheck-light-upgrade-notice',
                    style: 'margin-top: 8px; margin-bottom: 0; font-size: 12px;'
                }).text('Loading full commercial provider intelligence...');
                $message.append($upgradeNotice);

                fetchIpIntelligence(targetIp, 'full').then(function (fullData) {
                    if (!fullData || typeof fullData !== 'object') {
                        if (!dialogClosed && $upgradeNotice) {
                            $upgradeNotice.text('Full commercial intelligence unavailable right now.');
                        }
                        return;
                    }
                    refreshRenderedBadgesForIp(fullData.ip || targetIp, fullData);
                    if (dialogClosed) {
                        return;
                    }
                    var updatedRisk = evaluateRisk(fullData);
                    renderDialogBody(fullData, updatedRisk);
                    if ($upgradeNotice) {
                        $upgradeNotice.remove();
                        $upgradeNotice = null;
                    }
                }).catch(function () {
                    if (!dialogClosed && $upgradeNotice) {
                        $upgradeNotice.text('Full commercial intelligence unavailable right now.');
                    }
                });
            }

            return Promise.resolve(
                OO.ui.alert($message, {
                    title: targetIp,
                    size: 'large'
                })
            ).then(function (dialogResult) {
                dialogClosed = true;
                return dialogResult;
            }, function (dialogErr) {
                dialogClosed = true;
                throw dialogErr;
            });
        }).catch(function (err) {
            console.warn('[proxycheck] Failed to open information dialog:', err);
        }).then(function (result) {
            infoDialogPromise = null;
            return result;
        });

        return infoDialogPromise;
    }

    function applyBaseBadgeStyle(badge) {
        badge.style.marginLeft = '4px';
        badge.style.fontSize = '0.85em';
        badge.style.fontFamily = 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace';
        badge.style.padding = '1px 5px';
        badge.style.borderRadius = '3px';
        badge.style.textDecoration = 'none';
        badge.style.whiteSpace = 'nowrap';
    }

    function createActionBadge(anchor, options) {
        if (accessBlocked || !anchor || !anchor.parentNode) {
            return null;
        }
        var nextEl = anchor.nextElementSibling;
        if (nextEl && nextEl.classList && nextEl.classList.contains(BADGE_CLASS)) {
            return null;
        }

        ensureUserscriptStyles();
        var badge = document.createElement('a');
        badge.className = BADGE_CLASS + (options.extraClass ? ' ' + options.extraClass : '');
        badge.href = '#';
        if (typeof badge.setAttribute === 'function') {
            badge.setAttribute('role', 'button');
        }
        badge.textContent = options.text;
        badge.title = options.title;
        applyBaseBadgeStyle(badge);
        if (options.backgroundColor) {
            badge.style.backgroundColor = options.backgroundColor;
        }
        if (options.color) {
            badge.style.color = options.color;
        }
        if (options.border) {
            badge.style.border = options.border;
        }
        badge.style.cursor = 'pointer';

        badge.addEventListener('click', function (event) {
            event.preventDefault();
            event.stopPropagation();
            if (accessBlocked) {
                return;
            }
            options.onClick(badge);
        });

        anchor.parentNode.insertBefore(badge, anchor.nextSibling);
        return badge;
    }

    function createErrorRetryBadge(anchor, ip) {
        createActionBadge(anchor, {
            extraClass: 'proxycheck-ip-badge-error',
            text: '[Retry]',
            title: 'ProxyCheck lookup failed. Click to retry.',
            onClick: function (retryBadge) {
                if (retryBadge.parentNode) {
                    retryBadge.parentNode.removeChild(retryBadge);
                }
                var cacheKey = canonicalizeIpKey(ip);
                if (cacheKey) {
                    ipPromiseCache.delete(cacheKey);
                    ipFullPromiseCache.delete(cacheKey);
                    latestResultByIp.delete(cacheKey);
                }
                ipPromiseCache.delete(ip.toLowerCase());
                ipFullPromiseCache.delete(ip.toLowerCase());
                latestResultByIp.delete(ip.toLowerCase());
                if (anchor.dataset) {
                    delete anchor.dataset.proxycheckProcessed;
                }
                processAnchor(anchor);
            }
        });
    }

    function resumeAfterConsent() {
        if (accessBlocked || consentDeclined || !document.body) {
            return;
        }
        var anchors = document.body.querySelectorAll(TARGET_SELECTOR);
        for (var i = 0; i < anchors.length; i++) {
            var anchor = anchors[i];
            if (!anchor || !anchor.dataset || anchor.dataset.proxycheckProcessed !== 'consent-declined') {
                continue;
            }
            var nextEl = anchor.nextElementSibling;
            if (
                nextEl &&
                nextEl.classList &&
                nextEl.classList.contains('proxycheck-ip-badge-consent') &&
                nextEl.parentNode
            ) {
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
            onClick: function () {
                ensureConsent(true).then(function (agreed) {
                    if (!agreed || accessBlocked) {
                        return;
                    }
                    resumeAfterConsent();
                });
            }
        });
    }

    function processAnchor(anchor) {
        if (
            accessBlocked ||
            !anchor ||
            !anchor.dataset ||
            (anchor.dataset.proxycheckProcessed && anchor.dataset.proxycheckProcessed !== 'observed')
        ) {
            return;
        }

        var ip = (anchor.textContent || '').trim();
        if (!isValidIp(ip)) {
            return;
        }

        anchor.dataset.proxycheckProcessed = 'pending';

        ensureConsent(false).then(function (agreed) {
            if (!agreed) {
                if (!accessBlocked && anchor.dataset.proxycheckProcessed === 'pending') {
                    anchor.dataset.proxycheckProcessed = 'consent-declined';
                    createConsentTriggerBadge(anchor);
                } else {
                    delete anchor.dataset.proxycheckProcessed;
                }
                return null;
            }
            return fetchIpIntelligence(ip, 'light');
        }).then(function (data) {
            if (!data) {
                if (!accessBlocked && anchor.dataset.proxycheckProcessed === 'pending') {
                    anchor.dataset.proxycheckProcessed = 'error';
                    createErrorRetryBadge(anchor, ip);
                }
                return;
            }
            if (!anchor.parentNode) {
                anchor.dataset.proxycheckProcessed = 'error';
                return;
            }
            if (anchor.dataset.proxycheckProcessed === 'true') {
                return;
            }
            var nextEl = anchor.nextElementSibling;
            if (nextEl && nextEl.classList.contains(BADGE_CLASS)) {
                anchor.dataset.proxycheckProcessed = 'true';
                return;
            }

            var resolvedIp = data.ip || ip;
            var badge = document.createElement('a');
            badge.className = BADGE_CLASS;
            badge.target = '_blank';
            badge.rel = 'noopener noreferrer';
            badge.addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();
                var currentKey = canonicalizeIpKey(resolvedIp) || canonicalizeIpKey(ip);
                var activeData = (currentKey && latestResultByIp.get(currentKey)) || data;
                showInfoDialog(activeData, activeData.ip || resolvedIp);
            });

            applyRiskStylingToAnchorAndBadge(anchor, badge, data, resolvedIp, false);
            registerRenderedBadge(canonicalizeIpKey(resolvedIp) || canonicalizeIpKey(ip), anchor, badge, resolvedIp);

            anchor.parentNode.insertBefore(badge, anchor.nextSibling);
            anchor.dataset.proxycheckProcessed = 'true';
        });
    }

    function matchesSelector(element, selector) {
        if (!element || element.nodeType !== 1) {
            return false;
        }
        var matcher = element.matches || element.webkitMatchesSelector || element.msMatchesSelector;
        if (!matcher) {
            return false;
        }
        return matcher.call(element, selector);
    }

    function closestElement(element, selector) {
        if (!element || element.nodeType !== 1) {
            return null;
        }
        if (typeof element.closest === 'function') {
            return element.closest(selector);
        }
        var current = element;
        while (current && current.nodeType === 1) {
            if (matchesSelector(current, selector)) {
                return current;
            }
            current = current.parentNode;
        }
        return null;
    }

    // Ignore text, comment, and script-owned nodes to prevent self-triggered observer loops
    function isProxycheckInternalNode(node) {
        if (!node) {
            return false;
        }
        if (node.nodeType === 3 || node.nodeType === 8) {
            return true;
        }
        if (node.nodeType !== 1) {
            return false;
        }
        return Boolean(closestElement(node, INTERNAL_NODE_SELECTOR));
    }

    function isIpInfoPanelMutation(target, addedNode) {
        if (closestElement(target, IPINFO_PANEL_SELECTOR)) {
            return true;
        }
        if (!addedNode || addedNode.nodeType !== 1) {
            return false;
        }
        if (matchesSelector(addedNode, IPINFO_PANEL_SELECTOR)) {
            return true;
        }
        return Boolean(addedNode.querySelector && addedNode.querySelector(IPINFO_PANEL_SELECTOR));
    }

    function scheduleIpContributionsUpdate(shouldRefreshSpur) {
        pendingContributionsPageCheck = true;
        if (shouldRefreshSpur) {
            pendingSpurRefresh = true;
        }
        if (ipContributionsObserverTimer !== null) {
            return;
        }
        ipContributionsObserverTimer = window.setTimeout(function () {
            ipContributionsObserverTimer = null;
            var runPageCheck = pendingContributionsPageCheck;
            var runSpurRefresh = pendingSpurRefresh;
            pendingContributionsPageCheck = false;
            pendingSpurRefresh = false;

            if (accessBlocked || !isIpContributionsPage) {
                return;
            }
            if (runPageCheck) {
                handleIPContributionsPage();
            }
            if (runSpurRefresh && typeof refreshPageInfoSpur === 'function') {
                refreshPageInfoSpur();
            }
        }, OBSERVER_THROTTLE_MS);
    }

    function scheduleAnchor(anchor) {
        if (accessBlocked || !anchor || !anchor.dataset || anchor.dataset.proxycheckProcessed) {
            return;
        }

        var ip = (anchor.textContent || '').trim();
        if (!isValidIp(ip)) {
            return;
        }

        var cacheKey = canonicalizeIpKey(ip);
        if (ipPromiseCache.has(cacheKey) || readPersistedIpResult(cacheKey)) {
            processAnchor(anchor);
            return;
        }

        if (viewportObserver) {
            anchor.dataset.proxycheckProcessed = 'observed';
            viewportObserver.observe(anchor);
            return;
        }

        processAnchor(anchor);
    }

    function scanSubtree(root) {
        if (accessBlocked || !root || root.nodeType !== 1 || isProxycheckInternalNode(root)) {
            return;
        }
        if (matchesSelector(root, TARGET_SELECTOR)) {
            scheduleAnchor(root);
        }
        var anchors = root.querySelectorAll(TARGET_SELECTOR);
        for (var i = 0; i < anchors.length; i++) {
            scheduleAnchor(anchors[i]);
        }
    }

    function getTargetQueryParam() {
        if (mw.util && typeof mw.util.getParamValue === 'function') {
            return mw.util.getParamValue('target');
        }
        try {
            if (typeof window !== 'undefined' && window.location && typeof window.location.search === 'string') {
                var query = window.location.search.replace(/^\?/, '');
                if (!query) {
                    return null;
                }
                var pairs = query.split('&');
                for (var i = 0; i < pairs.length; i++) {
                    var eqIdx = pairs[i].indexOf('=');
                    var rawKey = eqIdx === -1 ? pairs[i] : pairs[i].slice(0, eqIdx);
                    if (decodeURIComponent(rawKey.replace(/\+/g, ' ')) === 'target') {
                        var rawVal = eqIdx === -1 ? '' : pairs[i].slice(eqIdx + 1);
                        return decodeURIComponent(rawVal.replace(/\+/g, ' '));
                    }
                }
            }
        } catch (err) {
            console.warn('[proxycheck] Failed to parse query target parameter:', err);
        }
        return null;
    }

    function extractContributionsTargetIp() {
        var targetIp = mw.config.get('wgRelevantUserName');
        if (!targetIp) {
            var titleParts = (mw.config.get('wgTitle') || '').split('/');
            if (titleParts.length > 1) {
                targetIp = titleParts.slice(1).join('/');
            }
        }
        if (!targetIp) {
            targetIp = getTargetQueryParam();
        }
        return typeof targetIp === 'string' ? targetIp.trim() : '';
    }

    // Prefer IPInfo panel layout when ready, falling back to standard contributions headers
    function resolveContributionsMountTarget(allowFallback) {
        var $panel = $('.ext-ipinfo-panel-layout');
        if (
            $panel.length > 0 &&
            $panel.find('.ext-ipinfo-collapsible-layout-error, .oo-ui-flaggedElement-error, .oo-ui-icon-error').length === 0
        ) {
            var $panelBody = $panel.find('.oo-ui-fieldsetLayout-group.mw-collapsible-content').first();
            if ($panelBody.length === 0) {
                $panelBody = $panel.find('.oo-ui-fieldsetLayout-group').first();
            }
            if ($panelBody.length === 0) {
                $panelBody = $panel.first();
            }
            if ($panelBody.length > 0) {
                return { $element: $panelBody, method: 'prepend' };
            }
        }

        if (!allowFallback) {
            return null;
        }

        var fallbackCandidates = [
            { selector: '#mw-content-text .mw-contributions-header', method: 'before' },
            { selector: '#mw-content-text .mw-contributions-list', method: 'before' },
            { selector: '.mw-contributions-header', method: 'before' },
            { selector: '.mw-contributions-list', method: 'before' },
            { selector: '#mw-content-text .mw-contributions-form', method: 'after' },
            { selector: '.mw-contributions-form', method: 'after' },
            { selector: '#contentSub', method: 'after' },
            { selector: '#mw-content-text', method: 'prepend' },
            { selector: '#contentSub', method: 'prepend' }
        ];

        for (var i = 0; i < fallbackCandidates.length; i++) {
            var candidate = fallbackCandidates[i];
            var $node = $(candidate.selector).first();
            if ($node.length === 0) {
                continue;
            }
            if (
                (candidate.method === 'before' || candidate.method === 'after') &&
                $node.parent().length === 0
            ) {
                continue;
            }
            return { $element: $node, method: candidate.method };
        }

        return null;
    }

    function handleIPContributionsPage(allowFallback) {
        ensureUserscriptStyles();
        if (
            accessBlocked ||
            consentDeclined ||
            !isIpContributionsPage ||
            ipContributionsPending ||
            ipContributionsInvalidTarget ||
            document.getElementById('proxycheck-pageinfo')
        ) {
            return;
        }

        var targetIp = extractContributionsTargetIp();
        if (!isValidIp(targetIp)) {
            ipContributionsInvalidTarget = true;
            return;
        }

        var mountTarget = resolveContributionsMountTarget(Boolean(allowFallback));
        if (!mountTarget) {
            if (!allowFallback && ipContributionsFallbackTimer === null) {
                ipContributionsFallbackTimer = window.setTimeout(function () {
                    ipContributionsFallbackTimer = null;
                    handleIPContributionsPage(true);
                }, IPINFO_FALLBACK_DELAY_MS);
            }
            return;
        }

        if (ipContributionsFallbackTimer !== null) {
            window.clearTimeout(ipContributionsFallbackTimer);
            ipContributionsFallbackTimer = null;
        }

        ipContributionsPending = true;
        var $box = null;
        var $result = null;

        function isNodeInDocument(node) {
            if (!node) {
                return false;
            }
            if (typeof document !== 'undefined' && document.body && typeof document.body.contains === 'function') {
                return document.body.contains(node);
            }
            return true;
        }

        function mountBannerElement(target) {
            if (!$box || $box.length === 0 || !target || !target.$element || target.$element.length === 0) {
                return false;
            }
            var existingInDom = document.getElementById('proxycheck-pageinfo');
            if (existingInDom && existingInDom !== $box[0] && existingInDom.parentNode) {
                existingInDom.parentNode.removeChild(existingInDom);
            }
            target.$element[target.method]($box);
            return true;
        }

        function ensureBannerAttached() {
            if (!$box || $box.length === 0 || !$box[0]) {
                return false;
            }
            if (!isNodeInDocument($box[0])) {
                var freshTarget = resolveContributionsMountTarget(Boolean(allowFallback)) ||
                    resolveContributionsMountTarget(true);
                if (!mountBannerElement(freshTarget)) {
                    return false;
                }
            }
            return true;
        }

        function renderBannerFailure() {
            if (!$result || $result.length === 0) {
                return;
            }
            if (accessBlocked) {
                $result.text('[ProxyCheck] Access denied or disabled');
                return;
            }
            var $retryLink = $('<a>', {
                href: '#',
                role: 'button',
                'class': 'proxycheck-banner-retry',
                text: 'Retry ↻'
            });
            $retryLink.on('click', function (event) {
                event.preventDefault();
                event.stopPropagation();
                if (accessBlocked) {
                    return;
                }
                clearLoadingInterval();
                var retryCacheKey = canonicalizeIpKey(targetIp);
                if (retryCacheKey) {
                    ipPromiseCache.delete(retryCacheKey);
                    ipFullPromiseCache.delete(retryCacheKey);
                    latestResultByIp.delete(retryCacheKey);
                }
                var existingBanner = document.getElementById('proxycheck-pageinfo');
                if (existingBanner && existingBanner.parentNode) {
                    existingBanner.parentNode.removeChild(existingBanner);
                }
                ipContributionsPending = false;
                handleIPContributionsPage(Boolean(allowFallback));
            });
            $result.empty().append(
                document.createTextNode('[ProxyCheck] Failed to acquire data '),
                $retryLink
            );
        }

        ensureConsent().then(function (agreed) {
            if (!agreed || accessBlocked || document.getElementById('proxycheck-pageinfo')) {
                ipContributionsPending = false;
                return null;
            }

            var activeTarget = resolveContributionsMountTarget(Boolean(allowFallback)) || mountTarget;
            if (
                !activeTarget ||
                !activeTarget.$element ||
                activeTarget.$element.length === 0 ||
                (activeTarget.$element[0] && !isNodeInDocument(activeTarget.$element[0]))
            ) {
                activeTarget = resolveContributionsMountTarget(true);
            }
            if (!activeTarget) {
                ipContributionsPending = false;
                return null;
            }

            $box = $('<div>', {
                id: 'proxycheck-pageinfo',
                'class': 'proxycheck-pageinfo-banner'
            });
            $result = $('<span>', {
                id: 'proxycheck_result',
                text: '.'
            });
            $box.append($result);
            mountBannerElement(activeTarget);

            clearLoadingInterval();
            activeLoadingInterval = window.setInterval(function () {
                if ($result.html() === '.&nbsp;&nbsp;') {
                    $result.html('&nbsp;.&nbsp;');
                } else if ($result.html() === '&nbsp;.&nbsp;') {
                    $result.html('&nbsp;&nbsp;.');
                } else {
                    $result.html('.&nbsp;&nbsp;');
                }
            }, 300);

            return fetchIpIntelligence(targetIp, 'full').then(function (data) {
                clearLoadingInterval();
                ipContributionsPending = false;

                if (!ensureBannerAttached()) {
                    return;
                }

                if (!data) {
                    renderBannerFailure();
                    return;
                }

                var isStatsExpanded = false;

                function renderContributionsBannerData(bannerData) {
                    var risk = evaluateRisk(bannerData);
                    var resolvedIp = bannerData.ip || targetIp;
                    var $activeBox = ($box && $box.length > 0) ? $box : $('#proxycheck-pageinfo');
                    if ($activeBox && $activeBox.length > 0 && $activeBox[0]) {
                        var bannerTiers = ['high', 'medium', 'nonpublic', 'low'];
                        for (var t = 0; t < bannerTiers.length; t++) {
                            removeElementClass($activeBox[0], 'proxycheck-banner-tier-' + bannerTiers[t]);
                        }
                        addElementClass($activeBox[0], 'proxycheck-banner-tier-' + risk.riskTier);
                    }

                    var badgeClass = 'proxycheck-banner-badge proxycheck-tier-' + risk.riskTier;

                    if (risk.isNonPublic) {
                        $result.empty().append(
                            $('<span>', {
                                'class': badgeClass,
                                text: 'ProxyCheck [' + risk.nonPublicBadgeCode + ']'
                            }),
                            $('<span>').html(
                                ' &middot; <b>Address Type:</b> ' + mw.html.escape(risk.nonPublicReason) +
                                ' &middot; <b>Status:</b> External threat lookups skipped (non-public or reserved IP)' +
                                ' &middot; '
                            ),
                            $('<a>', {
                                href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp),
                                target: '_blank',
                                rel: 'noopener noreferrer',
                                text: 'Full Report ↗'
                            })
                        );
                        return;
                    }

                    var torBannerDesc = formatTorDescription(risk);
                    var cloudBannerDesc = formatCloudDescription(bannerData);
                    var verdictBannerText = typeof bannerData.arbitrationVerdict === 'string' && bannerData.arbitrationVerdict.trim()
                        ? bannerData.arbitrationVerdict.trim()
                        : '';
                    var ptrHostname = typeof bannerData.ptrHostname === 'string' ? bannerData.ptrHostname.trim() : '';
                    var ptrLabel = typeof bannerData.ptrLabel === 'string' ? bannerData.ptrLabel.trim() : '';

                    var $summary = $('<div>', { 'class': 'proxycheck-summary-line' }).append(
                        $('<span>', {
                            'class': badgeClass,
                            text: 'ProxyCheck'
                        })
                    );

                    function appendSummaryItem(label, valueNode) {
                        $summary.append(
                            document.createTextNode(' \u00b7 '),
                            $('<b>').text(label + ': '),
                            valueNode
                        );
                    }

                    appendSummaryItem('Prediction', document.createTextNode(risk.predictionTooltip));
                    if (verdictBannerText) {
                        appendSummaryItem('Verdict', document.createTextNode(verdictBannerText));
                    }
                    appendSummaryItem('Recommended CIDR', document.createTextNode(bannerData.recommendedCidr || 'N/A'));
                    appendSummaryItem('BGP CIDR', document.createTextNode(bannerData.mmdbCidr || 'N/A'));

                    if (ptrHostname || ptrLabel) {
                        var $ptrValue = $('<span>');
                        if (ptrHostname) {
                            $ptrValue.append($('<code>').text(ptrHostname));
                            if (ptrLabel) {
                                $ptrValue.append(document.createTextNode(' '));
                                $ptrValue.append(
                                    $('<span>', {
                                        'class': bannerData.ptrIsHighRisk ? 'proxycheck-ptr-label-risk' : 'proxycheck-ptr-label-normal',
                                        text: '(' + ptrLabel + ')'
                                    })
                                );
                            }
                        } else {
                            $ptrValue.text(ptrLabel);
                        }
                        appendSummaryItem('PTR', $ptrValue);
                    }

                    if (cloudBannerDesc) {
                        appendSummaryItem('Cloud', document.createTextNode(cloudBannerDesc));
                    }

                    appendSummaryItem(
                        'Broadcast IP',
                        risk.broadcastIp
                            ? $('<strong>', { 'class': 'proxycheck-banner-warning-text', text: 'At-risk' })
                            : document.createTextNode('No')
                    );
                    appendSummaryItem(
                        'Tor Node',
                        risk.isTor
                            ? $('<strong>', { 'class': 'proxycheck-banner-danger-text', text: torBannerDesc })
                            : document.createTextNode('No')
                    );

                    var renderedSpurText = getSpurProxyText();
                    var $detailsWrapper = $('<div>', {
                        'class': 'proxycheck-pageinfo-details',
                        style: isStatsExpanded ? 'display: block;' : 'display: none;'
                    }).append(buildResultDetailsPanel(bannerData, risk));

                    refreshPageInfoSpur = function () {
                        var latestSpurText = getSpurProxyText();
                        if (latestSpurText === renderedSpurText) {
                            return;
                        }
                        renderedSpurText = latestSpurText;
                        $detailsWrapper.empty().append(buildResultDetailsPanel(bannerData, risk));
                    };

                    var $statsToggle = $('<a>', {
                        href: '#',
                        role: 'button',
                        'class': 'proxycheck-stats-toggle',
                        'aria-expanded': isStatsExpanded ? 'true' : 'false',
                        text: isStatsExpanded ? 'Statistic ▾' : 'Statistic ▸'
                    });

                    var fullUpgradeRequested = false;
                    $statsToggle.on('click', function (event) {
                        event.preventDefault();
                        event.stopPropagation();
                        isStatsExpanded = !isStatsExpanded;
                        $detailsWrapper.css('display', isStatsExpanded ? 'block' : 'none');
                        $statsToggle.attr('aria-expanded', isStatsExpanded ? 'true' : 'false');
                        $statsToggle.text(isStatsExpanded ? 'Statistic ▾' : 'Statistic ▸');

                        if (isStatsExpanded && isPartialLightResult(bannerData) && !fullUpgradeRequested) {
                            fullUpgradeRequested = true;
                            var $bannerUpgradeNotice = $('<p>', {
                                'class': 'proxycheck-light-upgrade-notice',
                                style: 'margin-top: 8px; margin-bottom: 0; font-size: 12px;'
                            }).text('Loading full commercial provider intelligence...');
                            $detailsWrapper.append($bannerUpgradeNotice);

                            fetchIpIntelligence(resolvedIp, 'full').then(function (fullData) {
                                if (!fullData || typeof fullData !== 'object') {
                                    $bannerUpgradeNotice.text('Full commercial intelligence unavailable right now.');
                                    return;
                                }
                                refreshRenderedBadgesForIp(fullData.ip || resolvedIp, fullData);
                                if (!ensureBannerAttached()) {
                                    return;
                                }
                                renderContributionsBannerData(fullData);
                            });
                        }
                    });

                    $summary.append(
                        document.createTextNode(' \u00b7 '),
                        $('<a>', {
                            href: TOOL_BASE_URL + '/?ip=' + encodeURIComponent(resolvedIp),
                            target: '_blank',
                            rel: 'noopener noreferrer',
                            text: 'Full Report ↗'
                        }),
                        document.createTextNode(' \u00b7 '),
                        $statsToggle
                    );

                    $result.empty().append($summary, $detailsWrapper);
                }

                renderContributionsBannerData(data);
            }).catch(function (err) {
                clearLoadingInterval();
                ipContributionsPending = false;
                console.warn('[proxycheck] Failed to acquire contributions banner data:', err);
                if (ensureBannerAttached()) {
                    renderBannerFailure();
                }
            });
        }).catch(function (err) {
            clearLoadingInterval();
            ipContributionsPending = false;
            console.warn('[proxycheck] Contributions banner update failed:', err);
        });
    }

    $(function () {
        ensureUserscriptStyles();
        if (typeof window !== 'undefined' && typeof window.IntersectionObserver === 'function') {
            viewportObserver = new window.IntersectionObserver(function (entries) {
                if (accessBlocked) {
                    return;
                }
                for (var i = 0; i < entries.length; i++) {
                    var entry = entries[i];
                    if (entry && entry.isIntersecting && entry.target) {
                        viewportObserver.unobserve(entry.target);
                        processAnchor(entry.target);
                    }
                }
            }, {
                rootMargin: '200px 0px'
            });
        }

        handleIPContributionsPage();
        scanSubtree(document.body);

        if (isIpContributionsPage && mw.hook) {
            mw.hook('wikipage.content').add(function () {
                handleIPContributionsPage();
            });
        }

        observer = new MutationObserver(function (mutations) {
            if (accessBlocked) {
                return;
            }
            var hasExternalElementMutation = false;
            var hasIpInfoMutation = false;

            for (var i = 0; i < mutations.length; i++) {
                var mutation = mutations[i];
                if (!mutation.target || isProxycheckInternalNode(mutation.target)) {
                    continue;
                }
                if (matchesSelector(mutation.target, TARGET_SELECTOR)) {
                    scheduleAnchor(mutation.target);
                }
                for (var j = 0; j < mutation.addedNodes.length; j++) {
                    var addedNode = mutation.addedNodes[j];
                    if (!addedNode || addedNode.nodeType !== 1 || isProxycheckInternalNode(addedNode)) {
                        continue;
                    }
                    hasExternalElementMutation = true;
                    if (!hasIpInfoMutation && isIpInfoPanelMutation(mutation.target, addedNode)) {
                        hasIpInfoMutation = true;
                    }
                    scanSubtree(addedNode);
                }
            }

            if (isIpContributionsPage && hasExternalElementMutation) {
                scheduleIpContributionsUpdate(hasIpInfoMutation);
            }
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    });
})(mediaWiki, jQuery);