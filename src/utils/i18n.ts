import { computed, ref } from 'vue';
import enMessages from '../i18n/en.json' with { type: 'json' };
import zhHansMessages from '../i18n/zh-hans.json' with { type: 'json' };
import zhHantMessages from '../i18n/zh-hant.json' with { type: 'json' };

export type LocaleCode = 'en' | 'zh-hans' | 'zh-hant';
export type MessageKey = keyof typeof enMessages;

export interface LocaleOption {
  code: LocaleCode;
  label: string;
}

export const LOCALE_STORAGE_KEY = 'proxy_detector_lang';

export const SUPPORTED_LOCALES: readonly LocaleOption[] = [
  { code: 'en', label: 'English' },
  { code: 'zh-hans', label: '中文（简体）' },
  { code: 'zh-hant', label: '中文（繁體）' },
];

const MESSAGES: Record<LocaleCode, Record<MessageKey, string>> = {
  en: enMessages,
  'zh-hans': zhHansMessages,
  'zh-hant': zhHantMessages,
};

const LOCALE_HTML_LANG: Record<LocaleCode, string> = {
  en: 'en-GB',
  'zh-hans': 'zh-Hans',
  'zh-hant': 'zh-Hant',
};

const LOCALE_LABELS: Record<LocaleCode, string> = {
  en: 'English',
  'zh-hans': '中文（简体）',
  'zh-hant': '中文（繁體）',
};

export function normaliseLocale(raw?: string | null): LocaleCode | null {
  if (!raw || typeof raw !== 'string') return null;
  const cleaned = raw.trim().toLowerCase().replaceAll('_', '-');
  if (!cleaned) return null;
  if (cleaned === 'en' || cleaned.startsWith('en-')) return 'en';
  if (cleaned === 'zh-hans' || cleaned === 'zh-cn' || cleaned === 'zh-sg' || cleaned === 'zh-my') {
    return 'zh-hans';
  }
  if (cleaned === 'zh-hant' || cleaned === 'zh-tw' || cleaned === 'zh-hk' || cleaned === 'zh-mo') {
    return 'zh-hant';
  }
  return null;
}

export function resolveInitialLocale(search?: string, stored?: string | null): LocaleCode {
  if (search) {
    const params = new URLSearchParams(search);
    const fromQuery = normaliseLocale(params.get('uselang'));
    if (fromQuery) return fromQuery;
  }
  const fromStorage = normaliseLocale(stored);
  if (fromStorage) return fromStorage;
  return 'en';
}

function readStoredLocale(): string | null {
  try {
    if (typeof localStorage !== 'undefined') {
      return localStorage.getItem(LOCALE_STORAGE_KEY);
    }
  } catch {
    // Storage access may be restricted in private browsing contexts.
  }
  return null;
}

export function applyLocaleToDocument(code: LocaleCode): void {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = LOCALE_HTML_LANG[code];
}

const initialSearch = typeof window !== 'undefined' ? window.location.search : '';
const activeLocale = ref<LocaleCode>(resolveInitialLocale(initialSearch, readStoredLocale()));
applyLocaleToDocument(activeLocale.value);

export function setLocale(code: LocaleCode, options?: { persist?: boolean; clearUrlOverride?: boolean }): void {
  activeLocale.value = code;
  applyLocaleToDocument(code);

  if (options?.persist !== false) {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(LOCALE_STORAGE_KEY, code);
      }
    } catch {
      // Storage quota or private browsing may reject writes.
    }
  }

  if (options?.clearUrlOverride && typeof window !== 'undefined' && window.history?.replaceState) {
    const params = new URLSearchParams(window.location.search || '');
    if (params.has('uselang')) {
      params.delete('uselang');
      const basePath = window.location.pathname.startsWith('/') ? window.location.pathname : '/';
      const query = params.toString();
      window.history.replaceState(window.history.state, '', query ? `${basePath}?${query}` : basePath);
    }
  }
}

export function handleLocaleStorageSync(event: StorageEvent): void {
  if (event.key !== LOCALE_STORAGE_KEY) return;
  const synced = normaliseLocale(event.newValue) ?? 'en';
  setLocale(synced, { persist: false });
}

export function t(key: MessageKey, params?: Record<string, string | number>): string {
  const template = MESSAGES[activeLocale.value][key] ?? enMessages[key] ?? key;
  if (!params) return template;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match
  );
}

export function useI18n() {
  const locale = computed<LocaleCode>({
    get: () => activeLocale.value,
    set: (next) => setLocale(next, { persist: true, clearUrlOverride: true }),
  });

  const currentLocaleLabel = computed(() => LOCALE_LABELS[activeLocale.value]);

  const localeMenuItems = SUPPORTED_LOCALES.map((item) => ({
    label: item.label,
    value: item.code,
  }));

  return {
    locale,
    currentLocaleLabel,
    localeMenuItems,
    t,
  };
}
