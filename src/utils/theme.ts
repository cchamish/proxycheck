export type ThemeMode = 'dark' | 'light';

export const THEME_STORAGE_KEY = 'proxy_detector_theme';
export const DEFAULT_THEME: ThemeMode = 'dark';

const DARK_THEME_COLOUR = '#101418';
const LIGHT_THEME_COLOUR = '#f6f7f8';

/**
 * Normalises persisted theme strings, falling back to dark mode for absent or unrecognised values.
 */
export function normalizeTheme(value: unknown): ThemeMode {
  return value === 'light' ? 'light' : DEFAULT_THEME;
}

/**
 * Returns the opposite colour theme mode for toggle actions.
 */
export function getNextTheme(currentTheme: ThemeMode): ThemeMode {
  return currentTheme === 'dark' ? 'light' : 'dark';
}

/**
 * Reads the persisted theme preference from storage, defaulting safely to dark mode.
 */
export function readStoredTheme(
  storage: Pick<Storage, 'getItem'> | null | undefined =
    typeof localStorage !== 'undefined' ? localStorage : null
): ThemeMode {
  if (!storage) {
    return DEFAULT_THEME;
  }
  try {
    return normalizeTheme(storage.getItem(THEME_STORAGE_KEY));
  } catch {
    return DEFAULT_THEME;
  }
}

/**
 * Persists the active theme preference to storage.
 */
export function saveStoredTheme(
  theme: ThemeMode,
  storage: Pick<Storage, 'setItem'> | null | undefined =
    typeof localStorage !== 'undefined' ? localStorage : null
): void {
  if (!storage) {
    return;
  }
  try {
    storage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Ignore storage quota or private-browsing exceptions.
  }
}

/**
 * Applies the selected theme to the document root and browser theme-colour metadata.
 */
export function applyThemeToDocument(
  theme: ThemeMode,
  root: HTMLElement | null | undefined =
    typeof document !== 'undefined' ? document.documentElement : null,
  themeMeta: Pick<HTMLMetaElement, 'content'> | null | undefined =
    typeof document !== 'undefined'
      ? document.querySelector<HTMLMetaElement>('meta[name="theme-color"]')
      : null
): void {
  if (root) {
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
  }
  if (themeMeta) {
    themeMeta.content = theme === 'dark' ? DARK_THEME_COLOUR : LIGHT_THEME_COLOUR;
  }
}
