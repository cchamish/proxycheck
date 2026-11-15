import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  DEFAULT_THEME,
  THEME_STORAGE_KEY,
  applyThemeToDocument,
  getNextTheme,
  normalizeTheme,
  readStoredTheme,
  saveStoredTheme,
} from './theme';

test('Theme defaults to dark mode and normalises unrecognised stored values', () => {
  assert.equal(DEFAULT_THEME, 'dark');
  assert.equal(THEME_STORAGE_KEY, 'proxy_detector_theme');

  assert.equal(normalizeTheme(null), 'dark');
  assert.equal(normalizeTheme(undefined), 'dark');
  assert.equal(normalizeTheme(''), 'dark');
  assert.equal(normalizeTheme('system'), 'dark');
  assert.equal(normalizeTheme('dark'), 'dark');
  assert.equal(normalizeTheme('light'), 'light');
});

test('getNextTheme toggles cleanly between dark and light modes', () => {
  assert.equal(getNextTheme('dark'), 'light');
  assert.equal(getNextTheme('light'), 'dark');
});

test('readStoredTheme and saveStoredTheme persist selection and tolerate storage failures', () => {
  const backingStore = new Map<string, string>();
  const mockStorage = {
    getItem: (key: string) => backingStore.get(key) ?? null,
    setItem: (key: string, value: string) => {
      backingStore.set(key, value);
    },
  };

  assert.equal(readStoredTheme(mockStorage), 'dark');

  saveStoredTheme('light', mockStorage);
  assert.equal(backingStore.get(THEME_STORAGE_KEY), 'light');
  assert.equal(readStoredTheme(mockStorage), 'light');

  saveStoredTheme('dark', mockStorage);
  assert.equal(readStoredTheme(mockStorage), 'dark');

  const failingStorage = {
    getItem: () => {
      throw new Error('SecurityError');
    },
    setItem: () => {
      throw new Error('QuotaExceededError');
    },
  };
  assert.equal(readStoredTheme(failingStorage), 'dark');
  assert.doesNotThrow(() => saveStoredTheme('light', failingStorage));
  assert.equal(readStoredTheme(null), 'dark');
  assert.doesNotThrow(() => saveStoredTheme('light', null));
});

test('applyThemeToDocument updates root dataset, colorScheme, and theme-color metadata', () => {
  const root = {
    dataset: {} as DOMStringMap,
    style: { colorScheme: '' } as CSSStyleDeclaration,
  } as unknown as HTMLElement;
  const themeMeta = { content: '' };

  applyThemeToDocument('light', root, themeMeta);
  assert.equal(root.dataset.theme, 'light');
  assert.equal(root.style.colorScheme, 'light');
  assert.equal(themeMeta.content, '#f6f7f8');

  applyThemeToDocument('dark', root, themeMeta);
  assert.equal(root.dataset.theme, 'dark');
  assert.equal(root.style.colorScheme, 'dark');
  assert.equal(themeMeta.content, '#101418');
});

test('Frontend entry, header, and stylesheet default to dark mode with an accessible theme toggle', () => {
  const indexHtml = fs.readFileSync(path.resolve(process.cwd(), 'index.html'), 'utf8');
  assert.match(indexHtml, /<html\b[^>]*data-theme="dark"/);
  assert.match(indexHtml, /localStorage\.getItem\('proxy_detector_theme'\)\s*===\s*'light'/);

  const appVue = fs.readFileSync(path.resolve(process.cwd(), 'src/App.vue'), 'utf8');
  assert.match(
    appVue,
    /<cdx-button[^>]*?weight="quiet"[^>]*?class="admin-dashboard-btn"/
  );
  assert.match(
    appVue,
    /<\/template>\s*<cdx-button[^>]*?weight="quiet"[^>]*?class="theme-toggle-btn"[^>]*?:aria-label="themeToggleAriaLabel"[\s\S]*?@click="handleToggleTheme"\s*>\s*<cdx-icon\s+:icon="themeToggleIcon"[^>]*\/>\s*<\/cdx-button>/
  );
  assert.match(appVue, /WMCS-dark\.svg/);

  const codexCss = fs.readFileSync(path.resolve(process.cwd(), 'src/codex.css'), 'utf8');
  assert.match(codexCss, /:root\s*\{[\s\S]*?color-scheme:\s*dark;/);
  assert.match(codexCss, /html\[data-theme='light'\]\s*\{[\s\S]*?color-scheme:\s*light;/);
  const userPillRule = codexCss.match(/\.user-pill\s*\{([^}]*)\}/);
  assert.ok(userPillRule);
  assert.doesNotMatch(
    userPillRule[1],
    /(?:^|[\s;])border(?:-(?:top|right|bottom|left|color|style|width))?\s*:/
  );
  assert.doesNotMatch(
    userPillRule[1],
    /(?:^|[\s;])background(?:-color)?\s*:/
  );
});
