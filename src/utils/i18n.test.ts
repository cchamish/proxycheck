import test from 'node:test';
import assert from 'node:assert/strict';
import enMessages from '../i18n/en.json';
import zhHansMessages from '../i18n/zh-hans.json';
import zhHantMessages from '../i18n/zh-hant.json';
import { normaliseLocale, resolveInitialLocale, setLocale, t } from './i18n';

test('normalises locale codes and resolves ?uselang= over storage with English fallback', () => {
  const cases: Array<{ search: string; stored: string | null; expected: string }> = [
    { search: '', stored: null, expected: 'en' },
    { search: '', stored: 'zh-hans', expected: 'zh-hans' },
    { search: '', stored: 'zh-hant', expected: 'zh-hant' },
    { search: '?uselang=zh-hant', stored: 'zh-hans', expected: 'zh-hant' },
    { search: '?uselang=zh-CN', stored: 'en', expected: 'zh-hans' },
    { search: '?uselang=zh_TW', stored: 'en', expected: 'zh-hant' },
    { search: '?uselang=invalid', stored: 'zh-hans', expected: 'zh-hans' },
    { search: '?uselang=', stored: 'zh-hant', expected: 'zh-hant' },
    { search: '?uselang=fr', stored: 'unknown', expected: 'en' },
  ];

  for (const item of cases) {
    assert.equal(resolveInitialLocale(item.search, item.stored), item.expected);
  }

  assert.equal(normaliseLocale('en-GB'), 'en');
  assert.equal(normaliseLocale('zh-HK'), 'zh-hant');
  assert.equal(normaliseLocale(''), null);
});

test('keeps all translation bundles in key and placeholder parity with English', () => {
  const enKeys = Object.keys(enMessages).sort();
  const extractPlaceholders = (text: string): string[] =>
    [...(text.match(/\{[a-zA-Z0-9_]+\}/g) ?? [])].sort();

  for (const [label, bundle] of [
    ['zh-hans', zhHansMessages],
    ['zh-hant', zhHantMessages],
  ] as const) {
    assert.deepEqual(Object.keys(bundle).sort(), enKeys, `${label} keys must match en.json`);
    for (const key of enKeys as Array<keyof typeof enMessages>) {
      assert.ok(bundle[key].trim().length > 0, `${label}.${key} must be non-empty`);
      assert.deepEqual(
        extractPlaceholders(bundle[key]),
        extractPlaceholders(enMessages[key]),
        `${label}.${key} placeholders must match en.json`
      );
    }
  }
});

test('switches active locale and interpolates message placeholders', () => {
  try {
    setLocale('zh-hans', { persist: false });
    assert.equal(t('header-logout'), '退出登录');
    assert.equal(t('footer-executed-in', { duration: '0.123' }), '耗时0.123秒');

    setLocale('zh-hant', { persist: false });
    assert.equal(t('header-logout'), '登出');
    assert.equal(t('footer-executed-in', { duration: '0.123' }), '耗時0.123秒');
  } finally {
    setLocale('en', { persist: false });
  }
  assert.equal(t('header-logout'), 'Log out');
});
