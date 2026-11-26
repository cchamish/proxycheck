import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
// shortcut: imports transitive rolldown from vite, pin rolldown or oxc-minify if vite drops it
import { rolldown } from 'rolldown';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '..');
const DEFAULT_SOURCE_PATH = resolve(REPO_ROOT, 'scripts/user-gadget.js');
const DEFAULT_API_URL = 'https://meta.wikimedia.org/w/api.php';
const TARGET_PAGE = 'User:Hamish/proxycheck.js';
const USER_AGENT =
  'proxycheck-gadget-deploy/1.0 (https://meta.wikimedia.org/wiki/User:Hamish; https://github.com/cchamish/proxycheck)';
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_SUMMARY_LENGTH = 450;

export const PREAMBLE = [
  '// Unminify code: https://github.com/cchamish/proxycheck/blob/main/scripts/user-gadget.js',
  '/**',
  ' * Disclaimer:',
  ' * By using this script, you acknowledge that you fully understand and agree to comply with:',
  ' * - Wikimedia Foundation Access to Nonpublic Personal Data Policy (https://foundation.wikimedia.org/wiki/Policy:Wikimedia_Foundation_Access_to_Nonpublic_Personal_Data_Policy)',
  ' * - Privacy Policy (https://foundation.wikimedia.org/wiki/Special:MyLanguage/Policy:Privacy_policy)',
  ' * as well as all other applicable policies and guidelines regarding Temporary Account IP reveal.',
  ' */',
].join('\n');

export async function minifyGadget(sourcePath = DEFAULT_SOURCE_PATH) {
  const bundle = await rolldown({ input: sourcePath });
  try {
    const { output } = await bundle.generate({ format: 'es', minify: true });
    const code = output[0]?.code?.trim();
    if (!code) {
      throw new Error('Minifier returned empty output.');
    }
    return `${PREAMBLE}\n${code}\n`;
  } finally {
    await bundle.close();
  }
}

function buildEditSummary() {
  try {
    const sha = execFileSync('git', ['rev-parse', '--short', 'HEAD'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    }).trim();
    const subject = execFileSync('git', ['log', '-1', '--pretty=%s'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    }).trim();
    const raw = `Commit ${sha}: ${subject || 'Updated from repository'}`;
    return raw.length > MAX_SUMMARY_LENGTH ? `${raw.slice(0, MAX_SUMMARY_LENGTH - 3)}...` : raw;
  } catch {
    return 'Updated from repository';
  }
}

function updateCookies(jar, response) {
  const headers = typeof response.headers?.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
  for (const raw of headers) {
    const [pair, ...attrs] = raw.split(';');
    const eqIndex = pair.indexOf('=');
    if (eqIndex <= 0) continue;
    const name = pair.slice(0, eqIndex).trim();
    const value = pair.slice(eqIndex + 1).trim();
    const expired = value === 'deleted' || attrs.some((attr) => attr.trim().toLowerCase() === 'max-age=0');
    if (expired) {
      jar.delete(name);
    } else {
      jar.set(name, value);
    }
  }
}

function createApiClient(apiUrl, fetchImpl) {
  const cookies = new Map();

  return async function apiRequest(params, method = 'GET') {
    const payload = new URLSearchParams({ format: 'json', formatversion: '2', ...params });
    const headers = { 'User-Agent': USER_AGENT };
    if (cookies.size > 0) {
      headers.Cookie = [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    }

    const url = method === 'GET' ? `${apiUrl}?${payload}` : apiUrl;
    const init = {
      method,
      headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    };
    if (method === 'POST') {
      headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8';
      init.body = payload.toString();
    }

    const response = await fetchImpl(url, init);
    updateCookies(cookies, response);
    if (!response.ok) {
      throw new Error(`MediaWiki API HTTP ${response.status} (${params.action})`);
    }
    const data = await response.json();
    if (data.error) {
      throw new Error(`MediaWiki API error (${data.error.code}): ${data.error.info}`);
    }
    return data;
  };
}

export async function deployGadget({
  apiUrl = process.env.MW_API_URL || DEFAULT_API_URL,
  username = process.env.MW_USERNAME,
  password = process.env.MW_PASSWORD,
  sourcePath = DEFAULT_SOURCE_PATH,
  summary = buildEditSummary(),
  targetPage = TARGET_PAGE,
  fetchImpl = fetch,
} = {}) {
  const trimmedUrl = apiUrl.trim();
  const trimmedUser = username?.trim();
  if (!trimmedUrl.startsWith('https://')) {
    throw new Error('MW_API_URL must be an HTTPS URL.');
  }
  if (!trimmedUser || !password) {
    throw new Error('Missing MediaWiki credentials: set MW_USERNAME and MW_PASSWORD.');
  }

  const text = await minifyGadget(sourcePath);
  const api = createApiClient(trimmedUrl, fetchImpl);

  const loginTokenData = await api({ action: 'query', meta: 'tokens', type: 'login' });
  const loginToken = loginTokenData.query?.tokens?.logintoken;
  if (!loginToken) {
    throw new Error('Failed to retrieve MediaWiki login token.');
  }

  const loginData = await api(
    { action: 'login', lgname: trimmedUser, lgpassword: password, lgtoken: loginToken },
    'POST',
  );
  if (loginData.login?.result !== 'Success') {
    throw new Error(`MediaWiki login failed: ${loginData.login?.result || 'unknown'} (${loginData.login?.reason || 'no reason'})`);
  }

  const csrfTokenData = await api({ action: 'query', meta: 'tokens', type: 'csrf' });
  const csrfToken = csrfTokenData.query?.tokens?.csrftoken;
  if (!csrfToken || csrfToken === '+\\') {
    throw new Error('Failed to retrieve authenticated MediaWiki CSRF token.');
  }

  const editData = await api(
    {
      action: 'edit',
      title: targetPage,
      text,
      summary,
      token: csrfToken,
      assert: 'user',
    },
    'POST',
  );
  if (editData.edit?.result !== 'Success') {
    throw new Error(`MediaWiki edit failed: ${editData.edit?.result || 'unknown'}`);
  }

  return {
    nochange: Boolean(editData.edit.nochange),
    newrevid: editData.edit.newrevid ?? null,
    targetPage,
    bytes: Buffer.byteLength(text, 'utf8'),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const result = await deployGadget();
  if (result.nochange) {
    console.log(`No change on ${result.targetPage} (${result.bytes} bytes).`);
  } else {
    console.log(`Deployed ${result.targetPage} (rev ${result.newrevid}, ${result.bytes} bytes).`);
  }
}
