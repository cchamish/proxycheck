import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const REPO_ROOT = path.resolve(import.meta.dirname, '..', '..');
const GADGET_PATH = path.join(REPO_ROOT, 'scripts', 'user-gadget.js');
const GADGET_SOURCE = fs.readFileSync(GADGET_PATH, 'utf8');

type AnyRecord = Record<string, unknown>;

function checkConnected(node: MockNode | null, root: MockNode): boolean {
  for (let cur = node; cur; cur = cur.parentNode) if (cur === root) return true;
  return false;
}

class MockNode {
  nodeType: number;
  nodeValue: string | null = null;
  parentNode: MockElement | null = null;
  childNodes: MockNode[] = [];
  ownerDoc: MockDocument;

  constructor(nodeType: number, ownerDoc: MockDocument) {
    this.nodeType = nodeType;
    this.ownerDoc = ownerDoc;
  }

  get nextSibling(): MockNode | null {
    if (!this.parentNode) return null;
    const idx = this.parentNode.childNodes.indexOf(this);
    return idx >= 0 && idx + 1 < this.parentNode.childNodes.length ? this.parentNode.childNodes[idx + 1] : null;
  }

  get nextElementSibling(): MockElement | null {
    for (let cur = this.nextSibling; cur; cur = cur.nextSibling) if (cur instanceof MockElement) return cur;
    return null;
  }

  get isConnected(): boolean {
    return checkConnected(this, this.ownerDoc.documentElement);
  }

  get textContent(): string {
    return this.nodeValue ?? '';
  }

  set textContent(val: string) {
    this.nodeValue = String(val);
  }
}

class MockTextNode extends MockNode {
  constructor(text: string, ownerDoc: MockDocument) {
    super(3, ownerDoc);
    this.nodeValue = String(text);
  }
}

function matchesCompound(el: MockElement, compound: string): boolean {
  let rem = compound.trim();
  if (!rem) return false;
  const tagMatch = rem.match(/^[a-zA-Z][a-zA-Z0-9-]*/);
  if (tagMatch) {
    if (el.tagName !== tagMatch[0].toUpperCase()) return false;
    rem = rem.slice(tagMatch[0].length);
  }
  for (const idTok of rem.match(/#[a-zA-Z0-9_-]+/g) ?? []) if (el.id !== idTok.slice(1)) return false;
  rem = rem.replace(/#[a-zA-Z0-9_-]+/g, '');
  for (const clsTok of rem.match(/\.[a-zA-Z0-9_-]+/g) ?? []) if (!el.classList.contains(clsTok.slice(1))) return false;
  return rem.replace(/\.[a-zA-Z0-9_-]+/g, '').trim() === '';
}

function matchesSelector(el: MockElement, selector: string): boolean {
  return selector
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .some((branch) => {
      const parts = branch.split(/\s+/).filter(Boolean);
      if (parts.length === 0 || !matchesCompound(el, parts[parts.length - 1])) return false;
      let cur = el.parentNode;
      for (let i = parts.length - 2; i >= 0; i -= 1) {
        while (cur && !matchesCompound(cur, parts[i])) cur = cur.parentNode;
        if (!cur) return false;
        cur = cur.parentNode;
      }
      return true;
    });
}

class MockElement extends MockNode {
  tagName: string;
  style: Record<string, string> = {};
  dataset: Record<string, string | undefined> = {};
  checked = false;
  disabled = false;
  href = '';
  title = '';
  target = '';
  rel = '';
  type = '';
  role = '';
  private attrs = new Map<string, string>();
  private listeners = new Map<string, Array<(ev: AnyRecord) => void>>();

  readonly classList = {
    add: (...names: string[]): void => {
      const cur = this.className ? this.className.split(/\s+/).filter(Boolean) : [];
      for (const n of names) if (n && !cur.includes(n)) cur.push(n);
      this.className = cur.join(' ');
    },
    remove: (...names: string[]): void => {
      const cur = this.className ? this.className.split(/\s+/).filter(Boolean) : [];
      this.className = cur.filter((c) => !names.includes(c)).join(' ');
    },
    contains: (name: string): boolean =>
      (this.className ? this.className.split(/\s+/).filter(Boolean) : []).includes(name),
  };

  constructor(tagName: string, ownerDoc: MockDocument) {
    super(1, ownerDoc);
    this.tagName = tagName.toUpperCase();
  }

  get id(): string {
    return this.attrs.get('id') ?? '';
  }
  set id(val: string) {
    if (val) this.attrs.set('id', String(val));
    else this.attrs.delete('id');
  }

  get className(): string {
    return this.attrs.get('class') ?? '';
  }
  set className(val: string) {
    const str = String(val ?? '').trim();
    if (str) this.attrs.set('class', str);
    else this.attrs.delete('class');
  }

  override get textContent(): string {
    return this.childNodes.map((c) => c.textContent).join('');
  }
  override set textContent(val: string) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    const str = String(val ?? '');
    if (str !== '') {
      const tn = new MockTextNode(str, this.ownerDoc);
      tn.parentNode = this;
      this.childNodes.push(tn);
    }
  }

  setAttribute(name: string, val: string): void {
    const str = String(val);
    this.attrs.set(name, str);
    if (name === 'href') this.href = str;
    else if (name === 'title') this.title = str;
    else if (name === 'target') this.target = str;
    else if (name === 'rel') this.rel = str;
    else if (name === 'type') this.type = str;
    else if (name === 'role') this.role = str;
    else if (name.startsWith('data-')) {
      this.dataset[name.slice(5).replace(/-([a-z])/g, (_m, ch: string) => ch.toUpperCase())] = str;
    }
  }

  getAttribute(name: string): string | null {
    if (name === 'href' && this.href) return this.href;
    if (name === 'title' && this.title) return this.title;
    return this.attrs.get(name) ?? null;
  }

  appendChild<T extends MockNode>(child: T): T {
    return this.insertBefore(child, null);
  }

  insertBefore<T extends MockNode>(newChild: T, refChild: MockNode | null): T {
    if (newChild.parentNode) newChild.parentNode.removeChild(newChild);
    newChild.parentNode = this;
    const idx = refChild === null ? -1 : this.childNodes.indexOf(refChild);
    if (idx === -1) this.childNodes.push(newChild);
    else this.childNodes.splice(idx, 0, newChild);
    return newChild;
  }

  removeChild<T extends MockNode>(child: T): T {
    const idx = this.childNodes.indexOf(child);
    if (idx !== -1) {
      this.childNodes.splice(idx, 1);
      child.parentNode = null;
    }
    return child;
  }

  contains(other: MockNode | null): boolean {
    return checkConnected(other, this);
  }
  matches(selector: string): boolean {
    return matchesSelector(this, selector);
  }
  closest(selector: string): MockElement | null {
    if (this.matches(selector)) return this;
    return this.parentNode ? this.parentNode.closest(selector) : null;
  }

  querySelectorAll(selector: string): MockElement[] {
    const found: MockElement[] = [];
    const visit = (node: MockElement): void => {
      for (const child of node.childNodes) {
        if (child instanceof MockElement) {
          if (child.matches(selector)) found.push(child);
          visit(child);
        }
      }
    };
    visit(this);
    return found;
  }

  querySelector(selector: string): MockElement | null {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  addEventListener(type: string, fn: (ev: AnyRecord) => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(fn);
    this.listeners.set(type, list);
  }

  private dispatchBubble(ev: AnyRecord, isStopped: () => boolean): void {
    for (const fn of (this.listeners.get('click') ?? []).slice()) fn.call(this, ev);
    if (!isStopped() && this.parentNode) this.parentNode.dispatchBubble(ev, isStopped);
  }

  click(): void {
    let stopped = false;
    const ev: AnyRecord = {
      type: 'click',
      target: this,
      preventDefault() {},
      stopPropagation() {
        stopped = true;
      },
    };
    if (this.tagName === 'INPUT' && this.type === 'checkbox') this.checked = !this.checked;
    this.dispatchBubble(ev, () => stopped);
  }
}

class MockDocument {
  documentElement: MockElement;
  head: MockElement;
  body: MockElement;
  visibilityState = 'visible';

  constructor() {
    this.documentElement = new MockElement('html', this);
    this.head = new MockElement('head', this);
    this.body = new MockElement('body', this);
    this.documentElement.childNodes.push(this.head, this.body);
    this.head.parentNode = this.documentElement;
    this.body.parentNode = this.documentElement;
  }

  createElement(tag: string): MockElement {
    return new MockElement(tag, this);
  }
  createTextNode(text: string): MockTextNode {
    return new MockTextNode(text, this);
  }
  getElementById(id: string): MockElement | null {
    return this.documentElement.querySelector(`#${id}`);
  }
  querySelectorAll(selector: string): MockElement[] {
    return this.documentElement.querySelectorAll(selector);
  }
  querySelector(selector: string): MockElement | null {
    return this.documentElement.querySelector(selector);
  }
}

function createMinimalJQuery(doc: MockDocument, readyCallbacks: Array<() => void>) {
  function toNodes(item: unknown): MockNode[] {
    if (item === null || item === undefined) return [];
    if (item instanceof MockNode) return [item];
    if (typeof item === 'string') return [doc.createTextNode(item)];
    if (typeof item === 'object' && 'length' in (item as AnyRecord)) {
      const col = item as Record<number, MockElement> & { length: number };
      const out: MockNode[] = [];
      for (let i = 0; i < col.length; i++) if (col[i]) out.push(col[i]);
      return out;
    }
    return [];
  }

  function wrap(elements: MockElement[]) {
    const col: Record<number, MockElement> = {};
    elements.forEach((el, idx) => {
      col[idx] = el;
    });
    const api: AnyRecord = Object.assign(col, {
      length: elements.length,
      append(...items: unknown[]) {
        const firstEl = elements[0];
        if (firstEl) for (const item of items) for (const node of toNodes(item)) firstEl.appendChild(node);
        return api;
      },
      appendTo(target: MockElement | AnyRecord) {
        const dest = target instanceof MockElement ? target : (target[0] as MockElement | undefined);
        if (dest) for (const el of elements) dest.appendChild(el);
        return api;
      },
      empty() {
        for (const el of elements) {
          for (const child of el.childNodes) child.parentNode = null;
          el.childNodes = [];
        }
        return api;
      },
      remove() {
        for (const el of elements) if (el.parentNode) el.parentNode.removeChild(el);
        return api;
      },
      text(val?: string) {
        if (val === undefined) return elements.map((el) => el.textContent).join('');
        for (const el of elements) el.textContent = String(val);
        return api;
      },
      attr(name: string, val?: string) {
        if (val === undefined) return elements[0]?.getAttribute(name) ?? undefined;
        for (const el of elements) el.setAttribute(name, String(val));
        return api;
      },
      prop(name: string, val?: unknown) {
        if (val === undefined) return elements[0] ? (elements[0] as unknown as AnyRecord)[name] : undefined;
        for (const el of elements) (el as unknown as AnyRecord)[name] = val;
        return api;
      },
      css(name: string, val: string) {
        for (const el of elements) el.style[name] = val;
        return api;
      },
      addClass(cls: string) {
        for (const el of elements) el.classList.add(...cls.split(/\s+/).filter(Boolean));
        return api;
      },
      removeClass(cls: string) {
        for (const el of elements) el.classList.remove(...cls.split(/\s+/).filter(Boolean));
        return api;
      },
      find(selector: string) {
        const matched: MockElement[] = [];
        for (const el of elements) {
          for (const item of el.querySelectorAll(selector)) if (!matched.includes(item)) matched.push(item);
        }
        return wrap(matched);
      },
      first: () => wrap(elements[0] ? [elements[0]] : []),
      closest: (sel: string) => wrap(elements.map((el) => el.closest(sel)).filter((c): c is MockElement => c instanceof MockElement)),
      on(eventName: string, handler: (ev: AnyRecord) => void) {
        for (const el of elements) el.addEventListener(eventName, handler);
        return api;
      },
    });
    return api;
  }

  return function $(arg: unknown, attrs?: AnyRecord) {
    if (typeof arg === 'function') {
      readyCallbacks.push(arg as () => void);
      return undefined;
    }
    if (arg instanceof MockElement) return wrap([arg]);
    if (typeof arg === 'string') {
      const tagMatch = arg.trim().match(/^<([a-zA-Z0-9-]+)\s*\/?>$/);
      if (tagMatch) {
        const el = doc.createElement(tagMatch[1]);
        if (attrs && typeof attrs === 'object') {
          for (const [k, v] of Object.entries(attrs)) {
            if (v === undefined || v === null) continue;
            if (k === 'text') el.textContent = String(v);
            else if (k === 'class') el.className = String(v);
            else if (k === 'checked' || k === 'disabled') (el as unknown as AnyRecord)[k] = Boolean(v);
            else el.setAttribute(k, String(v));
          }
        }
        return wrap([el]);
      }
      return wrap(doc.querySelectorAll(arg.trim()));
    }
    return wrap([]);
  };
}

function makeProviderRow(provider: string, overrides: AnyRecord = {}): AnyRecord {
  return {
    provider,
    status: '200 OK',
    statusCode: 200,
    asn: '-',
    isp: '-',
    organisation: '-',
    location: '-',
    usageType: '-',
    securityFlags: [{ label: 'No Flags', isHighRisk: false }],
    ...overrides,
  };
}

function makeLightPayload(ip: string, overrides: AnyRecord = {}): AnyRecord {
  const asn = (overrides.primaryAsn as string | undefined) ?? 'AS17421';
  const isp = (overrides.isp as string | undefined) ?? 'Mobile Business Group';
  return {
    ip,
    fetchedAt: '2026-11-18T10:00:00+00:00',
    queryMode: 'light',
    isPartialMode: true,
    isCached: false,
    is_broadcast_ip: false,
    isTor: false,
    torIsExit: false,
    torRunning: false,
    torFlags: [],
    torLabel: null,
    torSummary: null,
    prediction_score: 0,
    predictionLabel: 'GetIPIntel Unavailable',
    predictionTier: 'neutral',
    getipintel_chance: null,
    arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
    arbitrationTier: 'neutral',
    isMajorityProxyVpn: false,
    suspectedResidentialProxy: false,
    highlySuspectedResidentialProxy: false,
    primaryCountry: 'Taiwan',
    primaryCoordinates: 'Unknown',
    primaryAsn: asn,
    ptrHostname: null,
    ptrCategory: 'none',
    ptrLabel: 'No PTR Record',
    ptrIsHighRisk: false,
    recommendedCidr: ip.includes(':') ? `${ip}/64` : `${ip}/32`,
    defaultCidr: ip.includes(':') ? `${ip}/64` : `${ip}/32`,
    mmdbCidr: null,
    bgpPrefix: null,
    cloudCidr: null,
    cloudProvider: null,
    isMobileOrCgnat: false,
    sharedPrivacyEgress: null,
    results: [
      makeProviderRow('MaxMind', { asn, isp, organisation: isp, location: 'Taiwan', usageType: 'unknown' }),
      makeProviderRow('GetIPIntel', {
        status: 'Deferred (Light Mode)',
        statusCode: null,
        isDeferred: true,
        securityFlags: [{ label: 'Deferred (Light Mode)', isHighRisk: false }],
      }),
      makeProviderRow('Spamhaus ZEN', { isListed: false, isPolicyRange: false, listedCodes: [] }),
      makeProviderRow('SpamCop', { isListed: false, listedCodes: [] }),
      makeProviderRow('StopForumSpam', { appears: false, blacklisted: false, frequency: 0 }),
      makeProviderRow('DShield', { attacks: 0, count: 0, threatfeeds: [] }),
      makeProviderRow('IPsum / DROP', { isListed: false, ipsumScore: 0, isIpsumListed: false, inSpamhausDrop: false }),
      makeProviderRow('X4BNet VPN', { isListed: false, isVpn: false, isHosting: false, isDatacenter: false }),
    ],
    ...overrides,
  };
}

function makeFullPayload(ip: string, overrides: AnyRecord = {}): AnyRecord {
  return makeLightPayload(ip, {
    queryMode: 'full',
    isPartialMode: false,
    prediction_score: 0,
    getipintel_chance: 0,
    predictionLabel: 'Normal',
    predictionTier: 'success',
    arbitrationVerdict: 'Clean Residential / Direct (0/5 Sources)',
    arbitrationTier: 'success',
    results: [
      makeProviderRow('MaxMind', { asn: 'AS3462', isp: 'Data Communication Business Group', usageType: 'unknown' }),
      makeProviderRow('GetIPIntel', { chance: 0, usageType: 'ML Prediction' }),
      makeProviderRow('AbuseIPDB', { usageType: 'Fixed Line ISP' }),
      makeProviderRow('Spamhaus ZEN', { isListed: false, isPolicyRange: false, listedCodes: [] }),
      makeProviderRow('SpamCop', { isListed: false, listedCodes: [] }),
      makeProviderRow('StopForumSpam', { appears: false, blacklisted: false, frequency: 0 }),
      makeProviderRow('DShield', { attacks: 0, count: 0, threatfeeds: [] }),
      makeProviderRow('IPsum / DROP', { isListed: false, ipsumScore: 0, isIpsumListed: false, inSpamhausDrop: false }),
      makeProviderRow('X4BNet VPN', { isListed: false, isVpn: false, isHosting: false, isDatacenter: false }),
    ],
    ...overrides,
  });
}

async function runGadgetWithPayloads(
  ips: string[],
  responder: (url: string, ip: string, bodyJson: AnyRecord | null) => AnyRecord | Promise<AnyRecord>
) {
  const doc = new MockDocument();
  const content = doc.createElement('div');
  content.id = 'mw-content-text';
  for (const ip of ips) {
    const anchor = doc.createElement('a');
    anchor.className = 'ext-checkuser-tempaccount-reveal-ip-anchor';
    anchor.textContent = ip;
    content.appendChild(anchor);
  }
  doc.body.appendChild(content);

  const mwStorage = new Map<string, string>([
    ['proxycheck-ip-policy-consent', '1'],
    ['proxycheck-gadget-token', 'signed-test-token'],
    ['proxycheck-gadget-token-user', 'AdminPatroller'],
    ['proxycheck-gadget-token-exp', String(1_763_420_000_000 + 3_600_000)],
  ]);
  const localStorage = new Map<string, string>();
  const readyCallbacks: Array<() => void> = [];
  const activeTimers = new Map<number, { fn: () => void; delay: number; isInterval: boolean }>();
  let nextTimerId = 1;
  const openDialogs: Array<{ host: MockElement; close: () => void }> = [];

  const makeWebStorage = (map: Map<string, string>) => ({
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => map.set(k, String(v)),
    removeItem: (k: string) => map.delete(k),
  });

  const mediaWiki = {
    config: {
      get: (k: string) =>
        ({
          wgUserName: 'AdminPatroller',
          wgUserIsTemp: false,
          wgServerName: 'zh.wikipedia.org',
          wgArticlePath: '/wiki/$1',
          wgCanonicalSpecialPageName: 'Recentchanges',
        }[k] ?? null),
    },
    storage: {
      get: (k: string) => (mwStorage.has(k) ? mwStorage.get(k)! : null),
      set: (k: string, v: string) => {
        mwStorage.set(k, String(v));
        return true;
      },
      remove: (k: string) => mwStorage.delete(k),
    },
    loader: { using: () => Promise.resolve() },
    util: { getUrl: (title: string) => `/wiki/${title}`, getParamValue: () => null, addCSS: () => {} },
    hook: () => ({ add: () => {}, fire: () => {} }),
  };

  const OO = {
    ui: {
      confirm: () => Promise.resolve(true),
      alert: ($message: AnyRecord) =>
        new Promise<void>((resolve) => {
          const host = doc.createElement('div');
          host.className = 'mock-ooui-dialog';
          if ($message && $message[0]) host.appendChild($message[0] as MockNode);
          doc.body.appendChild(host);
          openDialogs.push({
            host,
            close: () => {
              if (host.parentNode) host.parentNode.removeChild(host);
              resolve();
            },
          });
        }),
    },
  };

  class MockMutationObserver {
    observe() {}
    disconnect() {}
  }

  const fetchMock = (url: string, init: AnyRecord = {}) => {
    const bodyText = typeof init.body === 'string' ? init.body : '';
    const bodyJson = bodyText ? (JSON.parse(bodyText) as AnyRecord) : null;
    if (String(url).includes('/api/v1/detect/batch')) {
      const reqIps = (bodyJson?.ips as string[] | undefined) ?? [];
      return Promise.all(
        reqIps.map(async (ip) => [ip, await responder(String(url), ip, bodyJson)] as const)
      ).then((entries) => {
        const results = Object.fromEntries(entries);
        const serialized = JSON.stringify({ results, inputMap: {}, queryMode: 'light' });
        return {
          status: 200,
          ok: true,
          json: () => Promise.resolve(JSON.parse(serialized)),
          text: () => Promise.resolve(serialized),
        };
      });
    }
    const targetIp = new URL(String(url)).searchParams.get('ip') ?? ips[0];
    return Promise.resolve(responder(String(url), targetIp, bodyJson)).then((payload) => {
      const serialized = JSON.stringify(payload);
      return {
        status: 200,
        ok: true,
        json: () => Promise.resolve(JSON.parse(serialized)),
        text: () => Promise.resolve(serialized),
      };
    });
  };

  const windowObj = {
    location: { search: '' },
    localStorage: makeWebStorage(localStorage),
    sessionStorage: makeWebStorage(new Map()),
    setTimeout: (fn: () => void, delay = 0) => {
      const id = nextTimerId++;
      activeTimers.set(id, { fn, delay, isInterval: false });
      return id;
    },
    clearTimeout: (id: number) => activeTimers.delete(id),
    setInterval: (fn: () => void, delay = 0) => {
      const id = nextTimerId++;
      activeTimers.set(id, { fn, delay, isInterval: true });
      return id;
    },
    clearInterval: (id: number) => activeTimers.delete(id),
  };

  const sandbox = vm.createContext({
    window: windowObj,
    document: doc,
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    MutationObserver: MockMutationObserver,
    mediaWiki,
    jQuery: createMinimalJQuery(doc, readyCallbacks),
    OO,
    fetch: fetchMock,
    Date: class extends Date {
      static override now() {
        return 1_763_420_000_000;
      }
    },
    console,
    Promise,
    Map,
    Set,
    WeakSet,
    URL,
    encodeURIComponent,
    decodeURIComponent,
    parseInt,
    isNaN,
    isFinite,
    Number,
    String,
    Boolean,
    Array,
    Object,
    Math,
    JSON,
  });

  vm.runInContext(GADGET_SOURCE, sandbox, { filename: 'scripts/user-gadget.js' });
  for (const cb of readyCallbacks) cb();

  const flush = async () => {
    for (let i = 0; i < 8; i += 1) await new Promise<void>((resolve) => setImmediate(resolve));
  };
  await flush();
  for (let pass = 0; pass < 4; pass += 1) {
    const due = [...activeTimers.entries()].filter(([, entry]) => !entry.isInterval && entry.delay <= 100);
    if (due.length === 0) break;
    for (const [id, entry] of due) {
      activeTimers.delete(id);
      entry.fn();
    }
    await flush();
  }

  return {
    anchors: doc.querySelectorAll('.ext-checkuser-tempaccount-reveal-ip-anchor'),
    badges: doc.querySelectorAll('.proxycheck-ip-badge'),
    openDialogs,
    flush,
  };
}

test('Light mode highlights Spamhaus PBL, DShield, SpamCop, IPsum moderate, X4BNet Hosting, MaxMind Hosting, and Shodan flags yellow while preserving high-risk red and clean grey tiers', async () => {
  interface LightCase {
    ip: string;
    payload: AnyRecord;
    expectedTier: 'low' | 'medium' | 'high';
    expectedBadgeIncludes: string[];
    expectedBadgeExcludes?: string[];
  }

  const cases: LightCase[] = [
    {
      ip: '219.78.86.150',
      payload: makeLightPayload('219.78.86.150', {
        primaryAsn: 'AS4760',
        isMobileOrCgnat: true,
        results: [
          makeProviderRow('MaxMind', { asn: 'AS4760', isp: 'HKT Limited', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('Spamhaus ZEN', { isListed: false, isPolicyRange: false, listedCodes: [] }),
          makeProviderRow('DShield', { attacks: 0, count: 0, threatfeeds: [] }),
        ],
      }),
      expectedTier: 'low',
      expectedBadgeIncludes: ['[AS4760|HKT Limited]'],
    },
    {
      ip: '116.59.49.61',
      payload: makeLightPayload('116.59.49.61', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS17421', isp: 'Mobile Business Group', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('Spamhaus ZEN', {
            isListed: true,
            isPolicyRange: true,
            listedCodes: ['127.0.0.10'],
            securityFlags: [{ label: 'Policy/Dynamic ISP Range (PBL)', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['[AS17421|Mobile Business Group|Spamhaus:Listed]'],
      expectedBadgeExcludes: ['SPAMHAUS,'],
    },
    {
      ip: '2001:b400:e2a8:43d9:ecc4:7bb9:b0ce:ae00',
      payload: makeLightPayload('2001:b400:e2a8:43d9:ecc4:7bb9:b0ce:ae00', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS17421', isp: 'Mobile Business Group', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('DShield', {
            attacks: 3,
            count: 1,
            threatfeeds: [],
            securityFlags: [{ label: 'Attack Activity (3 attacks)', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['[AS17421|Mobile Business Group|DShield:Attack Activity (3 attacks)]'],
      expectedBadgeExcludes: ['DSHIELD,'],
    },
    {
      ip: '2402:7500:903:38e7:c0dd:a014:733d:e648',
      payload: makeLightPayload('2402:7500:903:38e7:c0dd:a014:733d:e648', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS24158', isp: 'Taiwan Mobile Co., Ltd.', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('DShield', {
            attacks: 0,
            count: 0,
            threatfeeds: ['blocklist_de'],
            securityFlags: [{ label: 'Feeds: blocklist_de', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['DShield:Feeds: blocklist_de'],
    },
    {
      ip: '198.51.100.14',
      payload: makeLightPayload('198.51.100.14', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('SpamCop', {
            isListed: true,
            listedCodes: ['127.0.0.2'],
            securityFlags: [{ label: 'SpamCop Listed (127.0.0.2)', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['SpamCop:SpamCop Listed (127.0.0.2)'],
    },
    {
      ip: '198.51.100.15',
      payload: makeLightPayload('198.51.100.15', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('IPsum / DROP', {
            isListed: true,
            isIpsumListed: true,
            inSpamhausDrop: false,
            ipsumScore: 2,
            securityFlags: [{ label: 'IPsum Moderate (2 lists)', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['IPsum:2 lists'],
    },
    {
      ip: '198.51.100.16',
      payload: makeLightPayload('198.51.100.16', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('X4BNet VPN', {
            isListed: true,
            isVpn: false,
            isHosting: true,
            isDatacenter: true,
            securityFlags: [{ label: 'Hosting / Datacentre', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['X4BNet:Hosting'],
    },
    {
      ip: '198.51.100.17',
      payload: makeLightPayload('198.51.100.17', {
        results: [
          makeProviderRow('MaxMind', {
            asn: 'AS24940',
            isp: 'Hetzner Online GmbH',
            usageType: 'hosting',
            hostingProvider: 'Hetzner',
            securityFlags: [{ label: 'Hosting', isHighRisk: true }],
          }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['[AS24940|Hetzner Online GmbH|MaxMind:Hosting]'],
    },
    {
      ip: '198.51.100.18',
      payload: makeLightPayload('198.51.100.18', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('Shodan InternetDB', {
            tags: ['malware'],
            openProxyPorts: [],
            securityFlags: [{ label: 'Shodan Tag: malware', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['Shodan InternetDB:Shodan Tag: malware'],
    },
    {
      ip: '198.51.100.22',
      payload: makeLightPayload('198.51.100.22', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('DShield', { attacks: 0, count: 2, threatfeeds: [], securityFlags: [] }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['DShield:Threat Feed'],
    },
    {
      ip: '198.51.100.23',
      payload: makeLightPayload('198.51.100.23', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('AbuseIPDB', {
            usageType: 'Data Center/Web Hosting/Transit',
            securityFlags: [{ label: 'Datacenter / Hosting', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedBadgeIncludes: ['AbuseIPDB:Datacenter / Hosting'],
    },
    {
      ip: '198.51.100.19',
      payload: makeLightPayload('198.51.100.19', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('Spamhaus ZEN', {
            status: '429 Query Blocked',
            statusCode: 429,
            isListed: false,
            isQueryRestricted: true,
            securityFlags: [{ label: 'Query Restricted (Unapplied)', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'low',
      expectedBadgeIncludes: ['[AS64512|Example ISP]'],
    },
    {
      ip: '198.51.100.20',
      payload: makeLightPayload('198.51.100.20', {
        arbitrationVerdict: 'Confirmed Proxy / VPN (1/1 Sources)',
        arbitrationTier: 'destructive',
        isMajorityProxyVpn: true,
        results: [
          makeProviderRow('MaxMind', { asn: 'AS64512', isp: 'Example ISP', usageType: 'unknown' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('Spamhaus ZEN', {
            isListed: true,
            isPolicyRange: false,
            listedCodes: ['127.0.0.2'],
            securityFlags: [{ label: 'Spamhaus SBL (127.0.0.2)', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'high',
      expectedBadgeIncludes: ['Spamhaus:Listed', 'Spamhaus ZEN:Spamhaus SBL (127.0.0.2)'],
    },
    {
      ip: '198.51.100.21',
      payload: makeLightPayload('198.51.100.21', {
        isTor: true,
        torLabel: 'Tor Exit',
        arbitrationVerdict: 'Confirmed Tor Exit (Tor Onionoo)',
        arbitrationTier: 'destructive',
      }),
      expectedTier: 'high',
      expectedBadgeIncludes: ['Tor Exit', 'TOR EXIT'],
    },
  ];

  const payloadMap = new Map(cases.map((c) => [c.ip, c.payload]));
  const { anchors, badges } = await runGadgetWithPayloads(
    cases.map((c) => c.ip),
    (_url, ip) => payloadMap.get(ip)!
  );

  assert.equal(badges.length, cases.length);
  for (let i = 0; i < cases.length; i += 1) {
    const tc = cases[i];
    const anchor = anchors[i];
    const badge = badges[i];
    assert.ok(badge.classList.contains(`proxycheck-tier-${tc.expectedTier}`), `${tc.ip} badge tier`);

    if (tc.expectedTier === 'medium') {
      assert.equal(anchor.classList.contains('proxycheck-anchor-risk-medium'), true, `${tc.ip} anchor yellow class`);
      assert.equal(anchor.style.backgroundColor, '#fff3cd', `${tc.ip} anchor yellow bg`);
      assert.equal(badge.classList.contains('proxycheck-badge-lite'), false, `${tc.ip} not lite badge`);
      assert.equal(badge.title.includes('Light screening passed'), false, `${tc.ip} tooltip updated`);
    } else if (tc.expectedTier === 'high') {
      assert.equal(anchor.classList.contains('proxycheck-anchor-risk-high'), true, `${tc.ip} anchor red class`);
      assert.equal(anchor.style.backgroundColor, '#ffcccc', `${tc.ip} anchor red bg`);
    } else {
      assert.equal(anchor.classList.contains('proxycheck-anchor-risk-medium'), false, `${tc.ip} no yellow class`);
      assert.equal(anchor.classList.contains('proxycheck-anchor-risk-high'), false, `${tc.ip} no red class`);
      assert.equal(badge.classList.contains('proxycheck-badge-lite'), true, `${tc.ip} keeps lite class`);
    }

    for (const part of tc.expectedBadgeIncludes) {
      assert.ok(badge.textContent.includes(part), `${tc.ip} badge "${badge.textContent}" should include "${part}"`);
    }
    for (const part of tc.expectedBadgeExcludes ?? []) {
      assert.equal(badge.textContent.includes(part), false, `${tc.ip} badge "${badge.textContent}" should omit "${part}"`);
    }
  }
});

test('Full mode keeps Spamhaus PBL and minor commercial disputes unhighlighted while marking DShield, SpamCop, IPsum moderate, X4BNet Hosting, and MaxMind Hosting yellow', async () => {
  const cases: Array<{ ip: string; payload: AnyRecord; expectedTier: 'low' | 'medium'; expectedText: string }> = [
    {
      ip: '118.169.6.34',
      payload: makeFullPayload('118.169.6.34', {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS3462', isp: 'Data Communication Business Group' }),
          makeProviderRow('GetIPIntel', { chance: 0 }),
          makeProviderRow('AbuseIPDB', { usageType: 'Fixed Line ISP' }),
          makeProviderRow('Spamhaus ZEN', {
            isListed: true,
            isPolicyRange: true,
            listedCodes: ['127.0.0.10'],
            securityFlags: [{ label: 'Policy/Dynamic ISP Range (PBL)', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'low',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.30',
      payload: makeFullPayload('198.51.100.30', {
        arbitrationVerdict: 'Clean Residential (1 Minor Attribute Dispute)',
        arbitrationTier: 'success',
        results: [
          makeProviderRow('MaxMind', { asn: 'AS7922', isp: 'Comcast' }),
          makeProviderRow('GetIPIntel', { chance: 0 }),
          makeProviderRow('IPData', { usageType: 'hosting', securityFlags: [{ label: 'Hosting', isHighRisk: true }] }),
          makeProviderRow('AbuseIPDB', { usageType: 'Fixed Line ISP' }),
        ],
      }),
      expectedTier: 'low',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.31',
      payload: makeFullPayload('198.51.100.31', {
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { chance: 0 }),
          makeProviderRow('DShield', {
            attacks: 4,
            count: 2,
            securityFlags: [{ label: 'Attack Activity (4 attacks)', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.32',
      payload: makeFullPayload('198.51.100.32', {
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { chance: 0 }),
          makeProviderRow('SpamCop', {
            isListed: true,
            listedCodes: ['127.0.0.2'],
            securityFlags: [{ label: 'SpamCop Listed (127.0.0.2)', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.33',
      payload: makeFullPayload('198.51.100.33', {
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { chance: 0 }),
          makeProviderRow('X4BNet VPN', {
            isListed: true,
            isVpn: false,
            isHosting: true,
            securityFlags: [{ label: 'Hosting / Datacentre', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.34',
      payload: makeFullPayload('198.51.100.34', {
        results: [
          makeProviderRow('MaxMind', {
            asn: 'AS24940',
            isp: 'Hetzner Online GmbH',
            usageType: 'hosting',
            hostingProvider: 'Hetzner',
            securityFlags: [{ label: 'Hosting', isHighRisk: true }],
          }),
          makeProviderRow('GetIPIntel', { chance: 0 }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.35',
      payload: makeFullPayload('198.51.100.35', {
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { chance: 0 }),
          makeProviderRow('IPsum / DROP', {
            isListed: true,
            isIpsumListed: true,
            inSpamhausDrop: false,
            ipsumScore: 2,
            securityFlags: [{ label: 'IPsum Moderate (2 lists)', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.36',
      payload: makeFullPayload('198.51.100.36', {
        getipintel_chance: null,
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { status: '502 Error', statusCode: 502 }),
          makeProviderRow('AbuseIPDB', { usageType: 'Fixed Line ISP' }),
          makeProviderRow('Spamhaus ZEN', { isListed: true, isPolicyRange: true, listedCodes: ['127.0.0.10'] }),
        ],
      }),
      expectedTier: 'low',
      expectedText: '[OK 0/1]',
    },
    {
      ip: '198.51.100.37',
      payload: makeFullPayload('198.51.100.37', {
        getipintel_chance: null,
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { status: '502 Error', statusCode: 502 }),
          makeProviderRow('DShield', {
            attacks: 2,
            count: 1,
            securityFlags: [{ label: 'Attack Activity (2 attacks)', isHighRisk: true }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[DSHIELD]',
    },
    {
      ip: '198.51.100.38',
      payload: makeFullPayload('198.51.100.38', {
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { chance: 0 }),
          makeProviderRow('Shodan InternetDB', {
            ports: [179],
            openProxyPorts: [],
            usageType: 'Indexed Ports (1)',
            securityFlags: [{ label: 'Open Ports', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[0%]',
    },
    {
      ip: '198.51.100.39',
      payload: makeFullPayload('198.51.100.39', {
        getipintel_chance: null,
        results: [
          makeProviderRow('MaxMind'),
          makeProviderRow('GetIPIntel', { status: '502 Error', statusCode: 502 }),
          makeProviderRow('Shodan InternetDB', {
            ports: [179],
            openProxyPorts: [],
            usageType: 'Indexed Ports (1)',
            securityFlags: [{ label: 'Open Ports', isHighRisk: false }],
          }),
        ],
      }),
      expectedTier: 'medium',
      expectedText: '[OPEN-PORTS]',
    },
  ];

  const payloadMap = new Map(cases.map((c) => [c.ip, c.payload]));
  const { anchors, badges } = await runGadgetWithPayloads(
    cases.map((c) => c.ip),
    (_url, ip) => payloadMap.get(ip)!
  );

  for (let i = 0; i < cases.length; i += 1) {
    const tc = cases[i];
    assert.ok(badges[i].classList.contains(`proxycheck-tier-${tc.expectedTier}`), `${tc.ip} tier`);
    assert.equal(badges[i].textContent, tc.expectedText, `${tc.ip} badge text`);
    assert.equal(anchors[i].classList.contains('proxycheck-anchor-risk-medium'), tc.expectedTier === 'medium');
  }
});

test('Upgrading a light Spamhaus PBL yellow badge to a clean full result clears the yellow anchor highlight and updates dialog risk details', async () => {
  const ip = '116.59.49.61';
  let resolveFullUpgrade: ((payload: AnyRecord) => void) | null = null;

  const { anchors, badges, openDialogs, flush } = await runGadgetWithPayloads([ip], (url) => {
    if (url.includes('/api/v1/detect/batch')) {
      return makeLightPayload(ip, {
        results: [
          makeProviderRow('MaxMind', { asn: 'AS17421', isp: 'Mobile Business Group' }),
          makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
          makeProviderRow('Spamhaus ZEN', {
            isListed: true,
            isPolicyRange: true,
            listedCodes: ['127.0.0.10'],
            securityFlags: [{ label: 'Policy/Dynamic ISP Range (PBL)', isHighRisk: false }],
          }),
        ],
      });
    }
    return new Promise<AnyRecord>((resolve) => {
      resolveFullUpgrade = resolve;
    });
  });

  assert.equal(badges[0].textContent, '[AS17421|Mobile Business Group|Spamhaus:Listed]');
  assert.equal(badges[0].classList.contains('proxycheck-tier-medium'), true);
  assert.equal(anchors[0].style.backgroundColor, '#fff3cd');

  badges[0].click();
  await flush();

  assert.equal(openDialogs.length, 1);
  assert.ok(openDialogs[0].host.textContent.includes('Policy/Dynamic ISP Range (PBL)'));
  assert.equal(openDialogs[0].host.textContent.includes('No high-risk signals detected'), false);

  resolveFullUpgrade!(
    makeFullPayload(ip, {
      results: [
        makeProviderRow('MaxMind', { asn: 'AS17421', isp: 'Mobile Business Group' }),
        makeProviderRow('GetIPIntel', { chance: 0 }),
        makeProviderRow('AbuseIPDB', { usageType: 'Mobile ISP' }),
        makeProviderRow('Spamhaus ZEN', {
          isListed: true,
          isPolicyRange: true,
          listedCodes: ['127.0.0.10'],
          securityFlags: [{ label: 'Policy/Dynamic ISP Range (PBL)', isHighRisk: false }],
        }),
      ],
    })
  );
  await flush();

  assert.equal(badges[0].textContent, '[0%]');
  assert.equal(badges[0].classList.contains('proxycheck-tier-low'), true);
  assert.equal(anchors[0].classList.contains('proxycheck-anchor-risk-medium'), false);
  assert.equal(anchors[0].style.backgroundColor, '');
  assert.ok(openDialogs[0].host.textContent.includes('No high-risk signals detected'));
  openDialogs[0].close();
  await flush();
});

test('Shodan ordinary open ports highlight yellow in light mode and list open ports in dialog risk details', async () => {
  const ip = '198.51.100.40';
  const payload = makeLightPayload(ip, {
    results: [
      makeProviderRow('MaxMind', { asn: 'AS17451', isp: 'BIZNET-AS-AP BIZNET NETWORKS' }),
      makeProviderRow('GetIPIntel', { status: 'Deferred (Light Mode)', statusCode: null, isDeferred: true }),
      makeProviderRow('Shodan InternetDB', {
        ports: [179],
        openProxyPorts: [],
        usageType: 'Indexed Ports (1)',
        securityFlags: [{ label: 'Open Ports', isHighRisk: false }],
      }),
    ],
  });

  const { anchors, badges, openDialogs, flush } = await runGadgetWithPayloads([ip], () => payload);

  assert.equal(badges[0].classList.contains('proxycheck-tier-medium'), true);
  assert.equal(anchors[0].classList.contains('proxycheck-anchor-risk-medium'), true);
  assert.ok(badges[0].textContent.includes('Shodan:Open Ports (179)'));

  badges[0].click();
  await flush();

  assert.equal(openDialogs.length, 1);
  assert.ok(openDialogs[0].host.textContent.includes('Open Ports (179)'));
  openDialogs[0].close();
  await flush();
});

test('Special:Block link prefills three-month expiry and blocked proxy reason synced with selected checkboxes', async () => {
  const cases: Array<{ ip: string; softBlock: boolean }> = [
    { ip: '198.51.100.41', softBlock: false },
    { ip: '100.64.12.41', softBlock: true },
  ];

  for (const tc of cases) {
    const payload = makeFullPayload(tc.ip, {
      recommendedCidr: `${tc.ip}/24`,
      isMobileOrCgnat: tc.softBlock,
      results: [
        makeProviderRow('MaxMind', { asn: 'AS17451', isp: 'metroNET By Biznet' }),
        makeProviderRow('IP2Location', { asn: 'AS17451', isp: 'BIZNET-AS-AP BIZNET NETWORKS' }),
        makeProviderRow('GetIPIntel', { chance: 95 }),
      ],
    });

    const { badges, openDialogs, flush } = await runGadgetWithPayloads([tc.ip], () => payload);
    badges[0].click();
    await flush();

    const dialog = openDialogs[0].host;
    const blockLink = dialog.querySelector('.proxycheck-link-block')!;
    const checkboxes = dialog.querySelectorAll('.proxycheck-result-checkbox');
    assert.equal(checkboxes.length, 3);
    assert.equal(checkboxes[0].checked, true);
    assert.equal(checkboxes[1].checked, false);
    assert.equal(checkboxes[2].checked, false);

    const parseParams = (href: string) => new URL(`https://zh.wikipedia.org${href}`).searchParams;

    let params = parseParams(blockLink.href);
    assert.equal(params.get('wpExpiry'), '3 months');
    assert.equal(params.get('wpReason'), 'other');
    assert.equal(
      params.get('wpReason-other'),
      '{{blocked proxy}}<!-- AS17451 ([[:m:User:Hamish/proxycheck.js|proxycheck]]) -->'
    );
    if (tc.softBlock) {
      assert.equal(params.get('wpAnonOnly'), '1');
      assert.equal(params.get('wpHardBlock'), '0');
      assert.equal(params.get('wpDisableUTEdit'), '0');
    } else {
      assert.equal(params.get('wpAnonOnly'), null);
    }

    checkboxes[1].click();
    checkboxes[2].click();
    params = parseParams(blockLink.href);
    assert.equal(params.get('wpExpiry'), '3 months');
    assert.equal(params.get('wpReason'), 'other');
    assert.equal(
      params.get('wpReason-other'),
      '{{blocked proxy}}<!-- AS17451, metroNET By Biznet, BIZNET-AS-AP BIZNET NETWORKS ([[:m:User:Hamish/proxycheck.js|proxycheck]]) -->'
    );

    checkboxes[0].click();
    checkboxes[1].click();
    checkboxes[2].click();
    params = parseParams(blockLink.href);
    assert.equal(
      params.get('wpReason-other'),
      '{{blocked proxy}}<!-- ([[:m:User:Hamish/proxycheck.js|proxycheck]]) -->'
    );

    openDialogs[0].close();
    await flush();
  }
});
