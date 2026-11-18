import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const REPO_ROOT = path.resolve(import.meta.dirname, '..', '..');
const GADGET_PATH = path.join(REPO_ROOT, 'scripts', 'user-gadget.js');
const GADGET_SOURCE = fs.readFileSync(GADGET_PATH, 'utf8');

type AnyRecord = Record<string, unknown>;

interface CapturedFetchCall {
  url: string; method: string; headers: Record<string, string>; bodyText: string; bodyJson: unknown;
}
interface MockResponseSpec { status?: number; body?: unknown; }
type FetchResponder = (call: CapturedFetchCall) => MockResponseSpec | Promise<MockResponseSpec>;
interface MutationRecordLike { target: MockNode; addedNodes: MockNode[]; }

function checkNodeConnected(node: MockNode | null, root: MockNode): boolean {
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

  get isConnected(): boolean { return checkNodeConnected(this, this.ownerDoc.documentElement); }
  get textContent(): string { return this.nodeValue ?? ''; }
  set textContent(val: string) {
    this.nodeValue = String(val);
    this.ownerDoc.enqueueMutation({ target: this, addedNodes: [] });
  }
}

class MockTextNode extends MockNode {
  constructor(text: string, ownerDoc: MockDocument) {
    super(3, ownerDoc);
    this.nodeValue = String(text);
  }
}

function splitSelectorBranches(selector: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < selector.length; i++) {
    const ch = selector[i];
    if (ch === '(' || ch === '[') depth += 1;
    else if (ch === ')' || ch === ']') depth = Math.max(0, depth - 1);
    else if (ch === ',' && depth === 0) { parts.push(selector.slice(start, i).trim()); start = i + 1; }
  }
  parts.push(selector.slice(start).trim());
  return parts.filter(Boolean);
}

function splitDescendantParts(selector: string): string[] {
  const tokens: string[] = [];
  let depth = 0;
  let cur = '';
  for (let i = 0; i < selector.length; i++) {
    const ch = selector[i];
    if (ch === '(' || ch === '[') { depth += 1; cur += ch; }
    else if (ch === ')' || ch === ']') { depth = Math.max(0, depth - 1); cur += ch; }
    else if (/\s/.test(ch) && depth === 0) { if (cur) tokens.push(cur); cur = ''; }
    else cur += ch;
  }
  if (cur) tokens.push(cur);
  return tokens;
}

function matchesCompound(el: MockElement, compound: string): boolean {
  let rem = compound.trim();
  if (!rem) return false;
  const negations: string[] = [];
  rem = rem.replace(/:not\(([^)]+)\)/g, (_m, inner: string) => { negations.push(inner.trim()); return ''; });
  if (negations.some((neg) => matchesSelectorList(el, neg))) return false;

  const attrs: Array<{ name: string; value: string | null }> = [];
  rem = rem.replace(/\[([^\]=]+)(?:="([^"]*)")?\]/g, (_m, rawName: string, rawVal?: string) => {
    attrs.push({ name: rawName.trim(), value: rawVal ?? null });
    return '';
  });
  for (const attr of attrs) {
    const actual = el.getAttribute(attr.name);
    if (attr.value === null ? actual === null : actual !== attr.value) return false;
  }

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

function matchesSegmentChain(el: MockElement, segments: string[], idx: number): boolean {
  if (!matchesCompound(el, segments[idx])) return false;
  if (idx === 0) return true;
  for (let anc = el.parentNode; anc; anc = anc.parentNode) if (matchesSegmentChain(anc, segments, idx - 1)) return true;
  return false;
}

function matchesSelectorList(el: MockElement, selector: string): boolean {
  return splitSelectorBranches(selector).some((branch) => {
    const segs = splitDescendantParts(branch);
    return segs.length > 0 && matchesSegmentChain(el, segs, segs.length - 1);
  });
}

function findClosestAncestor(start: MockElement | null, selector: string): MockElement | null {
  for (let cur = start; cur; cur = cur.parentNode) if (cur.matches(selector)) return cur;
  return null;
}

function dispatchClickBubble(target: MockElement, ev: AnyRecord, isStopped: () => boolean): void {
  for (let cur: MockElement | null = target; cur && !isStopped(); cur = cur.parentNode) {
    for (const handler of cur.getListeners('click')) handler.call(cur, ev);
  }
}

class MockElement extends MockNode {
  tagName: string;
  style: Record<string, string> = {};
  dataset: Record<string, string | undefined> = {};
  checked = false;
  disabled = false;
  value = '';
  href = '';
  title = '';
  target = '';
  rel = '';
  type = '';
  role = '';
  clickCount = 0;
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
    contains: (name: string): boolean => (this.className ? this.className.split(/\s+/).filter(Boolean) : []).includes(name),
  };

  constructor(tagName: string, ownerDoc: MockDocument) {
    super(1, ownerDoc);
    this.tagName = tagName.toUpperCase();
  }

  get id(): string { return this.attrs.get('id') ?? ''; }
  set id(val: string) { if (val) this.attrs.set('id', String(val)); else this.attrs.delete('id'); }
  get className(): string { return this.attrs.get('class') ?? ''; }
  set className(val: string) {
    const str = String(val ?? '').trim();
    if (str) this.attrs.set('class', str); else this.attrs.delete('class');
  }

  override get textContent(): string { return this.childNodes.map((c) => c.textContent).join(''); }
  override set textContent(val: string) {
    for (const child of this.childNodes) child.parentNode = null;
    this.childNodes = [];
    const str = String(val ?? '');
    if (str !== '') {
      const tn = new MockTextNode(str, this.ownerDoc);
      tn.parentNode = this;
      this.childNodes.push(tn);
      this.ownerDoc.enqueueMutation({ target: this, addedNodes: [tn] });
    } else {
      this.ownerDoc.enqueueMutation({ target: this, addedNodes: [] });
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
    else if (name === 'style') {
      for (const pair of str.split(';')) {
        const colon = pair.indexOf(':');
        if (colon > 0) this.style[pair.slice(0, colon).trim()] = pair.slice(colon + 1).trim();
      }
    } else if (name.startsWith('data-')) {
      this.dataset[name.slice(5).replace(/-([a-z])/g, (_m, ch: string) => ch.toUpperCase())] = str;
    }
  }

  getAttribute(name: string): string | null {
    if (name === 'href' && this.href) return this.href;
    if (name === 'title' && this.title) return this.title;
    return this.attrs.get(name) ?? null;
  }

  removeAttribute(name: string): void { this.attrs.delete(name); }
  appendChild<T extends MockNode>(child: T): T { return this.insertBefore(child, null); }

  insertBefore<T extends MockNode>(newChild: T, refChild: MockNode | null): T {
    if (newChild.parentNode) newChild.parentNode.removeChild(newChild);
    newChild.parentNode = this;
    const idx = refChild === null ? -1 : this.childNodes.indexOf(refChild);
    if (idx === -1) this.childNodes.push(newChild); else this.childNodes.splice(idx, 0, newChild);
    this.ownerDoc.enqueueMutation({ target: this, addedNodes: [newChild] });
    return newChild;
  }

  removeChild<T extends MockNode>(child: T): T {
    const idx = this.childNodes.indexOf(child);
    if (idx !== -1) { this.childNodes.splice(idx, 1); child.parentNode = null; }
    return child;
  }

  contains(other: MockNode | null): boolean { return checkNodeConnected(other, this); }
  matches(selector: string): boolean { return matchesSelectorList(this, selector); }
  closest(selector: string): MockElement | null { return findClosestAncestor(this, selector); }

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

  querySelector(selector: string): MockElement | null { return this.querySelectorAll(selector)[0] ?? null; }
  select(): void {}
  getListeners(type: string): Array<(ev: AnyRecord) => void> { return (this.listeners.get(type) ?? []).slice(); }

  addEventListener(type: string, fn: (ev: AnyRecord) => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(fn);
    this.listeners.set(type, list);
  }

  removeEventListener(type: string, fn: (ev: AnyRecord) => void): void {
    const list = this.listeners.get(type);
    if (list) this.listeners.set(type, list.filter((item) => item !== fn));
  }

  click(): void {
    this.clickCount += 1;
    let stopped = false;
    const ev: AnyRecord = {
      type: 'click',
      target: this,
      defaultPrevented: false,
      preventDefault() { ev.defaultPrevented = true; },
      stopPropagation() { stopped = true; },
    };
    if (this.tagName === 'INPUT' && this.type === 'checkbox') this.checked = !this.checked;
    dispatchClickBubble(this, ev, () => stopped);
  }
}

class MockDocument {
  documentElement: MockElement;
  head: MockElement;
  body: MockElement;
  visibilityState = 'visible';
  private observers: Array<(records: MutationRecordLike[]) => void> = [];
  private queuedMutations: MutationRecordLike[] = [];
  private flushScheduled = false;
  private docListeners = new Map<string, Array<() => void>>();

  constructor() {
    this.documentElement = new MockElement('html', this);
    this.head = new MockElement('head', this);
    this.body = new MockElement('body', this);
    this.documentElement.childNodes.push(this.head, this.body);
    this.head.parentNode = this.documentElement;
    this.body.parentNode = this.documentElement;
  }

  createElement(tag: string): MockElement { return new MockElement(tag, this); }
  createTextNode(text: string): MockTextNode { return new MockTextNode(text, this); }
  getElementById(id: string): MockElement | null { return this.documentElement.querySelector(`#${id}`); }
  querySelectorAll(selector: string): MockElement[] { return this.documentElement.querySelectorAll(selector); }
  querySelector(selector: string): MockElement | null { return this.documentElement.querySelector(selector); }

  addEventListener(type: string, fn: () => void): void {
    const list = this.docListeners.get(type) ?? [];
    list.push(fn);
    this.docListeners.set(type, list);
  }

  removeEventListener(type: string, fn: () => void): void {
    const list = this.docListeners.get(type);
    if (list) this.docListeners.set(type, list.filter((item) => item !== fn));
  }

  registerObserver(cb: (records: MutationRecordLike[]) => void): () => void {
    if (!this.observers.includes(cb)) this.observers.push(cb);
    return () => { this.observers = this.observers.filter((item) => item !== cb); };
  }

  enqueueMutation(record: MutationRecordLike): void {
    if (this.observers.length === 0 || !record.target.isConnected) return;
    this.queuedMutations.push(record);
    if (!this.flushScheduled) {
      this.flushScheduled = true;
      queueMicrotask(() => {
        this.flushScheduled = false;
        const batch = this.queuedMutations.splice(0, this.queuedMutations.length);
        if (batch.length > 0) for (const cb of this.observers.slice()) cb(batch);
      });
    }
  }
}

interface JQueryCollection {
  [index: number]: MockElement;
  length: number;
  append: (...items: unknown[]) => JQueryCollection;
  appendTo: (target: JQueryCollection | MockElement) => JQueryCollection;
  prepend: (item: unknown) => JQueryCollection;
  before: (item: unknown) => JQueryCollection;
  after: (item: unknown) => JQueryCollection;
  empty: () => JQueryCollection;
  remove: () => JQueryCollection;
  text: (val?: string) => string | JQueryCollection;
  attr: (name: string, val?: string) => string | undefined | JQueryCollection;
  prop: (name: string, val?: unknown) => unknown;
  css: (name: string, val: string) => JQueryCollection;
  addClass: (cls: string) => JQueryCollection;
  removeClass: (cls: string) => JQueryCollection;
  find: (selector: string) => JQueryCollection;
  first: () => JQueryCollection;
  parent: () => JQueryCollection;
  closest: (selector: string) => JQueryCollection;
  each: (fn: (this: MockElement, idx: number, el: MockElement) => void) => JQueryCollection;
  on: (eventName: string, handler: (ev: AnyRecord) => void) => JQueryCollection;
}

function createJQuery(doc: MockDocument, readyCallbacks: Array<() => void>) {
  function toNodes(item: unknown): MockNode[] {
    if (item === null || item === undefined) return [];
    if (item instanceof MockNode) return [item];
    if (typeof item === 'string') return [doc.createTextNode(item)];
    if (typeof item === 'object' && 'length' in (item as AnyRecord)) {
      const col = item as JQueryCollection;
      const out: MockNode[] = [];
      for (let i = 0; i < col.length; i++) if (col[i]) out.push(col[i]);
      return out;
    }
    return [];
  }

  function wrap(elements: MockElement[]): JQueryCollection {
    const col: Record<number, MockElement> = {};
    elements.forEach((el, idx) => {
      col[idx] = el;
    });
    const api: JQueryCollection = Object.assign(col, {
      length: elements.length,
      append(...items: unknown[]) {
        const firstEl = elements[0];
        if (firstEl) for (const item of items) for (const node of toNodes(item)) firstEl.appendChild(node);
        return api;
      },
      appendTo(target: JQueryCollection | MockElement) {
        const dest = target instanceof MockElement ? target : target[0];
        if (dest) for (const el of elements) dest.appendChild(el);
        return api;
      },
      prepend(item: unknown) {
        const firstEl = elements[0];
        if (firstEl) {
          const ref = firstEl.childNodes[0] ?? null;
          for (const node of toNodes(item)) firstEl.insertBefore(node, ref);
        }
        return api;
      },
      before(item: unknown) {
        const firstEl = elements[0];
        if (firstEl?.parentNode) for (const node of toNodes(item)) firstEl.parentNode.insertBefore(node, firstEl);
        return api;
      },
      after(item: unknown) {
        const firstEl = elements[0];
        if (firstEl?.parentNode) {
          const ref = firstEl.nextSibling;
          for (const node of toNodes(item)) firstEl.parentNode.insertBefore(node, ref);
        }
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
          for (const item of el.querySelectorAll(selector)) {
            if (!matched.includes(item)) matched.push(item);
          }
        }
        return wrap(matched);
      },
      first: () => wrap(elements[0] ? [elements[0]] : []),
      parent: () => wrap(elements.map((el) => el.parentNode).filter((p): p is MockElement => p instanceof MockElement)),
      closest: (sel: string) => wrap(elements.map((el) => el.closest(sel)).filter((c): c is MockElement => c instanceof MockElement)),
      each(fn: (this: MockElement, idx: number, el: MockElement) => void) {
        elements.forEach((el, idx) => fn.call(el, idx, el));
        return api;
      },
      on(eventName: string, handler: (ev: AnyRecord) => void) {
        for (const el of elements) el.addEventListener(eventName, handler);
        return api;
      },
    });
    return api;
  }

  return function $(arg: unknown, attrs?: AnyRecord): JQueryCollection | undefined {
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

interface GadgetHarnessOptions {
  mwConfig?: Record<string, unknown>;
  sharedMwStorage?: Map<string, string>;
  sharedLocalStorage?: Map<string, string>;
  nowMs?: () => number;
  provideIsTemporaryUser?: boolean;
  onFetch?: FetchResponder;
  setupDom?: (doc: MockDocument) => void;
}

interface OpenDialogHandle {
  host: MockElement;
  title: string;
  close: () => void;
}

function makeMockRow(provider: string, overrides: AnyRecord = {}): AnyRecord {
  return {
    provider,
    status: '200 OK',
    statusCode: 200,
    asn: '-',
    isp: '-',
    organisation: '-',
    location: '-',
    usageType: '-',
    securityFlags: [],
    ...overrides,
  };
}

function makeFullIpPayload(ip: string, overrides: AnyRecord = {}): AnyRecord {
  const baseCacheMeta: AnyRecord = {
    status: 'hit',
    layer: 'L2',
    isPartial: false,
    hitCount: 6,
    missCount: 0,
    cooldownCount: 0,
    totalSources: 6,
    cachedAt: '2026-11-01T08:30:00+00:00',
    fetchedAt: '2026-11-01T08:30:00+00:00',
    ageSeconds: 12 * 86400,
    staleThresholdSeconds: 90 * 86400,
    isStale: false,
    shouldAutoRefresh: false,
    refreshInProgress: false,
    degradedRefreshFallback: false,
    recommendFreshRecheck: false,
    hitProviders: ['cloudflare_radar', 'abuseipdb', 'ipdata', 'proxycheck'],
    missedProviders: [],
  };
  const customMeta = (overrides.cacheMeta as AnyRecord | undefined) ?? {};
  const isV6 = ip.includes(':');
  return {
    ip,
    fetchedAt: '2026-11-01T08:30:00+00:00',
    queryMode: 'full',
    isPartialMode: false,
    isCached: true,
    is_broadcast_ip: false,
    isTor: false,
    torIsExit: false,
    torRunning: false,
    torFlags: [],
    torLabel: '',
    torSummary: '',
    prediction_score: 94.25,
    predictionLabel: 'Proxy / VPN',
    predictionTier: 'destructive',
    getipintel_chance: 94.25,
    arbitrationVerdict: 'Confirmed Proxy / VPN (4/5 Sources)',
    arbitrationTier: 'destructive',
    isMajorityProxyVpn: true,
    suspectedResidentialProxy: false,
    primaryCountry: 'United States',
    primaryCoordinates: 'Unknown',
    primaryAsn: 'AS14061',
    ptrHostname: 'vps.example.net',
    ptrCategory: 'hosting_or_gateway',
    ptrLabel: 'Hosting / Gateway',
    ptrIsHighRisk: true,
    recommendedCidr: isV6 ? `${ip}/64` : `${ip}/24`,
    defaultCidr: isV6 ? `${ip}/64` : `${ip}/24`,
    mmdbCidr: isV6 ? `${ip}/48` : `${ip}/20`,
    bgpPrefix: isV6 ? `${ip}/48` : `${ip}/20`,
    cloudCidr: null,
    cloudProvider: null,
    cidrNote: 'Default range selected',
    escalationCidr: null,
    cidrRationale: 'Default range selected',
    isMobileOrCgnat: false,
    sharedPrivacyEgress: null,
    results: [
      makeMockRow('MaxMind', {
        asn: 'AS14061',
        isp: 'DigitalOcean, LLC',
        organisation: 'DigitalOcean, LLC',
        location: 'New York, United States',
        usageType: 'Hosting',
        securityFlags: [{ label: 'Hosting', isHighRisk: true }],
      }),
      makeMockRow('GetIPIntel', {
        usageType: 'Proxy / VPN',
        securityFlags: [{ label: 'High Prediction (94.25%)', isHighRisk: true }],
      }),
      makeMockRow('AbuseIPDB', {
        asn: 'AS14061',
        isp: 'DigitalOcean, LLC',
        organisation: 'DigitalOcean, LLC',
        location: 'United States',
        usageType: 'Data Center/Web Hosting/Transit',
        abuseConfidenceScore: 87,
        securityFlags: [{ label: 'Abuse Score: 87%', isHighRisk: true }],
      }),
    ],
    ...overrides,
    cacheMeta: { ...baseCacheMeta, ...customMeta },
  };
}

function createGadgetHarness(options: GadgetHarnessOptions = {}) {
  const doc = new MockDocument();
  const mwStorageMap = options.sharedMwStorage ?? new Map<string, string>();
  const localStorageMap = options.sharedLocalStorage ?? new Map<string, string>();
  const getNow = options.nowMs ?? (() => 1_763_420_000_000);

  if (!mwStorageMap.has('proxycheck-ip-policy-consent')) mwStorageMap.set('proxycheck-ip-policy-consent', '1');
  if (!mwStorageMap.has('proxycheck-gadget-token')) {
    mwStorageMap.set('proxycheck-gadget-token', 'signed-test-token');
    mwStorageMap.set('proxycheck-gadget-token-user', 'AdminPatroller');
    mwStorageMap.set('proxycheck-gadget-token-exp', String(getNow() + 3_600_000));
  }

  const configValues: Record<string, unknown> = {
    wgUserName: 'AdminPatroller',
    wgUserIsTemp: false,
    wgServerName: 'en.wikipedia.org',
    wgArticlePath: '/wiki/$1',
    wgCanonicalSpecialPageName: 'Recentchanges',
    wgPageName: 'Special:RecentChanges',
    wgTitle: 'RecentChanges',
    wgRelevantUserName: null,
    ...options.mwConfig,
  };

  if (options.setupDom) {
    options.setupDom(doc);
  } else {
    const content = doc.createElement('div');
    content.id = 'mw-content-text';
    doc.body.appendChild(content);
  }

  const fetchCalls: CapturedFetchCall[] = [];
  const mwApiCalls: AnyRecord[] = [];
  const clipboardWrites: string[] = [];
  const openDialogs: OpenDialogHandle[] = [];
  const readyCallbacks: Array<() => void> = [];
  const activeTimers = new Map<number, { fn: () => void; delay: number; isInterval: boolean }>();
  let nextTimerId = 1;

  const MockDate = class extends Date {
    static override now(): number {
      return getNow();
    }
  };

  const makeWebStorage = (map: Map<string, string>) => ({
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    setItem: (k: string, v: string) => {
      map.set(k, String(v));
    },
    removeItem: (k: string) => {
      map.delete(k);
    },
  });

  const mwUtil: AnyRecord = {
    getUrl: (title: string) => `/wiki/${title}`,
    getParamValue: () => null,
    addCSS: () => {},
  };
  if (options.provideIsTemporaryUser !== false) {
    mwUtil.isTemporaryUser = (name: string) => /^~\d{4}-/.test(name);
  }

  const hooks = new Map<string, Array<() => void>>();
  const mediaWiki = {
    config: { get: (key: string) => (key in configValues ? configValues[key] : null) },
    storage: {
      get: (key: string) => (mwStorageMap.has(key) ? mwStorageMap.get(key)! : null),
      set: (key: string, val: string) => {
        mwStorageMap.set(key, String(val));
        return true;
      },
      remove: (key: string) => {
        mwStorageMap.delete(key);
      },
    },
    loader: { using: () => Promise.resolve() },
    util: mwUtil,
    hook: (name: string) => ({
      add: (fn: () => void) => {
        const list = hooks.get(name) ?? [];
        list.push(fn);
        hooks.set(name, list);
      },
      fire: () => {
        for (const fn of hooks.get(name) ?? []) fn();
      },
    }),
    Api: class {
      get(params: AnyRecord) {
        mwApiCalls.push(params);
        return Promise.resolve({ centralauthtoken: { centralauthtoken: 'mock-centralauth-token' } });
      }
    },
  };

  const OO = {
    ui: {
      confirm: () => Promise.resolve(true),
      alert: ($message: JQueryCollection, opts: { title?: string }) =>
        new Promise<void>((resolve) => {
          const host = doc.createElement('div');
          host.className = 'mock-ooui-dialog';
          if ($message && $message[0]) host.appendChild($message[0]);
          doc.body.appendChild(host);
          openDialogs.push({
            host,
            title: opts?.title ?? '',
            close: () => {
              if (host.parentNode) host.parentNode.removeChild(host);
              resolve();
            },
          });
        }),
    },
  };

  class MockMutationObserver {
    private disconnectFn: (() => void) | null = null;
    private cb: (records: MutationRecordLike[]) => void;

    constructor(cb: (records: MutationRecordLike[]) => void) {
      this.cb = cb;
    }

    observe(): void {
      if (!this.disconnectFn) this.disconnectFn = doc.registerObserver(this.cb);
    }

    disconnect(): void {
      if (this.disconnectFn) {
        this.disconnectFn();
        this.disconnectFn = null;
      }
    }
  }

  const windowObj: AnyRecord = {
    location: { search: '' },
    localStorage: makeWebStorage(localStorageMap),
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

  const fetchMock = (url: string, init: AnyRecord = {}) => {
    const rawHeaders = (init.headers as Record<string, string> | undefined) ?? {};
    const bodyText = typeof init.body === 'string' ? init.body : '';
    let bodyJson: unknown = null;
    if (bodyText) {
      try {
        bodyJson = JSON.parse(bodyText);
      } catch {
        bodyJson = null;
      }
    }
    const call: CapturedFetchCall = {
      url: String(url),
      method: String(init.method ?? 'GET').toUpperCase(),
      headers: { ...rawHeaders },
      bodyText,
      bodyJson,
    };
    fetchCalls.push(call);

    const responder: FetchResponder =
      options.onFetch ??
      ((req) => {
        if (req.url.includes('/api/v1/detect/batch')) {
          const parsed = (req.bodyJson as { ips?: string[] } | null) ?? {};
          const results: Record<string, AnyRecord> = {};
          for (const ip of parsed.ips ?? []) {
            results[ip] = makeFullIpPayload(ip, { queryMode: 'light', isPartialMode: true });
          }
          return { status: 200, body: { results, inputMap: {}, queryMode: 'light' } };
        }
        const urlObj = new URL(req.url);
        const ip = urlObj.searchParams.get('ip') ?? '198.51.100.1';
        return { status: 200, body: makeFullIpPayload(ip) };
      });

    return Promise.resolve(responder(call)).then((spec) => {
      const status = spec.status ?? 200;
      const serialized = JSON.stringify(spec.body ?? {});
      return {
        status,
        ok: status >= 200 && status < 300,
        json: () => Promise.resolve(JSON.parse(serialized)),
        text: () => Promise.resolve(serialized),
      };
    });
  };

  const jQuery = createJQuery(doc, readyCallbacks);
  const sandbox = vm.createContext({
    window: windowObj, document: doc,
    navigator: { clipboard: { writeText: (text: string) => { clipboardWrites.push(String(text)); return Promise.resolve(); } } },
    MutationObserver: MockMutationObserver, mediaWiki, jQuery, OO, fetch: fetchMock, Date: MockDate,
    console, Promise, Map, Set, WeakSet, URL, encodeURIComponent, decodeURIComponent,
    parseInt, isNaN, isFinite, Number, String, Boolean, Array, Object, Math, JSON,
  });

  vm.runInContext(GADGET_SOURCE, sandbox, { filename: 'scripts/user-gadget.js' });
  for (const cb of readyCallbacks) cb();

  async function flushAsync(rounds = 8): Promise<void> {
    for (let i = 0; i < rounds; i++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
  }

  async function runPendingTimers(maxDelayMs = 100): Promise<void> {
    await flushAsync();
    for (let pass = 0; pass < 6; pass++) {
      const dueIds: number[] = [];
      for (const [id, entry] of activeTimers) {
        if (!entry.isInterval && entry.delay <= maxDelayMs) dueIds.push(id);
      }
      if (dueIds.length === 0) break;
      for (const id of dueIds) {
        const entry = activeTimers.get(id);
        if (entry) {
          activeTimers.delete(id);
          entry.fn();
        }
      }
      await flushAsync();
    }
  }

  return { doc, fetchCalls, mwApiCalls, clipboardWrites, openDialogs, mwStorageMap, localStorageMap, flushAsync, runPendingTimers };
}

test('Userscript source enforces XSS-safe DOM construction, provider palettes, and CheckUser API exclusion', () => {
  const forbiddenHtmlCall = '.ht' + 'ml(';
  const forbiddenInnerProp = 'inner' + 'HTML';
  assert.equal(GADGET_SOURCE.includes(forbiddenHtmlCall), false);
  assert.equal(GADGET_SOURCE.includes(forbiddenInnerProp), false);
  assert.equal(GADGET_SOURCE.toLowerCase().includes('/checkuser/v0/'), false);
  assert.equal(GADGET_SOURCE.toLowerCase().includes('batch-temporaryaccount'), false);
  assert.equal(GADGET_SOURCE.includes('copyWithSource'), false);
  assert.ok(GADGET_SOURCE.includes("{ label: 'ASN', entries: collectAsnEntries(rows), isRisk: false, emptyText: '-', copyable: true }"));
  assert.ok(GADGET_SOURCE.includes("{ label: 'ISP', entries: collectIspEntries(rows), isRisk: false, emptyText: '-', copyable: true }"));

});

test('Plain-text reveal spans receive badges without duplicating badges on container spans with child anchors', async () => {
  const harness = createGadgetHarness({
    setupDom(doc) {
      const content = doc.createElement('div');
      content.id = 'mw-content-text';

      const plainSpan = doc.createElement('span');
      plainSpan.className = 'ext-checkuser-tempaccount-reveal-ip';
      plainSpan.textContent = '198.51.100.11';

      const wrappedSpan = doc.createElement('span');
      wrappedSpan.className = 'ext-checkuser-tempaccount-reveal-ip';
      const innerAnchor = doc.createElement('a');
      innerAnchor.className = 'ext-checkuser-tempaccount-reveal-ip-anchor';
      innerAnchor.href = '/wiki/Special:IPContributions/198.51.100.22';
      innerAnchor.textContent = '198.51.100.22';
      wrappedSpan.appendChild(innerAnchor);

      const unrevealedBtn = doc.createElement('button');
      unrevealedBtn.className = 'ext-checkuser-tempaccount-reveal-ip-button';
      unrevealedBtn.textContent = 'Show IP';

      const dynamicSpan = doc.createElement('span');
      dynamicSpan.className = 'ext-checkuser-tempaccount-reveal-ip';

      content.appendChild(plainSpan);
      content.appendChild(wrappedSpan);
      content.appendChild(unrevealedBtn);
      content.appendChild(dynamicSpan);
      doc.body.appendChild(content);
    },
  });

  await harness.runPendingTimers(60);

  const initialBadges = harness.doc.querySelectorAll('.proxycheck-ip-badge');
  assert.equal(initialBadges.length, 2);
  assert.ok(initialBadges[0].href.includes('198.51.100.11'));
  assert.ok(initialBadges[1].href.includes('198.51.100.22'));

  const wrappedContainer = harness.doc.querySelectorAll('.ext-checkuser-tempaccount-reveal-ip')[1];
  assert.equal(wrappedContainer.nextElementSibling?.classList.contains('proxycheck-ip-badge') ?? false, false);
  assert.equal(harness.doc.querySelector('.ext-checkuser-tempaccount-reveal-ip-button')!.clickCount, 0);

  const dynamicSpan = harness.doc.querySelectorAll('.ext-checkuser-tempaccount-reveal-ip')[2];
  dynamicSpan.textContent = '198.51.100.33';
  await harness.runPendingTimers(60);

  const allBadges = harness.doc.querySelectorAll('.proxycheck-ip-badge');
  assert.equal(allBadges.length, 3);
  assert.ok(allBadges[2].href.includes('198.51.100.33'));
});

test('Temporary account contributions page awaits DOM reveal passively, supports multi-IP switching, and never leaks temp usernames', async () => {
  for (const provideIsTemporaryUser of [true, false]) {
    const harness = createGadgetHarness({
      provideIsTemporaryUser,
      mwConfig: {
        wgCanonicalSpecialPageName: 'Contributions',
        wgPageName: 'Special:Contributions/~2026-12345-6',
        wgTitle: 'Contributions/~2026-12345-6',
        wgRelevantUserName: '~2026-12345-6',
      },
      setupDom(doc) {
        const content = doc.createElement('div');
        content.id = 'mw-content-text';
        const list = doc.createElement('ul');
        list.className = 'mw-contributions-list';

        const row1 = doc.createElement('li');
        const tempLink = doc.createElement('a');
        tempLink.className = 'mw-tempuserlink';
        tempLink.textContent = '~2026-12345-6';
        const revealBtn = doc.createElement('button');
        revealBtn.className = 'ext-checkuser-tempaccount-reveal-ip-button';
        revealBtn.textContent = 'Show IP';
        row1.appendChild(tempLink);
        row1.appendChild(revealBtn);

        const row2 = doc.createElement('li');
        row2.textContent = 'Older revision ';
        list.appendChild(row1);
        list.appendChild(row2);
        content.appendChild(list);
        doc.body.appendChild(content);
      },
      onFetch(call) {
        if (call.url.includes('/api/v1/detect/batch')) {
          const parsed = (call.bodyJson as { ips?: string[] } | null) ?? {};
          const results: Record<string, AnyRecord> = {};
          for (const ip of parsed.ips ?? []) results[ip] = makeFullIpPayload(ip, { queryMode: 'light', isPartialMode: true });
          return { status: 200, body: { results, inputMap: {}, queryMode: 'light' } };
        }
        const ip = new URL(call.url).searchParams.get('ip') ?? '';
        if (ip === '198.51.100.41') {
          return { status: 200, body: makeFullIpPayload(ip, { arbitrationVerdict: 'Confirmed Proxy / VPN (5/6 Sources)', recommendedCidr: '198.51.100.0/24' }) };
        }
        return {
          status: 200,
          body: makeFullIpPayload(ip, {
            arbitrationVerdict: 'Clean Residential / Direct (0/5 Sources)',
            arbitrationTier: 'success',
            isMajorityProxyVpn: false,
            prediction_score: 5,
            getipintel_chance: 5,
            recommendedCidr: '203.0.113.88/32',
          }),
        };
      },
    });

    await harness.runPendingTimers(600);
    assert.equal(harness.doc.getElementById('proxycheck-pageinfo'), null);
    assert.equal(harness.fetchCalls.length, 0);
    assert.equal(harness.mwApiCalls.length, 0);
    assert.equal(harness.doc.querySelector('.ext-checkuser-tempaccount-reveal-ip-button')!.clickCount, 0);

    const rows = harness.doc.querySelectorAll('li');
    const firstRevealSpan = harness.doc.createElement('span');
    firstRevealSpan.className = 'ext-checkuser-tempaccount-reveal-ip';
    firstRevealSpan.textContent = '198.51.100.41';
    rows[0].appendChild(firstRevealSpan);
    await harness.runPendingTimers(120);

    const banner = harness.doc.getElementById('proxycheck-pageinfo');
    assert.ok(banner, 'Contributions banner should mount once a revealed IP appears in DOM');
    assert.ok(banner.textContent.includes('198.51.100.41'));
    assert.ok(banner.textContent.includes('Confirmed Proxy / VPN (5/6 Sources)'));

    const secondRevealSpan = harness.doc.createElement('span');
    secondRevealSpan.className = 'ext-checkuser-tempaccount-reveal-ip';
    const secondAnchor = harness.doc.createElement('a');
    secondAnchor.className = 'ext-checkuser-tempaccount-reveal-ip-anchor';
    secondAnchor.textContent = '203.0.113.88';
    secondRevealSpan.appendChild(secondAnchor);
    rows[1].appendChild(secondRevealSpan);
    await harness.runPendingTimers(120);

    const switcher = banner.querySelector('.proxycheck-temp-ip-switcher')!;
    assert.ok(switcher.textContent.includes('2 distinct revealed IPs on this page'));
    const pills = switcher.querySelectorAll('.proxycheck-ip-pill');
    assert.equal(pills.length, 2);
    assert.equal(pills[0].getAttribute('aria-pressed'), 'true');
    assert.equal(pills[1].getAttribute('aria-pressed'), 'false');

    pills[1].click();
    await harness.flushAsync();

    const updatedPills = banner.querySelectorAll('.proxycheck-ip-pill');
    assert.equal(updatedPills[1].getAttribute('aria-pressed'), 'true');
    assert.ok(banner.textContent.includes('203.0.113.88'));
    assert.ok(banner.textContent.includes('Clean Residential / Direct (0/5 Sources)'));

    for (const call of harness.fetchCalls) {
      assert.equal(call.url.includes('checkuser'), false);
      assert.equal(call.url.includes('~2026-'), false);
      assert.equal(call.bodyText.includes('~2026-'), false);
    }
    for (const [k, v] of harness.mwStorageMap) {
      assert.equal(k.includes('~2026-'), false);
      assert.equal(v.includes('~2026-'), false);
    }
    for (const [k, v] of harness.localStorageMap) {
      assert.equal(k.includes('~2026-'), false);
      assert.equal(v.includes('~2026-'), false);
    }
  }
});

test('Inline badges render relative cache age without auto-refresh, while dialog and banner run manual and >90d auto-SWR refetch', async () => {
  let pendingRefreshResolve: ((spec: MockResponseSpec) => void) | null = null;

  const harness = createGadgetHarness({
    setupDom(doc) {
      const content = doc.createElement('div');
      content.id = 'mw-content-text';
      for (const ip of ['198.51.100.50', '198.51.100.99']) {
        const anchor = doc.createElement('a');
        anchor.className = 'ext-checkuser-tempaccount-reveal-ip-anchor';
        anchor.textContent = ip;
        content.appendChild(anchor);
      }
      doc.body.appendChild(content);
    },
    onFetch(call) {
      if (call.url.includes('/api/v1/detect/batch')) {
        return {
          status: 200,
          body: {
            queryMode: 'light',
            inputMap: {},
            results: {
              '198.51.100.50': makeFullIpPayload('198.51.100.50', {
                queryMode: 'full',
                isPartialMode: false,
                cacheMeta: { ageSeconds: 15 * 86400, isStale: false, shouldAutoRefresh: false },
              }),
              '198.51.100.99': makeFullIpPayload('198.51.100.99', {
                queryMode: 'full',
                isPartialMode: false,
                prediction_score: 45,
                getipintel_chance: 45,
                arbitrationVerdict: 'Disputed Proxy / VPN (2/5 Sources)',
                arbitrationTier: 'warning',
                isMajorityProxyVpn: false,
                cacheMeta: { ageSeconds: 120 * 86400, isStale: true, shouldAutoRefresh: true },
              }),
            },
          },
        };
      }
      if (call.url.endsWith('/api/v1/detect/refresh')) {
        return new Promise<MockResponseSpec>((resolve) => {
          pendingRefreshResolve = resolve;
        });
      }
      return { status: 200, body: makeFullIpPayload('198.51.100.50') };
    },
  });

  await harness.runPendingTimers(60);

  const badges = harness.doc.querySelectorAll('.proxycheck-ip-badge');
  assert.equal(badges.length, 2);
  assert.ok(badges[0].title.includes('Cached 15d ago'));
  assert.equal(badges[0].classList.contains('proxycheck-badge-stale'), false);
  assert.ok(badges[1].title.includes('Cached 120d ago'));
  assert.equal(badges[1].classList.contains('proxycheck-badge-stale'), true);
  assert.equal(badges[1].style.borderStyle, 'dashed');
  assert.equal(harness.fetchCalls.some((c) => c.url.endsWith('/api/v1/detect/refresh')), false);

  badges[0].click();
  await harness.flushAsync();
  const manualDialog = harness.openDialogs[0].host;
  assert.ok(manualDialog.textContent.includes('Cached 15d ago'));
  const manualBtn = manualDialog.querySelector('.proxycheck-refetch-btn')!;
  assert.equal(manualBtn.textContent, 'Refetch');
  assert.equal(manualBtn.disabled, false);

  manualBtn.click();
  await harness.flushAsync();
  assert.equal(manualBtn.textContent, 'Updating...');
  assert.equal(manualBtn.disabled, true);

  const refreshCalls = harness.fetchCalls.filter((c) => c.url.endsWith('/api/v1/detect/refresh'));
  assert.equal(refreshCalls.length, 1);
  assert.equal(refreshCalls[0].method, 'POST');
  assert.equal(refreshCalls[0].headers.Authorization, 'Bearer signed-test-token');
  assert.deepEqual(refreshCalls[0].bodyJson, { ip: '198.51.100.50', mode: 'full', compact: false });

  pendingRefreshResolve!({
    status: 200,
    body: makeFullIpPayload('198.51.100.50', {
      prediction_score: 12,
      getipintel_chance: 12,
      arbitrationVerdict: 'Clean Residential / Direct (0/6 Sources)',
      arbitrationTier: 'success',
      isMajorityProxyVpn: false,
      isCached: false,
      cacheMeta: { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false },
    }),
  });
  await harness.flushAsync();

  assert.equal(manualBtn.textContent, 'Refetch');
  assert.equal(manualBtn.disabled, false);
  assert.ok(manualDialog.textContent.includes('Just updated'));
  assert.equal(badges[0].textContent, '[12%]');
  harness.openDialogs[0].close();
  await harness.flushAsync();

  pendingRefreshResolve = null;
  badges[1].click();
  await harness.flushAsync();

  const autoDialog = harness.openDialogs[1].host;
  assert.ok(autoDialog.textContent.includes('Disputed Proxy / VPN (2/5 Sources)'));
  const autoBtn = autoDialog.querySelector('.proxycheck-refetch-btn')!;
  assert.equal(autoBtn.textContent, 'Updating...');
  assert.equal(autoBtn.disabled, true);
  assert.equal(harness.fetchCalls.filter((c) => c.url.endsWith('/api/v1/detect/refresh')).length, 2);

  pendingRefreshResolve!({
    status: 200,
    body: makeFullIpPayload('198.51.100.99', {
      prediction_score: 99,
      getipintel_chance: 99,
      arbitrationVerdict: 'Confirmed Proxy / VPN (6/6 Sources)',
      arbitrationTier: 'destructive',
      isMajorityProxyVpn: true,
      isCached: false,
      cacheMeta: { status: 'miss', layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false },
    }),
  });
  await harness.flushAsync();

  assert.equal(autoBtn.textContent, 'Refetch');
  assert.equal(autoBtn.disabled, false);
  assert.ok(autoDialog.textContent.includes('Just updated'));
  assert.equal(badges[1].textContent, '[99%]');
  assert.equal(badges[1].classList.contains('proxycheck-badge-stale'), false);
});

test('Cross-tab mw.storage auto-SWR rate limiter caps background refreshes at 3 per 60s and stores only timestamps', async () => {
  const sharedMwStorage = new Map<string, string>();
  let currentNowMs = 1_763_420_000_000;
  const refreshUrls: string[] = [];

  async function openStaleContributionsTab(ip: string) {
    const tab = createGadgetHarness({
      sharedMwStorage,
      nowMs: () => currentNowMs,
      mwConfig: {
        wgCanonicalSpecialPageName: 'IPContributions',
        wgPageName: `Special:IPContributions/${ip}`,
        wgTitle: `IPContributions/${ip}`,
        wgRelevantUserName: ip,
      },
      onFetch(call) {
        if (call.url.endsWith('/api/v1/detect/refresh')) {
          refreshUrls.push(ip);
          return {
            status: 200,
            body: makeFullIpPayload(ip, {
              isCached: false,
              cacheMeta: { layer: 'upstream', ageSeconds: 0, isStale: false, shouldAutoRefresh: false },
            }),
          };
        }
        return {
          status: 200,
          body: makeFullIpPayload(ip, {
            cacheMeta: { ageSeconds: 110 * 86400, isStale: true, shouldAutoRefresh: true },
          }),
        };
      },
    });
    await tab.runPendingTimers(600);
    return tab;
  }

  await openStaleContributionsTab('203.0.113.1');
  currentNowMs += 5_000;
  await openStaleContributionsTab('203.0.113.2');
  currentNowMs += 5_000;
  await openStaleContributionsTab('203.0.113.3');
  currentNowMs += 5_000;
  const fourthTab = await openStaleContributionsTab('203.0.113.4');

  assert.deepEqual(refreshUrls, ['203.0.113.1', '203.0.113.2', '203.0.113.3']);
  const fourthBanner = fourthTab.doc.getElementById('proxycheck-pageinfo')!;
  assert.ok(fourthBanner.textContent.includes('Cached 110d ago'));
  const fourthBtn = fourthBanner.querySelector('.proxycheck-refetch-btn')!;
  assert.equal(fourthBtn.textContent, 'Refetch');
  assert.equal(fourthBtn.disabled, false);

  const rawLimiter = sharedMwStorage.get('proxycheck-auto-swr-timestamps-v1')!;
  const parsedLimiter = JSON.parse(rawLimiter) as unknown[];
  assert.equal(parsedLimiter.length, 3);
  assert.ok(parsedLimiter.every((entry) => typeof entry === 'number'));
  assert.equal(rawLimiter.includes('203.0.113'), false);
  assert.equal(rawLimiter.includes('AdminPatroller'), false);

  currentNowMs += 60_000;
  await openStaleContributionsTab('203.0.113.5');
  assert.deepEqual(refreshUrls, ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.5']);
});

test('Refresh preserves existing cached data and renders non-intrusive warning on degradedRefreshFallback or HTTP 429', async () => {
  const failureCases: Array<{ label: string; response: MockResponseSpec }> = [
    {
      label: 'degradedRefreshFallback',
      response: {
        status: 200,
        body: makeFullIpPayload('198.51.100.77', {
          arbitrationVerdict: 'Direct Connection (No Commercial Threats)',
          arbitrationTier: 'neutral',
          isMajorityProxyVpn: false,
          cacheMeta: { ageSeconds: 95 * 86400, isStale: true, shouldAutoRefresh: false, degradedRefreshFallback: true },
        }),
      },
    },
    {
      label: 'http429',
      response: {
        status: 429,
        body: { error: 'rate_limited', message: 'Refresh rate limit exceeded.', retryAfterSeconds: 42 },
      },
    },
  ];

  for (const scenario of failureCases) {
    const harness = createGadgetHarness({
      mwConfig: {
        wgCanonicalSpecialPageName: 'IPContributions',
        wgPageName: 'Special:IPContributions/198.51.100.77',
        wgTitle: 'IPContributions/198.51.100.77',
        wgRelevantUserName: '198.51.100.77',
      },
      onFetch(call) {
        if (call.url.endsWith('/api/v1/detect/refresh')) return scenario.response;
        return {
          status: 200,
          body: makeFullIpPayload('198.51.100.77', {
            arbitrationVerdict: 'Confirmed Proxy / VPN (5/5 Sources)',
            cacheMeta: { ageSeconds: 100 * 86400, isStale: true, shouldAutoRefresh: true },
          }),
        };
      },
    });

    await harness.runPendingTimers(600);

    const banner = harness.doc.getElementById('proxycheck-pageinfo')!;
    assert.ok(banner.textContent.includes('Confirmed Proxy / VPN (5/5 Sources)'), `Preserved for ${scenario.label}`);
    const refetchBtn = banner.querySelector('.proxycheck-refetch-btn')!;
    assert.equal(refetchBtn.textContent, 'Refetch');
    assert.equal(refetchBtn.disabled, false);

    const warning = banner.querySelector('.proxycheck-refresh-warning')!;
    assert.equal(warning.style.display, 'block');
    assert.ok(warning.textContent.includes('Preserving cached intelligence'));

    const persistedRaw = harness.localStorageMap.get('proxycheck-ip-result-cache-v1')!;
    assert.ok(persistedRaw.includes('Confirmed Proxy / VPN (5/5 Sources)'));
  }
});

test('Details panel renders privacy relay, CGNAT, residential proxy signals, soft-block Special:Block links, and desensitised Wikitext', async () => {
  const signalCases: Array<{ ip: string; overrides: AnyRecord; expectSoftBlock: boolean; expectedSnippets: string[] }> = [
    {
      ip: '172.224.226.10',
      overrides: {
        primaryAsn: 'AS14618',
        sharedPrivacyEgress: 'icloud_private_relay',
        recommendedCidr: '172.224.226.10/32',
        arbitrationVerdict: 'Shared Privacy Egress (iCloud Relay / WARP — Soft Block Recommended)',
        arbitrationTier: 'warning',
        isMajorityProxyVpn: false,
      },
      expectSoftBlock: true,
      expectedSnippets: ['Apple iCloud Private Relay', 'Soft / anon-only block recommended'],
    },
    {
      ip: '104.28.10.20',
      overrides: {
        primaryAsn: 'AS13335',
        sharedPrivacyEgress: 'cloudflare_warp',
        recommendedCidr: '104.28.10.20/32',
        arbitrationVerdict: 'Shared Privacy Egress (iCloud Relay / WARP — Soft Block Recommended)',
        arbitrationTier: 'warning',
        isMajorityProxyVpn: false,
      },
      expectSoftBlock: true,
      expectedSnippets: ['Cloudflare WARP', 'Soft / anon-only block recommended'],
    },
    {
      ip: '172.56.21.9',
      overrides: {
        primaryAsn: 'AS21928',
        isMobileOrCgnat: true,
        ptrCategory: 'mobile_or_cgnat',
        recommendedCidr: '172.56.21.9/32',
        cidrRationale: 'Mobile cellular or CGNAT network locked to /32 to avoid collateral damage',
      },
      expectSoftBlock: true,
      expectedSnippets: ['Mobile / CGNAT Network', '/32 (IPv4) or /64 (IPv6)'],
    },
    {
      ip: '2001:db8:abcd:1200::1',
      overrides: {
        primaryAsn: 'AS7922',
        suspectedResidentialProxy: true,
        recommendedCidr: '2001:db8:abcd:1200::/64',
        escalationCidr: '2001:db8:abcd:1200::/56',
        bgpPrefix: '2001:db8:abcd::/48',
        cidrRationale: 'Residential /56 escalation available within BGP /48',
        cacheMeta: { ageSeconds: 10 * 86400, isStale: false, shouldAutoRefresh: false, recommendFreshRecheck: true },
        results: [
          makeMockRow('MaxMind', {
            asn: 'AS7922',
            isp: 'Comcast Cable Communications',
            organisation: 'Comcast Cable Communications',
            location: 'Chicago, United States',
            usageType: 'Residential',
          }),
          makeMockRow('Shodan InternetDB', {
            usageType: 'Open Proxy Ports (1080, 8080)',
            openProxyPorts: [1080, 8080],
            securityFlags: [{ label: 'Open Proxy Ports (1080, 8080)', isHighRisk: true }],
          }),
          makeMockRow('GetIPIntel', {
            usageType: 'Proxy',
            securityFlags: [{ label: 'High Prediction (97.50%)', isHighRisk: true }],
          }),
        ],
      },
      expectSoftBlock: false,
      expectedSnippets: [
        'Suspected Residential Proxy / Compromised Host',
        'older than 7 days',
        'Shodan Open Proxy Ports: 1080, 8080',
        'Escalation: 2001:db8:abcd:1200::/56',
        'BGP: 2001:db8:abcd::/48',
        'Residential /56 escalation available within BGP /48',
      ],
    },
  ];

  for (const tc of signalCases) {
    const harness = createGadgetHarness({
      setupDom(doc) {
        const content = doc.createElement('div');
        content.id = 'mw-content-text';
        const anchor = doc.createElement('a');
        anchor.className = 'ext-checkuser-tempaccount-reveal-ip-anchor';
        anchor.textContent = tc.ip;
        content.appendChild(anchor);
        doc.body.appendChild(content);
      },
      onFetch() {
        return {
          status: 200,
          body: {
            queryMode: 'light',
            inputMap: {},
            results: {
              [tc.ip]: makeFullIpPayload(tc.ip, {
                fetchedAt: '2026-11-10T14:22:00+00:00',
                prediction_score: 97.5,
                getipintel_chance: 97.5,
                ...tc.overrides,
              }),
            },
          },
        };
      },
    });

    await harness.runPendingTimers(60);
    harness.doc.querySelector('.proxycheck-ip-badge')!.click();
    await harness.flushAsync();

    const dialog = harness.openDialogs[0].host;
    for (const snippet of tc.expectedSnippets) {
      assert.ok(dialog.textContent.includes(snippet), `Expected dialog for ${tc.ip} to include "${snippet}"`);
    }

    assert.ok(dialog.querySelector('.proxycheck-link-globalcontribs')!.href.includes(`Special:GlobalContributions/${tc.ip}`));
    assert.equal(dialog.querySelector('.proxycheck-link-rangeblock')!.href, `https://rangeblockfinder.toolforge.org/?ip=${encodeURIComponent(tc.ip)}`);
    assert.equal(dialog.querySelector('.proxycheck-link-whois')!.href, `https://whois.toolforge.org/gateway.py?lookup=true&ip=${encodeURIComponent(tc.ip)}`);

    const blockHref = dialog.querySelector('.proxycheck-link-block')!.href;
    const expectedCidr = String(tc.overrides.recommendedCidr);
    assert.ok(blockHref.includes(`Special:Block/${expectedCidr}`));
    if (tc.expectSoftBlock) {
      assert.ok(blockHref.includes('wpAnonOnly=1'));
      assert.ok(blockHref.includes('wpHardBlock=0'));
      assert.ok(blockHref.includes('wpDisableUTEdit=0'));
    } else {
      assert.equal(blockHref.includes('wpAnonOnly=1'), false);
    }

    dialog.querySelector('.proxycheck-copy-wikitext')!.click();
    await harness.flushAsync();

    const wikitext = harness.clipboardWrites[0];
    assert.ok(wikitext.includes(tc.ip));
    assert.ok(wikitext.includes(String(tc.overrides.primaryAsn)));
    assert.ok(wikitext.includes(expectedCidr));
    assert.ok(wikitext.includes('2026-11-10 UTC'));
    assert.equal(wikitext.includes('97.5'), false);
    assert.equal(wikitext.includes('87%'), false);
    assert.equal(wikitext.includes('GetIPIntel'), false);
    assert.equal(wikitext.includes('AbuseIPDB'), false);
  }
});
