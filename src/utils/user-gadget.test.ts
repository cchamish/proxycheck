import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const GADGET_PATH = path.resolve(process.cwd(), 'scripts/user-gadget.js');
const GADGET_SOURCE = fs.readFileSync(GADGET_PATH, 'utf8');

class MockNode {
  nodeType: number;
  ownerDocument: MockDocument;
  parentNode: MockElement | null = null;
  nextSibling: MockNode | null = null;
  previousSibling: MockNode | null = null;

  constructor(nodeType: number, ownerDocument: MockDocument) {
    this.nodeType = nodeType;
    this.ownerDocument = ownerDocument;
  }

  get isConnected(): boolean {
    if (Object.is(this, this.ownerDocument.documentElement)) {
      return true;
    }
    let cur: MockNode | null = this.parentNode;
    while (cur) {
      if (cur === this.ownerDocument.documentElement) {
        return true;
      }
      cur = cur.parentNode;
    }
    return false;
  }
}

class MockTextNode extends MockNode {
  nodeValue: string;

  constructor(text: string, ownerDocument: MockDocument) {
    super(3, ownerDocument);
    this.nodeValue = text;
  }

  get textContent(): string {
    return this.nodeValue;
  }

  set textContent(value: string) {
    this.nodeValue = String(value ?? '');
  }
}

function matchesSingleSelector(el: MockElement, rawSelector: string): boolean {
  const sel = rawSelector.trim();
  if (!sel) {
    return false;
  }
  const tokens = sel.match(/^(?:[a-zA-Z0-9_-]+)|(?:#[a-zA-Z0-9_-]+)|(?:\.[a-zA-Z0-9_-]+)/g);
  if (!tokens || tokens.join('') !== sel) {
    return false;
  }
  for (const token of tokens) {
    if (token.startsWith('#')) {
      if (el.id !== token.slice(1)) {
        return false;
      }
    } else if (token.startsWith('.')) {
      if (!el.classList.contains(token.slice(1))) {
        return false;
      }
    } else if (el.tagName.toLowerCase() !== token.toLowerCase()) {
      return false;
    }
  }
  return true;
}

class MockElement extends MockNode {
  tagName: string;
  childNodes: MockNode[] = [];
  attributes: Record<string, string> = {};
  dataset: Record<string, string> = {};
  style: Record<string, string> = {};
  listeners: Record<string, Array<(event: any) => void>> = {};
  id = '';
  href = '';
  title = '';
  target = '';
  rel = '';
  type = '';
  value = '';
  disabled = false;
  private classTokens: string[] = [];

  classList = {
    contains: (token: string) => this.classTokens.includes(token),
    add: (...tokens: string[]) => {
      for (const token of tokens) {
        const clean = String(token || '').trim();
        if (clean && !this.classTokens.includes(clean)) {
          this.classTokens.push(clean);
        }
      }
    },
    remove: (...tokens: string[]) => {
      const removeSet = new Set(tokens);
      this.classTokens = this.classTokens.filter((token) => !removeSet.has(token));
    },
  };

  constructor(tagName: string, ownerDocument: MockDocument) {
    super(1, ownerDocument);
    this.tagName = String(tagName || 'div').toUpperCase();
  }

  get className(): string {
    return this.classTokens.join(' ');
  }

  set className(value: string) {
    this.classTokens = String(value || '')
      .split(/\s+/)
      .filter(Boolean);
  }

  get children(): MockElement[] {
    return this.childNodes.filter((n): n is MockElement => n.nodeType === 1);
  }

  get nextElementSibling(): MockElement | null {
    let cur = this.nextSibling;
    while (cur) {
      if (cur.nodeType === 1) {
        return cur as MockElement;
      }
      cur = cur.nextSibling;
    }
    return null;
  }

  get previousElementSibling(): MockElement | null {
    let cur = this.previousSibling;
    while (cur) {
      if (cur.nodeType === 1) {
        return cur as MockElement;
      }
      cur = cur.previousSibling;
    }
    return null;
  }

  get textContent(): string {
    return this.childNodes
      .map((node) => (node instanceof MockTextNode ? node.nodeValue : (node as MockElement).textContent))
      .join('');
  }

  set textContent(value: string) {
    while (this.childNodes.length > 0) {
      this.removeChild(this.childNodes[0]!);
    }
    const str = String(value ?? '');
    if (str.length > 0) {
      this.appendChild(new MockTextNode(str, this.ownerDocument));
    }
  }

  private relinkChildren(): void {
    for (let i = 0; i < this.childNodes.length; i += 1) {
      const cur = this.childNodes[i]!;
      cur.previousSibling = i > 0 ? this.childNodes[i - 1]! : null;
      cur.nextSibling = i + 1 < this.childNodes.length ? this.childNodes[i + 1]! : null;
    }
  }

  appendChild<T extends MockNode>(node: T): T {
    return this.insertBefore(node, null);
  }

  insertBefore<T extends MockNode>(node: T, referenceNode: MockNode | null): T {
    if (node.parentNode) {
      node.parentNode.removeChild(node);
    }
    node.parentNode = this;
    if (!referenceNode) {
      this.childNodes.push(node);
    } else {
      const idx = this.childNodes.indexOf(referenceNode);
      if (idx === -1) {
        this.childNodes.push(node);
      } else {
        this.childNodes.splice(idx, 0, node);
      }
    }
    this.relinkChildren();
    return node;
  }

  removeChild<T extends MockNode>(node: T): T {
    const idx = this.childNodes.indexOf(node);
    if (idx !== -1) {
      this.childNodes.splice(idx, 1);
      node.parentNode = null;
      node.previousSibling = null;
      node.nextSibling = null;
      this.relinkChildren();
    }
    return node;
  }

  setAttribute(name: string, val: string): void {
    const str = String(val);
    this.attributes[name] = str;
    if (name === 'id') {
      this.id = str;
    } else if (name === 'class') {
      this.className = str;
    } else if (name === 'href') {
      this.href = str;
    } else if (name === 'title') {
      this.title = str;
    }
  }

  getAttribute(name: string): string | null {
    if (name === 'class') {
      return this.className || null;
    }
    if (name === 'id') {
      return this.id || null;
    }
    return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name]! : null;
  }

  removeAttribute(name: string): void {
    delete this.attributes[name];
    if (name === 'title') {
      this.title = '';
    } else if (name === 'target') {
      this.target = '';
    } else if (name === 'rel') {
      this.rel = '';
    }
  }

  matches(selector: string): boolean {
    return selector.split(',').some((part) => matchesSingleSelector(this, part));
  }

  closest(selector: string): MockElement | null {
    if (this.matches(selector)) {
      return this;
    }
    let cur: MockElement | null = this.parentNode;
    while (cur) {
      if (cur.matches(selector)) {
        return cur;
      }
      cur = cur.parentNode;
    }
    return null;
  }

  querySelectorAll(selector: string): MockElement[] {
    const results: MockElement[] = [];
    const visit = (node: MockElement): void => {
      for (const child of node.children) {
        if (child.matches(selector)) {
          results.push(child);
        }
        visit(child);
      }
    };
    visit(this);
    return results;
  }

  querySelector(selector: string): MockElement | null {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  contains(other: MockNode | null): boolean {
    let cur = other;
    while (cur) {
      if (cur === this) {
        return true;
      }
      cur = cur.parentNode;
    }
    return false;
  }

  addEventListener(event: string, fn: (e: any) => void): void {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event]!.push(fn);
  }

  click(): void {
    const event = {
      type: 'click',
      target: this,
      currentTarget: this,
      preventDefault() {},
      stopPropagation() {},
    };
    for (const listener of this.listeners.click ?? []) {
      listener(event);
    }
  }

  select(): void {}
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
    this.documentElement.appendChild(this.head);
    this.documentElement.appendChild(this.body);
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

  addEventListener(): void {}
  removeEventListener(): void {}
  execCommand(): boolean {
    return true;
  }
}

function createJQuery(doc: MockDocument, readyQueue: Array<() => void>) {
  function wrap(elements: MockElement[]): any {
    const col: any = {
      length: elements.length,
      append(...items: any[]) {
        const parent = elements[0];
        if (!parent) {
          return col;
        }
        for (const item of items) {
          if (item === null || item === undefined) {
            continue;
          }
          if (item instanceof MockNode) {
            parent.appendChild(item);
          } else if (typeof item === 'object' && typeof item.length === 'number') {
            for (let i = 0; i < item.length; i += 1) {
              if (item[i] instanceof MockNode) {
                parent.appendChild(item[i]);
              }
            }
          } else {
            parent.appendChild(doc.createTextNode(String(item)));
          }
        }
        return col;
      },
      appendTo(target: any) {
        $(target).append(col);
        return col;
      },
      prepend(item: any) {
        const parent = elements[0];
        if (parent) {
          const nodes = item instanceof MockNode ? [item] : [item?.[0]].filter(Boolean);
          for (const n of nodes) {
            parent.insertBefore(n, parent.childNodes[0] ?? null);
          }
        }
        return col;
      },
      before(item: any) {
        const ref = elements[0];
        if (ref?.parentNode) {
          const n = item instanceof MockNode ? item : item?.[0];
          if (n) {
            ref.parentNode.insertBefore(n, ref);
          }
        }
        return col;
      },
      after(item: any) {
        const ref = elements[0];
        if (ref?.parentNode) {
          const n = item instanceof MockNode ? item : item?.[0];
          if (n) {
            ref.parentNode.insertBefore(n, ref.nextSibling);
          }
        }
        return col;
      },
      empty() {
        for (const el of elements) {
          while (el.childNodes.length > 0) {
            el.removeChild(el.childNodes[0]!);
          }
        }
        return col;
      },
      remove() {
        for (const el of elements) {
          if (el.parentNode) {
            el.parentNode.removeChild(el);
          }
        }
        return col;
      },
      text(val?: string) {
        if (val === undefined) {
          return elements.map((el) => el.textContent).join('');
        }
        for (const el of elements) {
          el.textContent = String(val);
        }
        return col;
      },
      attr(name: string, val?: string) {
        if (val === undefined) {
          return elements[0]?.getAttribute(name) ?? undefined;
        }
        for (const el of elements) {
          el.setAttribute(name, val);
        }
        return col;
      },
      prop(name: string, val?: any) {
        if (val === undefined) {
          return elements[0] ? (elements[0] as any)[name] : undefined;
        }
        for (const el of elements) {
          (el as any)[name] = val;
        }
        return col;
      },
      css(propOrMap: string | Record<string, string>, val?: string) {
        const map = typeof propOrMap === 'string' ? { [propOrMap]: String(val ?? '') } : propOrMap;
        for (const el of elements) {
          Object.assign(el.style, map);
        }
        return col;
      },
      addClass(cls: string) {
        const parts = String(cls || '').split(/\s+/).filter(Boolean);
        for (const el of elements) {
          el.classList.add(...parts);
        }
        return col;
      },
      removeClass(cls: string) {
        const parts = String(cls || '').split(/\s+/).filter(Boolean);
        for (const el of elements) {
          el.classList.remove(...parts);
        }
        return col;
      },
      find(sel: string) {
        const found: MockElement[] = [];
        for (const el of elements) {
          found.push(...el.querySelectorAll(sel));
        }
        return wrap(found);
      },
      first() {
        return wrap(elements[0] ? [elements[0]] : []);
      },
      parent() {
        return wrap(elements[0]?.parentNode ? [elements[0].parentNode] : []);
      },
      closest(sel: string) {
        const match = elements[0]?.closest(sel);
        return wrap(match ? [match] : []);
      },
      each(fn: (idx: number, el: MockElement) => void) {
        elements.forEach((el, idx) => fn(idx, el));
        return col;
      },
      on(event: string, fn: (e: any) => void) {
        for (const el of elements) {
          el.addEventListener(event, fn);
        }
        return col;
      },
    };
    elements.forEach((el, idx) => {
      col[idx] = el;
    });
    return col;
  }

  function $(input: any, attrs?: Record<string, any>): any {
    if (typeof input === 'function') {
      readyQueue.push(input);
      return wrap([]);
    }
    if (!input) {
      return wrap([]);
    }
    if (input instanceof MockElement) {
      return wrap([input]);
    }
    if (typeof input === 'string') {
      const tagMatch = input.match(/^<([a-zA-Z0-9_-]+)>$/);
      if (tagMatch) {
        const el = doc.createElement(tagMatch[1]!);
        if (attrs) {
          for (const [k, v] of Object.entries(attrs)) {
            if (k === 'text') {
              el.textContent = String(v);
            } else if (k === 'class') {
              el.className = String(v);
            } else if (k === 'css' && typeof v === 'object') {
              Object.assign(el.style, v);
            } else {
              el.setAttribute(k, String(v));
              (el as any)[k] = v;
            }
          }
        }
        return wrap([el]);
      }
      return wrap(doc.documentElement.querySelectorAll(input));
    }
    if (typeof input === 'object' && typeof input.length === 'number') {
      const list: MockElement[] = [];
      for (let i = 0; i < input.length; i += 1) {
        if (input[i] instanceof MockElement) {
          list.push(input[i]);
        }
      }
      return wrap(list);
    }
    return wrap([]);
  }
  return $;
}

function makeFullPayload(ip: string, predictionPercent = 1): Record<string, any> {
  return {
    ip,
    queryMode: 'full',
    isPartialMode: false,
    isNonPublic: false,
    asn: 'AS15169',
    isp: 'Google LLC',
    organisation: 'Google LLC',
    location: 'United States',
    recommendedCidr: ip.includes(':') ? `${ip}/64` : `${ip}/32`,
    bgpPrefix: ip.includes(':') ? '2001:db8::/48' : '8.8.8.0/24',
    getipintel_chance: predictionPercent / 100,
    prediction_score: predictionPercent,
    isTor: false,
    is_broadcast_ip: false,
    isMajorityProxyVpn: false,
    results: [
      {
        provider: 'MaxMind',
        status: '200 OK',
        statusCode: 200,
        asn: 'AS15169',
        isp: 'Google LLC',
        organisation: 'Google LLC',
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
      {
        provider: 'Proxycheck',
        status: '200 OK',
        statusCode: 200,
        asn: 'AS15169',
        isp: 'Google LLC',
        securityFlags: [{ label: 'No Flags', isHighRisk: false }],
      },
    ],
    cacheMeta: {
      status: 'hit',
      layer: 'L1',
      isStale: false,
      shouldAutoRefresh: false,
      fetchedAt: '2026-11-20T00:00:00Z',
    },
  };
}

interface HarnessOptions {
  preConsent?: boolean;
  confirmResult?: boolean;
  fetchHandler: (url: string, init?: any) => Promise<any> | any;
  setupDom?: (doc: MockDocument) => void;
}

function createGadgetHarness(opts: HarnessOptions) {
  const doc = new MockDocument();
  opts.setupDom?.(doc);

  const localStorageMap = new Map<string, string>();
  const sessionStorageMap = new Map<string, string>();
  if (opts.preConsent !== false) {
    localStorageMap.set('proxycheck-ip-policy-consent', '1');
  }

  const fetchCalls: Array<{ url: string; init?: any }> = [];
  const alertCalls: Array<{ $message: any; options: any; resolve: () => void }> = [];
  const confirmCalls: any[] = [];
  const centralAuthCalls: number[] = [];
  const readyQueue: Array<() => void> = [];
  const pendingTimers = new Map<number, () => void>();
  let nextTimerId = 1;

  const win: any = {
    location: { search: '', href: 'https://en.wikipedia.org/wiki/Special:RecentChanges' },
    setTimeout(fn: () => void) {
      const id = nextTimerId++;
      pendingTimers.set(id, fn);
      return id;
    },
    clearTimeout(id: number) {
      pendingTimers.delete(id);
    },
    setInterval(fn: () => void) {
      const id = nextTimerId++;
      pendingTimers.set(id, fn);
      return id;
    },
    clearInterval(id: number) {
      pendingTimers.delete(id);
    },
  };

  class MockApi {
    get(params: Record<string, any>) {
      if (params.action === 'centralauthtoken') {
        centralAuthCalls.push(1);
        return Promise.resolve({ centralauthtoken: { centralauthtoken: `cat-${centralAuthCalls.length}` } });
      }
      return Promise.resolve({});
    }
  }

  class MockMutationObserver {
    observe() {}
    disconnect() {}
  }

  const mwConfig: Record<string, any> = {
    wgUserName: 'PatrollerUser',
    wgUserIsTemp: false,
    wgServerName: 'en.wikipedia.org',
    wgCanonicalSpecialPageName: 'Recentchanges',
    wgPageName: 'Special:RecentChanges',
    wgArticlePath: '/wiki/$1',
  };

  const sandbox: any = {
    window: win,
    document: doc,
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    console: { warn: () => {}, error: () => {}, log: () => {} },
    Date,
    URL,
    URLSearchParams,
    MutationObserver: MockMutationObserver,
    setTimeout: win.setTimeout,
    clearTimeout: win.clearTimeout,
    setInterval: win.setInterval,
    clearInterval: win.clearInterval,
    fetch: (url: string, init?: any) => {
      fetchCalls.push({ url, init });
      return Promise.resolve(opts.fetchHandler(url, init));
    },
    mediaWiki: {
      config: { get: (k: string) => mwConfig[k] },
      storage: {
        get: (k: string) => localStorageMap.get(k) ?? null,
        set: (k: string, v: string) => localStorageMap.set(k, String(v)),
        remove: (k: string) => localStorageMap.delete(k),
        session: {
          get: (k: string) => sessionStorageMap.get(k) ?? null,
          set: (k: string, v: string) => sessionStorageMap.set(k, String(v)),
          remove: (k: string) => sessionStorageMap.delete(k),
        },
      },
      loader: { using: () => Promise.resolve() },
      util: {
        getUrl: (title: string) => `/wiki/${title}`,
        getParamValue: () => null,
        isTemporaryUser: (name: string) => /^~\d{4}-/.test(name),
      },
      hook: () => ({ add: () => {} }),
      Api: MockApi,
    },
    OO: {
      ui: {
        confirm: ($msg: any) => {
          confirmCalls.push($msg);
          return Promise.resolve(opts.confirmResult ?? true);
        },
        alert: ($message: any, options: any) => {
          return new Promise<void>((resolve) => {
            alertCalls.push({ $message, options, resolve });
          });
        },
      },
    },
    jQuery: createJQuery(doc, readyQueue),
  };
  sandbox.mw = sandbox.mediaWiki;
  sandbox.$ = sandbox.jQuery;
  win.document = doc;
  win.mediaWiki = sandbox.mediaWiki;
  win.OO = sandbox.OO;
  win.jQuery = sandbox.jQuery;

  vm.runInNewContext(GADGET_SOURCE, sandbox);
  for (const fn of readyQueue) {
    fn();
  }

  return {
    doc,
    localStorageMap,
    sessionStorageMap,
    fetchCalls,
    alertCalls,
    confirmCalls,
    centralAuthCalls,
    async flushAsync() {
      for (let i = 0; i < 6; i += 1) {
        await new Promise((resolve) => setImmediate(resolve));
      }
    },
    runPendingTimers() {
      const fns = Array.from(pendingTimers.entries());
      pendingTimers.clear();
      for (const [, fn] of fns) {
        fn();
      }
    },
  };
}

function addRevealAnchor(doc: MockDocument, ip: string): MockElement {
  const row = doc.createElement('li');
  const anchor = doc.createElement('a');
  anchor.className = 'ext-checkuser-tempaccount-reveal-ip-anchor';
  anchor.textContent = ip;
  row.appendChild(anchor);
  doc.body.appendChild(row);
  return anchor;
}

test('excludes XSS and MediaWiki privacy APIs while splitting batches at MAX_BATCH_IPS = 10', async () => {
  assert.doesNotMatch(GADGET_SOURCE, /\.innerHTML\b|\.outerHTML\b|document\.write/);
  assert.doesNotMatch(GADGET_SOURCE, /checkuser-temporary-account|checkusertempaccount|globaluserinfo/);
  assert.match(GADGET_SOURCE, /mw\.storage\.session/);

  const batchBodies: string[][] = [];
  const harness = createGadgetHarness({
    setupDom(doc) {
      for (let i = 1; i <= 12; i += 1) {
        addRevealAnchor(doc, `198.51.100.${i}`);
      }
    },
    fetchHandler(url, init) {
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return { ok: true, status: 200, json: async () => ({ token: 'tok-batch', expires_in: 900 }) };
      }
      if (url.includes('/api/v1/detect/batch')) {
        const body = JSON.parse(init.body);
        batchBodies.push(body.ips);
        const results: Record<string, any> = {};
        for (const ip of body.ips) {
          results[ip] = makeFullPayload(ip);
        }
        return { ok: true, status: 200, json: async () => ({ queryMode: 'light', results, inputMap: {} }) };
      }
      return { ok: false, status: 404, text: async () => 'not found' };
    },
  });

  await harness.flushAsync();
  assert.equal(batchBodies.length, 1);
  assert.equal(batchBodies[0]!.length, 10);

  harness.runPendingTimers();
  await harness.flushAsync();
  assert.equal(batchBodies.length, 2);
  assert.equal(batchBodies[1]!.length, 2);
});

test('manages CentralAuth token in session storage, retries 401 once, and blocks cleanly on 403', async () => {
  let tokenSeq = 0;
  let batchAttempt = 0;
  let anchor401!: MockElement;

  const retryHarness = createGadgetHarness({
    setupDom(doc) {
      anchor401 = addRevealAnchor(doc, '8.8.8.8');
    },
    fetchHandler(url) {
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        tokenSeq += 1;
        return { ok: true, status: 200, json: async () => ({ token: `tok-${tokenSeq}`, expires_in: 900 }) };
      }
      if (url.includes('/api/v1/detect/batch')) {
        batchAttempt += 1;
        if (batchAttempt === 1) {
          return { ok: false, status: 401, text: async () => 'expired' };
        }
        return { ok: true, status: 200, json: async () => ({ results: { '8.8.8.8': makeFullPayload('8.8.8.8', 12) } }) };
      }
      return { ok: false, status: 500, text: async () => 'err' };
    },
  });

  await retryHarness.flushAsync();
  retryHarness.runPendingTimers();
  await retryHarness.flushAsync();

  const batchCalls = retryHarness.fetchCalls.filter((c) => c.url.includes('/api/v1/detect/batch'));
  assert.equal(batchCalls.length, 2);
  assert.equal(batchCalls[0]!.init.headers.Authorization, 'Bearer tok-1');
  assert.equal(batchCalls[1]!.init.headers.Authorization, 'Bearer tok-2');
  assert.equal(retryHarness.sessionStorageMap.get('proxycheck-gadget-token'), 'tok-2');
  assert.equal(retryHarness.localStorageMap.has('proxycheck-gadget-token'), false);
  assert.equal(anchor401.nextElementSibling?.textContent, '[12%]');

  let blockedAnchor!: MockElement;
  const blockHarness = createGadgetHarness({
    setupDom(doc) {
      blockedAnchor = addRevealAnchor(doc, '8.8.4.4');
    },
    fetchHandler(url) {
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return { ok: false, status: 403, text: async () => 'forbidden' };
      }
      return { ok: false, status: 403, text: async () => 'forbidden' };
    },
  });

  assert.equal(blockedAnchor.nextElementSibling?.textContent, '[…]');
  await blockHarness.flushAsync();
  blockHarness.runPendingTimers();
  await blockHarness.flushAsync();
  assert.equal(blockHarness.doc.body.querySelectorAll('.proxycheck-ip-badge-loading').length, 0);
  assert.equal(blockedAnchor.nextElementSibling, null);
  assert.equal(blockedAnchor.dataset.proxycheckProcessed, undefined);
});

test('renders immediate placeholder badges, updates in place on backfill, and recovers via Retry', async () => {
  let resolveBatch!: (val: any) => void;
  let shouldFailBatch = false;
  let anchor!: MockElement;

  const harness = createGadgetHarness({
    setupDom(doc) {
      anchor = addRevealAnchor(doc, '203.0.113.10');
    },
    fetchHandler(url) {
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return { ok: true, status: 200, json: async () => ({ token: 'tok-live', expires_in: 900 }) };
      }
      if (url.includes('/api/v1/detect/batch')) {
        if (shouldFailBatch) {
          return { ok: false, status: 500, text: async () => 'upstream fail' };
        }
        return new Promise((resolve) => {
          resolveBatch = resolve;
        });
      }
      return { ok: false, status: 404, text: async () => 'not found' };
    },
  });

  const placeholder = anchor.nextElementSibling;
  assert.ok(placeholder);
  assert.equal(placeholder.textContent, '[…]');
  assert.equal(placeholder.classList.contains('proxycheck-ip-badge-loading'), true);
  assert.equal(placeholder.getAttribute('aria-busy'), 'true');

  await harness.flushAsync();
  harness.runPendingTimers();
  await harness.flushAsync();
  assert.equal(typeof resolveBatch, 'function');

  resolveBatch({
    ok: true,
    status: 200,
    json: async () => ({ results: { '203.0.113.10': makeFullPayload('203.0.113.10', 99) } }),
  });
  await harness.flushAsync();

  assert.strictEqual(anchor.nextElementSibling, placeholder);
  assert.equal(placeholder.textContent, '[99%]');
  assert.equal(placeholder.getAttribute('aria-busy'), null);
  assert.equal(placeholder.classList.contains('proxycheck-tier-high'), true);

  let retryAnchor!: MockElement;
  shouldFailBatch = true;
  const failHarness = createGadgetHarness({
    setupDom(doc) {
      retryAnchor = addRevealAnchor(doc, '203.0.113.20');
    },
    fetchHandler(url) {
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return { ok: true, status: 200, json: async () => ({ token: 'tok-live', expires_in: 900 }) };
      }
      if (url.includes('/api/v1/detect/batch')) {
        if (shouldFailBatch) {
          return { ok: false, status: 500, text: async () => 'upstream fail' };
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ results: { '203.0.113.20': makeFullPayload('203.0.113.20', 5) } }),
        };
      }
      return { ok: false, status: 404, text: async () => 'not found' };
    },
  });

  const retryPlaceholder = retryAnchor.nextElementSibling!;
  await failHarness.flushAsync();
  failHarness.runPendingTimers();
  await failHarness.flushAsync();

  assert.strictEqual(retryAnchor.nextElementSibling, retryPlaceholder);
  assert.equal(retryPlaceholder.textContent, '[Retry]');
  assert.equal(retryPlaceholder.classList.contains('proxycheck-ip-badge-error'), true);

  shouldFailBatch = false;
  retryPlaceholder.click();
  await failHarness.flushAsync();
  failHarness.runPendingTimers();
  await failHarness.flushAsync();

  assert.equal(retryAnchor.nextElementSibling?.textContent, '[5%]');
  assert.equal(retryAnchor.nextElementSibling?.classList.contains('proxycheck-tier-low'), true);
});

test('renders non-public [LOCAL] and light badges, upgrades on dialog open, and sends compact Refetch', async () => {
  let localAnchor!: MockElement;
  let publicAnchor!: MockElement;
  const refreshBodies: any[] = [];

  const harness = createGadgetHarness({
    setupDom(doc) {
      localAnchor = addRevealAnchor(doc, '127.0.0.1');
      publicAnchor = addRevealAnchor(doc, '8.8.8.8');
    },
    fetchHandler(url, init) {
      if (url.endsWith('/api/v1/auth/gadget-token')) {
        return { ok: true, status: 200, json: async () => ({ token: 'tok-core', expires_in: 900 }) };
      }
      if (url.includes('/api/v1/detect/batch')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            queryMode: 'light',
            results: {
              '127.0.0.1': {
                ip: '127.0.0.1',
                isNonPublic: true,
                nonPublicCategory: 'loopback',
                nonPublicReason: 'Loopback address',
                results: [],
              },
              '8.8.8.8': {
                ip: '8.8.8.8',
                queryMode: 'light',
                isPartialMode: true,
                isNonPublic: false,
                asn: '-',
                isp: '-',
                getipintel_chance: null,
                results: [
                  {
                    provider: 'MaxMind',
                    status: '200 OK',
                    statusCode: 200,
                    asn: '-',
                    isp: '-',
                    securityFlags: [{ label: 'No Flags', isHighRisk: false }],
                  },
                ],
                cacheMeta: { status: 'hit', layer: 'L1', isStale: false, shouldAutoRefresh: false },
              },
            },
          }),
        };
      }
      if (url.includes('/api/v1/detect?ip=')) {
        assert.match(url, /compact=1/);
        assert.match(url, /mode=full/);
        return { ok: true, status: 200, json: async () => makeFullPayload('8.8.8.8', 45) };
      }
      if (url.endsWith('/api/v1/detect/refresh')) {
        refreshBodies.push(JSON.parse(init.body));
        return { ok: true, status: 200, json: async () => makeFullPayload('8.8.8.8', 25) };
      }
      return { ok: false, status: 404, text: async () => 'not found' };
    },
  });

  await harness.flushAsync();
  harness.runPendingTimers();
  await harness.flushAsync();

  assert.equal(localAnchor.nextElementSibling?.textContent, '[LOCAL]');
  const lightBadge = publicAnchor.nextElementSibling!;
  assert.equal(lightBadge.textContent, '[LIGHT]');

  lightBadge.click();
  await harness.flushAsync();

  assert.equal(harness.alertCalls.length, 1);
  assert.equal(lightBadge.textContent, '[45%]');
  assert.equal(
    harness.fetchCalls.some((c) => c.url.includes('/api/v1/detect?ip=8.8.8.8&compact=1&mode=full')),
    true
  );

  const refetchBtn = harness.alertCalls[0]!.$message.find('.proxycheck-refetch-btn')[0];
  assert.ok(refetchBtn);
  refetchBtn.click();
  await harness.flushAsync();

  assert.deepEqual(refreshBodies, [{ ip: '8.8.8.8', mode: 'full', compact: true }]);
  assert.match(harness.alertCalls[0]!.$message.text(), /25%|0\.25|Google/);
  harness.alertCalls[0]!.resolve();
  await harness.flushAsync();
});
