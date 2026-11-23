import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { JSDOM } from 'jsdom';

const gadgetSource = readFileSync(new URL('./user-gadget.js', import.meta.url), 'utf8');
const jquerySource = readFileSync(new URL('../node_modules/jquery/dist/jquery.js', import.meta.url), 'utf8');

async function badgedRevealedIps(ips: string[]): Promise<string[]> {
  const anchors = ips.map((ip) => `<a class="ext-checkuser-tempaccount-reveal-ip-anchor">${ip}</a>`).join(' ');
  const dom = new JSDOM(`<!DOCTYPE html><body>${anchors}</body>`, { runScripts: 'outside-only', url: 'https://en.wikipedia.org/wiki/Special:RecentChanges' });
  const { window } = dom;
  const values: Record<string, unknown> = { wgUserName: 'Example', wgDBname: 'enwiki' };
  Object.assign(window, {
    mediaWiki: {
      config: { get: (key: string) => values[key] ?? null },
      storage: { get: () => null, set: () => true, remove: () => true },
      loader: { using: () => new Promise(() => {}) },
    },
  });
  window.eval(jquerySource);
  window.eval(gadgetSource);
  await new Promise((resolve) => (window as unknown as { jQuery: (ready: () => void) => void }).jQuery(() => resolve(null)));

  const badged = [...window.document.querySelectorAll('.ext-checkuser-tempaccount-reveal-ip-anchor')]
    .filter((anchor) => anchor.nextElementSibling?.classList.contains('proxycheck-ip-badge'))
    .map((anchor) => anchor.textContent ?? '');
  window.close();
  return badged;
}

test('badges revealed IPv6 addresses written with an IPv4 tail', async () => {
  const valid = [
    '2001:db8:0:0:0:0:8.8.8.8', '2001:db8::8.8.8.8', '::ffff:1.2.3.4', '::8.8.8.8',
    '2001:DB8::192.0.2.255', '1:2:3:4:5:6:0.0.0.0', '::255.255.255.255',
    '2001:db8::808:808', '8.8.8.8',
  ];
  assert.deepEqual(await badgedRevealedIps(valid), valid);
});

test('does not badge malformed IPv4 tails', async () => {
  const invalid = [
    '2001:db8::256.8.8.8', '::ffff:1.2.3', '::ffff:1.2.3.4.5', '::ffff:01.2.3.4',
    '::ffff:1.2.3.-4', '::ffff:1.2.3.4junk', '1:2:3:4:5:8.8.8.8', '1:2:3:4:5:6:7:8.8.8.8',
    '1:2:3:4:5:6::8.8.8.8', '2001:::8.8.8.8', '1.2.3.4::',
  ];
  assert.deepEqual(await badgedRevealedIps(invalid), []);
});
