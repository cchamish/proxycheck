<template>
  <section class="rb-finder" aria-label="Cross-Wiki Rangeblock Finder">
    <cdx-message v-if="errorMessage" type="error" :inline="false">
      {{ errorMessage }}
    </cdx-message>

    <cdx-message v-else-if="isLoading" type="notice" :inline="false">
      Querying cross-wiki rangeblock aggregates and Wiki Replicas...
    </cdx-message>

    <template v-else-if="rangeblock">
      <div class="rb-header">
        <div class="rb-header__title">
          <h2 class="card-heading">Cross-Wiki Rangeblock Finder</h2>
          <cdx-info-chip :status="rangeblock.hasActive ? 'error' : 'notice'">
            rangeblock: {{ rangeblock.localTotal }}/{{ rangeblock.globalTotal }}
          </cdx-info-chip>
        </div>
        <span class="text-subtle">
          {{
            rangeblock.ipVersion === 6
              ? 'IPv6 scope: single IP and /64–/19 (47 targets; /127–/65 excluded)'
              : 'IPv4 scope: single IP and /32–/16 (18 targets)'
          }}
        </span>
      </div>

      <cdx-message v-if="rangeblock.realtimeDegraded" type="warning" :inline="false">
        Real-time Wiki Replicas lookup was temporarily unavailable; displaying cached ToolsDB aggregate records.
      </cdx-message>

      <div class="rb-filters">
        <cdx-toggle-button-group
          v-model="selectedWikiValue"
          :buttons="wikiButtons"
        />
        <cdx-toggle-switch v-if="selectedWikiSummary" v-model="showFullLadder">
          Show full CIDR ladder
        </cdx-toggle-switch>
      </div>

      <cdx-table
        caption="Rangeblock records"
        :hide-caption="true"
        :columns="rbColumns"
        :data="tableRows"
      >
        <template #item-target="{ row }">
          <code>{{ row.hit.target }}</code>
        </template>
        <template #item-upperBound="{ row }">
          <code>{{ row.hit.upperBound }}</code>
        </template>
        <template #item-status="{ row }">
          <cdx-info-chip v-if="row.hit.isActive" status="error">
            Active · {{ row.hit.indefinite ? 'Indefinite' : (formatExactUtcTimestamp(row.hit.expiry) || 'Active') }}
          </cdx-info-chip>
          <cdx-info-chip v-else-if="row.hit.count > 0" status="notice">
            Historical
          </cdx-info-chip>
          <span v-else class="text-subtle">-</span>
        </template>
        <template #item-count="{ row }">
          <strong>{{ row.hit.count }}</strong>
        </template>
        <template #item-links="{ row }">
          <div class="inline-group">
            <a :href="row.hit.logUrl" target="_blank" rel="noopener noreferrer">Special:Log</a>
            <a :href="row.hit.blockListUrl" target="_blank" rel="noopener noreferrer">
              {{ row.wiki === 'global' ? 'Special:GlobalBlockList' : 'Special:BlockList' }}
            </a>
          </div>
        </template>
        <template #empty-state>
          No rangeblock or single-IP block records found for {{ rangeblock.ip }}.
        </template>
      </cdx-table>
    </template>

    <p v-else class="text-subtle">
      Enter an IPv4 or IPv6 address above to inspect cross-wiki blocks without consuming commercial API quota.
    </p>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import {
  CdxInfoChip,
  CdxMessage,
  CdxTable,
  CdxToggleButtonGroup,
  CdxToggleSwitch,
  type ButtonGroupItem,
  type TableColumn,
} from '@wikimedia/codex';
import {
  canonicalizeIpAddress,
  formatExactUtcTimestamp,
  type RangeblockHitRow,
  type RangeblockSummary,
  type RangeblockWikiSummary,
} from '../utils/ip-detector-logic';

const props = defineProps<{
  rangeblock: RangeblockSummary | null;
  selectedWiki: string | null;
  isLoading: boolean;
  errorMessage: string;
}>();

const emit = defineEmits<{
  (event: 'select-wiki', wiki: string | null): void;
}>();

const ALL_WIKIS_VALUE = '__all__';

const rbColumns: TableColumn[] = [
  { id: 'wiki', label: 'Wiki' },
  { id: 'target', label: 'Target' },
  { id: 'cidr', label: 'CIDR' },
  { id: 'upperBound', label: 'Upper bound' },
  { id: 'status', label: 'Status' },
  { id: 'count', label: 'Blocks' },
  { id: 'links', label: 'Links' },
];

const showFullLadder = ref(false);

const selectedWikiValue = computed<string>({
  get: () => props.selectedWiki ?? ALL_WIKIS_VALUE,
  set: (value) => emit('select-wiki', value === ALL_WIKIS_VALUE ? null : value),
});

const wikiButtons = computed<ButtonGroupItem[]>(() => [
  { value: ALL_WIKIS_VALUE, label: `All Hits (${props.rangeblock?.wikis.length ?? 0})` },
  ...(props.rangeblock?.wikis ?? []).map((item) => ({
    value: item.wiki,
    label: `${item.wiki}${item.hasActive ? ' (active)' : ''} · ${item.count}`,
  })),
]);

watch(
  () => props.selectedWiki,
  (nextWiki) => {
    if (!nextWiki) showFullLadder.value = false;
  }
);

const selectedWikiSummary = computed<RangeblockWikiSummary | null>(() => {
  if (!props.rangeblock || !props.selectedWiki) return null;
  return props.rangeblock.wikis.find((w) => w.wiki === props.selectedWiki) ?? null;
});

function buildFullCidrLadder(rawIp: string, wikiSummary: RangeblockWikiSummary): RangeblockHitRow[] {
  const canonical = canonicalizeIpAddress(rawIp)?.split('%')[0] ?? '';
  if (!canonical) return wikiSummary.rows;

  const hitByTarget = new Map(wikiSummary.rows.map((row) => [row.target, row]));
  const isV6 = canonical.includes(':');
  const maxBits = isV6 ? 128n : 32n;
  const allMask = (1n << maxBits) - 1n;

  let addrInt = 0n;
  if (isV6) {
    const [leftRaw, rightRaw] = canonical.split('::');
    const left = leftRaw ? leftRaw.split(':') : [];
    const right = canonical.includes('::') && rightRaw ? rightRaw.split(':') : [];
    const missing = canonical.includes('::') ? Math.max(0, 8 - (left.length + right.length)) : 0;
    const groups = [...left, ...Array.from({ length: missing }, () => '0'), ...right];
    for (const g of groups) {
      addrInt = (addrInt << 16n) | BigInt(parseInt(g || '0', 16));
    }
  } else {
    const parts = canonical.split('.').map((part) => BigInt(Number(part)));
    addrInt = (parts[0]! << 24n) | (parts[1]! << 16n) | (parts[2]! << 8n) | parts[3]!;
  }

  const formatAddr = (val: bigint): string => {
    if (!isV6) {
      return [
        Number((val >> 24n) & 0xffn),
        Number((val >> 16n) & 0xffn),
        Number((val >> 8n) & 0xffn),
        Number(val & 0xffn),
      ].join('.');
    }
    const groups: string[] = [];
    for (let i = 7; i >= 0; i -= 1) {
      groups.push(((val >> BigInt(i * 16)) & 0xffffn).toString(16));
    }
    return canonicalizeIpAddress(groups.join(':')) ?? groups.join(':');
  };

  const makeRow = (target: string, cidr: number | null, upperBound: string): RangeblockHitRow => {
    const existing = hitByTarget.get(target);
    if (existing) return existing;
    const encoded = encodeURIComponent(target).replaceAll('%2F', '/').replaceAll('%3A', ':');
    const isGlobal = wikiSummary.wiki === 'global';
    return {
      target,
      cidr,
      upperBound,
      count: 0,
      isActive: false,
      expiry: null,
      indefinite: false,
      lastBlockedAt: null,
      logUrl: isGlobal
        ? `https://meta.wikimedia.org/wiki/Special:Log?type=gblblock&page=User:${encoded}`
        : `https://${wikiSummary.domain}/wiki/Special:Log?type=block&page=User:${encoded}`,
      blockListUrl: isGlobal
        ? `https://meta.wikimedia.org/wiki/Special:GlobalBlockList?ip=${encoded}`
        : `https://${wikiSummary.domain}/wiki/Special:BlockList?wpTarget=${encoded}`,
    };
  };

  const prefixes = isV6
    ? Array.from({ length: 46 }, (_, i) => 64 - i)
    : Array.from({ length: 17 }, (_, i) => 32 - i);

  const rows: RangeblockHitRow[] = [makeRow(canonical, null, canonical)];
  for (const prefix of prefixes) {
    const hostBits = maxBits - BigInt(prefix);
    const netMask = (allMask << hostBits) & allMask;
    const netStart = addrInt & netMask;
    const netEnd = netStart | ((1n << hostBits) - 1n);
    rows.push(makeRow(`${formatAddr(netStart)}/${prefix}`, prefix, formatAddr(netEnd)));
  }
  return rows;
}

const tableRows = computed(() => {
  if (!props.rangeblock) return [];

  const toTableRow = (wiki: string, hit: RangeblockHitRow) => ({
    wiki,
    hit,
    cidr: hit.cidr === null ? 'Single IP' : `/${hit.cidr}`,
  });

  if (selectedWikiSummary.value) {
    const wiki = selectedWikiSummary.value.wiki;
    const rows = showFullLadder.value
      ? buildFullCidrLadder(props.rangeblock.ip, selectedWikiSummary.value)
      : selectedWikiSummary.value.rows;
    return rows.map((row) => toTableRow(wiki, row));
  }

  const out: Array<{ wiki: string; hit: RangeblockHitRow; cidr: string }> = [];
  for (const wikiItem of props.rangeblock.wikis) {
    for (const row of wikiItem.rows) {
      out.push(toTableRow(wikiItem.wiki, row));
    }
  }
  return out;
});
</script>
