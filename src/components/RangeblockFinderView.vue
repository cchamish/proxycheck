<template>
  <section class="rb-finder" :aria-label="t('rb-title')">
    <cdx-message v-if="errorMessage" type="error" :inline="false">
      {{ errorMessage }}
    </cdx-message>

    <cdx-message v-else-if="isLoading" type="notice" :inline="false">
      {{ t('rb-loading') }}
    </cdx-message>

    <template v-else-if="rangeblock">
      <div class="rb-header">
        <div class="rb-header__title">
          <h2 class="card-heading">{{ t('rb-title') }}</h2>
          <cdx-info-chip :status="rangeblock.hasActive ? 'error' : (rangeblock.blockDataDegraded ? 'warning' : 'notice')">
            <template v-if="rangeblock.blockDataDegraded && rangeblock.localTotal === 0 && rangeblock.globalTotal === 0">{{ t('rb-chip-unavailable') }}</template>
            <template v-else>{{ t('rb-chip-summary', { local: rangeblock.localTotal, global: rangeblock.globalTotal }) }}</template>
          </cdx-info-chip>
        </div>
        <span class="text-subtle">
          {{ rangeblock.ipVersion === 6 ? t('rb-scope-v6') : t('rb-scope-v4') }}
        </span>
      </div>

      <cdx-message v-if="rangeblock.blockDataDegraded" type="warning" :inline="false">
        {{ t('rb-block-data-degraded') }}
      </cdx-message>
      <cdx-message v-if="rangeblock.realtimeDegraded && !rangeblock.blockDataDegraded" type="warning" :inline="false">
        {{ t('rb-realtime-degraded') }}
      </cdx-message>

      <div class="rb-filters">
        <cdx-toggle-button-group
          v-model="selectedWikiValue"
          :buttons="wikiButtons"
        />
        <cdx-toggle-switch v-if="selectedWikiSummary" v-model="showFullLadder">
          {{ t('rb-show-full-ladder') }}
        </cdx-toggle-switch>
      </div>

      <cdx-table
        :caption="t('rb-table-caption')"
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
            {{ t('rb-status-active') }} · {{ row.hit.indefinite ? t('rb-status-indefinite') : (formatExactUtcTimestamp(row.hit.expiry) || t('rb-status-active')) }}
          </cdx-info-chip>
          <cdx-info-chip v-else-if="row.hit.count > 0" status="notice">
            {{ t('rb-status-historical') }}
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
          <template v-if="rangeblock.blockDataDegraded">{{ t('rb-empty-unavailable', { ip: rangeblock.ip }) }}</template>
          <template v-else>{{ t('rb-empty-state', { ip: rangeblock.ip }) }}</template>
        </template>
      </cdx-table>
    </template>

    <p v-else class="text-subtle">
      {{ t('rb-idle-prompt') }}
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
import { useI18n } from '../utils/i18n';

const { t } = useI18n();

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

const rbColumns = computed<TableColumn[]>(() => [
  { id: 'wiki', label: t('rb-col-wiki') },
  { id: 'target', label: t('rb-col-target') },
  { id: 'cidr', label: t('rb-col-cidr') },
  { id: 'upperBound', label: t('rb-col-upper-bound') },
  { id: 'status', label: t('rb-col-status') },
  { id: 'count', label: t('rb-col-blocks') },
  { id: 'links', label: t('rb-col-links') },
]);

const showFullLadder = ref(false);

const selectedWikiValue = computed<string>({
  get: () => props.selectedWiki ?? ALL_WIKIS_VALUE,
  set: (value) => emit('select-wiki', value === ALL_WIKIS_VALUE ? null : value),
});

const wikiButtons = computed<ButtonGroupItem[]>(() => [
  { value: ALL_WIKIS_VALUE, label: t('rb-filter-all-hits', { count: props.rangeblock?.wikis.length ?? 0 }) },
  ...(props.rangeblock?.wikis ?? []).map((item) => ({
    value: item.wiki,
    label: `${item.wiki}${item.hasActive ? t('detector-rangeblock-active-suffix') : ''} · ${item.count}`,
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
    cidr: hit.cidr === null ? t('rb-single-ip') : `/${hit.cidr}`,
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
