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
            Active · {{ formatExpiry(row.hit) }}
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
  buildFullCidrLadder,
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
    if (!nextWiki) {
      showFullLadder.value = false;
    }
  }
);

const selectedWikiSummary = computed<RangeblockWikiSummary | null>(() => {
  if (!props.rangeblock || !props.selectedWiki) {
    return null;
  }
  return props.rangeblock.wikis.find((w) => w.wiki === props.selectedWiki) ?? null;
});

const displayedRows = computed<Array<{ wiki: string; row: RangeblockHitRow }>>(() => {
  if (!props.rangeblock) {
    return [];
  }
  if (selectedWikiSummary.value) {
    const rows = showFullLadder.value
      ? buildFullCidrLadder(props.rangeblock.ip, selectedWikiSummary.value)
      : selectedWikiSummary.value.rows;
    return rows.map((row) => ({ wiki: selectedWikiSummary.value!.wiki, row }));
  }
  const out: Array<{ wiki: string; row: RangeblockHitRow }> = [];
  for (const wikiItem of props.rangeblock.wikis) {
    for (const row of wikiItem.rows) {
      out.push({ wiki: wikiItem.wiki, row });
    }
  }
  return out;
});

const tableRows = computed(() =>
  displayedRows.value.map(({ wiki, row }) => ({
    wiki,
    hit: row,
    cidr: row.cidr === null ? 'Single IP' : `/${row.cidr}`,
  }))
);

function formatExpiry(row: RangeblockHitRow): string {
  if (row.indefinite) {
    return 'Indefinite';
  }
  return formatExactUtcTimestamp(row.expiry) || 'Active';
}
</script>
