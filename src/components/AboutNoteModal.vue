<template>
  <cdx-dialog
    v-model:open="dialogOpen"
    :title="aboutTitle"
    :use-close-button="true"
    :default-action="{ label: t('common-close') }"
    class="about-note-dialog"
    @default="dialogOpen = false"
  >
    <article class="about-note-content" v-html="aboutHtml" />
  </cdx-dialog>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { CdxDialog } from '@wikimedia/codex';
import aboutMarkdown from '../../docs/about.md?raw';
import { useI18n } from '../utils/i18n';

const { t } = useI18n();

const props = defineProps<{
  open: boolean;
}>();

const emit = defineEmits<{
  (event: 'update:open', value: boolean): void;
}>();

const dialogOpen = computed({
  get: () => props.open,
  set: (value: boolean) => emit('update:open', value),
});

const blocks = aboutMarkdown.replace(/\r\n/g, '\n').trim().split(/\n{2,}/);
const firstBlockLine = blocks[0]?.split('\n')[0]?.trim() ?? '';
const aboutTitle = firstBlockLine.replace(/^#{1,6}\s+/, '');

function renderInline(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;')
    .replace(
      /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
      '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
    )
    .replace(/\*([^*]+)\*/g, '<em>$1</em>');
}

const aboutHtml = blocks
  .map((block, index) => {
    const lines = block.split('\n');
    const headingLine = lines[0].trim();
    if (index === 0 && /^#{1,6}\s+/.test(headingLine)) return '';
    if (/^#{1,6}\s+/.test(headingLine)) {
      return `<h2>${renderInline(headingLine.replace(/^#{1,6}\s+/, ''))}</h2>`;
    }
    return `<p>${renderInline(lines.join(' '))}</p>`;
  })
  .join('');
</script>
