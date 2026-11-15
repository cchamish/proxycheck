<template>
  <cdx-dialog
    v-model:open="dialogOpen"
    title="A note from the maintainer"
    :use-close-button="true"
    :default-action="{ label: 'Close' }"
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

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function renderInlineMarkdown(value: string): string {
  let html = escapeHtml(value);
  html = html.replace(
    /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g,
    '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>'
  );
  return html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
}

function renderMarkdown(value: string): string {
  const blocks = value.replace(/\r\n/g, '\n').trim().split(/\n{2,}/);
  return blocks
    .map((block) => {
      const lines = block.split('\n');
      const firstLine = lines[0].trim();
      if (firstLine.startsWith('# ')) {
        return `<h2>${renderInlineMarkdown(firstLine.slice(2))}</h2>`;
      }
      return `<p>${renderInlineMarkdown(lines.join(' '))}</p>`;
    })
    .join('');
}

const aboutHtml = computed(() => renderMarkdown(aboutMarkdown));
</script>
