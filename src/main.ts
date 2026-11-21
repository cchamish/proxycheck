import { createApp } from 'vue';
import '@wikimedia/codex-design-tokens/dist/theme-wikimedia-ui.css';
import darkModeTokens from '@wikimedia/codex-design-tokens/dist/theme-wikimedia-ui-mode-dark.css?raw';
import '@wikimedia/codex/dist/codex.style.css';
import './codex.css';
import App from './App.vue';

const darkModeStyle = document.createElement('style');
darkModeStyle.textContent = darkModeTokens.replace(':root', "html[data-theme='dark']");
document.head.append(darkModeStyle);

createApp(App).mount('#app');
