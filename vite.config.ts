import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { execSync } from 'child_process';

let commitHash = 'dev';
try {
  commitHash = execSync('git rev-parse --short HEAD').toString().trim();
} catch {
  // Fallback to 'dev' when Git command fails or repo not present
}

export default defineConfig({
  plugins: [vue()],
  define: {
    __COMMIT_HASH__: JSON.stringify(commitHash),
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/oauth': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
    },
  },
});
