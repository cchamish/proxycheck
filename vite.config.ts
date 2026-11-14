import { defineConfig, loadEnv } from 'vite';
import vue from '@vitejs/plugin-vue';
import { execFileSync } from 'child_process';
import { formatUtcCommitTimestamp, normalizeUtcCommitTimestamp } from './src/utils/ip-detector-logic.ts';

function readGitMetadata(args: string[], cwd: string): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    env: {
      ...process.env,
      LC_ALL: 'C',
      LANG: 'C',
    },
  }).trim();
}

export function resolveCommitMetadata(
  env: Record<string, string | undefined> = process.env,
  cwd: string = process.cwd()
): { commitHash: string; commitTimestamp: string } {
  let commitHash = (env.VITE_COMMIT_HASH || env.COMMIT_HASH || '').trim();
  if (!commitHash) {
    try {
      commitHash = readGitMetadata(['rev-parse', '--short', 'HEAD'], cwd);
    } catch {
      // Fall back to build-time source commit or 'dev' when Git metadata is absent.
    }
  }
  if (!commitHash) {
    const sourceVersion = (env.SOURCE_VERSION || '').trim();
    if (/^[0-9a-f]{7,40}$/i.test(sourceVersion)) {
      commitHash = sourceVersion.slice(0, 7);
    }
  }
  if (!commitHash) {
    commitHash = 'dev';
  }

  let commitTimestamp = normalizeUtcCommitTimestamp(
    env.VITE_COMMIT_TIMESTAMP || env.COMMIT_TIMESTAMP || ''
  );
  if (!commitTimestamp) {
    try {
      const rawUnixSeconds = readGitMetadata(['log', '-1', '--format=%ct'], cwd);
      if (/^-?\d+$/.test(rawUnixSeconds)) {
        const unixSeconds = Number.parseInt(rawUnixSeconds, 10);
        if (Number.isFinite(unixSeconds)) {
          commitTimestamp = formatUtcCommitTimestamp(new Date(unixSeconds * 1000));
        }
      }
    } catch {
      // Fall back to the UTC build timestamp when Git metadata is absent.
    }
  }
  if (!commitTimestamp) {
    commitTimestamp = formatUtcCommitTimestamp(new Date());
  }

  return { commitHash, commitTimestamp };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const { commitHash, commitTimestamp } = resolveCommitMetadata(env, process.cwd());

  return {
    plugins: [vue()],
    define: {
      __COMMIT_HASH__: JSON.stringify(commitHash),
      __COMMIT_TIMESTAMP__: JSON.stringify(commitTimestamp),
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
  };
});
