import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'playwright/test';

const frontendDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(frontendDir, '..');

export default defineConfig({
    testDir: './tests',
    timeout: 60000,
    expect: {
        timeout: 15000,
    },
    use: {
        baseURL: 'http://127.0.0.1:18081',
        headless: true,
    },
    webServer: {
        command: 'go run ./cmd/server',
        cwd: repoRoot,
        url: 'http://127.0.0.1:18081/api/v1/health/ready',
        reuseExistingServer: true,
        stdout: 'pipe',
        stderr: 'pipe',
        env: {
            ...process.env,
            HTTP_PORT: '18081',
            DNS_PORT: '15354',
            DOT_PORT: '18554',
            TLS_ENABLED: 'false',
            OTEL_ENABLED: 'false',
            PROMETHEUS_ENABLED: 'false',
            PPROF_ENABLED: 'false',
            CACHE_PERSIST_PATH: '/tmp/dnsresolver-playwright-cache.json',
            BLOCKLIST_PATH: resolve(repoRoot, 'blocklist.txt'),
        },
    },
});
