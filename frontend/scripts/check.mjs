import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..', '..');
const webRoot = resolve(repoRoot, 'internal', 'api', 'web');

const requiredFiles = [
    resolve(webRoot, 'index.html'),
    resolve(webRoot, 'css', 'app.css'),
    resolve(webRoot, 'js', 'api.js'),
    resolve(webRoot, 'js', 'app.js'),
];

for (const file of requiredFiles) {
    if (!existsSync(file)) {
        throw new Error(`required embedded web asset missing: ${file}`);
    }
}

const indexHTML = readFileSync(resolve(webRoot, 'index.html'), 'utf8');
const appJS = readFileSync(resolve(webRoot, 'js', 'app.js'), 'utf8');
const apiJS = readFileSync(resolve(webRoot, 'js', 'api.js'), 'utf8');

if (!indexHTML.includes('js/app.js') || !indexHTML.includes('js/api.js')) {
    throw new Error('index.html does not reference the embedded JavaScript assets');
}
if (!appJS.includes('renderQueryResult') || !appJS.includes('loadHistory')) {
    throw new Error('app.js is missing expected UI entrypoints');
}
if (!apiJS.includes("const API_BASE = '/api/v1';") || !apiJS.includes('async resolve(') || !apiJS.includes('async getHistory(')) {
    throw new Error('api.js is missing expected backend integrations');
}

console.log('embedded web asset checks passed');
