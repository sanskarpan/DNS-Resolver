import { cpSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '..', '..');
const sourceDir = resolve(repoRoot, 'internal', 'api', 'web');
const targetDir = resolve(repoRoot, 'frontend', 'build');

if (!existsSync(sourceDir)) {
    throw new Error(`embedded web source not found: ${sourceDir}`);
}

rmSync(targetDir, { recursive: true, force: true });
mkdirSync(targetDir, { recursive: true });
cpSync(sourceDir, targetDir, { recursive: true });

console.log(`frontend build mirrored embedded web assets from ${sourceDir} to ${targetDir}`);
