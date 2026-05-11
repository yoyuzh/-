import { cp, mkdir, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(scriptDir, '..');
const distDir = resolve(webRoot, 'dist');

await rm(resolve(webRoot, 'assets'), { force: true, recursive: true });
await mkdir(webRoot, { recursive: true });
await cp(resolve(distDir, 'index.html'), resolve(webRoot, 'index.html'));
await cp(resolve(distDir, 'assets'), resolve(webRoot, 'assets'), { recursive: true });
