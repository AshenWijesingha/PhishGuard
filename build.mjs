/**
 * PhishGuard build script (esbuild).
 *
 * Produces dist/ ready for "Load unpacked":
 *   - bundles each entry point (background, content, page-hook, UI pages)
 *   - copies static assets (manifest.json, HTML, CSS, icons)
 *
 * Usage: node build.mjs [--watch]
 */
import * as esbuild from 'esbuild';
import { cp, mkdir, rm } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';

const watch = process.argv.includes('--watch');
const outdir = 'dist';

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

// Generate placeholder icons if missing (solid-color PNGs).
if (!existsSync('public/icons/icon-128.png')) {
  execSync('node scripts/gen-icons.mjs', { stdio: 'inherit' });
}

/** @type {esbuild.BuildOptions} */
const options = {
  entryPoints: [
    { in: 'src/background/service-worker.ts', out: 'background' },
    { in: 'src/content/main.ts', out: 'content' },
    { in: 'src/content/page-hook.ts', out: 'page-hook' },
    { in: 'src/ui/popup/popup.ts', out: 'popup' },
    { in: 'src/ui/dashboard/dashboard.ts', out: 'dashboard' },
    { in: 'src/ui/interstitial/blocked.ts', out: 'blocked' },
  ],
  bundle: true,
  format: 'iife', // content scripts and MV3 pages cannot rely on import maps
  target: 'chrome120',
  outdir,
  sourcemap: process.env.NODE_ENV === 'development' ? 'inline' : false,
  minify: false, // store review friendliness; flip to true for release if desired
  logLevel: 'info',
};

async function copyStatic() {
  await cp('public', outdir, { recursive: true });
}

if (watch) {
  const ctx = await esbuild.context(options);
  await copyStatic();
  await ctx.watch();
  console.log('watching…');
} else {
  await esbuild.build(options);
  await copyStatic();
  console.log('build complete → dist/');
}
