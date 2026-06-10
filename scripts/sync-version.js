#!/usr/bin/env node
/**
 * Synchronizuje src/version.ts z wersją z package.json.
 * Uruchamiane automatycznie jako `prebuild` - gwarantuje, że nagłówek
 * x-silker-client-version zawsze odpowiada publikowanej wersji pakietu.
 */
const fs = require('fs');
const path = require('path');

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8'));
const target = path.join(__dirname, '..', 'src', 'version.ts');

const contents = `/**
 * Wersja SDK - generowana ze \`package.json\` przez \`scripts/sync-version.js\`
 * (prebuild). NIE edytować ręcznie.
 */
export const SDK_VERSION = '${pkg.version}';
`;

if (!fs.existsSync(target) || fs.readFileSync(target, 'utf-8') !== contents) {
  fs.writeFileSync(target, contents);
  console.log(`[sync-version] src/version.ts -> ${pkg.version}`);
}
