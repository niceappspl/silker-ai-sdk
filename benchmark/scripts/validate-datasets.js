#!/usr/bin/env node
/**
 * Validates benchmark dataset integrity: uniqueness, min category coverage, schema.
 * Exit 1 on failure (usable in CI for extended release checks).
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '../datasets');

function loadMerged(suite) {
  const files = ['prompt-injection.json', 'sqli.json', 'xss.json'];
  const all = [];
  for (const file of files) {
    const corePath = path.join(ROOT, 'core', file);
    const core = fs.existsSync(corePath) ? JSON.parse(fs.readFileSync(corePath, 'utf-8')) : [];
    all.push(...core.map((s) => ({ ...s, file })));
    if (suite === 'extended') {
      const addPath = path.join(ROOT, 'extended', 'additions', file);
      if (fs.existsSync(addPath)) {
        all.push(...JSON.parse(fs.readFileSync(addPath, 'utf-8')).map((s) => ({ ...s, file })));
      }
    }
  }
  const seen = new Set();
  return all.filter((s) => {
    const key = `${s.file}::${s.text}`;
    if (seen.has(s.text)) return false;
    seen.add(s.text);
    return true;
  });
}

function validate(suite, opts) {
  const samples = loadMerged(suite);
  const errors = [];

  if (samples.length < opts.minTotal) {
    errors.push(`${suite}: expected >= ${opts.minTotal} unique samples, got ${samples.length}`);
  }

  const texts = new Set();
  for (const s of samples) {
    if (!s.text || typeof s.text !== 'string') errors.push('missing text field');
    if (s.label !== 'attack' && s.label !== 'benign') errors.push(`invalid label: ${s.label}`);
    if (!s.category) errors.push('missing category');
    if (texts.has(s.text)) errors.push(`duplicate text: ${s.text.slice(0, 40)}…`);
    texts.add(s.text);
  }

  const byFile = {};
  for (const s of samples) {
    byFile[s.file] = byFile[s.file] ?? { attack: 0, benign: 0, cats: new Set() };
    byFile[s.file][s.label]++;
    byFile[s.file].cats.add(s.category);
  }

  for (const [file, stats] of Object.entries(byFile)) {
    if (stats.attack < opts.minAttacksPerFile) {
      errors.push(`${file}: only ${stats.attack} attacks (min ${opts.minAttacksPerFile})`);
    }
    if (stats.benign < opts.minBenignPerFile) {
      errors.push(`${file}: only ${stats.benign} benign (min ${opts.minBenignPerFile})`);
    }
    if (stats.cats.size < opts.minCategoriesPerFile) {
      errors.push(`${file}: only ${stats.cats.size} categories (min ${opts.minCategoriesPerFile})`);
    }
  }

  return { samples: samples.length, errors, byFile };
}

const core = validate('core', {
  minTotal: 200,
  minAttacksPerFile: 15,
  minBenignPerFile: 15,
  minCategoriesPerFile: 8,
});

const extended = validate('extended', {
  minTotal: 1000,
  minAttacksPerFile: 80,
  minBenignPerFile: 80,
  minCategoriesPerFile: 15,
});

console.log('Benchmark dataset validation\n');
console.log(`Core:     ${core.samples} unique samples`);
console.log(`Extended: ${extended.samples} unique samples`);

const allErrors = [...core.errors, ...extended.errors];
if (allErrors.length) {
  console.error('\nFAILURES:');
  allErrors.forEach((e) => console.error(`  - ${e}`));
  process.exit(1);
}

console.log('\nAll checks passed.');
process.exit(0);
