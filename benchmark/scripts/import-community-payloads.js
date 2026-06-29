#!/usr/bin/env node
/**
 * Imports labeled attack/benign payloads from public community sources into
 * benchmark/datasets/community/ for the `community` benchmark suite.
 *
 * Sources (MIT-licensed):
 * - PayloadsAllTheThings Intruder lists (SQLi + XSS)
 * - Morzeux/HttpParamsDataset payload_test.csv (sqli / xss / norm)
 *
 * Regenerate: npm run benchmark:import-community
 */
const fs = require('fs');
const path = require('path');
const https = require('https');

const OUT = path.join(__dirname, '../datasets/community');
const PAT_BASE = 'https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master';

const PAT_SQL_INTRUDER = [
  'SQL Injection/Intruder/Auth_Bypass.txt',
  'SQL Injection/Intruder/Auth_Bypass2.txt',
  'SQL Injection/Intruder/Generic_ErrorBased.txt',
  'SQL Injection/Intruder/Generic_TimeBased.txt',
  'SQL Injection/Intruder/Generic_UnionSelect.txt',
  'SQL Injection/Intruder/SQLi_Polyglots.txt',
  'SQL Injection/Intruder/payloads-sql-blind-MySQL-ORDER_BY',
  'SQL Injection/Intruder/payloads-sql-blind-MySQL-WHERE',
];

const PAT_XSS_INTRUDER = [
  'XSS Injection/Intruders/JHADDIX_XSS.txt',
  'XSS Injection/Intruders/XSS_Polyglots.txt',
  'XSS Injection/Intruders/BRUTELOGIC-XSS-STRINGS.txt',
  'XSS Injection/Intruders/xss_payloads_quick.txt',
  'XSS Injection/Intruders/IntrudersXSS.txt',
];

const HTTP_PARAMS_CSV =
  'https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_test.csv';

const LIMITS = {
  sqliAttack: 800,
  xssAttack: 400,
  sqliBenign: 200,
  xssBenign: 200,
};

function fetchText(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          fetchText(res.headers.location).then(resolve).catch(reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      })
      .on('error', reject);
  });
}

function parsePatLines(text, category, source) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => ({
      text: line,
      label: 'attack',
      category,
      source,
    }));
}

function parseHttpParamsCsv(text) {
  const lines = text.split(/\r?\n/).slice(1);
  const out = { sqli: [], xss: [], norm: [] };
  for (const line of lines) {
    const match = line.match(/^"(.*)","(\d+)","([^"]*)","([^"]*)"$/);
    if (!match) continue;
    const payload = match[1].replace(/""/g, '"');
    const attackType = match[3];
    if (!payload || payload.length > 2048) continue;
    if (attackType === 'sqli') out.sqli.push(payload);
    else if (attackType === 'xss') out.xss.push(payload);
    else if (attackType === 'norm') out.norm.push(payload);
  }
  return out;
}

function dedupeSamples(samples) {
  const seen = new Set();
  return samples.filter((s) => {
    if (seen.has(s.text)) return false;
    seen.add(s.text);
    return true;
  });
}

function cap(samples, limit) {
  return samples.slice(0, limit);
}

function sample(payload, label, category, source) {
  return { text: payload, label, category, source };
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });

  const sqliAttacks = [];
  const xssAttacks = [];
  const sqliBenign = [];
  const xssBenign = [];

  console.log('Fetching PayloadsAllTheThings SQLi lists…');
  for (const rel of PAT_SQL_INTRUDER) {
    const url = `${PAT_BASE}/${rel}`;
    try {
      const text = await fetchText(url);
      const cat = `pat-${path.basename(rel).replace(/\.[^.]+$/, '')}`;
      sqliAttacks.push(...parsePatLines(text, cat, 'PayloadsAllTheThings'));
      console.log(`  + ${rel}: ${text.split('\n').filter(Boolean).length} lines`);
    } catch (e) {
      console.warn(`  ! skip ${rel}: ${e.message}`);
    }
  }

  console.log('Fetching PayloadsAllTheThings XSS lists…');
  for (const rel of PAT_XSS_INTRUDER) {
    const url = `${PAT_BASE}/${rel}`;
    try {
      const text = await fetchText(url);
      const cat = `pat-${path.basename(rel).replace(/\.[^.]+$/, '')}`;
      xssAttacks.push(...parsePatLines(text, cat, 'PayloadsAllTheThings'));
      console.log(`  + ${rel}`);
    } catch (e) {
      console.warn(`  ! skip ${rel}: ${e.message}`);
    }
  }

  console.log('Fetching HttpParamsDataset payload_test.csv…');
  const csv = await fetchText(HTTP_PARAMS_CSV);
  const httpParams = parseHttpParamsCsv(csv);
  sqliAttacks.push(
    ...httpParams.sqli.map((p) => sample(p, 'attack', 'httpparams-sqli', 'HttpParamsDataset'))
  );
  xssAttacks.push(
    ...httpParams.xss.map((p) => sample(p, 'attack', 'httpparams-xss', 'HttpParamsDataset'))
  );
  sqliBenign.push(
    ...httpParams.norm.map((p) => sample(p, 'benign', 'httpparams-norm', 'HttpParamsDataset'))
  );
  xssBenign.push(
    ...httpParams.norm.map((p) => sample(p, 'benign', 'httpparams-norm', 'HttpParamsDataset'))
  );
  console.log(
    `  HttpParams: ${httpParams.sqli.length} sqli, ${httpParams.xss.length} xss, ${httpParams.norm.length} norm`
  );

  const sqli = dedupeSamples([
    ...cap(sqliAttacks, LIMITS.sqliAttack),
    ...cap(sqliBenign, LIMITS.sqliBenign),
  ]);
  const xss = dedupeSamples([
    ...cap(xssAttacks, LIMITS.xssAttack),
    ...cap(xssBenign, LIMITS.xssBenign),
  ]);

  const manifest = {
    generatedAt: new Date().toISOString(),
    sources: [
      {
        name: 'PayloadsAllTheThings',
        url: 'https://github.com/swisskyrepo/PayloadsAllTheThings',
        license: 'MIT',
      },
      {
        name: 'HttpParamsDataset',
        url: 'https://github.com/Morzeux/HttpParamsDataset',
        license: 'MIT',
      },
    ],
    counts: {
      sqli: sqli.length,
      xss: xss.length,
      sqliAttacks: sqli.filter((s) => s.label === 'attack').length,
      sqliBenign: sqli.filter((s) => s.label === 'benign').length,
      xssAttacks: xss.filter((s) => s.label === 'attack').length,
      xssBenign: xss.filter((s) => s.label === 'benign').length,
    },
    note:
      'Community suite uses third-party payloads. Scores are informational only - never a completeness guarantee.',
  };

  fs.writeFileSync(path.join(OUT, 'sqli.json'), JSON.stringify(sqli, null, 2) + '\n');
  fs.writeFileSync(path.join(OUT, 'xss.json'), JSON.stringify(xss, null, 2) + '\n');
  fs.writeFileSync(path.join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  console.log('\nWrote community datasets:');
  console.log(`  sqli.json  ${sqli.length} samples (${manifest.counts.sqliAttacks} attack / ${manifest.counts.sqliBenign} benign)`);
  console.log(`  xss.json   ${xss.length} samples (${manifest.counts.xssAttacks} attack / ${manifest.counts.xssBenign} benign)`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
