#!/usr/bin/env node
import * as readline from 'readline';
import * as fs from 'fs';
import * as path from 'path';

const PLATFORM_URL = 'https://platform.silkerai.com';

const colors = {
  red:    (s: string) => `\x1b[31m${s}\x1b[0m`,
  green:  (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  cyan:   (s: string) => `\x1b[36m${s}\x1b[0m`,
  bold:   (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim:    (s: string) => `\x1b[2m${s}\x1b[0m`,
};

function print(msg: string) { process.stdout.write(msg + '\n'); }
function ask(rl: readline.Interface, q: string): Promise<string> {
  return new Promise(resolve => rl.question(q, resolve));
}

function detectFramework(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf-8'));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (deps['next']) return 'nextjs';
    if (deps['express']) return 'express';
  } catch {}
  return 'node';
}

function envFileExists(): boolean {
  return fs.existsSync(path.join(process.cwd(), '.env')) ||
         fs.existsSync(path.join(process.cwd(), '.env.local'));
}

function addToEnv(key: string, value: string) {
  const envPath = path.join(process.cwd(), '.env.local');
  const line = `${key}=${value}\n`;
  if (fs.existsSync(envPath)) {
    const content = fs.readFileSync(envPath, 'utf-8');
    if (content.includes(key)) return; // already set
    fs.appendFileSync(envPath, line);
  } else {
    fs.writeFileSync(envPath, line);
  }
}

function getSnippet(framework: string, apiKey: string): { file: string; code: string } {
  const hasKey = apiKey && apiKey !== 'skip';
  const keyLine = hasKey ? `\nSILKER_API_KEY=${apiKey}` : '\nSILKER_API_KEY=sk_your_key_here';

  if (framework === 'nextjs') {
    return {
      file: 'middleware.ts',
      code: `import { nextMiddleware } from '@silker-ai/agent/next';

export const middleware = nextMiddleware();

export const config = { matcher: '/api/:path*' };
// Add to .env.local:${keyLine}
`,
    };
  }

  if (framework === 'express') {
    return {
      file: 'server.ts (or app.ts)',
      code: `import express from 'express';
import { middleware } from '@silker-ai/agent';

const app = express();
app.use(middleware());
// Add to .env:${keyLine}
`,
    };
  }

  return {
    file: 'index.ts',
    code: `import { initSilker } from '@silker-ai/agent';

await initSilker();
// Add to .env:${keyLine}
`,
  };
}

async function main() {
  print('');
  print(colors.bold(colors.red('  ◆ Silker AI') + colors.dim(' - setup wizard')));
  print(colors.dim('  Runtime security for your web app'));
  print('');

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  // Detect framework
  const detected = detectFramework();
  const frameworkNames: Record<string, string> = { nextjs: 'Next.js', express: 'Express', node: 'Node.js' };
  print(`  ${colors.dim('Detected framework:')} ${colors.cyan(frameworkNames[detected])}`);
  print('');

  const frameworkInput = await ask(rl, `  Framework? ${colors.dim(`[nextjs/express/node, Enter = ${detected}]`)} `);
  const framework = frameworkInput.trim() || detected;
  print('');

  // API key
  print(`  Get your API key at: ${colors.cyan(PLATFORM_URL)}`);
  const apiKeyInput = await ask(rl, `  ${colors.bold('API key')} ${colors.dim('[sk_... or Enter to skip]')} `);
  const apiKey = apiKeyInput.trim();
  print('');

  // Write to .env
  if (apiKey && apiKey.startsWith('sk_')) {
    addToEnv('SILKER_API_KEY', apiKey);
    print(`  ${colors.green('✓')} SILKER_API_KEY added to .env.local`);
  }

  // Show snippet
  const { file, code } = getSnippet(framework, apiKey);
  print(`  ${colors.bold('Add to')} ${colors.cyan(file)}:`);
  print('');
  code.split('\n').forEach(line => print(`    ${colors.dim(line)}`));
  print('');

  // Install if needed
  const hasSilker = (() => {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf-8'));
      return !!pkg.dependencies?.['@silker-ai/agent'];
    } catch { return false; }
  })();

  if (!hasSilker) {
    const install = await ask(rl, `  Install ${colors.cyan('@silker-ai/agent')} now? ${colors.dim('[Y/n]')} `);
    if (!install.trim() || install.trim().toLowerCase() === 'y') {
      rl.close();
      print(`  ${colors.dim('Running npm install @silker-ai/agent...')}`);
      const { execSync } = require('child_process');
      try {
        execSync('npm install @silker-ai/agent', { stdio: 'inherit', cwd: process.cwd() });
        print(`  ${colors.green('✓')} Installed`);
      } catch {
        print(`  ${colors.yellow('!')} Run manually: npm install @silker-ai/agent`);
      }
    } else {
      rl.close();
      print(`  Run: ${colors.cyan('npm install @silker-ai/agent')}`);
    }
  } else {
    rl.close();
    print(`  ${colors.green('✓')} @silker-ai/agent already installed`);
  }

  print('');
  print(`  ${colors.green('Done!')} Deploy and check your dashboard at ${colors.cyan(PLATFORM_URL)}`);
  print('');
}

main().catch(e => { console.error(e); process.exit(1); });
