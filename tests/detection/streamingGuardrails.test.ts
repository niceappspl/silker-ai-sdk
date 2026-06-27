import { createGuardrailTransform, isStreamingContentType } from '../../src/detection/streamingGuardrails';

async function runTransform(chunks: string[]): Promise<{ out: string; findings: string[] }> {
  const findings: string[] = [];
  const ts = createGuardrailTransform({ onDetect: (f) => findings.push(...f) });
  const writer = ts.writable.getWriter();
  const reader = ts.readable.getReader();
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let out = '';

  const readAll = (async () => {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      out += dec.decode(value);
    }
  })();

  try {
    for (const chunk of chunks) await writer.write(enc.encode(chunk));
    await writer.close();
  } catch {
    // terminate() rejects the writer once tripped - expected for cut-off.
  }
  await readAll;
  return { out, findings };
}

describe('createGuardrailTransform', () => {
  it('passes a clean stream through unchanged', async () => {
    const parts = ['The weather ', 'today is sunny ', 'with a light breeze.'];
    const { out, findings } = await runTransform(parts);
    expect(findings).toHaveLength(0);
    expect(out).toBe(parts.join(''));
  });

  it('cuts off the stream when a secret leaks mid-stream', async () => {
    const parts = [
      'Sure, here is the value you asked for: ',
      'sk_live_1234567890abcdef123456',
      ' and some more trailing text that should never be emitted',
    ];
    const { out, findings } = await runTransform(parts);
    expect(findings.length).toBeGreaterThan(0);
    expect(out).toContain('[Silker AI]');
    expect(out).not.toContain('trailing text that should never be emitted');
  });
});

describe('isStreamingContentType', () => {
  it('recognizes SSE and ndjson', () => {
    expect(isStreamingContentType('text/event-stream')).toBe(true);
    expect(isStreamingContentType('application/x-ndjson')).toBe(true);
  });
  it('rejects plain json/html', () => {
    expect(isStreamingContentType('application/json')).toBe(false);
    expect(isStreamingContentType(null)).toBe(false);
  });
});
