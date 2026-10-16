import { expect, test } from 'bun:test';
import { sealEnvelope, serializeEnvelope } from '@bunker/offline';

const zero = '0x0000000000000000000000000000000000000000' as const;
const envelope = sealEnvelope({
  version: 2,
  kind: 'bunker-transfer',
  chainId: 31337,
  safe: '0x0000000000000000000000000000000000000002',
  safeVersion: '1.4.1',
  guard: '0x0000000000000000000000000000000000000003',
  guardVersion: 2,
  manifestId: `0x${'11'.repeat(32)}`,
  nonce: '0',
  to: '0x0000000000000000000000000000000000000004',
  value: '1',
  data: '0x',
  operation: 1,
  safeTxGas: '100000',
  baseGas: '0',
  gasPrice: '0',
  gasToken: zero,
  refundReceiver: zero,
  currentOwner: '0x0000000000000000000000000000000000000005',
  nextOwner: '0x0000000000000000000000000000000000000006',
  nextIndex: 1,
  safeTxHash: `0x${'33'.repeat(32)}`,
});

test('production deployment configuration is absent', async () => {
  expect(await Bun.file(new URL('../../../wrangler.jsonc', import.meta.url)).exists()).toBe(false);
});

test('loopback relayer only validates bounded envelopes and never broadcasts', async () => {
  const reserved = Bun.serve({
    hostname: '127.0.0.1',
    port: 0,
    fetch: () => new Response('reserved'),
  });
  const port = reserved.port;
  reserved.stop(true);
  const child = Bun.spawn(['bun', new URL('./index.ts', import.meta.url).pathname], {
    env: { ...process.env, PORT: String(port) },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const url = `http://127.0.0.1:${port}`;
  try {
    let ready = false;
    for (let i = 0; i < 40; ++i) {
      try {
        await fetch(`${url}/health`);
        ready = true;
        break;
      } catch {
        await Bun.sleep(50);
      }
    }
    expect(ready).toBe(true);
    const health = await fetch(`${url}/health`);
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ mode: 'validation-only', broadcast: false });
    expect(health.headers.get('cache-control')).toBe('no-store');
    expect((await fetch(`${url}/missing`)).status).toBe(404);
    const submit = (body: string) => fetch(`${url}/v2/validate`, { method: 'POST', body });
    expect((await submit('{')).status).toBe(422);
    expect((await submit('x'.repeat(65537))).status).toBe(413);
    const accepted = await submit(serializeEnvelope(envelope));
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toMatchObject({
      formatAccepted: true,
      signaturePresent: false,
      broadcast: false,
    });
    const { checksum: _checksum, ...unsigned } = envelope;
    const signed = sealEnvelope({
      ...unsigned,
      signature: `0x${'11'.repeat(65)}` as `0x${string}`,
    });
    const refused = await submit(serializeEnvelope(signed));
    expect(refused.status).toBe(501);
    expect(await refused.json()).toMatchObject({
      formatAccepted: true,
      signaturePresent: true,
      broadcast: false,
    });
    for (let i = 0; i < 9; ++i) {
      const response = await submit('{');
      if (i === 8) expect(response.status).toBe(429);
    }
  } finally {
    child.kill();
    await child.exited;
  }
});
