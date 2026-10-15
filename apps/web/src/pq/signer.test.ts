import { expect, test } from 'bun:test';
import { PQSigner } from './signer';

const digest = `0x${'00'.repeat(32)}` as const;
const publicKey = `0x${'11'.repeat(32)}` as const;
const c10Signature = `0x${'22'.repeat(4008)}` as const;

function worker() {
  let sent: { id: number; op: string } | undefined;
  let terminated = false;
  const fake = {
    onmessage: undefined as ((event: { data: unknown }) => void) | undefined,
    onerror: undefined as (() => void) | undefined,
    onmessageerror: undefined as (() => void) | undefined,
    postMessage: (message: { id: number; op: string }) => {
      sent = message;
    },
    terminate: () => {
      terminated = true;
    },
  };
  const signer = new PQSigner(() => fake as unknown as Worker);
  const reply = (result: unknown, id = sent!.id) => fake.onmessage!({ data: { id, result } });
  return { signer, fake, reply, sent: () => sent, terminated: () => terminated };
}

test('lock rejects pending work and ignores stale messages', async () => {
  const { signer, reply, sent, terminated } = worker();
  const pending = signer.init('public test phrase', 'c10');
  await expect(signer.sign(digest)).rejects.toThrow('busy');
  const id = sent()!.id;
  signer.close();
  await expect(pending).rejects.toThrow('locked');
  expect(terminated()).toBe(true);
  reply({ mode: 'c10', publicKey }, id);
  await expect(signer.init('another public test phrase', 'mldsa44')).rejects.toThrow('locked');
});

test('valid worker responses are shaped and bound to the selected algorithm', async () => {
  const { signer, reply } = worker();
  const initialized = signer.init('test', 'c10');
  reply({ mode: 'c10', publicKey });
  expect(await initialized).toEqual({ mode: 'c10', publicKey });
  await expect(signer.sign('0x12')).rejects.toThrow('digest');
  const pending = signer.sign(digest);
  reply(c10Signature);
  expect(await pending).toBe(c10Signature);
});

test('ML-DSA worker output requires exact public-key, blob and signature lengths', async () => {
  const { signer, reply, terminated } = worker();
  const publicKey = `0x${'11'.repeat(1312)}` as `0x${string}`;
  const blob = `0x${'00'.repeat(20545)}` as `0x${string}`;
  const initialized = signer.init('test', 'mldsa44');
  reply({ mode: 'mldsa44', publicKey, blob });
  expect(await initialized).toEqual({ mode: 'mldsa44', publicKey, blob });
  const pending = signer.sign(digest);
  reply(`0x${'22'.repeat(2420)}`);
  expect((await pending).length).toBe(4842);
  expect(terminated()).toBe(false);
});

test('failed reinitialization terminates the old signing identity', async () => {
  const { signer, reply, fake, sent, terminated } = worker();
  const first = signer.init('test', 'c10');
  reply({ mode: 'c10', publicKey });
  await first;
  const failed = signer.init('invalid', 'mldsa44');
  // A worker failure must not leave the previous key available.
  fake.onmessage!({ data: { id: sent()!.id, error: 'Invalid initialization' } });
  await expect(failed).rejects.toThrow('Invalid initialization');
  expect(terminated()).toBe(true);
  await expect(signer.sign(digest)).rejects.toThrow('locked');
});

test('malformed, mismatched and stale init responses terminate the signer', async () => {
  for (const result of [
    null,
    { mode: 'mldsa44', publicKey },
    { mode: 'c10', publicKey: '0x12' },
    { mode: 'c10', publicKey, blob: '0x12' },
  ]) {
    const { signer, reply, terminated } = worker();
    const pending = signer.init('test', 'c10');
    reply({ mode: 'c10', publicKey }, 999); // Old or unrelated worker response.
    reply(result);
    await expect(pending).rejects.toThrow('locked');
    expect(terminated()).toBe(true);
  }
});

test('null worker message fails closed instead of leaving a pending signer', async () => {
  const { signer, fake, terminated } = worker();
  const pending = signer.init('test', 'c10');
  fake.onmessage!({ data: null });
  await expect(pending).rejects.toThrow('locked');
  expect(terminated()).toBe(true);
});

test('malformed signature response and worker decoding/dispatch failures lock', async () => {
  const { signer, reply, terminated } = worker();
  const initialized = signer.init('test', 'c10');
  reply({ mode: 'c10', publicKey });
  await initialized;
  const pending = signer.sign(digest);
  reply('0x1234');
  await expect(pending).rejects.toThrow('locked');
  expect(terminated()).toBe(true);

  let dispatchTerminated = false;
  const dispatch = {
    onmessage: undefined as unknown,
    onerror: undefined as unknown,
    onmessageerror: undefined as unknown,
    postMessage: () => {
      throw new Error('structured clone failed');
    },
    terminate: () => {
      dispatchTerminated = true;
    },
  };
  const failed = new PQSigner(() => dispatch as unknown as Worker);
  await expect(failed.init('test', 'c10')).rejects.toThrow('locked');
  expect(dispatchTerminated).toBe(true);
  await expect(failed.init('test', 'c10')).rejects.toThrow('locked');

  const { signer: other, fake } = worker();
  const decoding = other.init('test', 'c10');
  fake.onmessageerror!();
  await expect(decoding).rejects.toThrow('locked');
});
