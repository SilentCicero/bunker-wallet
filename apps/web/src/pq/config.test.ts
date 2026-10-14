import { expect, test } from 'bun:test';
import { experimentalEnabled, sharedFactoryV2, sharedFactoryV3 } from './config';

const setHost = (hostname: string) => {
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { hostname } });
};

test('experimental signing is gated to exact local and isolated-preview hostnames', () => {
  const location = Object.getOwnPropertyDescriptor(globalThis, 'location');
  const previous = process.env.VITE_EXPERIMENTAL_PQ;
  try {
    process.env.VITE_EXPERIMENTAL_PQ = '1';
    for (const hostname of [
      'bunker.supplies',
      'localhost.evil.example',
      'bunker-wallet-pq-sepolia-test.pages.dev.evil.example',
    ]) {
      setHost(hostname);
      expect(experimentalEnabled()).toBe(false);
      expect(sharedFactoryV2()).toBeUndefined();
      expect(sharedFactoryV3()).toBeUndefined();
    }
    for (const hostname of ['localhost', '127.0.0.1', 'bunker-wallet-pq-sepolia-test.pages.dev']) {
      setHost(hostname);
      expect(experimentalEnabled()).toBe(true);
    }
    expect(sharedFactoryV2()).toBe('0xe8bd10e94f67a4592ee9191ee6b3ab8e76b2c9bf');
    setHost('localhost');
    process.env.VITE_EXPERIMENTAL_PQ = '0';
    expect(experimentalEnabled()).toBe(false);
  } finally {
    if (location) Object.defineProperty(globalThis, 'location', location);
    else Reflect.deleteProperty(globalThis, 'location');
    if (previous === undefined) delete process.env.VITE_EXPERIMENTAL_PQ;
    else process.env.VITE_EXPERIMENTAL_PQ = previous;
  }
});
