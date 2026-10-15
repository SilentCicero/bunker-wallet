import { expect, test } from 'bun:test';
import { experimentalEnabled, sharedFactoryV2, sharedFactoryV3 } from './config';

const setHost = (hostname: string) => {
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { hostname } });
};

test('experimental signing is build-gated to exact local and approved public hosts', () => {
  const previousLocation = Object.getOwnPropertyDescriptor(globalThis, 'location');
  const previousFlag = process.env.VITE_EXPERIMENTAL_PQ;
  try {
    process.env.VITE_EXPERIMENTAL_PQ = '1';
    for (const hostname of [
      'bunker.supplies.evil.example',
      'sub.bunker.supplies',
      'localhost.evil.example',
      'bunker-wallet-pq-sepolia-test.pages.dev.evil.example',
    ]) {
      setHost(hostname);
      expect(experimentalEnabled()).toBe(false);
      expect(sharedFactoryV2()).toBeUndefined();
      expect(sharedFactoryV3()).toBeUndefined();
    }
    for (const hostname of ['bunker.supplies', 'bunker-wallet-pq-sepolia-test.pages.dev']) {
      setHost(hostname);
      expect(experimentalEnabled()).toBe(true);
      expect(sharedFactoryV2()).toBe('0xe8bd10e94f67a4592ee9191ee6b3ab8e76b2c9bf');
      expect(sharedFactoryV3()).toBe('0x85e66387d341aa1e03f9165cfd2013340a738a45');
    }
    for (const hostname of ['localhost', '127.0.0.1']) {
      setHost(hostname);
      expect(experimentalEnabled()).toBe(true);
      expect(sharedFactoryV2()).toBeUndefined();
      expect(sharedFactoryV3()).toBeUndefined();
    }
    setHost('bunker.supplies');
    process.env.VITE_EXPERIMENTAL_PQ = '0';
    expect(experimentalEnabled()).toBe(false);
    expect(sharedFactoryV2()).toBeUndefined();
    expect(sharedFactoryV3()).toBeUndefined();
  } finally {
    if (previousLocation) Object.defineProperty(globalThis, 'location', previousLocation);
    else Reflect.deleteProperty(globalThis, 'location');
    if (previousFlag === undefined) delete process.env.VITE_EXPERIMENTAL_PQ;
    else process.env.VITE_EXPERIMENTAL_PQ = previousFlag;
  }
});
