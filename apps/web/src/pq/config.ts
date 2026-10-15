import type { Address } from 'viem';

const localHosts = ['localhost', '127.0.0.1'];
const publicHosts = ['bunker-wallet-pq-sepolia-test.pages.dev', 'bunker.supplies'];

export const experimentalEnabled = () =>
  import.meta.env.VITE_EXPERIMENTAL_PQ === '1' &&
  [...localHosts, ...publicHosts].includes(location.hostname);

export const sharedFactoryV3 = (): Address | undefined => {
  if (!experimentalEnabled()) return;
  if (publicHosts.includes(location.hostname)) return '0x85e66387d341aa1e03f9165cfd2013340a738a45';
  const local =
    import.meta.env.MODE !== 'production' && localHosts.includes(location.hostname)
      ? import.meta.env.VITE_EXPERIMENTAL_V3_LOCAL_FACTORY
      : undefined;
  return local && /^0x[0-9a-fA-F]{40}$/.test(local) ? (local as Address) : undefined;
};

export const sharedFactoryV2 = (): Address | undefined => {
  if (!experimentalEnabled()) return;
  if (publicHosts.includes(location.hostname)) return '0xe8bd10e94f67a4592ee9191ee6b3ab8e76b2c9bf';
  // Local Anvil tests may inject their own factory; public Sepolia is never used on localhost.
  const local =
    import.meta.env.MODE !== 'production' && localHosts.includes(location.hostname)
      ? import.meta.env.VITE_EXPERIMENTAL_V2_LOCAL_FACTORY
      : undefined;
  return local && /^0x[0-9a-fA-F]{40}$/.test(local) ? (local as Address) : undefined;
};
