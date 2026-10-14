import type { Address } from 'viem';
export const experimentalEnabled = () => import.meta.env.VITE_EXPERIMENTAL_PQ === '1' && ['localhost','127.0.0.1','bunker-wallet-pq-sepolia-test.pages.dev'].includes(location.hostname);
export const sharedFactoryV3 = ():Address|undefined => {
 if(!experimentalEnabled())return;
 // Public V3 is enabled only after on-chain bytecode attestation and release gates.
 const local=import.meta.env.MODE!=='production'&&['localhost','127.0.0.1'].includes(location.hostname)?import.meta.env.VITE_EXPERIMENTAL_V3_LOCAL_FACTORY:undefined;
 return local&&/^0x[0-9a-fA-F]{40}$/.test(local)?local as Address:undefined;
};
export const sharedFactoryV2 = ():Address|undefined => {
 if(!experimentalEnabled())return;
 if(location.hostname==='bunker-wallet-pq-sepolia-test.pages.dev')return '0xe8bd10e94f67a4592ee9191ee6b3ab8e76b2c9bf';
 // Local Anvil tests may inject their own factory; the public Sepolia address is never used on localhost.
 const local=import.meta.env.MODE!=='production'&&['localhost','127.0.0.1'].includes(location.hostname)?import.meta.env.VITE_EXPERIMENTAL_V2_LOCAL_FACTORY:undefined;
 return local&&/^0x[0-9a-fA-F]{40}$/.test(local)?local as Address:undefined;
};
