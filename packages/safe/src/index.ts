import { isAddress, type Address, type Hex } from 'viem';
import { SecurityPolicyError, assertSupportedChain, ZERO_ADDRESS } from '@bunker/core';

export type DeploymentManifest = {
  chainId: number;
  safeVersion: '1.4.1';
  singleton: Address;
  proxyFactory: Address;
  multiSendCallOnly: Address;
  guard: Address;
  codeHashes: Record<'singleton' | 'proxyFactory' | 'multiSendCallOnly' | 'guard', Hex>;
};

export function validateManifest(m: DeploymentManifest) {
  if (!m || typeof m !== 'object') throw new SecurityPolicyError('Deployment manifest is invalid.');
  assertSupportedChain(m.chainId);
  if (m.safeVersion !== '1.4.1') throw new SecurityPolicyError('Unsupported Safe version.');
  for (const a of [m.singleton, m.proxyFactory, m.multiSendCallOnly, m.guard]) {
    if (!isAddress(a, { strict: true }) || a === ZERO_ADDRESS) {
      throw new SecurityPolicyError('Deployment address is invalid.');
    }
  }
  const keys = ['singleton', 'proxyFactory', 'multiSendCallOnly', 'guard'] as const;
  const hashes = m.codeHashes;
  if (
    !hashes ||
    typeof hashes !== 'object' ||
    Array.isArray(hashes) ||
    Object.keys(hashes).length !== keys.length ||
    keys.some((key) => !/^0x[0-9a-fA-F]{64}$/.test(hashes[key]) || /^0x0{64}$/i.test(hashes[key]))
  ) {
    throw new SecurityPolicyError('Deployment code hash is invalid.');
  }
  return m;
}

export * from './hybrid';
