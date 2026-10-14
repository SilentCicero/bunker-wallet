import { expect, test } from 'bun:test';
import { keccak256, toHex, type Hex } from 'viem';
import { validateManifest, type DeploymentManifest } from './index';

const address = (n: number) => toHex(n, { size: 20 });
const manifest: DeploymentManifest = {
  chainId: 11155111,
  safeVersion: '1.4.1',
  singleton: address(2),
  proxyFactory: address(3),
  multiSendCallOnly: address(4),
  guard: address(5),
  codeHashes: {
    singleton: keccak256('0x01'),
    proxyFactory: keccak256('0x02'),
    multiSendCallOnly: keccak256('0x03'),
    guard: keccak256('0x04'),
  },
};

test('accepts complete pinned Safe deployment metadata', () => {
  expect(validateManifest(structuredClone(manifest))).toEqual(manifest);
});

test('rejects wrong chain, Safe version, or deployment address before RPC', () => {
  expect(() => validateManifest({ ...manifest, chainId: 1 })).toThrow('Mainnet');
  expect(() => validateManifest({ ...manifest, safeVersion: '1.3.0' } as never)).toThrow('version');
  for (const singleton of [address(0), '0xinvalid']) {
    expect(() => validateManifest({ ...manifest, singleton } as DeploymentManifest)).toThrow(
      'address',
    );
  }
});

test('requires exactly four named, nonzero 32-byte code hashes', () => {
  const hashes = manifest.codeHashes;
  for (const key of Object.keys(hashes) as (keyof typeof hashes)[]) {
    const { [key]: _removed, ...missing } = hashes;
    expect(() => validateManifest({ ...manifest, codeHashes: missing } as never)).toThrow('hash');
    expect(() =>
      validateManifest({ ...manifest, codeHashes: { ...hashes, [key]: '0x12' } }),
    ).toThrow('hash');
    expect(() =>
      validateManifest({
        ...manifest,
        codeHashes: { ...hashes, [key]: toHex(0, { size: 32 }) as Hex },
      }),
    ).toThrow('hash');
  }
  expect(() =>
    validateManifest({ ...manifest, codeHashes: { ...hashes, decoy: keccak256('0x05') } } as never),
  ).toThrow('hash');
  expect(() => validateManifest({ ...manifest, codeHashes: null } as never)).toThrow('hash');
});
