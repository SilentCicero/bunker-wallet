import {
  createPublicClient,
  createWalletClient,
  http,
  parseAbi,
  encodeFunctionData,
  encodeAbiParameters,
  encodeDeployData,
  keccak256,
  concatHex,
  padHex,
  toHex,
  hexToBytes,
  bytesToHex,
  getContractAddress,
  hashTypedData,
  hashStruct,
  parseEventLogs,
  parseEther,
  isAddress,
  formatEther,
  parseTransaction,
  recoverTransactionAddress,
  TransactionReceiptNotFoundError,
  type Address,
  type Hex,
  type Abi,
} from 'viem';
import { mnemonicToAccount, privateKeyToAccount } from 'viem/accounts';
import { sepolia } from 'viem/chains';
import artifactsJSON from './generated/artifacts.json';
import { PQSigner, type PublicPQ } from './signer';
import {
  outboxKey as deriveOutboxKey,
  sealTransaction,
  openTransaction,
  type SealedTransaction,
} from './outbox';
import type { PQMode } from '../../../../packages/pq/src/keys';
import {
  hybridMessageDigest,
  encodeHybridSignatures,
  c10KeyId,
} from '../../../../packages/safe/src/experimental';
const ZERO = '0x0000000000000000000000000000000000000000' as Address;
const SENTINEL = '0x0000000000000000000000000000000000000001' as Address;
export const EXPERIMENTAL_CHAIN = 11155111;
const RPC = import.meta.env.VITE_EXPERIMENTAL_RPC || 'https://ethereum-sepolia.publicnode.com';
const SINGLETON = '0x41675C099F32341bf84BFc5382aF534df5C7461a' as Address;
const PROXIES = '0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67' as Address;
const MULTI = '0x9641d764fc13c8B624c04430C7356C1C7C8102e2' as Address;
const PROXY_HASH = '0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c' as Hex;
const official = [
  [SINGLETON, '0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4'],
  [PROXIES, '0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317'],
  [MULTI, '0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939'],
] as const;
const GUARD_SLOT = '0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8' as Hex;
export const safeABI = parseAbi([
  'function getOwners() view returns(address[])',
  'function getThreshold() view returns(uint256)',
  'function nonce() view returns(uint256)',
  'function swapOwner(address,address,address)',
  'function execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes) payable returns(bool)',
  'function getTransactionHash(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,uint256) view returns(bytes32)',
]);
const multiABI = parseAbi(['function multiSend(bytes) payable']);
const types = {
  SafeTx: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
    { name: 'operation', type: 'uint8' },
    { name: 'safeTxGas', type: 'uint256' },
    { name: 'baseGas', type: 'uint256' },
    { name: 'gasPrice', type: 'uint256' },
    { name: 'gasToken', type: 'address' },
    { name: 'refundReceiver', type: 'address' },
    { name: 'nonce', type: 'uint256' },
  ],
} as const;
type Artifact = {
  abi: Abi;
  bytecode: Hex;
  runtime: Hex;
  immutables: Record<string, { start: number; length: number }[]>;
};
export const artifacts = artifactsJSON as unknown as Record<string, Artifact> & { helper: Hex };
export type WalletRecord = {
  version: 1;
  chainId: 11155111;
  mode: PQMode;
  account: 0;
  index: 0;
  epoch: 0;
  ecSequenceVersion: 1;
  publicKey: Hex;
  parts: Record<string, Address>;
  safe?: Address;
  pending?: { kind: string; hash: Hex; sealed?: SealedTransaction };
};
/** Read-only routing hint. Full Standard/PQ attestation after deriving the phrase is mandatory. */
export async function detectSafeMode(safe: Address): Promise<'standard' | PQMode> {
  if (!isAddress(safe)) throw new Error('Enter a valid Safe address');
  const rpc = import.meta.env.VITE_EXPERIMENTAL_RPC || import.meta.env.VITE_SEPOLIA_RPC || RPC,
    client = createPublicClient({ chain: sepolia, transport: http(rpc) });
  if ((await client.getChainId()) !== EXPERIMENTAL_CHAIN)
    throw new Error('Only Ethereum Sepolia is supported');
  const code = await client.getCode({ address: safe });
  if (!code || keccak256(code) !== PROXY_HASH) throw new Error('Not a supported Safe proxy');
  const [owners, threshold, guard] = await Promise.all([
    client.readContract({ address: safe, abi: safeABI, functionName: 'getOwners' }),
    client.readContract({ address: safe, abi: safeABI, functionName: 'getThreshold' }),
    client.getStorageAt({ address: safe, slot: GUARD_SLOT }),
  ]);
  if (!guard || BigInt(guard) === 0n) throw new Error('Safe has no supported guard');
  if (owners.length === 1 && threshold === 1n) return 'standard';
  if (owners.length !== 2 || threshold !== 2n)
    throw new Error('Unsupported Safe signing configuration');
  const [ecCode, pqCode] = await Promise.all(
    owners.map((owner) => client.getCode({ address: owner })),
  );
  if ((ecCode && ecCode !== '0x') || !pqCode || pqCode === '0x')
    throw new Error('Unsupported Safe owner configuration');
  const ownerABI = parseAbi([
    'function safe() view returns(address)',
    'function algorithm() view returns(uint256)',
  ]);
  let bound: Address, algorithm: bigint;
  try {
    [bound, algorithm] = await Promise.all([
      client.readContract({ address: owners[1]!, abi: ownerABI, functionName: 'safe' }),
      client.readContract({ address: owners[1]!, abi: ownerABI, functionName: 'algorithm' }),
    ]);
  } catch {
    throw new Error('Unsupported Safe owner contract');
  }
  if (bound.toLowerCase() !== safe.toLowerCase())
    throw new Error('PQ owner is not bound to this Safe');
  if (algorithm === 1n) return 'c10';
  if (algorithm === 2n) return 'mldsa44';
  throw new Error('Unknown Safe signing algorithm');
}
export function validateRecord(record: WalletRecord) {
  if (!record || typeof record !== 'object')
    throw new Error('Unsupported experimental recovery metadata');
  if (
    record.version !== 1 ||
    record.chainId !== 11155111 ||
    !['c10', 'mldsa44'].includes(record.mode) ||
    record.account !== 0 ||
    record.index !== 0 ||
    record.epoch !== 0 ||
    record.ecSequenceVersion !== 1 ||
    typeof record.parts !== 'object' ||
    !record.parts ||
    Array.isArray(record.parts) ||
    !/^0x(?:[0-9a-fA-F]{2})+$/.test(record.publicKey) ||
    hexToBytes(record.publicKey).length !== (record.mode === 'c10' ? 32 : 1312)
  )
    throw new Error('Unsupported experimental recovery metadata');
  const validAddress = (value: unknown) =>
    typeof value === 'string' && isAddress(value, { strict: true }) && BigInt(value) > 1n;
  const pending = record.pending;
  if (
    Object.values(record.parts).some((a) => !validAddress(a)) ||
    ('safe' in record && !validAddress(record.safe)) ||
    ('pending' in record &&
      (!pending ||
        ![
          'helper',
          'blob',
          'SphincsC10Asm',
          'MLDSA44Verifier',
          'ExperimentalFactory',
          'ExperimentalSharedFactoryV2',
          'ExperimentalSharedFactoryV3',
          'fund',
          'send',
          'renew',
          'create',
          'createV2',
          'createV3',
        ].includes(pending.kind) ||
        !/^0x[0-9a-fA-F]{64}$/.test(pending.hash) ||
        (pending.sealed !== undefined &&
          (!pending.sealed ||
            !/^0x[0-9a-f]{24}$/.test(pending.sealed.iv) ||
            !/^0x(?:[0-9a-f]{2})+$/.test(pending.sealed.ciphertext) ||
            pending.sealed.ciphertext.length > 400000))))
  )
    throw new Error('Invalid experimental deployment metadata');
  return record;
}
function materialize(a: Artifact, values: Record<string, Hex | bigint | number>) {
  const bytes = hexToBytes(a.runtime);
  for (const [key, refs] of Object.entries(a.immutables)) {
    const value = values[key];
    if (value === undefined) throw new Error(`Missing ${key} binding`);
    const word = hexToBytes(
      typeof value === 'string' ? padHex(value, { size: 32 }) : toHex(BigInt(value), { size: 32 }),
    );
    for (const ref of refs) bytes.set(word, ref.start);
  }
  return bytesToHex(bytes);
}
export function runtime(name: string, values: Record<string, Hex | bigint | number>) {
  const a = artifacts[name];
  if (!a) throw new Error('Unknown artifact');
  return materialize(a, values);
}
export function dataCreation(code: Hex): Hex {
  if (typeof code !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(code))
    throw new Error('Invalid data-contract bytecode');
  const length = (code.length - 2) / 2;
  if (length > 24576) throw new Error('Data contract exceeds EVM limit');
  return concatHex([
    '0x61',
    toHex(length, { size: 2 }),
    '0x600e60003961',
    toHex(length, { size: 2 }),
    '0x6000f3',
    code,
  ]);
}
const packed = (to: Address, value: bigint, data: Hex = '0x') =>
  concatHex([
    '0x00',
    to,
    toHex(value, { size: 32 }),
    toHex(BigInt((data.length - 2) / 2), { size: 32 }),
    data,
  ]);
export function createExperimentalWallet(
  onRecord: (r: WalletRecord) => void,
  signer = new PQSigner(),
  rpc = RPC,
  sharedFactory?: Address,
  sharedFactoryV3?: Address,
) {
  const client = createPublicClient({
    chain: sepolia,
    transport: http(rpc),
    pollingInterval:
      import.meta.env.MODE !== 'production' &&
      ['localhost', '127.0.0.1'].includes(new URL(rpc).hostname)
        ? 50
        : 4000,
  });
  let v2Artifact: Artifact | undefined, v3Artifact: Artifact | undefined;
  const sharedArtifact = async (version: 2 | 3 = 2) =>
    version === 2
      ? (v2Artifact ??
        (v2Artifact = (await import('./generated/artifactsV2.json')).default as Artifact))
      : (v3Artifact ??
        (v3Artifact = (await import('./generated/artifactsV3.json')).default as Artifact));
  let ecRoot: ReturnType<ReturnType<typeof mnemonicToAccount>['getHdKey']> | undefined;
  let encryptionKey: CryptoKey | undefined;
  let mnemonic: string | undefined,
    pub: PublicPQ | undefined,
    record: WalletRecord | undefined,
    closed = false,
    confirmedBlock: bigint | undefined;
  const snapshotBlock = async (explicit?: bigint) => {
    if (explicit !== undefined) return explicit;
    const latest = await client.getBlockNumber();
    return confirmedBlock !== undefined && latest < confirmedBlock ? confirmedBlock : latest;
  };
  const active = () => {
    if (closed || !mnemonic || !pub || !record) throw new Error('Wallet locked');
  };
  const commit = (next: WalletRecord) => {
    if (closed) throw new Error('Wallet locked');
    onRecord(structuredClone(next));
    record = next;
  };
  const complete = (hash: Hex, change?: (next: WalletRecord) => void) => {
    if (record?.pending?.hash !== hash) throw new Error('Pending state changed');
    const next = structuredClone(record);
    change?.(next);
    delete next.pending;
    commit(next);
  };
  const outboxAAD = (kind: string, hash: Hex) =>
    JSON.stringify({
      version: 1,
      chainId: 11155111,
      mode: record!.mode,
      publicKey: pub!.publicKey,
      kind,
      hash,
    });
  const account = (index = 0, cycle = 0) => {
    active();
    if (
      !Number.isSafeInteger(cycle) ||
      cycle < 0 ||
      cycle >= 0x80000000 ||
      !Number.isInteger(index) ||
      index < 0 ||
      index > 20
    )
      throw new Error('Unsupported EC sequence');
    // Cycle zero exactly preserves the incumbent EC derivation. Renewal uses a separate hardened branch.
    if (cycle > 0 && index === 0) {
      cycle--;
      index = 20;
    }
    const branch =
      cycle === 0
        ? ecRoot!.deriveChild(0)
        : ecRoot!.deriveChild(0x80000003).deriveChild(0x80000000 + cycle);
    const child = branch.deriveChild(cycle === 0 ? index : 0x80000000 + index - 1),
      key = child.privateKey;
    if (!key) throw new Error('EC key unavailable');
    const result = privateKeyToAccount(bytesToHex(key));
    child.wipePrivateData();
    branch.wipePrivateData();
    return result;
  };
  const chain = async () => {
    if ((await client.getChainId()) !== 11155111)
      throw new Error('Only Ethereum Sepolia is supported');
  };
  const read = async (
    address: Address,
    name: string,
    fn: string,
    args: readonly unknown[] = [],
    blockNumber?: bigint,
  ) =>
    client.readContract({
      address,
      abi: artifacts[name]!.abi,
      functionName: fn,
      args,
      ...(blockNumber === undefined ? {} : { blockNumber }),
    }) as Promise<any>;
  const code = async (address: Address, blockNumber?: bigint) => {
    const x = await client.getCode({
      address,
      ...(blockNumber === undefined ? {} : { blockNumber }),
    });
    if (!x || x === '0x') throw new Error('Deployment unavailable');
    return x;
  };
  const check = async (address: Address, expected: Hex, blockNumber?: bigint) => {
    if ((await code(address, blockNumber)).toLowerCase() !== expected.toLowerCase())
      throw new Error('Deployment bytecode verification failed');
  };
  const standards = async (blockNumber?: bigint) => {
    await chain();
    for (const [address, hash] of official)
      if (keccak256(await code(address, blockNumber)) !== hash)
        throw new Error('Official Safe component changed');
  };
  const dependency = async (target: Address) => ({
    target,
    codeHash: keccak256(await code(target)),
  });
  async function transact(kind: string, data: Hex, to?: Address, index = 0, value = 0n, cycle = 0) {
    active();
    await chain();
    active();
    let hash: Hex;
    if (record!.pending) {
      if (record!.pending.kind !== kind) throw new Error('Resume the pending transaction first');
      hash = record!.pending.hash;
    } else {
      const a = account(index, cycle),
        wallet = createWalletClient({ account: a, chain: sepolia, transport: http(rpc) });
      const [latest, pending] = await Promise.all([
        client.getTransactionCount({ address: a.address, blockTag: 'latest' }),
        client.getTransactionCount({ address: a.address, blockTag: 'pending' }),
      ]);
      if (latest !== pending)
        throw new Error('An earlier transaction is pending. Wait and recover its status.');
      const request = { account: a, data, ...(to ? { to } : {}), value };
      const estimated = await client.estimateGas(request),
        gas = estimated + estimated / 10n;
      const [block, fees, balance] = await Promise.all([
        client.getBlock(),
        client.estimateFeesPerGas(),
        client.getBalance({ address: a.address }),
      ]);
      if (gas > block.gasLimit)
        throw new Error('Estimated transaction exceeds current block gas limit');
      const required = gas * fees.maxFeePerGas + value;
      if (balance < required)
        throw new Error(
          `Broadcaster ${a.address} needs up to ${formatEther(required)} Sepolia test ETH for this step. Top up and retry; completed steps are retained.`,
        );
      const prepared = await wallet.prepareTransactionRequest({
        ...request,
        gas,
        maxFeePerGas: fees.maxFeePerGas,
        maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
      });
      active();
      if (
        prepared.chainId !== 11155111 ||
        prepared.nonce !== latest ||
        prepared.to?.toLowerCase() !== to?.toLowerCase() ||
        prepared.data !== data ||
        prepared.value !== value ||
        prepared.gas !== gas ||
        prepared.maxFeePerGas !== fees.maxFeePerGas ||
        prepared.maxPriorityFeePerGas !== fees.maxPriorityFeePerGas
      )
        throw new Error('RPC changed the prepared transaction');
      const serialized = await a.signTransaction(prepared);
      active();
      hash = keccak256(serialized);
      const sealed = await sealTransaction(
        encryptionKey!,
        {
          raw: serialized,
          kind,
          chainId: 11155111,
          sender: a.address,
          nonce: latest,
          to: to ?? null,
          value: value.toString(),
          data,
          index,
          cycle,
          gas: gas.toString(),
          maxFeePerGas: fees.maxFeePerGas.toString(),
          maxPriorityFeePerGas: fees.maxPriorityFeePerGas.toString(),
        },
        outboxAAD(kind, hash),
      );
      active();
      commit({ ...record!, pending: { kind, hash, sealed } }); // Durable commit BEFORE in-memory authority or broadcast.
      try {
        active();
      } catch (error) {
        complete(hash);
        throw error;
      }
      try {
        const returned = await wallet.sendRawTransaction({ serializedTransaction: serialized });
        if (returned.toLowerCase() !== hash.toLowerCase()) throw new Error('RPC hash mismatch');
      } catch {
        throw new Error(
          `Broadcast outcome unknown for ${hash}. Reconcile or explicitly rebroadcast the same encrypted outbox transaction; no new action is allowed.`,
        );
      }
    }
    const receipt = await client.waitForTransactionReceipt({ hash });
    const authenticated = await pendingIntent(record!.pending!);
    checkedReceipt(receipt, record!.pending!, authenticated);
    if (receipt.status !== 'success')
      throw new Error(
        'Transaction reported reverted. The original signed intent is retained; inspect its canonical receipt before retrying.',
      );
    confirmedBlock = receipt.blockNumber;
    return receipt;
  }
  async function deploy(name: string, args: readonly unknown[] = [], key = name, raw?: Hex) {
    if (record!.parts[key]) return record!.parts[key]!;
    const a = artifacts[name];
    const data = raw
      ? dataCreation(raw)
      : encodeDeployData({ abi: a!.abi, bytecode: a!.bytecode, args });
    await transact(key, data);
    const settled = await reconcile();
    if (!settled || !record!.parts[key])
      throw new Error('Deployment receipt unavailable. Original signed transaction is retained.');
    active();
    return record!.parts[key]!;
  }
  async function open(
    phrase: string,
    mode: PQMode,
    saved?: WalletRecord,
    options: {
      persist?: boolean;
      expectedPublicKey?: Hex | undefined;
      beforePersist?: (publicKey: Hex) => Promise<void>;
    } = {},
  ) {
    if (closed) throw new Error('Wallet locked');
    record = undefined;
    pub = undefined;
    mnemonic = undefined;
    encryptionKey = undefined;
    confirmedBlock = undefined;
    ecRoot?.wipePrivateData();
    ecRoot = undefined;
    pub = await signer.init(phrase, mode);
    if (closed) throw new Error('Wallet locked');
    if (
      options.expectedPublicKey &&
      pub.publicKey.toLowerCase() !== options.expectedPublicKey.toLowerCase()
    )
      throw new Error('Recovery phrase does not match the encrypted vault');
    mnemonic = phrase;
    ecRoot = mnemonicToAccount(phrase, { path: "m/44'/60'/7331'" }).getHdKey();
    let candidate: WalletRecord;
    if (saved) {
      validateRecord(saved);
      if (saved.mode !== mode || saved.publicKey.toLowerCase() !== pub.publicKey.toLowerCase())
        throw new Error('Recovery phrase or signing mode does not match');
      candidate = structuredClone(saved);
    } else
      candidate = {
        version: 1,
        chainId: 11155111,
        mode,
        account: 0,
        index: 0,
        epoch: 0,
        ecSequenceVersion: 1,
        publicKey: pub.publicKey,
        parts: sharedFactoryV3
          ? { ExperimentalSharedFactoryV3: sharedFactoryV3 }
          : sharedFactory
            ? { ExperimentalSharedFactoryV2: sharedFactory }
            : {},
      };
    encryptionKey = await deriveOutboxKey(
      phrase,
      JSON.stringify({ chainId: 11155111, mode, publicKey: pub.publicKey }),
    );
    if (closed) {
      encryptionKey = undefined;
      throw new Error('Wallet locked');
    }
    if (options.persist !== false) await options.beforePersist?.(pub.publicKey);
    if (closed) throw new Error('Wallet locked');
    if (options.persist === false) record = candidate;
    else commit(candidate);
    return { address: account().address, publicKey: pub.publicKey };
  }
  async function verifyFactory(factory: Address, at: bigint) {
    const atRead = (address: Address, name: string, fn: string, args: readonly unknown[] = []) =>
        read(address, name, fn, args, at),
      atCode = (address: Address) => code(address, at),
      atCheck = (address: Address, expected: Hex) => check(address, expected, at);
    // Each registered factory version exposes the same immutable bindings.
    const vals: Record<string, Hex> = {};
    for (const key of Object.keys(artifacts.ExperimentalFactory!.immutables))
      vals[key] = await atRead(factory, 'ExperimentalFactory', key);
    const actual = await atCode(factory),
      v1 = runtime('ExperimentalFactory', vals);
    let version = actual.toLowerCase() === v1.toLowerCase() ? 1 : 0;
    for (const [candidate, address] of [
      [2, sharedFactory],
      [3, sharedFactoryV3],
    ] as const)
      if (
        !version &&
        address &&
        factory.toLowerCase() === address.toLowerCase() &&
        actual.toLowerCase() === materialize(await sharedArtifact(candidate), vals).toLowerCase()
      )
        version = candidate;
    if (!version) throw new Error('Factory bytecode or shared address verification failed');
    const guard = vals.guard as Address,
      setup = vals.setup as Address;
    if (
      vals.singleton?.toLowerCase() !== SINGLETON.toLowerCase() ||
      vals.proxyFactory?.toLowerCase() !== PROXIES.toLowerCase()
    )
      throw new Error('Factory policy mismatch');
    if (vals.singletonCodeHash !== official[0][1] || vals.proxyFactoryCodeHash !== official[1][1])
      throw new Error('Factory dependency mismatch');
    const helper = vals.mldsaHelper as Address,
      c10 = vals.c10Verifier as Address,
      mldsa = vals.mldsaVerifier as Address;
    await atCheck(helper, artifacts.helper);
    await atCheck(c10, runtime('SphincsC10Asm', {}));
    await atCheck(mldsa, runtime('MLDSA44Verifier', { F1600: helper }));
    if (
      vals.c10VerifierCodeHash !== keccak256(await atCode(c10)) ||
      vals.mldsaVerifierCodeHash !== keccak256(await atCode(mldsa))
    )
      throw new Error('Verifier binding mismatch');
    await atCheck(
      guard,
      runtime(version === 3 ? 'ExperimentalRotationGuardV3' : 'ExperimentalRotationGuard', {
        factory,
        singleton: SINGLETON,
        singletonCodeHash: official[0][1],
        proxyFactory: PROXIES,
        proxyFactoryCodeHash: official[1][1],
        multiSendCallOnly: MULTI,
        multiSendCodeHash: official[2][1],
        proxyCodeHash: PROXY_HASH,
      }),
    );
    await atCheck(setup, runtime('ExperimentalSetup', { guard, proxyFactory: PROXIES }));
    if (
      vals.guardCodeHash !== keccak256(await atCode(guard)) ||
      vals.setupCodeHash !== keccak256(await atCode(setup))
    )
      throw new Error('Setup binding mismatch');
    return { version, guard, setup, helper, c10, mldsa };
  }
  async function attest(safe: Address, blockNumber?: bigint) {
    active();
    const at = await snapshotBlock(blockNumber);
    for (let retry = 0; ; retry++)
      try {
        return await attestAt(safe, at);
      } catch (error) {
        if (retry >= 3 || !String(error).toLowerCase().includes('block not found')) throw error;
        await new Promise((resolve) => setTimeout(resolve, 1000 * (retry + 1)));
        active(); // Retry the same block, never silently lower the attestation height.
      }
  }
  async function attestAt(safe: Address, at: bigint) {
    active();
    const atRead = (address: Address, name: string, fn: string, args: readonly unknown[] = []) =>
        read(address, name, fn, args, at),
      atCode = (address: Address) => code(address, at),
      atCheck = (address: Address, expected: Hex) => check(address, expected, at);
    await standards(at);
    if (keccak256(await atCode(safe)) !== PROXY_HASH)
      throw new Error('Not the official Safe proxy');
    const owners = await client.readContract({
      address: safe,
      abi: safeABI,
      functionName: 'getOwners',
      blockNumber: at,
    });
    if (owners.length !== 2) throw new Error('Expected two owners');
    const [ec, pq] = owners as [Address, Address];
    const guardWord = await client.getStorageAt({
      address: safe,
      slot: GUARD_SLOT,
      blockNumber: at,
    });
    if (!guardWord) throw new Error('Missing guard');
    const guard = ('0x' + guardWord.slice(-40)) as Address;
    const factory = (await atRead(pq, 'ExperimentalC10Owner', 'factory')) as Address;
    const bindings = await verifyFactory(factory, at);
    if (bindings.guard.toLowerCase() !== guard.toLowerCase())
      throw new Error('Factory guard mismatch');
    const { helper, c10, mldsa } = bindings;
    const c = pub!.mode === 'c10',
      algorithm = c ? 1 : 2,
      verifier = c ? c10 : mldsa,
      verifierCodeHash = keccak256(await atCode(verifier));
    const seed = c
      ? padHex(('0x' + pub!.publicKey.slice(2, 34)) as Hex, { size: 32, dir: 'right' })
      : ('0x' as Hex);
    const root = c
      ? padHex(('0x' + pub!.publicKey.slice(34)) as Hex, { size: 32, dir: 'right' })
      : ('0x' as Hex);
    const keyId = c ? c10KeyId(seed, root) : keccak256(pub!.publicKey);
    const base = { algorithm, keyId, verifier, verifierCodeHash, epoch: 0, factory };
    if (c)
      await atCheck(pq, runtime('ExperimentalC10Owner', { ...base, pkSeed: seed, pkRoot: root }));
    else {
      const blob = (await atRead(pq, 'ExperimentalMLDSAOwner', 'pkBlob')) as Address;
      await atCheck(blob, pub!.blob!);
      await atCheck(
        pq,
        runtime('ExperimentalMLDSAOwner', {
          ...base,
          pkBlob: blob,
          blobCodeHash: keccak256(pub!.blob!),
          verifierHelper: helper,
        }),
      );
    }
    await atRead(guard, 'ExperimentalRotationGuard', 'attest', [safe, ec, pq]);
    const state = await atRead(guard, 'ExperimentalRotationGuard', 'state', [safe]);
    const index = Number(state[2]),
      cycle = Number(await atRead(guard, 'ExperimentalRotationGuard', 'sequenceEpoch', [safe]));
    if (index > 19 || account(index, cycle).address.toLowerCase() !== ec.toLowerCase())
      throw new Error('Recovery does not match current EC owner');
    for (let i = index; i < 20; i++) {
      const committed = await atRead(guard, 'ExperimentalRotationGuard', 'committedOwner', [
        safe,
        BigInt(i),
      ]);
      if (committed.toLowerCase() !== account(i + 1, cycle).address.toLowerCase())
        throw new Error('Committed EC recovery sequence mismatch');
    }
    const balance = await client.getBalance({ address: safe, blockNumber: at });
    active();
    return {
      safe,
      ec,
      pq,
      nextEc: account(index + 1, cycle).address,
      guard,
      factory,
      factoryVersion: bindings.version,
      index,
      cycle,
      keyId,
      verifier,
      verifierCodeHash,
      algorithm: algorithm as 1 | 2,
      balance,
    };
  }
  async function create(value = 0n) {
    active();
    await standards();
    if (record!.safe) {
      await attest(record!.safe);
      return record!.safe;
    }
    const c = pub!.mode === 'c10',
      sequence = Array.from({ length: 20 }, (_, i) => account(i + 1).address);
    const key = (blob: Address) => ({
      algorithm: c ? 1n : 2n,
      seed: c
        ? padHex(('0x' + pub!.publicKey.slice(2, 34)) as Hex, { size: 32, dir: 'right' })
        : padHex('0x', { size: 32 }),
      root: c
        ? padHex(('0x' + pub!.publicKey.slice(34)) as Hex, { size: 32, dir: 'right' })
        : padHex('0x', { size: 32 }),
      blob,
      publicKey: c ? '0x' : pub!.publicKey,
    });
    const shared =
      record!.parts.ExperimentalSharedFactoryV3 ?? record!.parts.ExperimentalSharedFactoryV2;
    if (shared) {
      if (record!.parts.ExperimentalFactory)
        throw new Error('Shared Safe cannot use a legacy factory');
      const bindings = await verifyFactory(shared, await snapshotBlock());
      if (bindings.version !== (record!.parts.ExperimentalSharedFactoryV3 ? 3 : 2))
        throw new Error('Unknown shared factory');
      let blob = ZERO;
      if (!c) {
        blob = await deploy('', [], 'blob', pub!.blob!);
        await check(blob, pub!.blob!);
      }
      const funding = value || parseEther('0.01');
      if (funding <= 0n)
        throw new Error('Top up the setup key before creating and funding the Safe');
      await transact(
        bindings.version === 3 ? 'createV3' : 'createV2',
        encodeFunctionData({
          abi: (await sharedArtifact(bindings.version)).abi,
          functionName: 'createAndFund',
          args: [account().address, sequence, key(blob), 0n],
        }),
        shared,
        0,
        funding,
      );
    } else {
      if (value !== 0n)
        throw new Error('Legacy Safe funding requires a separate confirmed transaction');
      const helper = await deploy('', [], 'helper', artifacts.helper);
      await check(helper, artifacts.helper);
      const c10 = await deploy('SphincsC10Asm');
      await check(c10, runtime('SphincsC10Asm', {}));
      const mldsa = await deploy('MLDSA44Verifier', [helper]);
      await check(mldsa, runtime('MLDSA44Verifier', { F1600: helper }));
      let blob = ZERO;
      if (!c) {
        blob = await deploy('', [], 'blob', pub!.blob!);
        await check(blob, pub!.blob!);
      }
      const args = [
        await dependency(SINGLETON),
        await dependency(PROXIES),
        await dependency(MULTI),
        await dependency(c10),
        await dependency(mldsa),
        await dependency(helper),
        PROXY_HASH,
      ];
      const factory = await deploy('ExperimentalFactory', args);
      const guard = getContractAddress({ from: factory, nonce: 1n }),
        setup = getContractAddress({ from: factory, nonce: 2n });
      await check(
        factory,
        runtime('ExperimentalFactory', {
          singleton: SINGLETON,
          singletonCodeHash: official[0][1],
          proxyFactory: PROXIES,
          proxyFactoryCodeHash: official[1][1],
          guard,
          guardCodeHash: keccak256(await code(guard)),
          setup,
          setupCodeHash: keccak256(await code(setup)),
          c10Verifier: c10,
          c10VerifierCodeHash: keccak256(await code(c10)),
          mldsaVerifier: mldsa,
          mldsaVerifierCodeHash: keccak256(await code(mldsa)),
          mldsaHelper: helper,
        }),
      );
      await transact(
        'create',
        encodeFunctionData({
          abi: artifacts.ExperimentalFactory!.abi,
          functionName: 'create',
          args: [account().address, sequence, key(blob), 0n],
        }),
        factory,
      );
    }
    const settled = await reconcile();
    if (!settled || !record!.safe)
      throw new Error(
        'Safe creation receipt unavailable. Original signed transaction is retained.',
      );
    return record!.safe;
  }
  async function pendingIntent(pending: NonNullable<WalletRecord['pending']>) {
    active();
    if (!pending.sealed)
      throw new Error(
        'Authenticated outbox missing. Reconcile manually; never submit a duplicate.',
      );
    const intent = (await openTransaction(
      encryptionKey!,
      pending.sealed,
      outboxAAD(pending.kind, pending.hash),
    )) as {
      raw: Hex;
      kind: string;
      chainId: number;
      sender: Address;
      nonce: number;
      to: Address | null;
      value: string;
      data: Hex;
      index: number;
      cycle: number;
      gas: string;
      maxFeePerGas: string;
      maxPriorityFeePerGas: string;
    };
    if (typeof intent.raw !== 'string' || !/^0x02(?:[0-9a-f]{2})+$/.test(intent.raw))
      throw new Error('Invalid encrypted transaction');
    const tx = parseTransaction(intent.raw),
      sender = await recoverTransactionAddress({
        serializedTransaction: intent.raw as `0x02${string}`,
      });
    const matches = {
      hash: keccak256(intent.raw) === pending.hash,
      kind: intent.kind === pending.kind,
      chain: intent.chainId === 11155111 && tx.chainId === 11155111,
      nonce: tx.nonce === intent.nonce,
      to: (tx.to ?? null)?.toLowerCase() === intent.to?.toLowerCase(),
      value: (tx.value ?? 0n).toString() === intent.value,
      data: (tx.data ?? '0x').toLowerCase() === intent.data.toLowerCase(),
      gas: (tx.gas ?? 0n).toString() === intent.gas,
      fee: (tx.maxFeePerGas ?? 0n).toString() === intent.maxFeePerGas,
      priority: (tx.maxPriorityFeePerGas ?? 0n).toString() === intent.maxPriorityFeePerGas,
      sender: sender.toLowerCase() === intent.sender.toLowerCase(),
      derivation:
        sender.toLowerCase() === account(intent.index, intent.cycle).address.toLowerCase(),
    };
    for (const [field, matched] of Object.entries(matches))
      if (!matched) throw new Error(`Encrypted transaction ${field} mismatch`);
    return intent;
  }
  function checkedReceipt(
    receipt: { transactionHash: Hex; from: Address; to: Address | null },
    pending: NonNullable<WalletRecord['pending']>,
    intent: Awaited<ReturnType<typeof pendingIntent>>,
  ) {
    if (
      receipt.transactionHash.toLowerCase() !== pending.hash.toLowerCase() ||
      receipt.from.toLowerCase() !== intent.sender.toLowerCase() ||
      receipt.to?.toLowerCase() !== intent.to?.toLowerCase()
    )
      throw new Error('Receipt does not match authenticated signed intent');
  }
  async function rebroadcast() {
    active();
    await chain();
    const pending = record!.pending;
    if (!pending) throw new Error('No pending transaction');
    const intent = await pendingIntent(pending);
    active();
    let receipt;
    try {
      receipt = await client.getTransactionReceipt({ hash: pending.hash });
    } catch (error) {
      if (!(error instanceof TransactionReceiptNotFoundError))
        throw new Error(
          'Original receipt check failed; signed transaction retained. Retry checking before rebroadcasting.',
        );
    }
    if (!receipt) {
      active();
      try {
        const returned = await client.request({
          method: 'eth_sendRawTransaction',
          params: [intent.raw],
        });
        if (returned.toLowerCase() !== pending.hash.toLowerCase())
          throw new Error('RPC hash mismatch');
      } catch {
        throw new Error(
          'Broadcast remains uncertain. The original encrypted transaction is retained.',
        );
      }
      receipt = await client.waitForTransactionReceipt({ hash: pending.hash });
    }
    const settled = await reconcile();
    if (!settled)
      throw new Error('Original receipt is unavailable. The signed transaction is retained.');
    return settled.hash;
  }
  async function reconcile() {
    active();
    const pending = record!.pending;
    if (!pending) return;
    await chain();
    const intent = await pendingIntent(pending);
    let receipt;
    try {
      receipt = await client.getTransactionReceipt({ hash: pending.hash });
    } catch (error) {
      if (error instanceof TransactionReceiptNotFoundError) return;
      throw error;
    }
    active();
    checkedReceipt(receipt, pending, intent);
    confirmedBlock = receipt.blockNumber;
    if (receipt.status !== 'success')
      throw new Error(
        'Original transaction reported reverted. Signed intent retained; verify the canonical receipt manually before retrying.',
      );
    if (pending.kind === 'create' || pending.kind === 'createV2' || pending.kind === 'createV3') {
      const version = pending.kind === 'createV3' ? 3 : pending.kind === 'createV2' ? 2 : 1,
        shared = version !== 1,
        factory =
          record!.parts[
            version === 3
              ? 'ExperimentalSharedFactoryV3'
              : shared
                ? 'ExperimentalSharedFactoryV2'
                : 'ExperimentalFactory'
          ];
      if (!factory || intent.to?.toLowerCase() !== factory.toLowerCase())
        throw new Error('Signed Safe creation targets a different factory');
      const events = parseEventLogs({
        abi: shared
          ? (await sharedArtifact(version as 2 | 3)).abi
          : artifacts.ExperimentalFactory!.abi,
        logs: receipt.logs,
        eventName: 'Created',
      }) as { address: Address; args: { safe: Address } }[];
      const event = events.find((log) => log.address.toLowerCase() === factory.toLowerCase());
      if (events.length !== 1 || !event?.args.safe)
        throw new Error('Original Safe creation event is missing or mismatched');
      const state = await attest(event.args.safe, receipt.blockNumber);
      if (
        state.factory.toLowerCase() !== factory.toLowerCase() ||
        state.factoryVersion !== version ||
        (shared && state.balance < BigInt(intent.value))
      )
        throw new Error('Safe creation or funding attestation failed');
      complete(pending.hash, (next) => {
        next.safe = event.args.safe;
      });
    } else if (['fund', 'send', 'renew'].includes(pending.kind)) {
      if (!record!.safe) throw new Error('Pending Safe transaction has no saved Safe address');
      await attest(record!.safe, receipt.blockNumber);
      complete(pending.hash);
    } else {
      const address = receipt.contractAddress,
        expected = getContractAddress({ from: intent.sender, nonce: BigInt(intent.nonce) });
      if (
        !address ||
        address.toLowerCase() !== expected.toLowerCase() ||
        record!.parts[pending.kind]
      )
        throw new Error('Original deployment address does not match signed transaction');
      let bytecode: Hex;
      if (pending.kind === 'helper') bytecode = artifacts.helper;
      else if (pending.kind === 'SphincsC10Asm') bytecode = runtime('SphincsC10Asm', {});
      else if (pending.kind === 'MLDSA44Verifier')
        bytecode = runtime('MLDSA44Verifier', { F1600: record!.parts.helper! });
      else if (pending.kind === 'blob' && pub!.mode === 'mldsa44') bytecode = pub!.blob!;
      else if (pending.kind === 'ExperimentalFactory') {
        const parts = record!.parts,
          guard = getContractAddress({ from: address, nonce: 1n }),
          setup = getContractAddress({ from: address, nonce: 2n });
        if (!parts.helper || !parts.SphincsC10Asm || !parts.MLDSA44Verifier)
          throw new Error('Factory dependencies are missing');
        await standards(receipt.blockNumber);
        await check(parts.helper, artifacts.helper, receipt.blockNumber);
        await check(parts.SphincsC10Asm, runtime('SphincsC10Asm', {}), receipt.blockNumber);
        await check(
          parts.MLDSA44Verifier,
          runtime('MLDSA44Verifier', { F1600: parts.helper }),
          receipt.blockNumber,
        );
        bytecode = runtime('ExperimentalFactory', {
          singleton: SINGLETON,
          singletonCodeHash: official[0][1],
          proxyFactory: PROXIES,
          proxyFactoryCodeHash: official[1][1],
          guard,
          guardCodeHash: keccak256(await code(guard, receipt.blockNumber)),
          setup,
          setupCodeHash: keccak256(await code(setup, receipt.blockNumber)),
          c10Verifier: parts.SphincsC10Asm,
          c10VerifierCodeHash: keccak256(await code(parts.SphincsC10Asm, receipt.blockNumber)),
          mldsaVerifier: parts.MLDSA44Verifier,
          mldsaVerifierCodeHash: keccak256(await code(parts.MLDSA44Verifier, receipt.blockNumber)),
          mldsaHelper: parts.helper,
        });
        await check(
          guard,
          runtime('ExperimentalRotationGuard', {
            factory: address,
            singleton: SINGLETON,
            singletonCodeHash: official[0][1],
            multiSendCallOnly: MULTI,
            multiSendCodeHash: official[2][1],
            proxyCodeHash: PROXY_HASH,
          }),
          receipt.blockNumber,
        );
        await check(
          setup,
          runtime('ExperimentalSetup', { guard, proxyFactory: PROXIES }),
          receipt.blockNumber,
        );
      } else throw new Error('Unsupported pending setup transaction');
      await check(address, bytecode, receipt.blockNumber);
      complete(pending.hash, (next) => {
        next.parts[pending.kind] = address;
      });
    }
    return { ...pending, blockNumber: receipt.blockNumber };
  }
  async function noPending() {
    if (record!.pending) {
      const settled = await reconcile();
      throw new Error(
        settled
          ? `Previous ${settled.kind} confirmed. Review balances before submitting another transaction.`
          : 'Pending outcome is unknown. Reconcile or rebroadcast the same encrypted transaction; do not create a replacement.',
      );
    }
  }
  async function restore(safe: Address) {
    if (!isAddress(safe)) throw new Error('Invalid Safe address');
    if (record?.pending && record.safe?.toLowerCase() !== safe.toLowerCase())
      throw new Error('Resolve the pending transaction before changing Safe');
    const state = await attest(safe);
    active();
    const next = structuredClone(record!);
    if (
      (next.parts.ExperimentalFactory &&
        next.parts.ExperimentalFactory.toLowerCase() !== state.factory.toLowerCase()) ||
      (next.parts.blob && !next.parts.ExperimentalFactory && state.factoryVersion === 1)
    )
      throw new Error('Saved setup does not match this Safe factory');
    if (state.factoryVersion !== 1) {
      const key =
        state.factoryVersion === 3 ? 'ExperimentalSharedFactoryV3' : 'ExperimentalSharedFactoryV2';
      if (next.parts[key] && next.parts[key]!.toLowerCase() !== state.factory.toLowerCase())
        throw new Error('Shared factory mismatch');
      if (next.safe && next.parts[key]?.toLowerCase() !== state.factory.toLowerCase())
        throw new Error('Saved Safe factory changed');
      delete next.parts.ExperimentalFactory;
      delete next.parts.ExperimentalSharedFactoryV2;
      delete next.parts.ExperimentalSharedFactoryV3;
      next.parts[key] = state.factory;
    } else {
      delete next.parts.ExperimentalSharedFactoryV2;
      delete next.parts.ExperimentalSharedFactoryV3;
      next.parts.ExperimentalFactory = state.factory;
    }
    commit({ ...next, safe });
    return state;
  }
  async function fund(value: bigint) {
    active();
    await noPending();
    if (!record!.safe || value <= 0n) throw new Error('Enter a positive test ETH amount');
    const state = await attest(record!.safe);
    const receipt = await transact('fund', '0x', record!.safe, state.index, value, state.cycle);
    complete(receipt.transactionHash);
    return receipt.transactionHash;
  }
  async function send(to: Address, value: bigint) {
    active();
    await noPending();
    if (!record!.safe || !isAddress(to) || value <= 0n)
      throw new Error('Enter recipient and positive test ETH amount');
    const s = await attest(record!.safe);
    if (s.index >= 19) throw new Error('Renew the ECDSA sequence before sending again.');
    if (value + parseEther('0.001') > s.balance)
      throw new Error('Keep 0.001 test ETH for the next broadcaster');

    const next = account(s.index + 1, s.cycle).address;
    const data = encodeFunctionData({
      abi: multiABI,
      functionName: 'multiSend',
      args: [
        concatHex([
          packed(to, value),
          packed(next, parseEther('0.001')),
          packed(
            s.safe,
            0n,
            encodeFunctionData({
              abi: safeABI,
              functionName: 'swapOwner',
              args: [SENTINEL, s.ec, next],
            }),
          ),
        ]),
      ],
    });
    return execute(s, data, 'send');
  }
  async function renew() {
    active();
    await noPending();
    if (!record!.safe) throw new Error('Create or recover the Safe first');
    const s = await attest(record!.safe);
    if (s.index !== 19) throw new Error('Renewal is only permitted at the reserved final owner');
    if (s.balance < parseEther('0.001'))
      throw new Error('Fund the Safe for the reserved broadcaster');
    const next = account(20, s.cycle).address,
      sequence = Array.from({ length: 20 }, (_, i) => account(i + 1, s.cycle + 1).address);
    const data = encodeFunctionData({
      abi: multiABI,
      functionName: 'multiSend',
      args: [
        concatHex([
          packed(next, parseEther('0.001')),
          packed(
            s.safe,
            0n,
            encodeFunctionData({
              abi: safeABI,
              functionName: 'swapOwner',
              args: [SENTINEL, s.ec, next],
            }),
          ),
          packed(
            s.guard,
            0n,
            encodeFunctionData({
              abi: artifacts.ExperimentalRotationGuard!.abi,
              functionName: 'renew',
              args: [sequence],
            }),
          ),
        ]),
      ],
    });
    return execute(s, data, 'renew');
  }
  async function execute(s: Awaited<ReturnType<typeof attest>>, data: Hex, kind: 'send' | 'renew') {
    const nonce = await client.readContract({
      address: s.safe,
      abi: safeABI,
      functionName: 'nonce',
    });
    const tx = {
      to: MULTI,
      value: 0n,
      data,
      operation: 1,
      safeTxGas: 0n,
      baseGas: 0n,
      gasPrice: 0n,
      gasToken: ZERO,
      refundReceiver: ZERO,
      nonce,
    } as const;
    const domain = { chainId: 11155111, verifyingContract: s.safe };
    const hash = hashTypedData({ domain, types, primaryType: 'SafeTx', message: tx });
    const preimage = concatHex([
      '0x1901',
      keccak256(
        encodeAbiParameters(
          [{ type: 'bytes32' }, { type: 'uint256' }, { type: 'address' }],
          [
            keccak256(toHex('EIP712Domain(uint256 chainId,address verifyingContract)')),
            11155111n,
            s.safe,
          ],
        ),
      ),
      hashStruct({ data: tx, types, primaryType: 'SafeTx' }),
    ]);
    const rpcHash = await client.readContract({
      address: s.safe,
      abi: safeABI,
      functionName: 'getTransactionHash',
      args: [tx.to, tx.value, data, 1, 0n, 0n, 0n, ZERO, ZERO, nonce],
    });
    if (hash !== rpcHash) throw new Error('Safe digest mismatch');
    const digest = hybridMessageDigest({
      chainId: 11155111,
      safe: s.safe,
      preimage,
      algorithm: s.algorithm,
      version: 1,
      adapter: s.pq,
      keyId: s.keyId,
      verifier: s.verifier,
      verifierCodeHash: s.verifierCodeHash,
      epoch: 0n,
    });
    const pqSignature = await signer.sign(digest);
    active();
    const ecSignature = await account(s.index, s.cycle).sign({ hash });
    active();
    const signatures = encodeHybridSignatures(s.ec, s.pq, ecSignature, pqSignature, s.algorithm);
    const receipt = await transact(
      kind,
      encodeFunctionData({
        abi: safeABI,
        functionName: 'execTransaction',
        args: [MULTI, 0n, data, 1, 0n, 0n, 0n, ZERO, ZERO, signatures],
      }),
      s.safe,
      s.index,
      0n,
      s.cycle,
    );
    const after = await attest(s.safe, receipt.blockNumber);
    if (
      after.index !== (kind === 'renew' ? 0 : s.index + 1) ||
      after.cycle !== s.cycle + (kind === 'renew' ? 1 : 0) ||
      after.pq !== s.pq
    )
      throw new Error('Unexpected rotation outcome');
    complete(receipt.transactionHash);
    return receipt.transactionHash;
  }
  return {
    open,
    create,
    restore,
    attest,
    reconcile,
    rebroadcast,
    fund,
    send,
    renew,
    balance: async (a: Address) =>
      client.getBalance({ address: a, blockNumber: await snapshotBlock() }),
    close() {
      closed = true;
      mnemonic = undefined;
      encryptionKey = undefined;
      ecRoot?.wipePrivateData();
      ecRoot = undefined;
      pub = undefined;
      signer.close();
    },
    get record() {
      return record;
    },
  };
}
