import { isAddress, isHex, keccak256, stringToHex, type Address, type Hex } from 'viem';
import { assertSupportedChain, SecurityPolicyError, ZERO_ADDRESS } from '@bunker/core';
export const MAX_ENVELOPE_BYTES = 64 * 1024;
const KEYS = [
  'version',
  'kind',
  'chainId',
  'safe',
  'safeVersion',
  'guard',
  'guardVersion',
  'manifestId',
  'nonce',
  'to',
  'value',
  'data',
  'operation',
  'safeTxGas',
  'baseGas',
  'gasPrice',
  'gasToken',
  'refundReceiver',
  'currentOwner',
  'nextOwner',
  'nextIndex',
  'safeTxHash',
  'signature',
  'checksum',
] as const;
export type OfflineEnvelope = {
  version: 2;
  kind: 'bunker-transfer';
  chainId: 31337 | 11155111;
  safe: Address;
  safeVersion: '1.4.1';
  guard: Address;
  guardVersion: 2;
  manifestId: Hex;
  nonce: string;
  to: Address;
  value: string;
  data: '0x';
  operation: 1;
  safeTxGas: string;
  baseGas: '0';
  gasPrice: '0';
  gasToken: typeof ZERO_ADDRESS;
  refundReceiver: typeof ZERO_ADDRESS;
  currentOwner: Address;
  nextOwner: Address;
  nextIndex: number;
  safeTxHash: Hex;
  signature?: Hex;
  checksum: Hex;
};
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`)
    .join(',')}}`;
}
function checksum(value: Omit<OfflineEnvelope, 'checksum'>): Hex {
  return keccak256(stringToHex(canonical(value)));
}
export function sealEnvelope(value: Omit<OfflineEnvelope, 'checksum'>): OfflineEnvelope {
  return validateEnvelope({ ...value, checksum: checksum(value) });
}
export function serializeEnvelope(value: OfflineEnvelope): string {
  return `${canonical(validateEnvelope(value))}\n`;
}
function decimal(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value))
    throw new SecurityPolicyError(`${label} must be a canonical decimal string.`);
  return value;
}
export function validateEnvelope(input: unknown): OfflineEnvelope {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new SecurityPolicyError('Envelope must be an object.');
  const obj = input as Record<string, unknown>;
  const unknown = Object.keys(obj).filter((k) => !KEYS.includes(k as (typeof KEYS)[number]));
  if (unknown.length) throw new SecurityPolicyError('Envelope contains unknown fields.');
  if (
    obj.version !== 2 ||
    obj.kind !== 'bunker-transfer' ||
    obj.safeVersion !== '1.4.1' ||
    obj.guardVersion !== 2 ||
    obj.operation !== 1 ||
    obj.data !== '0x'
  )
    throw new SecurityPolicyError('Envelope version or operation is unsupported.');
  if (typeof obj.chainId !== 'number' || !Number.isInteger(obj.chainId))
    throw new SecurityPolicyError('Chain ID must be an integer.');
  assertSupportedChain(obj.chainId);
  for (const key of ['safe', 'guard', 'to', 'currentOwner', 'nextOwner'] as const)
    if (
      typeof obj[key] !== 'string' ||
      !isAddress(obj[key] as string, { strict: true }) ||
      obj[key] === ZERO_ADDRESS
    )
      throw new SecurityPolicyError(`${key} is invalid.`);
  for (const key of ['manifestId', 'safeTxHash', 'checksum'] as const)
    if (
      typeof obj[key] !== 'string' ||
      !isHex(obj[key] as string, { strict: true }) ||
      (obj[key] as string).length !== 66
    )
      throw new SecurityPolicyError(`${key} must be bytes32.`);
  if (
    obj.signature !== undefined &&
    (typeof obj.signature !== 'string' ||
      !isHex(obj.signature as string, { strict: true }) ||
      (obj.signature as string).length !== 132)
  )
    throw new SecurityPolicyError('Signature must be canonical 65-byte hex.');
  for (const key of ['nonce', 'value', 'safeTxGas', 'baseGas', 'gasPrice'] as const)
    decimal(obj[key], key);
  if (
    ['nonce', 'value', 'safeTxGas'].some((key) => BigInt(obj[key] as string) >= 1n << 256n) ||
    BigInt(obj.value as string) === 0n ||
    BigInt(obj.value as string) > 10n ** 22n
  )
    throw new SecurityPolicyError('Envelope amount or nonce is out of bounds.');
  if (
    (obj.currentOwner as string).toLowerCase() === (obj.nextOwner as string).toLowerCase() ||
    BigInt(obj.currentOwner as string) <= 1n ||
    BigInt(obj.nextOwner as string) <= 1n
  )
    throw new SecurityPolicyError('Owner rotation is invalid.');
  if (
    obj.baseGas !== '0' ||
    obj.gasPrice !== '0' ||
    obj.gasToken !== ZERO_ADDRESS ||
    obj.refundReceiver !== ZERO_ADDRESS
  )
    throw new SecurityPolicyError('Safe refunds are disabled.');
  if (!Number.isSafeInteger(obj.nextIndex) || Number(obj.nextIndex) < 0)
    throw new SecurityPolicyError('Rotation counter is invalid.');
  const { checksum: provided, ...rest } = obj;
  if (checksum(rest as Omit<OfflineEnvelope, 'checksum'>) !== provided)
    throw new SecurityPolicyError('Envelope checksum mismatch.');
  return obj as OfflineEnvelope;
}
export function parseEnvelope(text: string): OfflineEnvelope {
  if (new TextEncoder().encode(text).byteLength > MAX_ENVELOPE_BYTES)
    throw new SecurityPolicyError('Envelope exceeds 64 KiB.');
  try {
    return validateEnvelope(JSON.parse(text) as unknown);
  } catch (e) {
    if (e instanceof SecurityPolicyError) throw e;
    throw new SecurityPolicyError('Envelope is not valid JSON.');
  }
}
