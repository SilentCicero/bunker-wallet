import type { Hex } from 'viem';
import type { PQMode } from '../../../../packages/pq/src/keys';

export type PublicPQ = { mode: PQMode; publicKey: Hex; blob?: Hex };
const hexBytes = (value: unknown, length: number): value is Hex =>
  typeof value === 'string' &&
  value.length === 2 + length * 2 &&
  /^0x(?:[0-9a-fA-F]{2})+$/.test(value);

/** One worker per unlocked experimental wallet. Lock/cancel terminates WASM and rejects in-flight work. */
export class PQSigner {
  private worker: Worker | undefined;
  private mode: PQMode | undefined;
  private next = 0;
  private pending:
    | { id: number; resolve: (v: unknown) => void; reject: (e: Error) => void }
    | undefined;

  constructor(
    makeWorker = () =>
      new Worker(new URL('./signer.worker.ts', import.meta.url), { type: 'module' }),
  ) {
    this.worker = makeWorker();
    this.worker.onmessage = ({ data }) => {
      const p = this.pending;
      if (!data || typeof data !== 'object') return this.close();
      if (!p || p.id !== data.id) return;
      this.pending = undefined;
      if (data.error) {
        p.reject(new Error(typeof data.error === 'string' ? data.error : 'PQ signer failed'));
        this.close();
      } else {
        p.resolve(data.result);
      }
    };
    this.worker.onerror = () => this.close();
    this.worker.onmessageerror = () => this.close();
  }

  private request(op: string, data: object): Promise<unknown> {
    if (!this.worker || this.pending) return Promise.reject(new Error('Signer locked or busy'));
    return new Promise((resolve, reject) => {
      const id = ++this.next;
      this.pending = { id, resolve, reject };
      try {
        this.worker!.postMessage({ id, op, ...data });
      } catch {
        this.close();
      }
    });
  }

  async init(mnemonic: string, mode: PQMode): Promise<PublicPQ> {
    this.mode = undefined;
    const result = await this.request('init', { mnemonic, mode });
    const output = result as Partial<PublicPQ> | null;
    if (
      !output ||
      output.mode !== mode ||
      !hexBytes(output.publicKey, mode === 'c10' ? 32 : 1312) ||
      (mode === 'c10' ? output.blob !== undefined : !hexBytes(output.blob, 20545))
    ) {
      this.close();
      throw new Error('Signer locked: invalid worker output');
    }
    this.mode = mode;
    return output as PublicPQ;
  }

  async sign(digest: Hex): Promise<Hex> {
    if (!hexBytes(digest, 32)) throw new Error('Invalid signing digest');
    if (!this.mode && !this.pending) throw new Error('Signer locked or not initialized');
    const result = await this.request('sign', { digest });
    if (!hexBytes(result, this.mode === 'c10' ? 4008 : 2420)) {
      this.close();
      throw new Error('Signer locked: invalid worker signature');
    }
    return result;
  }

  close() {
    this.worker?.terminate();
    this.worker = undefined;
    this.mode = undefined;
    this.pending?.reject(new Error('Signer locked'));
    this.pending = undefined;
  }
}
