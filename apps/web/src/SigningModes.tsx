import { For, Show } from "solid-js";
import { sharedFactoryV2 } from './pq/config';

type Mode = "standard" | "c10" | "mldsa44";
const modes = [
  {
    id: "standard", name: "Standard", available: true,
    summary: "Rotating ECDSA owner. No post-quantum signature.",
    description: "Rotating ECDSA owner. No post-quantum signature. This is the only available mode.",
    cost: "Baseline transaction cost; network fees and next-owner funding still apply.",
    setupGas: 2926596, setupTransactions: 4, sendGas: 189548,
    sources: [{ label: "Safe signature handling", href: "https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol" }],
  },
  {
    id: "c10", name: "Quantum Shield", available: false,
    summary: "Rotating ECDSA + fixed SPHINCs+C10 · 2 of 2.",
    description: "ECDSA + SPHINCs+C10, both signatures required. Experimental custom hash-based scheme, not NIST SLH-DSA. Unavailable: compatible browser signer and independent review are missing.",
    cost: "Production deployment and signing costs have not been measured.",
    setupGas: 17523175, setupTransactions: 6, sendGas: 581292,
    sources: [
      { label: "C10 verifier source", href: "https://github.com/nconsigny/SPHINCs-/blob/55b2f3e25d8d7cc0df33ccdb13becca1a168b26f/src/keccak/SPHINCs-C10Asm.sol" },
      { label: "FIPS 205 (not C10)", href: "https://doi.org/10.6028/NIST.FIPS.205" },
    ],
  },
  {
    id: "mldsa44", name: "Maximum", available: false,
    summary: "Rotating ECDSA + fixed ML-DSA-44 · 2 of 2.",
    description: "ECDSA + ML-DSA-44, both signatures required. ML-DSA is standardized; this wallet and verifier are not NIST-certified. Unavailable: reviewed key registration and browser integration are missing.",
    cost: "Production public-key deployment and signing costs have not been measured.",
    setupGas: 22919688, setupTransactions: 7, sendGas: 1654704,
    sources: [
      { label: "ML-DSA verifier safety requirements", href: "https://github.com/fireblocks-labs/evm-ml-dsa-verifier/blob/cca262b537a5ac2ee55efb427e5c61de0308e566/docs/SAFETY.md" },
      { label: "FIPS 204", href: "https://doi.org/10.6028/NIST.FIPS.204" },
    ],
  },
] as const;

const gasLabel=(gas:number)=>gas>=1_000_000?`${(gas/1_000_000).toFixed(2)}M`:`${Math.round(gas/1_000)}k`;
const atOneGwei=(gas:number)=>(gas/1_000_000_000).toFixed(6);
/** A mode choice creates a new Safe; it never upgrades an existing one. */
export function SigningModes(props: {experimental?:boolean; selected?:Mode; onSelect?:(mode:Mode)=>void} = {}) {
  const selected = () => modes.find(mode => mode.id === (props.selected ?? "standard"))!;
  const metrics=(mode:typeof modes[number])=>props.experimental&&sharedFactoryV2()?mode.id==='c10'?{setupGas:11267678,setupTransactions:1,sendGas:939802}:mode.id==='mldsa44'?{setupGas:44585236,setupTransactions:2,sendGas:2011795}:mode:mode;
  const active=()=>metrics(selected());
  return <Show when={props.experimental} fallback={<fieldset class="signing-modes" aria-describedby="signing-mode-limits">
    <legend>Signing mode</legend>
    <p id="signing-mode-limits">Optional hybrid post-quantum signing is in local research, not available for wallet creation. These names are not a proven security ranking.</p>
    <For each={modes}>{mode => <div class="signing-choice">
      <label><input type="radio" name="signing-mode" value={mode.id} checked={(props.selected ?? "standard") === mode.id} disabled={!mode.available} onChange={()=>props.onSelect?.(mode.id)} aria-describedby={`${mode.id}-details`} /><strong>{mode.name}</strong><span>{mode.available ? "Available" : "Unavailable"}</span></label>
      <div id={`${mode.id}-details`}><p>{mode.description}</p><p class="signing-cost">{mode.cost}</p></div>
      <div class="signing-sources"><For each={mode.sources}>{source => <a href={source.href} target="_blank" rel="noopener noreferrer">{source.label}</a>}</For></div>
    </div>}</For>
    <p>Existing Safes need an on-chain migration, not a setting change. One root seed can simplify unlocking, but gives algorithmic diversity—not two independent secrets.</p>
  </fieldset>}>
    <div class="security-selector">
      <label for="security-level"><strong>{selected().name} · {selected().id==="standard"?"Single Signature":"Dual Signature (2 of 2)"}</strong><span class="security-gas">~{gasLabel(active().setupGas)} setup / ~{gasLabel(active().sendGas)} sending</span></label>
      <input id="security-level" aria-label="Signing mode" type="range" min="0" max="2" step="1" value={modes.findIndex(mode => mode.id === selected().id)} onInput={e=>props.onSelect?.(modes[Number(e.currentTarget.value)]!.id)} aria-valuetext={`${selected().name}, ${selected().id==='standard'?'Single Signature':'Dual Signature, 2 of 2'}, about ${gasLabel(active().setupGas)} setup gas and ${gasLabel(active().sendGas)} gas per supported send`}  />
      <div class="security-ticks" role="group" aria-label="Choose signing mode"><For each={modes}>{mode=><button type="button" aria-label={`Select ${mode.name}`} aria-pressed={mode.id===selected().id} onClick={()=>props.onSelect?.(mode.id)}>{mode.name}<small>{mode.id==='standard'?'Non-experimental':'Experimental'}</small></button>}</For></div>
      <details class="security-details"><summary><span class="security-summary">{selected().summary}</span><span class="details-toggle">Read details</span></summary>
        <p>Sepolia test ETH only · unaudited. Names describe signing combinations, not a proven security ranking. Budget at least 0.03 test ETH for setup; ML-DSA can need more when gas prices rise.</p>
        <p><strong>Setup:</strong> ~{gasLabel(active().setupGas)} gas across {active().setupTransactions} {active().setupTransactions===1?'transaction':'transactions'}. <strong>Send + rotate:</strong> ~{gasLabel(active().sendGas)} gas{selected().id==='standard'?' (baseline)':` (+${gasLabel(active().sendGas-modes[0].sendGas)} vs Standard)`}.</p>
        <p>At 1 gwei per gas: ~{atOneGwei(active().setupGas)} test ETH setup and ~{atOneGwei(active().sendGas)} test ETH per send. Actual fee = gas used × network gas price; these {selected().id==='standard'?'local Standard samples':sharedFactoryV2()?'historical Sepolia V2 PQ receipts (shared infrastructure excluded; V3 public-Safe costs unmeasured)':'local V1 samples'} are not a fee quote. Safe funding is extra. Extra signing is not proven safer.</p>
        <p>{selected().id === "standard" ? "Standard ECDSA only. No post-quantum signature." : selected().id === "c10" ? "C10 is an experimental custom hash-based scheme, not NIST SLH-DSA. Its signature budget is finite: never reuse a C10 phrase across wallets." : "ML-DSA-44 is a standardized parameter set, but this wallet and verifier are unaudited and not NIST-certified. On-chain checks cannot prove genuine browser KeyGen."}</p>
        <p>One phrase derives both owners, not two independent secrets. Existing Safes cannot switch modes without on-chain migration. Browser key generation is trusted; use disposable Sepolia test ETH only.</p>
        <div class="signing-sources"><For each={selected().sources}>{source => <a href={source.href} target="_blank" rel="noopener noreferrer">{source.label}</a>}</For></div>
      </details>
    </div>
  </Show>;
}
