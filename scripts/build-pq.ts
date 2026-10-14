import { homedir } from 'node:os';
import { join } from 'node:path';
import { readdirSync } from 'node:fs';
const forge = process.env.FORGE || join(homedir(), '.foundry/bin/forge');
function run(cmd: string[], cwd: string) { const p = Bun.spawnSync(cmd, {cwd, stdout:'inherit', stderr:'inherit'}); if (p.exitCode) throw new Error(`${cmd[0]} failed`); }
run(['cargo','build','--locked','--release','--target','wasm32-unknown-unknown'], 'packages/pq/c10');
await Bun.write('apps/web/src/pq/generated/c10.wasm', Bun.file('packages/pq/c10/target/wasm32-unknown-unknown/release/bunker_c10.wasm'));
const result: Record<string, unknown> = {};
for (const [dir, names] of [
 ['packages/contracts-experimental', ['ExperimentalFactory','ExperimentalSharedFactoryV2','ExperimentalSharedFactoryV3','ExperimentalRotationGuard','ExperimentalRotationGuardV3','ExperimentalSetup','ExperimentalC10Owner','ExperimentalMLDSAOwner']],
 ['packages/pq/verifiers/c10', ['SphincsC10Asm']],
 ['packages/pq/verifiers/mldsa', ['MLDSA44Verifier']],
] as const) {
 run([forge,'build','--force','--ast'],dir);
 const artifacts = readdirSync(dir+'/out',{recursive:true}).filter(x=>String(x).endsWith('.json')).map(x=>JSON.parse(require('node:fs').readFileSync(dir+'/out/'+x,'utf8')));
 const namesById: Record<string,string> = {};
 function visit(x: any) { if (!x || typeof x !== 'object') return; if (x.nodeType === 'VariableDeclaration' && x.mutability === 'immutable') namesById[x.id] = x.name; for (const v of Object.values(x)) if (typeof v === 'object') { if (Array.isArray(v)) v.forEach(visit); else visit(v); } }
 artifacts.forEach(x=>visit(x.ast));
 for (const name of names) {
  const a = artifacts.find(x=>x.metadata?.settings?.compilationTarget && Object.values(x.metadata.settings.compilationTarget).includes(name));
  if (!a) throw new Error(`Missing ${name}`);
  if ((a.deployedBytecode.object.length-2)/2 > 24576 || (a.bytecode.object.length-2)/2 > 49152) throw new Error(`${name} exceeds EVM deployment limits`);
  const immutables = Object.fromEntries(Object.entries(a.deployedBytecode.immutableReferences ?? {}).map(([id, refs])=>{if(!namesById[id])throw new Error('Unresolved immutable');return [namesById[id],refs]}));
  result[name] = {abi:a.abi, bytecode:a.bytecode.object, runtime:a.deployedBytecode.object, immutables};
 }
}
await Bun.write('apps/web/src/pq/generated/artifactsV2.json',JSON.stringify(result.ExperimentalSharedFactoryV2));
await Bun.write('apps/web/src/pq/generated/artifactsV3.json',JSON.stringify(result.ExperimentalSharedFactoryV3));
delete result.ExperimentalSharedFactoryV2;
delete result.ExperimentalSharedFactoryV3;
result.helper = '0x'+(await Bun.file('packages/pq/verifiers/mldsa/helper.hex').text()).trim().replace(/^0x/,'');
await Bun.write('apps/web/src/pq/generated/artifacts.json', JSON.stringify(result));
console.log('Built dedicated C10, real verifiers, and separately namespaced experimental contracts.');
