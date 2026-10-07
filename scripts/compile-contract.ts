import solc from "solc";
import { dirname, join, normalize } from "node:path";

const root = "packages/contracts";
const entry = "src/BunkerRotationGuard.sol";
const sources: Record<string, { content: string }> = {};
const queue = [entry];
const diskPath = (name: string) => name.startsWith("@safe-global/safe-contracts/")
  ? join(root, "lib", name)
  : join(root, name);
while (queue.length) {
  const name = queue.pop()!;
  if (sources[name]) continue;
  const content = await Bun.file(diskPath(name)).text();
  sources[name] = { content };
  for (const match of content.matchAll(/import\s+(?:[^"']+from\s+)?["']([^"']+)["'];/g)) {
    const specifier = match[1]!;
    queue.push(specifier.startsWith(".") ? normalize(join(dirname(name), specifier)).replaceAll("\\", "/") : specifier);
  }
}
const output = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity", sources,
  settings: { optimizer: { enabled: true, runs: 100000 }, viaIR: true, outputSelection: { [entry]: { BunkerRotationGuard: ["abi", "evm.bytecode.object"] } } },
}))) as { errors?: { severity: string; formattedMessage: string }[]; contracts?: Record<string, Record<string, { abi: unknown[]; evm: { bytecode: { object: string } } }>> };
for (const error of output.errors ?? []) if (error.severity === "error") console.error(error.formattedMessage);
if ((output.errors ?? []).some(error => error.severity === "error")) process.exit(1);
const contract = output.contracts?.[entry]?.BunkerRotationGuard;
if (!contract?.evm.bytecode.object) throw new Error("BunkerRotationGuard bytecode was not produced.");
console.log(`Compiled BunkerRotationGuard with solc ${solc.version()} (${contract.evm.bytecode.object.length / 2} bytes).`);
