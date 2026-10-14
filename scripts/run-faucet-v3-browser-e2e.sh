#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if curl -fsS --max-time 1 -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:18545 >/dev/null 2>&1 || curl -fsS --max-time 1 http://127.0.0.1:4173/ >/dev/null 2>&1; then echo 'Anvil or Vite port is in use; refusing to reuse another process.' >&2; exit 1; fi
umask 077
tmp=$(mktemp -d)
cleanup(){ if [[ -n "${anvil_pid:-}" ]]; then kill "$anvil_pid" 2>/dev/null || true; wait "$anvil_pid" 2>/dev/null || true; fi; rm -rf "$tmp"; }
trap cleanup EXIT
FAUCET_ENV_FILE="$tmp/faucet.env" bun -e 'import {randomBytes} from "node:crypto";import {writeFileSync} from "node:fs";import {entropyToMnemonic} from "@scure/bip39";import {wordlist} from "@scure/bip39/wordlists/english.js";import {mnemonicToAccount} from "viem/accounts";import {toHex} from "viem";const phrase=entropyToMnemonic(randomBytes(32),wordlist),key=mnemonicToAccount(phrase,{path:"m/44\x27/60\x27/0\x27/0/0"}).getHdKey().privateKey;writeFileSync(process.env.FAUCET_ENV_FILE!,`LOCAL_FAUCET_MNEMONIC="${phrase}"\nLOCAL_FAUCET_PRIVATE_KEY="${toHex(key!)}"\n`,{mode:0o600})'
set -a
source "$tmp/faucet.env"
set +a
"${ANVIL_BIN:-${HOME}/.foundry/bin/anvil}" --chain-id 11155111 --hardfork osaka --port 18545 --gas-limit 100000000 --disable-code-size-limit --silent --mnemonic "$LOCAL_FAUCET_MNEMONIC" --accounts 1 >"$tmp/anvil.log" 2>&1 &
anvil_pid=$!
for i in {1..30}; do if curl -fsS --max-time 1 -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:18545 >/dev/null 2>&1; then break; fi; sleep 1; done
kill -0 "$anvil_pid" 2>/dev/null || { echo 'Anvil did not start' >&2; exit 1; }
export VITE_EXPERIMENTAL_PQ=1 VITE_BROWSER_SEPOLIA_E2E=1 VITE_EXPERIMENTAL_RPC=http://127.0.0.1:18545 VITE_SEPOLIA_RPC=http://127.0.0.1:18545
export VITE_EXPERIMENTAL_V3_LOCAL_FACTORY="$(V3_FIXTURE=1 bun scripts/faucet-browser-fixture.ts)"
BROWSER_FAUCET_E2E=1 bunx playwright test tests/e2e/faucet-lifecycle.e2e.ts --workers=1
