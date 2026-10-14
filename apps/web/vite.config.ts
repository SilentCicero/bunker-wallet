import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
export default defineConfig({ plugins: [solid()], optimizeDeps: { include: ["@noble/post-quantum/ml-dsa.js", "@scure/bip39", "@scure/bip39/wordlists/english.js", "@noble/hashes/hkdf.js", "@noble/hashes/sha2.js", "@noble/hashes/sha3.js"] }, resolve: { dedupe: ["solid-js"] }, build: { target: "es2022", sourcemap: false }, server: { port: 4173 } });
