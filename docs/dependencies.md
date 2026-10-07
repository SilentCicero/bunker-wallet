# Dependencies

Direct runtime dependencies are SolidJS, viem, audited Scure/Noble primitives, and official Safe 1.4.1 contracts. Vite and TypeScript are development dependencies. Versions are exact and `bun.lock` is committed. No lifecycle package is trusted in `package.json`. Run `bun run dependency:report` and `bun audit` before release. Cryptographic, Safe, hardware, and signing dependency changes require manual security review.
