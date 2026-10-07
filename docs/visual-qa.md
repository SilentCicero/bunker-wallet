# Visual QA

Playwright rendered the live SolidJS application at 1440×900, 1920×1080, 768×1024, 390×844, and 360×800 in dark and light themes. Theme captures plus the Base Sepolia burner flow are stored in `.impeccable/review/`.

Verified:

- no horizontal overflow at any required viewport;
- primary content and unaudited-use warning remain visible;
- mobile navigation remains reachable;
- both themes render with explicit focus and selection colors;
- one-click burner creation opens the allowlisted Base Sepolia faucet without persisting a burner key;
- recovery confirmation remains disabled until the backup acknowledgement is checked;
- the mechanical Impeccable detector returned no findings.

The browser tests do not establish contract safety, hardware compatibility, mainnet readiness, or resistance to compromised browser code. Manual security-screen review and external contract review remain release gates.
