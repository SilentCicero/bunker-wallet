# Design system

Bunker uses a modern-fintech visual system: bright operational surfaces, firm near-black typography, cobalt actions, and mint confirmation. The product should feel robust and practical rather than cryptographic or theatrical.

## Core composition

- Landing pages pair a concise product claim with a visible stable-address/key-rotation mechanism.
- The primary journey is always three steps: create, fund, use.
- Wallet screens lead with stable address, balance, and current owner index; advanced detail follows.
- Recovery and hardware choices use one quiet list behind “Other setup options.”

## Tokens

- Light ground `#f5f7fa`, surface `#ffffff`, text `#101820`, muted `#63707c`.
- Dark ground `#0b0f14`, surface `#121820`, text `#f1f5f8`.
- Cobalt `#146bff` is reserved for actions; mint `#18b889` means confirmed/current.
- System sans only; no third-party font requests. Display tracking stays tight, body copy remains neutral.
- Corners use 0.65–1.25rem based on scale. Borders are quiet; shadows appear only on the key mechanism.

## Interaction

One primary action per stage. Rotation is shown as an owner sequence under one unchanged address. Loading copy names both the action and key rotation. Errors state what failed and how to recover.

## Responsive behavior

The landing pair collapses to a linear mobile flow. Wallet actions stack above history. Addresses wrap safely. Controls remain full-width on narrow screens and keyboard focus uses the cobalt token.

## Prohibited patterns

No gradients, glass, neon, crypto-dashboard charts, decorative token cards, fake audit badges, unqualified post-quantum claims, or hidden mainnet affordances.
