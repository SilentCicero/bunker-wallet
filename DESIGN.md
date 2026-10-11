# Design system

Bunker uses an institutional custody-ledger visual system. The interface makes a stable address and its changing owner read like one precise register: bordered records, connected sequence cells, firm rules, and explicit status. It should feel controlled and inspectable—not like a crypto dashboard, generic SaaS landing page, or collection of floating cards.

## Core composition

- The landing viewport pairs a rail-bound product promise with a bordered owner register showing the stable address and spent, current, and next keys.
- Landing sections use ruled ledgers, asymmetric columns, and dense/quiet pacing rather than repeated cards.
- Setup and recovery screens use one narrow workflow register with a four-stage progress rail.
- Wallet screens lead with balance and owner rotation, then stable address, signer sequence, ETH-send controls, and history in one connected record.
- Mobile retains the same reading order, keeps Setup options reachable, and stacks ledger cells without changing their meaning.

## Tokens

- Light ground `#f2f3f5`, surface `#ffffff`, text `#111820`, muted `#58636f`.
- Dark ground `#0b0e12`, surface `#12171d`, text `#f3f5f7`, muted `#a9b3bd`.
- Cobalt `#064cff` in light mode and `#5d88ff` in dark mode signal actions and the active owner.
- Mint `#007b59` in light contexts and `#4ed4aa` on dark contexts means verified, current, or confirmed.
- System sans is retained for operational clarity; display type uses tight but readable tracking with a 6rem ceiling.
- Corners stay nearly square at `.15rem–.25rem`. Rules are structural; shadows are reserved for the hero register and transient notices.

## Components

- Primary actions are solid cobalt planes with a dark inset edge; secondary actions use transparent bordered fields.
- Address, sequence, setup, activity, and transaction regions share the same ledger rules and tabular alignment.
- Mint is never decorative. It appears only on current/confirmed state labels or progress.
- Form fields remain plain operational surfaces with visible focus rings and at least 44px targets.
- Standalone links and header controls maintain touch-size hit areas on mobile.

## Interaction

One primary action leads each stage. Rotation is always shown under one unchanged address. Loading copy names the blockchain action and rotation state. Errors state the problem and recovery path. Motion is limited to meaningful progress; reduced-motion preferences disable it.

## Responsive behavior

The landing pair collapses into promise, actions, then owner register. Ledger sequences become vertical when horizontal comparison no longer fits. Wallet actions stack above history. Addresses wrap safely. Setup options remain available from mobile navigation, and all essential controls remain keyboard accessible.

## Prohibited patterns

No gradients, glass, neon, crypto charts, decorative token cards, generic floating-card grids, fake audit badges, unqualified post-quantum claims, hidden mainnet affordances, or color used without a textual state label.
