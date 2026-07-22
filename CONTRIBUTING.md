# Contributing to zkCoins API

> **Status: scaffold.** The public API surface is currently served by
> [zk-coins/node](https://github.com/zk-coins/node) directly. This repo will
> hold the standalone API layer — REST + LNURL on top of the node's internal
> kernel RPC ([specification §7.5 / §7.8](https://docs.zkcoins.com/specification)) —
> once the kernel RPC contract stabilises.

## What belongs here

- The public **REST + LNURL** service layer (multi-tenant, hosted-wallet surface).
- Its own **non-value-bearing** database (LNURL mappings, aliasing, rate limits,
  push subscriptions). Coins, proofs, and the nullifier accumulator stay in the
  node — this layer never touches the node's database directly.
- No SPEND keys, no Bitcoin access — proving, broadcasting, and chain scanning
  stay in the node.

API-surface changes that affect the live system today go to
[zk-coins/node](https://github.com/zk-coins/node) instead.

## Workflow

- Default branch is `develop`; open PRs against it.
- Commit messages: English, concise, *what* not *how*.
- House rules (trust model, code style, CI conventions) follow
  [zk-coins/node/CONTRIBUTING.md](https://github.com/zk-coins/node/blob/develop/CONTRIBUTING.md).

## Related Repos

- [zk-coins/node](https://github.com/zk-coins/node) — trustless kernel (currently also serves the API).
- [zk-coins/sdk](https://github.com/zk-coins/sdk) — TypeScript client consuming this surface.
- [zk-coins/docs](https://github.com/zk-coins/docs) — specification ([docs.zkcoins.com](https://docs.zkcoins.com)).
