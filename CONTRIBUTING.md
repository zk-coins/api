# Contributing to zkCoins API

This repository **is** the standalone API process (`src/startup.rs` loads
config and connects the kernel). It exposes REST on top of the node's
internal kernel RPC
([specification §7.5 / §7.8](https://docs.zkcoins.com/specification)).

## What belongs here

- The public **REST** service layer (multi-tenant, hosted-wallet surface).
- Its own **non-value-bearing** database (LNURL mappings, aliasing, rate limits,
  push subscriptions). Coins, proofs, and the nullifier accumulator stay in the
  node — this layer never touches the node's database directly.
- No SPEND keys, no Bitcoin access — proving, broadcasting, and chain scanning
  stay in the node.

## Workflow

- Default branch is `develop`; open PRs against it.
- Commit messages: English, concise, *what* not *how*.
- House rules (trust model, code style, CI conventions) follow
  [zk-coins/node/CONTRIBUTING.md](https://github.com/zk-coins/node/blob/develop/CONTRIBUTING.md).

## Related Repos

- [zk-coins/node](https://github.com/zk-coins/node) — trustless kernel.
- [zk-coins/sdk](https://github.com/zk-coins/sdk) — TypeScript client consuming this surface.
- [zk-coins/docs](https://github.com/zk-coins/docs) — specification ([docs.zkcoins.com](https://docs.zkcoins.com)).
