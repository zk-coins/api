# zkCoins API

**Private Bitcoin payments via Shielded CSV** — no new chain, no token, no consensus change, no trusted operator. Only Bitcoin, zero-knowledge proofs, and the user's own keys.

The **public API layer** for zkCoins — REST + LNURL on top of the node's internal kernel RPC. This is the multi-tenant, hosted-wallet service surface that wallets, the SDK, and the explorer speak. It is **optional** and operator-run; the trustless core is the [node](https://github.com/zk-coins/node).

> Full system docs: **[docs.zkcoins.com](https://docs.zkcoins.com)** · Specification: **[docs.zkcoins.com/specification](https://docs.zkcoins.com/specification)**

## What zkCoins is

zkCoins lets you send value on Bitcoin without anyone seeing the amount, the asset, who paid, or who received. Bitcoin stores only opaque markers that a spend happened — not the coin's contents, which travel privately between sender and receiver as a small encrypted bundle. Double-spend protection is the chain's job; your seed derives every key, your wallet is the only thing that can spend, any node can serve you, and you verify everything against Bitcoin yourself. Built on the zkCoins concept (Robin Linus) and the Shielded CSV construction (Jonas Nick, Liam Eagen, Robin Linus).

## The system, end to end

| Layer | What it is | Repo |
|---|---|---|
| **App · Explorer** | end-user wallet (LNURL receive) · public explorer web-app | [`zk-coins/app`](https://github.com/zk-coins/app) · [`zk-coins/explorer`](https://github.com/zk-coins/explorer) |
| **SDK** | thin TypeScript client — on-device keys, signing, node/API calls | [`zk-coins/sdk`](https://github.com/zk-coins/sdk) |
| **zkCoins API** | public REST + LNURL, hosted-wallet service (optional) | **[`zk-coins/api`](https://github.com/zk-coins/api)** ← this repo |
| **zkCoins node** | trustless kernel — scan · accumulator · verify · prove · store · publisher | [`zk-coins/node`](https://github.com/zk-coins/node) |
| **bitcoind · Nostr relay** | Bitcoin L1 settlement and ordering · off-chain transport and data availability | upstream (own or external) |

Supporting repos: [`zk-coins/research`](https://github.com/zk-coins/research), [`zk-coins/plonky2`](https://github.com/zk-coins/plonky2), [`zk-coins/docs`](https://github.com/zk-coins/docs).

## This repository (api)

The API layer sits **outward** of the node. It consumes the node's internal **kernel RPC** (gRPC `kernel.v1`, [specification §7.8](https://docs.zkcoins.com/specification)) and exposes the **public REST API** ([§7.5](https://docs.zkcoins.com/specification)) plus **LNURL**/aliasing to wallets, the SDK, the app, and the explorer — REST outward, gRPC inward.

- It owns its **own, non-value-bearing** database (LNURL mappings, `username`/aliasing, rate-limits, push-subscription registrations). The **value-bearing** data — coins, proofs, bundles, the nullifier accumulator — stays in the node ([§4.8](https://docs.zkcoins.com/specification)); the API layer **never** touches the node's database directly.
- It never touches Bitcoin and holds no SPEND key. Capability-gating, rate-limiting, and the LNURL receive flow live here; proving, broadcasting, and chain scanning stay in the node.
- Running it is **optional**: a sovereign personal node serves its own wallet directly; the API layer is the "public service node" role that hosts other accounts.

> **Status: scaffold.** The API surface is currently served by [`zk-coins/node`](https://github.com/zk-coins/node) directly; this repo will hold the standalone API layer once the kernel RPC contract stabilises. The full design is specified in [§6.1 (kernel and API)](https://docs.zkcoins.com/specification), [§7.5 (REST)](https://docs.zkcoins.com/specification), and [§7.8 (kernel RPC)](https://docs.zkcoins.com/specification).

### Inventory and skeleton (this branch)

- Full §7.5 endpoint inventory (method, capability, feature, kernel RPC): [`docs/rest-surface.md`](docs/rest-surface.md).
- Rust process (`axum` + `tonic` client dep): only **`GET /health`** and **`GET /`** are registered. No placeholder routes.
- **`GET /` discovery follows registration:** the response `endpoints` object lists only surfaces this process actually serves (today: `health`). The full 29-key §7.5 catalogue stays as inventory; unbuilt surfaces are omitted, not faked.
- Fail-closed env: `ZKCOINS_BIND_ADDR`, `ZKCOINS_KERNEL_ADDR`, `ZKCOINS_FEATURES` (see the inventory doc).

## License

MIT
