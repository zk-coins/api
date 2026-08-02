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

### Current surface

- Full §7.5 endpoint inventory (method, capability, feature, kernel RPC): [`docs/rest-surface.md`](docs/rest-surface.md).
- Rust process (`axum` + `tonic 0.13.1` client): **`GET /`**, **`GET /health`**, info/chain reads, the job surface, **attest/grants**, pull/records/account, **`GET /v1/receipts/stream`** (SSE over `SubscribeReceipts`), bootstrap/publish, and optional Blossom. No placeholder routes for unbuilt keys.
- **OwnershipProof** for attest/grants is verified at the API edge (BIP-340, action-bound domain, `chan_bind`, `request_hash`) **before** any kernel call that would consume a challenge nonce.
- **`GET /` discovery follows registration** via `ServedSurface` — only served keys are advertised. Known-but-disabled inventory paths answer `404 feature_disabled`. The 29-key catalogue stays as inventory.
- Kernel contract: carried `proto/kernel/v1/kernel.proto` with SHA-256 identity pin (`src/proto_identity.rs`); REST errors from `ErrorInfo.metadata["http_status"]` only (API-local auth failures use §7.5 `401 unauthorized` directly).
- Codegen lives in the workspace member **`kernel-proto`** (tonic client stubs only). Workspace `default-members = ["."]` keeps default `cargo clippy` / `cargo test` on the **api** package so generated code is not linted.
- Fail-closed env: `ZKCOINS_BIND_ADDR`, `ZKCOINS_KERNEL_ADDR`, `ZKCOINS_FEATURES`, `ZKCOINS_PUBLIC_HOST` (see the inventory doc). Optional Blossom store: `ZKCOINS_BLOSSOM_STORE` (+ max bytes / allowed ops companions).

## License

MIT
