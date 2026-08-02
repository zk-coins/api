# Öffentliche REST-Oberfläche — Bestandsaufnahme

Normative Quelle: `docs-vectors` Spec **v1.2** (`docs/specification.md`), Abschnitte
**§7.5** (Node REST API), **§6.1** (Kernel und API — zwei Grenzen, Feature-Menge),
**§7.8** (Kernel RPC), ergänzt um die in den §7.5-`endpoints`-Schlüsseln genannten
Oberflächen **§7.4** (Blossom), **§7.6** (Publisher-Hand-off) und **§7.7** (Bootstrap).

Zeilennummern beziehen sich auf `docs-vectors/docs/specification.md` am Stand der
Bestandsaufnahme (Worktree `zk-coins/docs-vectors`).

## Geschlossene Mengen (normativ)

| Menge | Werte | Fundstelle |
|---|---|---|
| API-`features` | `{wallet, explorer, publisher, lightning_bridge, mail_bridge}` | §6.1 L2322, L2333–L2341; §7.5 `/v1/info` L2877 |
| `GET /` · `endpoints`-Schlüssel | siehe Tabelle unten (29 geschlossene Keys) | §7.5 L2874 |
| Kernel-Prozeduren | siehe §7.8-Tabelle | §7.8 L3138–L3159 |

**Feature-Semantik (§6.1):** Jedes Feature ist **off**, bis der Operator es einschaltet.
Ein Request gegen ein deaktiviertes Feature **MUST** mit `404 feature_disabled` beantwortet
werden (§7.5 L2866). `lightning_bridge` und `mail_bridge` öffnen **keine** eigenen Pfade in
§7.5 — sie sind Erweiterungen (`/lightning-bridge`, `/mail-bridge`); in der REST-Tabelle
unten erscheinen sie nur dort, wo die Spec sie als Feature nennt, nicht als zusätzliche
§7.5-Routen.

**Capability:** „Ja“ = OwnershipProof / GrantProof / Pull-Session / Nostr-Auth-Event
erforderlich. „Nein“ = öffentlich bzw. selbstauthentifizierend (Submit) bzw.
permissionless (Publisher-Hand-off).

**Kernel-RPC:** „API-lokal“ = kein Kernel-Aufruf (§7.5 L2866). Sonst die §7.8-Prozedur
aus der Backs-Spalte (L3138–L3159). Blossom läuft über den Kernel-Store / die Blossom-Ebene
(§7.8 L3490: API erreicht Blobs über Kernel oder öffentlichen `/blossom`-Pfad — **kein**
eigenes `Kernel`-RPC-Verb in der Procedure-Tabelle).

---

## Vollständige Endpunkt-Tabelle

| # | Method | Path | Capability | Feature | §7.8-Prozedur / API-lokal | Spec-Fundstelle |
|---|---|---|---|---|---|---|
| 1 | `GET` | `/` | Nein | immer (API-Prozess) | **API-lokal** | §7.5 L2874 |
| 2 | `GET` | `/health` | Nein | immer | **API-lokal** | §7.5 L2875 |
| 3 | `GET` | `/health/ready` | Nein | immer | `GetInfo` (ready / ready_reason) | §7.5 L2876; §7.8 L3140 |
| 4 | `GET` | `/v1/info` | Nein | immer | `GetInfo` (+ API baut `features` selbst, §7.8 L3211–L3214) | §7.5 L2877; §7.8 L3140 |
| 5 | `GET` | `/v1/chain/accumulator` | Nein | `explorer` | `GetAccumulator` | §7.5 L2878; §7.8 L3141; Feature §6.1 L2338 |
| 6 | `GET` | `/v1/chain/inscriptions` | Nein | `explorer` | `ListInscriptions` | §7.5 L2879; §7.8 L3142; Feature §6.1 L2338 |
| 7 | `GET` | `/v1/chain/nullifier/<pubkey>` | Nein | `explorer` | `GetNullifierPath` | §7.5 L2880; §7.8 L3143; Feature §6.1 L2338 |
| 8 | `POST` | `/v1/tx` | Nein (Proof selbstauthentifizierend) | `wallet` | `SubmitTransition` | §7.5 L2888, L2884; §7.8 L3144; Feature §6.1 L2337 |
| 9 | `GET` | `/v1/jobs/<job_id>` | Nein | `wallet` | `GetJob` | §7.5 L2889; §7.8 L3145; Feature §6.1 L2337 |
| 10 | `GET` | `/v1/jobs/<job_id>/stream` | Nein | `wallet` | `StreamJob` | §7.5 L2890; §7.8 L3146; Feature §6.1 L2337 |
| 11 | `POST` | `/v1/jobs/<job_id>/sign` | Nein (Wallet-Signatur) | `wallet` | `SignTransition` | §7.5 L2891; §7.8 L3147; Feature §6.1 L2337 |
| 12 | `POST` | `/v1/jobs/<job_id>/cancel` | Nein | `wallet` | `CancelJob` | §7.5 L2892; §7.8 L3148; Feature §6.1 L2337 |
| 13 | `POST` | `/v1/attest/balance/challenge` | Nein (stellt Challenge aus) | `wallet` | `OpenPullChallenge` (`action = attest_balance`) | §7.5 L2893; §7.8 L3149, L3341–L3345; Feature §6.1 L2337 |
| 14 | `POST` | `/v1/attest/balance` | **Ja** — action-bound OwnershipProof | `wallet` | `AttestBalance` | §7.5 L2894; §7.8 L3158; Feature §6.1 L2337 |
| 15 | `POST` | `/v1/grants/challenge` | Nein (stellt Challenge aus) | `wallet` | `OpenPullChallenge` (`action = issue_grant`) | §7.5 L2895; §7.8 L3149, L3341–L3345; Feature §6.1 L2337 |
| 16 | `POST` | `/v1/grants` | **Ja** — action-bound OwnershipProof (kein GrantProof) | `wallet` | `IssueViewGrant` | §7.5 L2896; §7.8 L3159; Feature §6.1 L2337 |
| 17 | `POST` | `/v1/pull/challenge` | Nein (stellt Challenge aus) | `wallet` | `OpenPullChallenge` | §7.5 L3039; §7.8 L3149; Feature §6.1 L2337 |
| 18 | `POST` | `/v1/pull` | **Ja** — OwnershipProof oder GrantProof | `wallet` | `Pull` | §7.5 L3040; §7.8 L3150; Feature §6.1 L2337 |
| 19 | `GET` | `/v1/record/<record_id>` | **Ja** — Pull-Session Bearer | `wallet` | `GetRecord` | §7.5 L3041; §7.8 L3151; Feature §6.1 L2337 |
| 20 | `GET` | `/v1/proof/<coin_id>` | **Ja** — Pull-Session Bearer | `wallet` | `GetCoinProof` | §7.5 L3042; §7.8 L3152; Feature §6.1 L2337 |
| 21 | `GET` | `/v1/account/state` | **Ja** — Ownership-Pull-Session (kein Grant) | `wallet` | `GetAccountState` | §7.5 L3043; §7.8 L3153; Feature §6.1 L2337 |
| 22 | `GET` | `/v1/receipts/stream` | **Ja** — Pull-Session Bearer (Ownership oder Grant) | `wallet` | `SubscribeReceipts` | §7.5 L3044, L2953–L2955; §7.8 L3154; Feature §6.1 L2337 |
| 23 | `POST` | `/v1/publish/spendrecord` | Nein (permissionless) | `publisher` | `Publish` | §7.6 L3050–L3054; §7.8 L3155; Feature §6.1 L2339 |
| 24 | `POST` | `/v1/bootstrap/challenge` | Nein (stellt Challenge aus) | `wallet` | `OpenPullChallenge` (`action` entrust/revoke) | §7.7 L3118; §7.8 L3149, L3341–L3344; Feature §6.1 L2337 |
| 25 | `POST` | `/v1/bootstrap/entrust` | **Ja** — OwnershipProof (Entrust-Domain) | `wallet` | `EntrustOperationalBundle` | §7.7 L3119; §7.8 L3156; Feature §6.1 L2337 |
| 26 | `POST` | `/v1/bootstrap/revoke` | **Ja** — OwnershipProof (Revoke-Domain) | `wallet` | `RevokeOperationalBundle` | §7.7 L3120; §7.8 L3157; Feature §6.1 L2337 |
| 27 | `GET` | `/blossom/<sha256>` | Nein (Ciphertext) | `explorer` (blob fetch) | Blossom-Ebene / Kernel-Store — **kein** eigenes Kernel-RPC-Verb (§7.8 L3490) | §7.4 L2804; Feature §6.1 L2338; `endpoints`-Key §7.5 L2874 |
| 28 | `HEAD` | `/blossom/<sha256>` | Nein | `explorer` (blob fetch) | Blossom-Ebene / Kernel-Store | §7.4 L2805; Feature §6.1 L2338; Key §7.5 L2874 |
| 29 | `PUT` | `/blossom/upload` | **Ja** — Nostr kind-`24242` Auth-Event | `explorer` / `wallet` (Replica-Upload) | Blossom-Ebene / Kernel-Store | §7.4 L2806, L2821–L2827; Keys §7.5 L2874 |
| 30 | `POST` | `/blossom/upload` | **Ja** — Nostr kind-`24242` Auth-Event | `explorer` / `wallet` (Replica-Upload) | Blossom-Ebene / Kernel-Store (äquivalent zu PUT) | §7.4 L2806, L2809; Keys §7.5 L2874 |
| 31 | `DELETE` | `/blossom/<sha256>` | **Ja** — Nostr kind-`24242` Auth-Event (Original-Uploader) | `explorer` / `wallet` | Blossom-Ebene / Kernel-Store | §7.4 L2807, L2821–L2827; Keys §7.5 L2874 |

### Geschlossene `endpoints`-Schlüssel von `GET /` (§7.5 L2874)

Genau diese 29 Keys — wörtlich, vollständig:

| Key | Typischer Pfad |
|---|---|
| `health` | `/health` |
| `health_ready` | `/health/ready` |
| `info` | `/v1/info` |
| `chain_accumulator` | `/v1/chain/accumulator` |
| `chain_inscriptions` | `/v1/chain/inscriptions` |
| `chain_nullifier` | `/v1/chain/nullifier/<pubkey>` |
| `tx` | `/v1/tx` |
| `jobs` | `/v1/jobs/<job_id>` |
| `jobs_stream` | `/v1/jobs/<job_id>/stream` |
| `jobs_sign` | `/v1/jobs/<job_id>/sign` |
| `jobs_cancel` | `/v1/jobs/<job_id>/cancel` |
| `attest_balance_challenge` | `/v1/attest/balance/challenge` |
| `attest_balance` | `/v1/attest/balance` |
| `grants_challenge` | `/v1/grants/challenge` |
| `grants` | `/v1/grants` |
| `pull_challenge` | `/v1/pull/challenge` |
| `pull` | `/v1/pull` |
| `record` | `/v1/record/<record_id>` |
| `proof` | `/v1/proof/<coin_id>` |
| `account_state` | `/v1/account/state` |
| `receipts_stream` | `/v1/receipts/stream` |
| `publish_spendrecord` | `/v1/publish/spendrecord` |
| `bootstrap_challenge` | `/v1/bootstrap/challenge` |
| `bootstrap_entrust` | `/v1/bootstrap/entrust` |
| `bootstrap_revoke` | `/v1/bootstrap/revoke` |
| `blossom_get` | `/blossom/<sha256>` |
| `blossom_head` | `/blossom/<sha256>` |
| `blossom_upload` | `/blossom/upload` |
| `blossom_delete` | `/blossom/<sha256>` |

Spec-Regel (§7.5 L2874): Ein Producer emittiert **genau** die geschlossene Schlüsselmenge
für die Oberflächen, die dieses Deployment exponiert, und **MUST** Keys für nicht
beworbene optionale Rollen weglassen. Unbekannte Keys beim Lesen ignorieren.

---

## Zählung (Kurzform)

| Kategorie | Anzahl |
|---|---|
| HTTP-Endpunkte (Method+Path) in der Tabelle oben | **31** |
| davon in §7.5-Haupttext (ohne §7.4/§7.6/§7.7) | **22** |
| + Publisher §7.6 | **1** |
| + Bootstrap §7.7 | **3** |
| + Blossom §7.4 (GET/HEAD/PUT/POST/DELETE) | **5** |
| Geschlossene `endpoints`-Keys | **29** |
| Capability-gebunden (Ownership / Grant / Session / Nostr-Auth) | **13** (#14, #16, #18–22, #25–26, #29–31) |
| Challenge-Aussteller ohne Capability | **4** (#13, #15, #17, #24) |
| API-lokal | **2** (`GET /`, `GET /health`) |

### Pro Feature (Method+Path, ohne „immer“)

| Feature | Endpunkte | Nummern |
|---|---|---|
| immer (API-Prozess) | 4 | #1–#4 |
| `wallet` | 19 | #8–#22, #24–#26 (+ Blossom-Upload/Delete geteilt) |
| `explorer` | 3 Chain + Blossom-Fetch (+ Upload/Delete geteilt) | #5–#7, #27–#28 (+ #29–#31 geteilt) |
| `publisher` | 1 | #23 |
| `lightning_bridge` | 0 in §7.5 | Erweiterung `/lightning-bridge` |
| `mail_bridge` | 0 in §7.5 | Erweiterung `/mail-bridge` |

Blossom-Upload/Delete (#29–#31) sind weder rein `wallet` noch rein `explorer` in der
Feature-Tabelle §6.1; sie gehören zur öffentlichen Blossom-Ebene (§7.4) und werden von
Deployments mit Wallet- und/oder Explorer-Rolle benötigt (Replica-/Blob-Pfad).

---

## Implementierungsstand dieses Repos

| Endpunkt | Status |
|---|---|
| `GET /health` | **implementiert** — `200` mit Body `"ok"` |
| `GET /health/ready` | **implementiert** — Readiness aus Kernel-`GetInfo` (`ready` / `ready_reason`); Body-Form `{ ready, reason? }`, nie die generische Fehlerform. Bei fehlgeschlagenem `GetInfo` (z. B. fehlende `ChainIdentity` im node): **503** `{ ready: false, reason: "dependency_unavailable" }` — nie grünes `ready: true`. |
| `GET /` | **implementiert** — `{ name, version, endpoints }` mit **genau** den Flächen, die dieser Prozess registriert (`ServedSurface`). Inventur der 29 Keys in `CLOSED_ENDPOINT_KEYS`; unregistrierte Keys werden weggelassen. |
| `GET /v1/info` | **implementiert** — Kernel-`GetInfo` + API-eigene `features` aus `ZKCOINS_FEATURES` (`kernel_parts` bleibt intern). |
| `GET /v1/chain/accumulator` | **implementiert** — `GetAccumulator`; `root` ist pass-through der Kernel-`nav_root`, keine Nachrechnung. |
| `GET /v1/chain/inscriptions` | **implementiert** — `ListInscriptions` (Server-Stream → eine Seite); Triple-Cursor ganz-oder-gar-nicht; leerer Katalog → leere Liste (kein 404). |
| `GET /v1/chain/nullifier/<pubkey>` | **implementiert** — `GetNullifierPath`; `present`/`absent` bleiben getrennt; Kernel-`internal_error` wird **nicht** als absent umgeschrieben. |
| `POST /v1/tx` | **implementiert** — `SubmitTransition` |
| `GET /v1/jobs/{job_id}` | **implementiert** — `GetJob` |
| `GET /v1/jobs/{job_id}/stream` | **implementiert** — `StreamJob` als SSE |
| `POST /v1/jobs/{job_id}/sign` | **implementiert** — `SignTransition` |
| `POST /v1/jobs/{job_id}/cancel` | **implementiert** — `CancelJob` |
| `POST /v1/attest/balance/challenge` | **implementiert** — `OpenPullChallenge` (`action = attest_balance`) |
| `POST /v1/attest/balance` | **implementiert** — OwnershipProof-Verifikation am API-Rand, dann `AttestBalance` |
| `POST /v1/grants/challenge` | **implementiert** — `OpenPullChallenge` (`action = issue_grant`) |
| `POST /v1/grants` | **implementiert** — OwnershipProof-Verifikation am API-Rand, dann `IssueViewGrant` |
| `POST /v1/pull/challenge` | **implementiert** — `OpenPullChallenge` (`action = pull`) |
| `POST /v1/pull` | **implementiert** — OwnershipProof am API-Rand, dann `Pull` (GrantProof fail-closed) |
| `GET /v1/record/<record_id>` | **implementiert** — `GetRecord` (Bearer-Session) |
| `GET /v1/proof/<coin_id>` | **implementiert** — `GetCoinProof` (Bearer-Session) |
| `GET /v1/account/state` | **implementiert** — `GetAccountState` (Ownership-Session) |
| `GET /v1/receipts/stream` | **implementiert** — `SubscribeReceipts` als SSE (Ownership- **oder** Grant-Session; 401/410-Trennung wie Proof) |
| `POST /v1/bootstrap/challenge` | **implementiert** — `OpenPullChallenge` (`action = entrust` \| `revoke`) |
| `POST /v1/bootstrap/entrust` | **implementiert** — OwnershipProof (Entrust-Domain) + Bundle-Längenprüfung (161 B), dann `EntrustOperationalBundle`; Bundle wird nie geloggt |
| `POST /v1/bootstrap/revoke` | **implementiert** — OwnershipProof (Revoke-Domain), dann `RevokeOperationalBundle` |
| `POST /v1/publish/spendrecord` | **implementiert** — `Publish`; Ablehnung → HTTP 200 `{accepted:false, reason}`; v1-Fee-Felder → 400 |
| `GET`/`HEAD`/`DELETE /blossom/<sha256>`, `PUT`/`POST /blossom/upload` | **implementiert** wenn `ZKCOINS_BLOSSOM_STORE` gesetzt — API-lokaler inhaltsadressierter Store (§7.4); kein Kernel-RPC; ohne Store unregistriert |
| alle übrigen Method+Path | **nicht registriert** — kein Handler, kein `todo!()`, kein Platzhalter |

**Bewusst nicht beworben:**

| Key | Warum |
|---|---|
| `blossom_*` (ohne `ZKCOINS_BLOSSOM_STORE`) | §7.4; die vier Schlüssel werden **nur** advertised, wenn der inhaltsadressierte Store konfiguriert ist. |

Router und Discovery teilen eine Quelle (`ServedSurface` in `src/routes.rs`): die
aktive Mengen folgt `Config::features` und dem Blossom-Store; eine neue
registrierte Fläche erscheint automatisch in `GET /`; deaktivierte Features
sind unregistriert und unbeworben (fail-closed, §7.5). Path-Parameter in
Discovery/`CLOSED_ENDPOINT_KEYS` nutzen die Spec-Schreibweise `<name>`
(Axum-Matcher: `:name`).

gRPC: getragenes `proto/kernel/v1/kernel.proto` (Identität per SHA-256-Pin +
Sibling-Vergleich mit `zk-coins/node`), Client `tonic 0.13.1`, Fehlerübersetzung
ausschließlich über `google.rpc.ErrorInfo` (`domain`, `reason`,
`metadata["http_status"]`) — keine zweite Status-Tabelle im api.

### Dokumentierte Lücken

| Lücke | Warum |
|---|---|
| Blossom `ReplicaReceiptV1` | §4.6 Dual-Commit (Blob + Delivery-Event) fehlt; Upload antwortet ehrlich nur mit `{ blob_id }` — kein `receipt`. |
| — | Feature-Gating (§6.1 / §7.5) ist aktiv: `ServedSurface::active` filtert nach `ZKCOINS_FEATURES` + Blossom-Store; deaktivierte Flächen sind unregistriert (HTTP 404) und fehlen in `GET /`. |

---

## Pflicht-Umgebungsvariablen (fail-closed)

| Variable | Bedeutung |
|---|---|
| `ZKCOINS_BIND_ADDR` | Socket-Adresse für den HTTP-Listener (z. B. `127.0.0.1:8080`). **Kein Default.** |
| `ZKCOINS_KERNEL_ADDR` | Adresse des Kernel-gRPC (z. B. `http://127.0.0.1:50051`). **Kein Default.** Pflicht, auch wenn dieser Scaffold den Kanal noch nicht öffnet — Start ohne konfigurierte Kernel-Adresse ist unzulässig. |
| `ZKCOINS_FEATURES` | Komma-separierte Teilmenge von `{wallet,explorer,publisher,lightning_bridge,mail_bridge}`. Darf leer sein (alle Features off). Unbekannter Token → **Startfehler**. Variable selbst ist Pflicht (explizit leer = absichtlich nichts freigeschaltet). |
| `ZKCOINS_PUBLIC_HOST` | Komma-separierte autoritative Hostnamen für §5.1 `chan_bind` (lowercase, trailing-dot gestrichen). **Nie** aus `Host`-Header. Darf leer sein (dann schlägt OwnershipProof-Auth laut fehl). Variable selbst ist Pflicht. |

### Optionale Blossom-Fläche (§7.4)

| Variable | Bedeutung |
|---|---|
| `ZKCOINS_BLOSSOM_STORE` | Wurzelverzeichnis des inhaltsadressierten Blob-Stores. **Abwesend** ⇒ die vier Blossom-Keys bleiben unbeworben und unmontiert. **Kein Default-Pfad**, kein `/tmp`-Rückfall. Leer gesetzt → Startfehler. |
| `ZKCOINS_BLOSSOM_MAX_BLOB_BYTES` | Pflicht-Begleiter wenn der Store gesetzt ist: ausgewiesene Upload-Obergrenze (`> 0`). Body darüber → `413 payload_too_large`. |
| `ZKCOINS_BLOSSOM_ALLOWED_OPS` | Pflicht-Begleiter wenn der Store gesetzt ist: komma-separierte lowercase-hex-32B-`op`-Pubkeys (gepaarte Konten + Replikations-Peers). Darf leer sein (dann ist jeder Upload `403`). |
