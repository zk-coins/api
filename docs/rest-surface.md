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
| `GET /` · `endpoints`-Schlüssel | siehe Tabelle unten (31 geschlossene Keys) | §7.5; Data Permanence (kein `blossom_delete`) |
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
aus der Backs-Spalte (L3138–L3159). Blossom ist der **API-lokale Filesystem-Store**
(`ZKCOINS_BLOSSOM_STORE`) — es gibt keinen Kernel-Store und **kein** Kernel-RPC für Blobs.

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
| 17 | `POST` | `/v1/grants/revoke/challenge` | Nein (stellt Challenge aus) | `wallet` | **API-lokal** (kein Kernel-Dial, §5.2) | §7.5 |
| 18 | `POST` | `/v1/grants/revoke` | **Ja** — action-bound OwnershipProof (RevokeGrant-Domain) | `wallet` | **API-lokal** (kein Kernel-Dial, §5.2) | §7.5 |
| 19 | `POST` | `/v1/pull/challenge` | Nein (stellt Challenge aus) | `wallet` | `OpenPullChallenge` | §7.5 L3039; §7.8 L3149; Feature §6.1 L2337 |
| 20 | `POST` | `/v1/pull` | **Ja** — OwnershipProof oder GrantProof | `wallet` | `Pull` | §7.5 L3040; §7.8 L3150; Feature §6.1 L2337 |
| 21 | `GET` | `/v1/record/<record_id>` | **Ja** — Pull-Session Bearer | `wallet` | `GetRecord` | §7.5 L3041; §7.8 L3151; Feature §6.1 L2337 |
| 22 | `GET` | `/v1/proof/<coin_id>` | **Ja** — Pull-Session Bearer | `wallet` | `GetCoinProof` | §7.5 L3042; §7.8 L3152; Feature §6.1 L2337 |
| 23 | `GET` | `/v1/account/state` | **Ja** — Ownership-Pull-Session (kein Grant) | `wallet` | `GetAccountState` | §7.5 L3043; §7.8 L3153; Feature §6.1 L2337 |
| 24 | `GET` | `/v1/receipts/stream` | **Ja** — Pull-Session Bearer (Ownership oder Grant) | `wallet` | `SubscribeReceipts` | §7.5 L3044, L2953–L2955; §7.8 L3154; Feature §6.1 L2337 |
| 25 | `POST` | `/v1/publish/spendrecord` | Nein (permissionless) | `publisher` | `Publish` | §7.6 L3050–L3054; §7.8 L3155; Feature §6.1 L2339 |
| 26 | `POST` | `/v1/bootstrap/challenge` | Nein (stellt Challenge aus) | `wallet` | `OpenPullChallenge` (`action` entrust/revoke) | §7.7 L3118; §7.8 L3149, L3341–L3344; Feature §6.1 L2337 |
| 27 | `POST` | `/v1/bootstrap/entrust` | **Ja** — OwnershipProof (Entrust-Domain) | `wallet` | `EntrustOperationalBundle` | §7.7 L3119; §7.8 L3156; Feature §6.1 L2337 |
| 28 | `POST` | `/v1/bootstrap/revoke` | **Ja** — OwnershipProof (Revoke-Domain) | `wallet` | `RevokeOperationalBundle` | §7.7 L3120; §7.8 L3157; Feature §6.1 L2337 |
| 29 | `GET` | `/blossom/<sha256>` | Nein (Ciphertext) | `explorer` (blob fetch) | API-lokaler Filesystem-Store — **kein** Kernel-RPC | §7.4 L2804; Feature §6.1 L2338; `endpoints`-Key §7.5 L2874 |
| 30 | `HEAD` | `/blossom/<sha256>` | Nein | `explorer` (blob fetch) | API-lokaler Filesystem-Store — **kein** Kernel-RPC | §7.4 L2805; Feature §6.1 L2338; Key §7.5 L2874 |
| 31 | `PUT` | `/blossom/upload` | **Ja** — Nostr kind-`24242` Auth-Event | `explorer` / `wallet` | API-lokaler Filesystem-Store — **kein** Kernel-RPC | §7.4; Keys §7.5; Data Permanence (append-only, Antwort `{ blob_id }`) |
| 32 | `POST` | `/blossom/upload` | **Ja** — Nostr kind-`24242` Auth-Event | `explorer` / `wallet` | API-lokaler Filesystem-Store — **kein** Kernel-RPC (äquivalent zu PUT) | §7.4; Keys §7.5 |
| 33 | `GET` | `/v1/token/<asset_id>/provenance` | Nein (offen, unauthentifiziert) | **immer** — nicht feature-gated | `GetTokenProvenance` — offene Class-B-Provenienz; self-verifying; `404 not_found` wenn der Node keine Terms für `asset_id` hält | §7.5; §7.8; §4.6 Class B |

**Kein** `DELETE /blossom/<sha256>` — Data Permanence (Requirement 12): der Blob-Store
ist append-only; empfangene Daten werden nie gelöscht. `ReplicaReceiptV1` / §4.6
Dual-Commit und `retention_hold` entfallen mit der Spec.

### Geschlossene `endpoints`-Schlüssel von `GET /` (§7.5)

Genau diese 31 Keys — wörtlich, vollständig (Inventur-Reihenfolge von
`CLOSED_ENDPOINT_KEYS`):

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
| `grants_revoke_challenge` | `/v1/grants/revoke/challenge` |
| `grants_revoke` | `/v1/grants/revoke` |
| `token_provenance` | `/v1/token/<asset_id>/provenance` |

Spec-Regel (§7.5): Ein Producer emittiert **genau** die geschlossene Schlüsselmenge
für die Oberflächen, die dieses Deployment exponiert, und **MUST** Keys für nicht
beworbene optionale Rollen weglassen. Unbekannte Keys beim Lesen ignorieren.

---

## Zählung (Kurzform)

| Kategorie | Anzahl |
|---|---|
| HTTP-Endpunkte (Method+Path) in der Tabelle oben | **33** |
| davon in §7.5-Haupttext (ohne §7.4/§7.6/§7.7) | **25** |
| + Publisher §7.6 | **1** |
| + Bootstrap §7.7 | **3** |
| + Blossom §7.4 (GET/HEAD/PUT/POST; kein DELETE) | **4** |
| Geschlossene `endpoints`-Keys | **31** |
| Capability-gebunden (Ownership / Grant / Session / Nostr-Auth) | **12** (#14, #16, #18, #20–24, #27–28, #31–32) |
| Challenge-Aussteller ohne Capability | **5** (#13, #15, #17, #19, #26) |
| API-lokal (origin-lokal, immer an, kein Kernel) | **2** (`GET /`, `GET /health`) |
| API-lokal (kernel-los, feature-gated) | **2** (Grant-Revoke #17/#18; bereits in der Endpunkt-Tabelle) |

### Pro Feature (Method+Path, ohne „immer“)

| Feature | Endpunkte | Nummern |
|---|---|---|
| immer (API-Prozess) | 5 | #1–#4, #33 |
| `wallet` | 20 | #8–#24, #26–#28 (+ Blossom-Upload geteilt) |
| `explorer` | 3 Chain + Blossom-Fetch (+ Upload geteilt) | #5–#7, #29–#30 (+ #31–#32 geteilt) |
| `publisher` | 1 | #25 |
| `lightning_bridge` | 0 in §7.5 | Erweiterung `/lightning-bridge` |
| `mail_bridge` | 0 in §7.5 | Erweiterung `/mail-bridge` |

Blossom-Upload (#31–#32) sind weder rein `wallet` noch rein `explorer` in der
Feature-Tabelle §6.1; sie gehören zur öffentlichen Blossom-Ebene (§7.4) und werden von
Deployments mit Wallet- und/oder Explorer-Rolle benötigt (Blob-Pfad).

---

## Implementierungsstand dieses Repos

| Endpunkt | Status |
|---|---|
| `GET /health` | **implementiert** — `200` mit Body `"ok"` |
| `GET /health/ready` | **implementiert** — Readiness aus Kernel-`GetInfo` (`ready` / `ready_reason`); Body-Form `{ ready, reason? }`, nie die generische Fehlerform. Bei fehlgeschlagenem `GetInfo` (z. B. fehlende `ChainIdentity` im node): **503** `{ ready: false, reason: "dependency_unavailable" }` — nie grünes `ready: true`. |
| `GET /` | **implementiert** — `{ name, version, endpoints }` mit **genau** den Flächen, die dieser Prozess registriert (`ServedSurface`). Inventur der 31 Keys in `CLOSED_ENDPOINT_KEYS`; unregistrierte Keys werden weggelassen. |
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
| `POST /v1/grants/revoke/challenge` | **implementiert** — API-lokal, stellt Single-Use-Nonce für Grant-Revoke aus; kein Kernel-Dial (§5.2) |
| `POST /v1/grants/revoke` | **implementiert** — OwnershipProof-Verifikation am API-Rand (RevokeGrant-Domain, grant→subject binding), dann `revoked_grants`; kein Kernel-Dial (§5.2) |
| `POST /v1/pull/challenge` | **implementiert** — `OpenPullChallenge` (`action = ""` meaning pull) |
| `POST /v1/pull` | **implementiert** — OwnershipProof oder GrantProof am API-Rand, dann `Pull`. GrantProof ohne veröffentlichten Subject-Op-Eintrag wird 401 (kind-30420-Auflösung nicht verdrahtet); halbgeprüfte Grants sind verboten |
| `GET /v1/record/<record_id>` | **implementiert** — `GetRecord` (Bearer-Session) |
| `GET /v1/proof/<coin_id>` | **implementiert** — `GetCoinProof` (Bearer-Session) |
| `GET /v1/account/state` | **implementiert** — `GetAccountState` (Ownership-Session) |
| `GET /v1/receipts/stream` | **implementiert** — `SubscribeReceipts` als SSE (Ownership- **oder** Grant-Session; 401/410-Trennung wie Proof) |
| `POST /v1/bootstrap/challenge` | **implementiert** — `OpenPullChallenge` (`action = entrust` \| `revoke`) |
| `POST /v1/bootstrap/entrust` | **implementiert** — OwnershipProof (Entrust-Domain) + Bundle-Längenprüfung (161 B), dann `EntrustOperationalBundle`; Bundle wird nie geloggt |
| `POST /v1/bootstrap/revoke` | **implementiert** — OwnershipProof (Revoke-Domain), dann `RevokeOperationalBundle` |
| `POST /v1/publish/spendrecord` | **implementiert** — `Publish`; Ablehnung → HTTP 200 `{accepted:false, reason}`; v1-Fee-Felder → 400 |
| `GET /v1/token/<asset_id>/provenance` | **implementiert** — `GetTokenProvenance`-Pass-through; offen/unauthentifiziert, nie feature-gated; §7.5-JSON (`name` hex, v1/v2, `cap_total` u128-Dezimalstring, `terms_salt` hex); `404 not_found` ohne Terms; kein Leak (nur IssuanceTerms-Preimage). |
| `GET`/`HEAD /blossom/<sha256>`, `PUT`/`POST /blossom/upload` | **implementiert** bei Store ∧ Rolle — GET/HEAD: `ZKCOINS_BLOSSOM_STORE` **und** `explorer`; Upload: Store **und** (`wallet` **oder** `explorer`); API-lokaler append-only Store (§7.4 / Data Permanence); kein Kernel-RPC; ohne Store unregistriert (bare 404); Store ohne passende Rolle: Stub `404 feature_disabled`, unbeworben; **kein** DELETE |
| alle übrigen Method+Path | **nicht registriert** — kein Handler, kein `todo!()`, kein Platzhalter |

**Bewusst nicht beworben:**

| Key | Warum |
|---|---|
| `blossom_*` (ohne Store bzw. ohne passende Rolle) | §7.4; die drei Schlüssel (`get`/`head`/`upload`) werden **nur** advertised, wenn der Store **und** die jeweilige Rolle greifen (GET/HEAD: `explorer`; Upload: `wallet` **oder** `explorer`). Store ohne passende Rolle → Stub `404 feature_disabled`, nicht in `GET /`. Ohne Store → unregistriert, unbeworben. |
| `blossom_delete` | Data Permanence — existiert nicht mehr in der Inventur. |

Router und Discovery teilen eine Quelle (`ServedSurface` in `src/routes.rs`): die
aktive Menge folgt `Config::features` und dem Blossom-Store; eine neue
registrierte Fläche erscheint automatisch in `GET /`; deaktivierte bekannte
Flächen antworten als Stub `404 feature_disabled` und bleiben unbeworben;
unkonfigurierter Blossom-Store bleibt unregistriert (bare 404)
(fail-closed, §7.5). Path-Parameter in
Discovery/`CLOSED_ENDPOINT_KEYS` nutzen die Spec-Schreibweise `<name>`
(Axum-Matcher: `:name`).

gRPC: getragenes `proto/kernel/v1/kernel.proto`. CI-Identität ist der SHA-256-Pin
gegen diese getragene proto-Datei (`src/proto_identity.rs`, `PROTO_IDENTITY_CI_BOUNDARY`).
Sibling-Vergleich mit `zk-coins/node` ist optional/lokal, kein CI-Gate. Client
`tonic 0.13.1`, Fehlerübersetzung ausschließlich über `google.rpc.ErrorInfo`
(`domain`, `reason`, `metadata["http_status"]`) — keine zweite Status-Tabelle im api.

### Dokumentierte Lücken

| Lücke | Warum |
|---|---|
| — | Feature-Gating (§6.1 / §7.5) ist aktiv: `ServedSurface::active` filtert nach `ZKCOINS_FEATURES` + Blossom-Store; deaktivierte bekannte Flächen sind Stub `404 feature_disabled` und fehlen in `GET /`; unkonfigurierter Blossom-Store ist unregistriert (bare 404). |
| — | Data Permanence: Blossom ist append-only (`PUT`/`POST`/`GET`/`HEAD` only); Upload → `{ blob_id }` ohne `receipt`; kein `retention_hold`, kein Orphan-Prune. |

---

## Pflicht-Umgebungsvariablen (fail-closed)

| Variable | Bedeutung |
|---|---|
| `ZKCOINS_BIND_ADDR` | Socket-Adresse für den HTTP-Listener (z. B. `127.0.0.1:8080`). **Kein Default.** |
| `ZKCOINS_KERNEL_ADDR` | Adresse des Kernel-gRPC (z. B. `http://127.0.0.1:50051`). **Kein Default.** Pflicht — dieser API-Prozess dialt den Kernel vor dem Serve; Start ohne konfigurierte Kernel-Adresse ist unzulässig. |
| `ZKCOINS_FEATURES` | Komma-separierte Teilmenge von `{wallet,explorer,publisher,lightning_bridge,mail_bridge}`. Darf leer sein (alle Features off). Unbekannter Token → **Startfehler**. Variable selbst ist Pflicht (explizit leer = absichtlich nichts freigeschaltet). |
| `ZKCOINS_PUBLIC_HOST` | Komma-separierte autoritative Hostnamen für §5.1 `chan_bind` (lowercase, trailing-dot gestrichen). **Nie** aus `Host`-Header. Darf leer sein (dann schlägt OwnershipProof-Auth laut fehl). Variable selbst ist Pflicht. |

### Optionale Blossom-Fläche (§7.4)

| Variable | Bedeutung |
|---|---|
| `ZKCOINS_BLOSSOM_STORE` | Wurzelverzeichnis des inhaltsadressierten Blob-Stores. **Abwesend** ⇒ die drei Blossom-Keys (`get`/`head`/`upload`) bleiben unbeworben und unmontiert. **Kein Default-Pfad**, kein `/tmp`-Rückfall. Leer gesetzt → Startfehler. |
| `ZKCOINS_BLOSSOM_MAX_BLOB_BYTES` | Pflicht-Begleiter wenn der Store gesetzt ist: ausgewiesene Upload-Obergrenze (`> 0`). Body darüber → `413 payload_too_large`. |
| `ZKCOINS_BLOSSOM_ALLOWED_OPS` | Pflicht-Begleiter wenn der Store gesetzt ist: komma-separierte lowercase-hex-32B-`op`-Pubkeys (gepaarte Konten + Replikations-Peers). Darf leer sein (dann ist jeder Upload `403`). |
