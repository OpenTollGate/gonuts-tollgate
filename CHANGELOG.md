# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- NUT-08 melt change (cashu-audit #68 B3): the mint returns overpaid fee
  reserve as change — blank outputs are validated before the quote claim,
  journaled durably before the payment attempt, and on settlement the
  overpay (`inputs − input fees − invoice amount − fee actually spent`)
  is split into keyset denominations, imprinted on the blank outputs in
  request order, signed with DLEQ and persisted BEFORE the Paid write
  (the #59 discipline — every crash point leaves the change recoverable).
  The poll-path reconciler signs change the same way from the journal; a
  PAID quote re-POSTed with the identical outputs answers idempotently
  from the stored signatures (works past the NUT-19 cache TTL and across
  restarts); melt-quote state responses carry the stored change; info
  declares NUT-08 supported. Backends report the fee actually spent via
  the new `PaymentStatus.FeeSpent`/`FeeSpentKnown` (CLN wires
  amount_sent−amount; a backend that cannot report keeps its reserve —
  never returned on a guess); FakeBackend grows a `FeeReserveSats` knob
  (default 0) and `cmd/mint` a `MINT_FAKE_FEE_RESERVE` env.

### Fixed
- The wallet consumes NUT-08 change with the binding disciplines intact:
  mint-assigned amounts are legal only at the NUT-08 boundary
  (`constructMeltChangeProofs` — signature i answers blank output i at
  the same keyset, no more signatures than blanks, keyset denominations
  only, total bounded by the wallet's own overpay; DLEQ verified) — the
  swap-response binding (#38) had made every real change answer fail
  after the invoice was already paid. Melt crash-recovery unblinds
  recovered change through the same disciplines (the old resume tail
  mis-passed the full blank set and failed on any partial change).
- Melt blank-output amounts are ignored per NUT-08 ("Bob MUST ignore
  it, imprinting the amount himself") — wallets legitimately send
  nonzero amounts there and the reference families accept them.

### Fixed
- Melt-quote double-settlement: atomic UNPAID→PENDING CAS before payment
  (two concurrent melts on one quote both paid); failure paths roll the
  claim back so quotes stay retryable (cashu-audit #59 P0).
- Same-proofs/two-quotes double spend: proof settlement
  (pending→used) is one transaction and the pending-insert checks
  proofs-used inside its own transaction — the two-statement settle
  left a re-claim window.
- Mint-quote double issuance: atomic PAID→PENDING CAS in MintTokens plus
  full quote-state transition discipline — every mint-quote writer is
  conditional (the invoice-subscription settled event previously wrote
  PAID over Pending/Issued, resurrecting finished states).
- SIG_ALL spec alignment (tollgate #809): the witness lives in the
  FIRST input and signs the aggregated transaction message (melt binds
  the quote id) — P2PK and HTLC arms; the non-spec per-output witness
  lane is retired; melts no longer reject SIG_ALL. n_sigs=0 and
  n_sigs_refund=0 are malformed; duplicate keys per pathway rejected;
  locktime expiry is additive (refund AND primary; no-refund =
  anyone-can-spend); the wallet produces the spec witness.
- NUT-20 mint-quote signatures: dual-accept (legacy cdk framing AND the
  spec `Cashu_MintQuoteSig_v1` domain-separated framing).
- NUT-19: melt responses are replay-cached — a lost melt response
  replays byte-identical instead of erroring ambiguously.
- Mint saga crash-consistency: signatures persist before the Issued
  write, and Pending/Issued quotes with a fully signed output set replay
  the stored signatures (completing Pending→Issued) — a client can
  recover its signatures after any crash point.
- Melt saga completion: the quote-state poll reconciles crash orphans —
  a not-found outgoing payment (crash before the payment attempt)
  releases the claim back to UNPAID with proofs re-spendable; a paid-
  but-unsettled quote settles atomically with its preimage; polls never
  reconcile underneath an in-flight melt.

### Added
- NUT-29 batch endpoints: atomic batch mint across paid quotes
  (claim/rollback discipline, NUT-20 per-quote signatures over the
  consolidated outputs, output limit 1000) and batch quote check
  (request-order, all-or-nothing, limit 50); limits advertised in info.
- Quote hygiene: quote ids are UUID v7, amount_issued accounting in
  quote-state responses, zero-amount mint quotes rejected.

### Changed
- Test infrastructure: a subprocess SIGKILL kill/restart harness exercises
  the melt saga's crash boundaries against the real binary over HTTP
  (`go test ./mint/ -tags killtest`); FakeBackend gained durable
  outgoing-payment state and settlement self-healing for it.
- Swap inputs are claimed (pending-proofs) before signing — the loser
  fails before signature computation; defense-in-depth on top of the
  settle-time uniqueness guard.

## [v0.15.0] - 2026-10-28

### Added

- Pending-op intents for the mint and melt paths (#497): the intent —
  exact request bytes, secrets, blinding factors, derivation range — is
  persisted atomically with the counter reservation BEFORE the POST, and
  `ResumePendingOperations` (supersedes `ResumePendingSwaps`, alias kept)
  replays mint and melt requests the same way swaps already recovered.
  The melt premise (a completed melt re-served idempotently with its
  change signatures) is pinned empirically against cdk-mintd, like the
  swap pin before it.
- NUT-09 `/v1/restore` fallback for journaled swaps the mint refuses with
  11001 "proofs already spent" (tollgate #866): when the swap landed but
  the mint's NUT-19 response-cache window is gone (TTL expired, or the
  mint restarted and lost its in-memory cache), the resume path restores
  the journaled outputs from the mint's persistent blind-signature store
  (verified against cdk-mintd: byte-identical signatures, proofs unspent
  and spendable). Only 11001 arms the fallback; every contradictory
  restore answer keeps the intent journaled.

### Fixed

- Swap responses are bound to the request: every blind signature must
  answer the blinded message this wallet sent at the same index (same
  amount, same keyset id) — a tampered or hostile response can no longer
  mint-label proofs (tollgate #831/#833). The replay path is also wrapped
  so one malformed mint answer cannot boot-loop the daemon.
- A proof on a keyset the wallet cannot price refuses the swap instead of
  silently pricing it at zero fees (tollgate #832) — the refusal matches
  what cdk and Nutshell wallets do for unknown keysets, with the id and
  mint named.
- Spent-input retirement on recovery: a replayed or restored swap now
  retires its input proofs from the wallet db exactly as a completed swap
  does, closing a double-count for wallet-resident inputs (self-swaps,
  keyset rotation, fee splits).
- The `--tags=integration` test build compiles again: the honest-keyset
  fixtures moved out of the `!integration`-tagged file that hid them from
  that configuration.

## [v0.14.1] - 2026-10-24

### Added

- `wallet.IsUnknownKeysetError` — classifies a mint's NUT-19 "unknown keyset"
  refusal (typed `cashu.Error` code 12001, the detail text mints spell it
  with, and wrapped/message-only forms) so callers can separate "the mint
  retired this keyset" from every other fetch failure.

### Fixed

- Wallet load no longer aborts when a mint has rotated out a cached keyset:
  `loadWalletMints` treated every stored keyset with uncached public keys as
  fetch-or-die, so a NUT-19 12001 "Unknown Keyset" answer on a reachable mint
  made `LoadWallet` fail and left tollgate gateways bricked in degraded mode
  until `wallet.db` was moved aside, discarding proofs (tollgate #818). The
  retired record is now skipped in memory and retained on disk untouched —
  derivation counter and unspent proofs preserved — while the mint's current
  keyset set is re-fetched (NUT-02) and init proceeds.
- `getActiveKeyset` no longer attempts to persist the zero-value
  `WalletKeyset` when every stored record of a mint was skipped at load —
  bolt rejected the empty bucket name ("bucket name required"), a latent
  crash the retired-keyset skip exposes.
