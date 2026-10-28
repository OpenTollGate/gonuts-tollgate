# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
