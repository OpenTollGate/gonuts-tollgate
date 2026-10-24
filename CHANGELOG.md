# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
