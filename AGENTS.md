# AGENTS.md — OpenTollGate/gonuts-tollgate

Instructions for AI coding agents. The cross-repository policy (ownership
map, verification hierarchy, agent principles) is
https://github.com/OpenTollGate/physical-router-test-automation/blob/main/docs/engineering-policy.md

## Cross-Repository Engineering Ownership and Verification

**This repository owns the Cashu wallet/mint layer used by the Go TollGate
implementation** (the maintained fork of `elnosh/gonuts`, which is dead
upstream).

Neighbors — do not duplicate them:

- `OpenTollGate/tollgate-module-basic-go` consumes this fork through
  `replace` directives in every Go module that carries the dependency
  (discover them by `glob("**/go.mod")`, never by a remembered list).
  Wallet-level fixes land **here first**, are tagged, then bumped
  downstream — never patched around locally in a consumer.
- Router-level payment verification (kill/restart at transaction
  boundaries, mint faults) is owned by
  `OpenTollGate/physical-router-test-automation` and the module repo's
  cloud-lab conformance lane.

Agent rules: every change here is fund-safety-critical — read the
fund-safety and derivation-counter rules in the consuming repo's AGENTS.md
before touching derivation, keysets, swap/mint/melt or persistence. Never
re-expose a derivation range; keyset counters are monotonic; ambiguous
network results are reconciled, never blindly retried.
