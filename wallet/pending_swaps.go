package wallet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut09"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/client"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// resumeHTTP is the replay transport, overridable in tests.
var resumeHTTP = &http.Client{Timeout: 30 * time.Second}

// postRestore is declared as a variable so tests can override it
// (the same seam family as postMeltBolt11 / postMintBolt11 / swap).
var postRestore = client.PostRestore

// ResumePendingSwaps replays every recorded swap intent against its mint
// and completes the ones the mint answers with signatures. It is the
// crash-recovery half of the #497 invariant: because the intent (exact
// request bytes, secrets, blinding factors) was written atomically with
// its counter reservation BEFORE the original POST, and mints sign
// deterministically (verified against cdk-mintd 0.17.6: an identical
// re-POST returns HTTP 200 with byte-identical signatures), a re-POST
// reconstructs proofs that a crash between the mint's acceptance and
// SaveProofs would otherwise have destroyed.
//
// When the mint refuses the replay with 11001 "proofs already spent" —
// the swap landed, but the mint's NUT-19 response-cache window is gone
// (TTL expired, or the mint restarted and lost its in-memory cache) —
// recovery continues via NUT-09 /v1/restore with the journaled outputs:
// the mint returns the blind signatures it persisted when it signed
// them, which unblind to the same proofs the lost replay carried
// (verified against cdk-mintd 0.17.6: byte-identical signatures, proofs
// unspent and spendable — tollgate #866).
//
// Per-intent failure policy: an intent the mint cannot answer (down,
// wedged, a non-200 that is not a replayable signature set, or a restore
// result that contradicts the mint's own spend state) is LEFT in place
// and reported — never deleted on a bad guess. Retries happen on the
// next call (boot, or an operator-driven sweep); callers should back off
// rather than hammer a down mint.
func (w *Wallet) ResumePendingSwaps() (recovered uint64, failed int, err error) {
	intents := w.db.GetPendingSwaps()
	for _, intent := range intents {
		amount, rErr := w.resumeOneSwap(intent)
		if rErr != nil {
			failed++
			log.Printf("wallet: pending swap %s (%s) not recoverable this pass: %v", intent.OpID, intent.MintURL, rErr)
			continue
		}
		recovered += amount
	}
	if failed > 0 && recovered == 0 && len(intents) > 0 {
		return 0, failed, fmt.Errorf("%d pending swap(s) unrecoverable this pass", failed)
	}
	return recovered, failed, nil
}

func (w *Wallet) resumeOneSwap(intent *storage.PendingSwapIntent) (uint64, error) {
	url := intent.MintURL
	if len(url) == 0 || url[len(url)-1] != '/' {
		url += "/"
	}
	resp, err := resumeHTTP.Post(url+"v1/swap", "application/json", bytes.NewReader(intent.RequestBytes))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		if isProofsAlreadySpentRefusal(body) {
			return w.resumeSwapViaRestore(intent)
		}
		return 0, fmt.Errorf("mint answered replay with HTTP %d: %s", resp.StatusCode, truncateForLog(body, 200))
	}

	var swapResponse nut03.PostSwapResponse
	if err := json.Unmarshal(body, &swapResponse); err != nil {
		return 0, fmt.Errorf("could not parse replay response: %w", err)
	}

	return w.finishRecoveredSwap(intent, swapResponse.Signatures, intent.Outputs, intent.Secrets, intentBlindingFactors(intent), "")
}

// resumeSwapViaRestore is the fallback for a replay the mint refused with
// 11001 "proofs already spent": the inputs are consumed (the swap landed)
// but the mint can no longer serve the cached answer. NUT-09 /v1/restore
// asks the mint for the blind signatures it persisted for exactly these
// outputs when it signed them — recovery that does not depend on any
// cache window or mint uptime.
func (w *Wallet) resumeSwapViaRestore(intent *storage.PendingSwapIntent) (uint64, error) {
	resp, err := postRestore(intent.MintURL, nut09.PostRestoreRequest{Outputs: intent.Outputs})
	if err != nil {
		return 0, fmt.Errorf("mint refused the replay (proofs already spent) and the NUT-09 restore attempt failed: %w", err)
	}
	if len(resp.Signatures) == 0 {
		// 11001 says the inputs were consumed, which means these outputs
		// were signed — an empty restore contradicts that. The mint may
		// have refused /v1/restore outright; either way, do not guess.
		return 0, errors.New("mint refused the replay (proofs already spent) but NUT-09 restore returned no signatures — keeping the intent journaled")
	}
	if len(resp.Signatures) != len(resp.Outputs) {
		return 0, fmt.Errorf("NUT-09 restore returned %d signatures for %d outputs — malformed response, keeping the intent journaled", len(resp.Signatures), len(resp.Outputs))
	}
	if len(resp.Signatures) != len(intent.Outputs) {
		// A landed swap signed ALL the journaled outputs atomically; a
		// partial restore (e.g. a mint skipping expired-keyset outputs)
		// is not a shape to guess value from — retry next pass or by
		// operator.
		return 0, fmt.Errorf("NUT-09 restore returned %d of %d journaled outputs — keeping the intent journaled", len(resp.Signatures), len(intent.Outputs))
	}

	// The mint returns only previously-signed outputs, in its own order:
	// realign with the journal by B_ before unblinding.
	indexOfB := make(map[string]int, len(intent.Outputs))
	for j, out := range intent.Outputs {
		indexOfB[out.B_] = j
	}
	rsAll := intentBlindingFactors(intent)
	secrets := make([]string, len(resp.Outputs))
	rs := make([]*secp256k1.PrivateKey, len(resp.Outputs))
	for i, out := range resp.Outputs {
		j, ok := indexOfB[out.B_]
		if !ok {
			return 0, fmt.Errorf("NUT-09 restore returned an output the intent never journaled (B_=%s) — keeping the intent journaled", truncateForLog([]byte(out.B_), 16))
		}
		secrets[i] = intent.Secrets[j]
		rs[i] = rsAll[j]
	}

	return w.finishRecoveredSwap(intent, resp.Signatures, resp.Outputs, secrets, rs, " via NUT-09 restore")
}

// finishRecoveredSwap unblinds the recovered signatures against the
// journaled derivation material, stores the proofs, and retires the
// intent. It is the shared tail of both recovery paths — the NUT-19
// replay (200 + signatures, aligned as journaled) and the NUT-09 restore
// fallback (realigned by B_) — so both leave identical postconditions:
// proofs saved, intent deleted, amount reported.
func (w *Wallet) finishRecoveredSwap(
	intent *storage.PendingSwapIntent,
	signatures cashu.BlindedSignatures,
	messages cashu.BlindedMessages,
	secrets []string,
	rs []*secp256k1.PrivateKey,
	via string,
) (uint64, error) {
	keyset := w.db.GetKeyset(intent.KeysetID)
	if keyset == nil {
		return 0, fmt.Errorf("keyset %s no longer in wallet db (rotated away?)", intent.KeysetID)
	}

	proofs, err := constructProofs(signatures, messages, secrets, rs, keyset)
	if err != nil {
		return 0, fmt.Errorf("could not unblind replayed signatures: %w", err)
	}

	// SaveProofs is keyed by secret, so a lingering intent whose proofs
	// were already saved replays idempotently.
	if err := w.db.SaveProofs(proofs); err != nil {
		return 0, fmt.Errorf("could not store recovered proofs: %w", err)
	}

	// The recovered signatures prove the swap landed, which consumed its
	// inputs: retire them exactly as a completed swap would (a proof the
	// crash left in the db would otherwise double-count the balance).
	var spent nut03.PostSwapRequest
	if err := json.Unmarshal(intent.RequestBytes, &spent); err == nil {
		for _, proof := range spent.Inputs {
			if dErr := w.db.DeleteProof(proof.Secret); dErr != nil && !errors.Is(dErr, storage.ProofNotFound) {
				return 0, fmt.Errorf("recovered proofs stored but input proof %s not retired: %w", truncateForLog([]byte(proof.Secret), 16), dErr)
			}
		}
	}

	if err := w.db.DeletePendingSwap(intent.OpID); err != nil {
		return 0, fmt.Errorf("proofs stored but intent %s not deleted: %w", intent.OpID, err)
	}
	log.Printf("wallet: pending swap %s recovered %d sats from %s%s", intent.OpID, proofs.Amount(), intent.MintURL, via)
	return proofs.Amount(), nil
}

func intentBlindingFactors(intent *storage.PendingSwapIntent) []*secp256k1.PrivateKey {
	rs := make([]*secp256k1.PrivateKey, len(intent.Rs))
	for i, raw := range intent.Rs {
		rs[i] = secp256k1.PrivKeyFromBytes(raw)
	}
	return rs
}

// isProofsAlreadySpentRefusal reports whether a mint error body is the
// 11001 "proofs already spent" refusal: the replay's inputs were
// consumed, so the swap landed — its answer must be recovered, not
// re-executed. cdk-mintd emits exactly
// {"code":11001,"detail":"Token Already Spent"} for a swap re-POST once
// its NUT-19 response cache no longer holds the original answer.
func isProofsAlreadySpentRefusal(body []byte) bool {
	var mintErr cashu.Error
	if err := json.Unmarshal(body, &mintErr); err != nil {
		return false
	}
	return mintErr.Code == cashu.ProofAlreadyUsedErrCode
}

func truncateForLog(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
