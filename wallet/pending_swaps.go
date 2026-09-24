package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut20"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// resumeHTTP is the replay transport, overridable in tests.
var resumeHTTP = &http.Client{Timeout: 30 * time.Second}

// ResumePendingOperations replays every recorded pending operation
// (swap or mint) against its mint and completes the ones the mint
// answers with signatures.
//
// It is the crash-recovery half of the #497 invariant: because the
// intent (exact request bytes, secrets, blinding factors) was written
// atomically with its counter reservation BEFORE the original POST, and
// mints sign deterministically (verified against cdk-mintd 0.17.6 for
// both /v1/swap and /v1/mint/bolt11: an identical re-POST returns
// byte-identical signatures), a re-POST reconstructs proofs that a
// crash between the mint's acceptance and SaveProofs would otherwise
// have destroyed.
//
// Per-intent failure policy: an intent the mint cannot answer (down,
// wedged, or a non-200 that is not a replayable signature set) is LEFT
// in place and reported — never deleted on a bad guess. Retries happen
// on the next call (boot, or an operator-driven sweep); callers should
// back off rather than hammer a down mint.
func (w *Wallet) ResumePendingOperations() (recovered uint64, failed int, err error) {
	intents := w.db.GetPendingSwaps()
	for _, intent := range intents {
		amount, rErr := w.resumeOneOperation(intent)
		if rErr != nil {
			failed++
			log.Printf("wallet: pending op %s (%s) not recoverable this pass: %v", intent.OpID, intent.MintURL, rErr)
			continue
		}
		recovered += amount
	}
	if failed > 0 && recovered == 0 && len(intents) > 0 {
		return 0, failed, fmt.Errorf("%d pending operation(s) unrecoverable this pass", failed)
	}
	return recovered, failed, nil
}

// ResumePendingSwaps is the original name of ResumePendingOperations;
// kept so callers written before mint intents exist keep working.
func (w *Wallet) ResumePendingSwaps() (uint64, int, error) {
	return w.ResumePendingOperations()
}

func (w *Wallet) resumeOneOperation(intent *storage.PendingSwapIntent) (uint64, error) {
	switch intent.OpType {
	case storage.PendingOpMint:
		return w.resumeOneMint(intent)
	case storage.PendingOpMelt:
		return w.resumeOneMelt(intent)
	default:
		// empty OpType = the original swap records
		return w.resumeOneSwap(intent)
	}
}

// resumeOneMint replays a /v1/mint/bolt11 request. A 20008 answer means
// the persisted bytes carry the amended NUT-20 signature but the mint
// verifies the legacy form (cdk <= 0.17.x): re-sign from the stored
// quote key — the same retry MintTokens performs live.
func (w *Wallet) resumeOneMint(intent *storage.PendingSwapIntent) (uint64, error) {
	url := intent.MintURL
	if len(url) == 0 || url[len(url)-1] != '/' {
		url += "/"
	}
	resp, err := resumeHTTP.Post(url+"v1/mint/bolt11", "application/json", bytes.NewReader(intent.RequestBytes))
	if err != nil {
		return 0, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if readErr != nil {
		return 0, readErr
	}
	if resp.StatusCode != http.StatusOK {
		var cashuErr cashu.Error
		if resp.StatusCode == http.StatusBadRequest && json.Unmarshal(body, &cashuErr) == nil &&
			cashuErr.Code == cashu.MintQuoteInvalidSigErrCode {
			retried, rErr := w.retryMintReplayWithLegacySig(intent)
			if rErr != nil {
				return 0, rErr
			}
			resp, err = retried, nil
			body, readErr = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if readErr != nil {
				return 0, readErr
			}
			if resp.StatusCode != http.StatusOK {
				return 0, fmt.Errorf("mint answered legacy-sig replay with HTTP %d: %s", resp.StatusCode, truncateForLog(body, 200))
			}
		} else {
			return 0, fmt.Errorf("mint answered replay with HTTP %d: %s", resp.StatusCode, truncateForLog(body, 200))
		}
	}
	if err != nil {
		return 0, err
	}

	var mintResponse nut04.PostMintBolt11Response
	if err := json.Unmarshal(body, &mintResponse); err != nil {
		return 0, fmt.Errorf("could not parse replay response: %w", err)
	}
	return w.finishResume(intent, mintResponse.Signatures)
}

// resumeOneMelt replays a /v1/melt/bolt11 request. cdk-mintd replays
// melts idempotently — a paid quote re-POSTed with identical bytes
// returns state PAID with the same change signatures (verified live) —
// so the persisted factors recover the change exactly as in swaps.
func (w *Wallet) resumeOneMelt(intent *storage.PendingSwapIntent) (uint64, error) {
	url := intent.MintURL
	if len(url) == 0 || url[len(url)-1] != '/' {
		url += "/"
	}
	resp, err := resumeHTTP.Post(url+"v1/melt/bolt11", "application/json", bytes.NewReader(intent.RequestBytes))
	if err != nil {
		return 0, err
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if readErr != nil {
		return 0, readErr
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("mint answered melt replay with HTTP %d: %s", resp.StatusCode, truncateForLog(body, 200))
	}
	var meltResponse nut05.PostMeltQuoteBolt11Response
	if err := json.Unmarshal(body, &meltResponse); err != nil {
		return 0, fmt.Errorf("could not parse melt replay response: %w", err)
	}
	if meltResponse.State != nut05.Paid {
		return 0, fmt.Errorf("melt replay state %v, not PAID", meltResponse.State)
	}
	// The change signatures are the recovery target; an empty change
	// (no fee overpayment) carries no value, so success with nothing to
	// unblind is a clean completion.
	if len(meltResponse.Change) == 0 {
		if err := w.db.DeletePendingSwap(intent.OpID); err != nil {
			return 0, fmt.Errorf("melt recovered (no change) but intent %s not deleted: %w", intent.OpID, err)
		}
		return 0, nil
	}
	return w.finishResume(intent, meltResponse.Change)
}

func (w *Wallet) retryMintReplayWithLegacySig(intent *storage.PendingSwapIntent) (*http.Response, error) {
	var req nut04.PostMintBolt11Request
	if err := json.Unmarshal(intent.RequestBytes, &req); err != nil {
		return nil, fmt.Errorf("could not parse stored mint request: %w", err)
	}
	quote := w.db.GetMintQuoteById(req.Quote)
	if quote == nil || quote.PrivateKey == nil {
		return nil, fmt.Errorf("quote %s has no stored key to re-sign the legacy NUT-20 form", req.Quote)
	}
	legacySig, err := nut20.SignMintQuoteLegacy(quote.PrivateKey, req.Quote, req.Outputs)
	if err != nil {
		return nil, fmt.Errorf("could not legacy-sign replay: %w", err)
	}
	req.Signature = hex.EncodeToString(legacySig.Serialize())
	intent.RequestBytes = mustMarshalMintRequest(req)
	if err := w.db.PutPendingSwap(intent); err != nil {
		log.Printf("wallet: could not persist legacy-signed replay bytes for %s: %v", intent.OpID, err)
	}
	url := intent.MintURL
	if len(url) == 0 || url[len(url)-1] != '/' {
		url += "/"
	}
	return resumeHTTP.Post(url+"v1/mint/bolt11", "application/json", bytes.NewReader(intent.RequestBytes))
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
		return 0, fmt.Errorf("mint answered replay with HTTP %d: %s", resp.StatusCode, truncateForLog(body, 200))
	}

	var swapResponse nut03.PostSwapResponse
	if err := json.Unmarshal(body, &swapResponse); err != nil {
		return 0, fmt.Errorf("could not parse replay response: %w", err)
	}

	keyset := w.db.GetKeyset(intent.KeysetID)
	if keyset == nil {
		return 0, fmt.Errorf("keyset %s no longer in wallet db (rotated away?)", intent.KeysetID)
	}

	rs := make([]*secp256k1.PrivateKey, len(intent.Rs))
	for i, raw := range intent.Rs {
		rs[i] = secp256k1.PrivKeyFromBytes(raw)
	}

	return w.finishResume(intent, swapResponse.Signatures)
}

// finishResume unblinds the replayed signatures with the intent's
// persisted factors, stores the proofs (secret-keyed, hence idempotent
// on double recovery) and deletes the intent.
func (w *Wallet) finishResume(intent *storage.PendingSwapIntent, signatures cashu.BlindedSignatures) (uint64, error) {
	keyset := w.db.GetKeyset(intent.KeysetID)
	if keyset == nil {
		return 0, fmt.Errorf("keyset %s no longer in wallet db (rotated away?)", intent.KeysetID)
	}
	rs := make([]*secp256k1.PrivateKey, len(intent.Rs))
	for i, raw := range intent.Rs {
		rs[i] = secp256k1.PrivKeyFromBytes(raw)
	}
	proofs, err := constructProofs(signatures, intent.Outputs, intent.Secrets, rs, keyset)
	if err != nil {
		return 0, fmt.Errorf("could not unblind replayed signatures: %w", err)
	}
	if err := w.db.SaveProofs(proofs); err != nil {
		return 0, fmt.Errorf("could not store recovered proofs: %w", err)
	}
	if err := w.db.DeletePendingSwap(intent.OpID); err != nil {
		return 0, fmt.Errorf("proofs stored but intent %s not deleted: %w", intent.OpID, err)
	}
	log.Printf("wallet: pending op %s recovered %d sats from %s", intent.OpID, proofs.Amount(), intent.MintURL)
	return proofs.Amount(), nil
}

func truncateForLog(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}

// mintIntent builds the pending-op record for a /v1/mint/bolt11 POST.
// OpType routes the resume path; RequestBytes are the exact bytes to
// re-POST, including whichever NUT-20 signature form is on the wire.
func mintIntent(opID, mintURL, keysetID string, counterStart uint32, req nut04.PostMintBolt11Request, outputs cashu.BlindedMessages, secrets []string, rs []*secp256k1.PrivateKey) *storage.PendingSwapIntent {
	requestBytes, err := json.Marshal(req)
	if err != nil {
		panic(fmt.Sprintf("marshal mint request: %v", err))
	}
	return baseIntent(opID, mintURL, keysetID, counterStart, requestBytes, outputs, secrets, rs, storage.PendingOpMint)
}

// meltIntent builds the pending-op record for a /v1/melt/bolt11 POST:
// the recovery target is the NUT-08 change, and the mint replays the
// melt idempotently (state PAID with the same change signatures).
func meltIntent(opID, mintURL, keysetID string, counterStart uint32, req nut05.PostMeltBolt11Request, outputs cashu.BlindedMessages, secrets []string, rs []*secp256k1.PrivateKey) *storage.PendingSwapIntent {
	requestBytes, err := json.Marshal(req)
	if err != nil {
		panic(fmt.Sprintf("marshal melt request: %v", err))
	}
	return baseIntent(opID, mintURL, keysetID, counterStart, requestBytes, outputs, secrets, rs, storage.PendingOpMelt)
}

func baseIntent(opID, mintURL, keysetID string, counterStart uint32, requestBytes []byte, outputs cashu.BlindedMessages, secrets []string, rs []*secp256k1.PrivateKey, opType string) *storage.PendingSwapIntent {
	serRs := make([][]byte, len(rs))
	for i, r := range rs {
		serRs[i] = r.Serialize()
	}
	return &storage.PendingSwapIntent{
		OpID:         opID,
		MintURL:      mintURL,
		KeysetID:     keysetID,
		CounterStart: counterStart,
		CounterEnd:   counterStart + uint32(len(outputs)),
		RequestBytes: requestBytes,
		Outputs:      outputs,
		Secrets:      secrets,
		Rs:           serRs,
		OpType:       opType,
	}
}

func mustMarshalMintRequest(req nut04.PostMintBolt11Request) []byte {
	b, err := json.Marshal(req)
	if err != nil {
		// nut04 request types are plain JSON structs; a marshal failure
		// here is a programming error, not a runtime condition.
		panic(fmt.Sprintf("marshal mint request: %v", err))
	}
	return b
}
