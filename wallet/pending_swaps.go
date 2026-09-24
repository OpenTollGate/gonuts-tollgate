package wallet

import (
	"bytes"
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
		amount, rErr := w.resumeOneOperationSafe(intent)
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

// resumeOneOperationSafe keeps one malformed mint answer (or a future bug
// in any replay path — swap, mint or melt) from taking the whole boot
// down: the resume runs at daemon startup, where no caller-provided
// recover exists, so a panic here would be a boot-loop. Converted into a
// per-intent failure, the intent stays journaled and the next boot
// retries it (audit finding #833; the guard now covers every op type the
// dispatcher can route to).
func (w *Wallet) resumeOneOperationSafe(intent *storage.PendingSwapIntent) (amount uint64, err error) {
	defer func() {
		if r := recover(); r != nil {
			amount, err = 0, fmt.Errorf("replay panicked: %v", r)
		}
	}()
	return w.resumeOneOperation(intent)
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

// resumeOneMint replays a /v1/mint/bolt11 request. The persisted bytes
// carry the cdk-verified NUT-20 signature (#34 made the concatenation form
// the primary), so there is no second signing format to fall back to: a
// refusal surfaces as a failed intent and the bytes stay journaled —
// identical in spirit to the pre-#34 20008 retry, which re-signed in the
// form cdk accepts (that form is now the only one on the wire).
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
		return 0, fmt.Errorf("mint answered replay with HTTP %d: %s", resp.StatusCode, truncateForLog(body, 200))
	}
	if err != nil {
		return 0, err
	}

	var mintResponse nut04.PostMintBolt11Response
	if err := json.Unmarshal(body, &mintResponse); err != nil {
		return 0, fmt.Errorf("could not parse replay response: %w", err)
	}
	return w.finishResume(intent, mintResponse.Signatures)
>>>>>>> d3cf84b (feat(wallet): pending-op intents for the mint path — crashed mints recover by replay (#497))
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
