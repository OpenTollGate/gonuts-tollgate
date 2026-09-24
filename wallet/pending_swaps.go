package wallet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// resumeHTTP is the replay transport, overridable in tests.
var resumeHTTP = &http.Client{Timeout: 30 * time.Second}

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
// Per-intent failure policy: an intent the mint cannot answer (down,
// wedged, or a non-200 that is not a replayable signature set) is LEFT
// in place and reported — never deleted on a bad guess. Retries happen
// on the next call (boot, or an operator-driven sweep); callers should
// back off rather than hammer a down mint.
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

	proofs, err := constructProofs(swapResponse.Signatures, intent.Outputs, intent.Secrets, rs, keyset)
	if err != nil {
		return 0, fmt.Errorf("could not unblind replayed signatures: %w", err)
	}

	// SaveProofs is keyed by secret, so a lingering intent whose proofs
	// were already saved replays idempotently.
	if err := w.db.SaveProofs(proofs); err != nil {
		return 0, fmt.Errorf("could not store recovered proofs: %w", err)
	}
	if err := w.db.DeletePendingSwap(intent.OpID); err != nil {
		return 0, fmt.Errorf("proofs stored but intent %s not deleted: %w", intent.OpID, err)
	}
	log.Printf("wallet: pending swap %s recovered %d sats from %s", intent.OpID, proofs.Amount(), intent.MintURL)
	return proofs.Amount(), nil
}

func truncateForLog(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}
