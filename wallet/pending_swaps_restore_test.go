package wallet

// The #866 acceptance shapes: a replay the mint refuses with 11001
// ("proofs already spent" — the swap landed, but the NUT-19 response
// cache window is gone) must recover via NUT-09 /v1/restore with the
// journaled outputs, and every restore shape that does not unambiguously
// reconstruct the signed outputs keeps the intent journaled.
import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut09"
)

// crashAfterMintAccepts overrides the swap seam to POST the real request
// and then "die" before processing the response — the #497 crash window,
// leaving a journaled intent behind and the mint holding the signatures.
func crashAfterMintAccepts(mintURL string, req swapRequestPayload) (cashu.Proofs, error) {
	body, _ := json.Marshal(nut03.PostSwapRequest{Inputs: req.inputs, Outputs: req.outputs})
	resp, err := http.Post(mintURL+"/v1/swap", "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return nil, errSimulatedCrash
}

func spendRefusal() *cashu.Error {
	return cashu.BuildCashuError("Token Already Spent", cashu.ProofAlreadyUsedErrCode)
}

// The beyond-window crash: the mint accepted the swap (it signed), the
// wallet died, and by boot time the mint's response cache is gone — the
// replay is refused 11001. The journaled outputs still restore, and the
// restored proofs are the recovered balance.
func TestResumeRecoversViaNut09RestoreAfterSpentRefusal(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	defer func() { swap = origSwap }()
	swap = crashAfterMintAccepts

	req := m.newSwapRequest(t, w, 64)
	if _, _, recErr := w.swapWithIntent(m.server.URL, req); recErr == nil {
		t.Fatal("simulated crash must surface an error")
	}
	if m.swaps != 1 || len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("mint signed %d times, %d intent(s) — want 1 and 1", m.swaps, len(w.db.GetPendingSwaps()))
	}

	swap = origSwap
	m.refusal = spendRefusal()

	recovered, failed, err := w.ResumePendingSwaps()
	if err != nil || failed != 0 {
		t.Fatalf("resume: recovered=%d failed=%d err=%v", recovered, failed, err)
	}
	if recovered != 64 {
		t.Fatalf("recovered %d, want 64", recovered)
	}
	if w.GetBalance() != 64 {
		t.Fatalf("balance after restore = %d, want 64", w.GetBalance())
	}
	if len(w.db.GetPendingSwaps()) != 0 {
		t.Fatal("intent must be deleted after restore recovery")
	}
	if m.restoreCalls != 1 {
		t.Fatalf("restore called %d times, want 1", m.restoreCalls)
	}
	if m.swaps != 2 {
		t.Fatalf("mint saw %d swaps (original + refused replay), want 2", m.swaps)
	}
}

// The proofs the restore path reconstructs must be exactly the proofs a
// successful replay would have produced: the stub signs deterministically,
// so unblinding the restored signatures must yield the balances above and
// idempotent re-resume must be a no-op.
func TestResumeViaRestoreIsIdempotentAndComplete(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	swap = crashAfterMintAccepts
	req := m.newSwapRequest(t, w, 32)
	_, _, _ = w.swapWithIntent(m.server.URL, req)
	swap = origSwap
	m.refusal = spendRefusal()

	if _, _, err := w.ResumePendingSwaps(); err != nil {
		t.Fatalf("first resume: %v", err)
	}
	recovered, failed, err := w.ResumePendingSwaps()
	if err != nil || failed != 0 || recovered != 0 {
		t.Fatalf("second resume must be a no-op, got recovered=%d failed=%d err=%v", recovered, failed, err)
	}
	if w.GetBalance() != 32 {
		t.Fatalf("balance = %d, want 32", w.GetBalance())
	}
}

// A 11001 refusal the mint's own /v1/restore contradicts (nothing was
// ever signed for these outputs) must keep the intent journaled — never
// delete on a contradictory guess.
func TestResumeKeepsIntentWhenRestoreReturnsNothing(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	defer func() { swap = origSwap }()
	swap = func(string, swapRequestPayload) (cashu.Proofs, error) {
		return nil, errSimulatedCrash
	}
	_, _, _ = w.swapWithIntent(m.server.URL, m.newSwapRequest(t, w, 16))
	swap = origSwap
	m.refusal = spendRefusal()

	recovered, failed, _ := w.ResumePendingSwaps()
	if recovered != 0 || failed != 1 {
		t.Fatalf("recovered=%d failed=%d, want 0 and 1", recovered, failed)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatal("intent must survive a contradictory restore")
	}
	if w.GetBalance() != 0 {
		t.Fatalf("balance = %d, want 0", w.GetBalance())
	}
	if m.restoreCalls != 1 {
		t.Fatalf("restore called %d times, want 1", m.restoreCalls)
	}
}

// A restore that cannot be fetched (mint wedged on /v1/restore) keeps the
// intent journaled for the next pass.
func TestResumeKeepsIntentWhenRestoreTransportFails(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	swap = crashAfterMintAccepts
	_, _, _ = w.swapWithIntent(m.server.URL, m.newSwapRequest(t, w, 16))
	swap = origSwap
	m.refusal = spendRefusal()

	origPostRestore := postRestore
	defer func() { postRestore = origPostRestore }()
	postRestore = func(string, nut09.PostRestoreRequest) (*nut09.PostRestoreResponse, error) {
		return nil, errors.New("connection reset")
	}

	recovered, failed, _ := w.ResumePendingSwaps()
	if recovered != 0 || failed != 1 {
		t.Fatalf("recovered=%d failed=%d, want 0 and 1", recovered, failed)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatal("intent must survive a failed restore transport")
	}
}

// Only the 11001 spent-refusal arms the restore fallback: other mint
// errors keep the plain not-recoverable-this-pass behavior and never hit
// /v1/restore.
func TestResumeDoesNotRestoreOnNonSpentRefusal(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	swap = crashAfterMintAccepts
	_, _, _ = w.swapWithIntent(m.server.URL, m.newSwapRequest(t, w, 16))
	swap = origSwap
	m.refusal = cashu.BuildCashuError("proof verification failed", cashu.CashuErrCode(10001))

	recovered, failed, _ := w.ResumePendingSwaps()
	if recovered != 0 || failed != 1 {
		t.Fatalf("recovered=%d failed=%d, want 0 and 1", recovered, failed)
	}
	if m.restoreCalls != 0 {
		t.Fatalf("restore called %d times, want 0 — only 11001 arms the fallback", m.restoreCalls)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatal("intent must survive a non-spent refusal")
	}
}

// A partial restore (the mint returns fewer signatures than journaled
// outputs) is not a shape to guess value from: keep the intent journaled.
func TestResumeKeepsIntentOnPartialRestore(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	swap = crashAfterMintAccepts
	req := m.newSwapRequest(t, w, 64)
	if len(req.outputs) < 2 {
		t.Fatalf("fixture needs multiple outputs to make a partial restore, got %d", len(req.outputs))
	}
	_, _, _ = w.swapWithIntent(m.server.URL, req)
	swap = origSwap
	m.refusal = spendRefusal()
	m.dropLastRestore = true

	recovered, failed, _ := w.ResumePendingSwaps()
	if recovered != 0 || failed != 1 {
		t.Fatalf("recovered=%d failed=%d, want 0 and 1", recovered, failed)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatal("intent must survive a partial restore")
	}
	if w.GetBalance() != 0 {
		t.Fatalf("balance = %d, want 0 — partial value must not be banked on a guess", w.GetBalance())
	}
}

// When the crashed swap's inputs were wallet-resident proofs (a self
// swap, keyset rotation, fee split — not customer-received tokens), the
// crash leaves them in the db while the mint has already consumed them:
// recovery must retire them, or the balance double-counts the recovered
// value.
func TestResumeRetiresWalletResidentInputsOnRestoreRecovery(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	mint, ok := w.mints[m.server.URL]
	if !ok {
		t.Fatal("stub mint not registered")
	}
	inputs := cashu.Proofs{{Id: m.keyset.Id, Amount: 64, Secret: "db-resident-input", C: "02ab"}}
	if err := w.db.SaveProofs(inputs); err != nil {
		t.Fatalf("SaveProofs(inputs): %v", err)
	}
	if w.GetBalance() != 64 {
		t.Fatalf("fixture balance = %d, want 64", w.GetBalance())
	}

	req, err := w.createSwapRequest(inputs, &mint)
	if err != nil {
		t.Fatalf("createSwapRequest: %v", err)
	}
	origSwap := swap
	swap = crashAfterMintAccepts
	_, _, _ = w.swapWithIntent(m.server.URL, req)
	swap = origSwap
	m.refusal = spendRefusal()

	recovered, failed, err := w.ResumePendingSwaps()
	if err != nil || failed != 0 || recovered != 64 {
		t.Fatalf("resume: recovered=%d failed=%d err=%v, want 64/0/nil", recovered, failed, err)
	}
	if w.GetBalance() != 64 {
		t.Fatalf("balance = %d, want 64 — spent inputs must be retired, not double-counted", w.GetBalance())
	}
	if len(w.db.GetPendingSwaps()) != 0 {
		t.Fatal("intent must be retired after restore recovery")
	}
}

// cdk's /v1/restore returns matched-only outputs in its own order, not the
// request's — the B_-join realignment must unblind correctly regardless.
func TestResumeHandlesShuffledRestoreOrder(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	swap = crashAfterMintAccepts
	req := m.newSwapRequest(t, w, 64)
	if len(req.outputs) < 2 {
		t.Fatalf("fixture needs multiple outputs to shuffle, got %d", len(req.outputs))
	}
	_, _, _ = w.swapWithIntent(m.server.URL, req)
	swap = origSwap
	m.refusal = spendRefusal()
	m.shuffleRestore = true

	recovered, failed, err := w.ResumePendingSwaps()
	if err != nil || failed != 0 || recovered != 64 {
		t.Fatalf("resume: recovered=%d failed=%d err=%v, want 64/0/nil", recovered, failed, err)
	}
	if w.GetBalance() != 64 {
		t.Fatalf("balance = %d, want 64 — shuffled order must not corrupt unblinding", w.GetBalance())
	}
	if len(w.db.GetPendingSwaps()) != 0 {
		t.Fatal("intent must be retired after shuffled-restore recovery")
	}
	if m.restoreCalls != 1 {
		t.Fatalf("restore called %d times, want 1", m.restoreCalls)
	}
}

// Three journaled intents, three mint verdicts on replay: one refused 11001
// (recovers via restore), one answered 200 (recovers via replay), one refused
// non-11001 (stays journaled). Resume must treat them independently.
func TestResumeMixedOutcomesAcrossIntents(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	mint, ok := w.mints[m.server.URL]
	if !ok {
		t.Fatal("stub mint not registered")
	}
	crashIntent := func(secret string, amount uint64) {
		origSwap := swap
		swap = crashAfterMintAccepts
		inputs := cashu.Proofs{{Id: m.keyset.Id, Amount: amount, Secret: secret, C: "02ab"}}
		req, cErr := w.createSwapRequest(inputs, &mint)
		if cErr != nil {
			t.Fatalf("createSwapRequest(%s): %v", secret, cErr)
		}
		_, _, _ = w.swapWithIntent(m.server.URL, req)
		swap = origSwap
	}
	crashIntent("spent-restore-path", 16)
	crashIntent("replay-cache-path", 8)
	crashIntent("other-err-path", 4)
	if len(w.db.GetPendingSwaps()) != 3 {
		t.Fatalf("fixture: %d intents journaled, want 3", len(w.db.GetPendingSwaps()))
	}

	m.refusalFor = func(req *nut03.PostSwapRequest) *cashu.Error {
		for _, in := range req.Inputs {
			if strings.Contains(in.Secret, "spent-restore") {
				return spendRefusal()
			}
			if strings.Contains(in.Secret, "other-err") {
				return cashu.BuildCashuError("proof verification failed", cashu.CashuErrCode(10001))
			}
		}
		return nil
	}

	recovered, failed, err := w.ResumePendingSwaps()
	if err != nil || failed != 1 || recovered != 24 {
		t.Fatalf("resume: recovered=%d failed=%d err=%v, want 24/1/nil", recovered, failed, err)
	}
	if w.GetBalance() != 24 {
		t.Fatalf("balance = %d, want 24 (16 restored + 8 replayed)", w.GetBalance())
	}
	if remaining := len(w.db.GetPendingSwaps()); remaining != 1 {
		t.Fatalf("%d intents remaining, want exactly the non-11001 one", remaining)
	}
	if m.restoreCalls != 1 {
		t.Fatalf("restore called %d times, want 1 — only the 11001 refusal arms it", m.restoreCalls)
	}
}
