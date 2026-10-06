package wallet

import (
	"errors"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
)

// The 10002 retry path must not leak its superseded intent: the mint's
// "outputs already signed" is a definitive refusal (inputs not consumed),
// so the first attempt's intent is unrecoverable-by-design and deleting it
// keeps the pending set exactly the set of ambiguous outcomes. Without the
// delete, every retried swap leaves an immortal phantom that resurfaces as
// a failed entry at every ResumePendingSwaps.
func Test10002RetryDeletesSupersededIntent(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	proofs := cashu.Proofs{{Id: m.keyset.Id, Amount: 8, Secret: "input-secret", C: "02ab"}}
	mint, ok := w.mints[m.server.URL]
	if !ok {
		t.Fatal("stub mint not registered")
	}
	firstReq, err := w.createSwapRequest(proofs, &mint)
	if err != nil {
		t.Fatalf("createSwapRequest: %v", err)
	}

	// The mint refuses the FIRST attempt with 10002; the wallet's retry
	// (fresh outputs, fresh range) reaches the fixture mint and succeeds.
	origSwap := swap
	defer func() { swap = origSwap }()
	calls := 0
	swap = func(mintURL string, req swapRequestPayload) (cashu.Proofs, error) {
		calls++
		if calls == 1 {
			return nil, cashu.BlindedMessageAlreadySigned
		}
		return origSwap(mintURL, req)
	}

	newProofs, opID, err := w.swapWithRetry(m.server.URL, firstReq, proofs, &mint, nut10SecretNone(t))
	if err != nil {
		t.Fatalf("swapWithRetry: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected exactly two attempts, got %d", calls)
	}

	pending := w.db.GetPendingSwaps()
	if len(pending) != 1 {
		t.Fatalf("after a retried swap exactly ONE intent (the retry's) may remain, have %d", len(pending))
	}
	if pending[0].OpID != opID {
		t.Fatalf("the remaining intent must be the retry's (%s), found %s", opID, pending[0].OpID)
	}

	// The caller's completion flow empties the set — no phantoms.
	if err := w.db.SaveProofs(newProofs); err != nil {
		t.Fatalf("SaveProofs: %v", err)
	}
	if err := w.db.DeletePendingSwap(opID); err != nil {
		t.Fatalf("DeletePendingSwap: %v", err)
	}
	if n := len(w.db.GetPendingSwaps()); n != 0 {
		t.Fatalf("a completed 10002-retried swap must leave ZERO intents, have %d", n)
	}
}

// Non-10002 errors keep the intent: the delete is scoped to the definitive
// refusal, never to ambiguity.
func TestNonRefusalErrorKeepsIntent(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	proofs := cashu.Proofs{{Id: m.keyset.Id, Amount: 8, Secret: "input-secret", C: "02ab"}}
	mint, ok := w.mints[m.server.URL]
	if !ok {
		t.Fatal("stub mint not registered")
	}
	req, err := w.createSwapRequest(proofs, &mint)
	if err != nil {
		t.Fatalf("createSwapRequest: %v", err)
	}

	origSwap := swap
	defer func() { swap = origSwap }()
	genericErr := errors.New("transport broke mid-flight")
	swap = func(string, swapRequestPayload) (cashu.Proofs, error) {
		return nil, genericErr
	}

	_, _, sErr := w.swapWithRetry(m.server.URL, req, proofs, &mint, nut10SecretNone(t))
	if !errors.Is(sErr, genericErr) {
		t.Fatalf("expected the generic error to surface, got %v", sErr)
	}
	if n := len(w.db.GetPendingSwaps()); n != 1 {
		t.Fatalf("an ambiguous outcome must keep its intent, have %d", n)
	}
}

func nut10SecretNone(t *testing.T) (s nut10.WellKnownSecret) {
	t.Helper()
	return s
}
