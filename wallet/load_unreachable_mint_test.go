package wallet

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
)

// eofMint accepts the connection and closes it without a response. This is
// what a mint process that is down / crashed / mid-restart looks like to the
// wallet, and it surfaces as io.EOF rather than connection-refused.
func eofMint(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("response writer does not support hijacking")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestLoadWalletSkipsUnreachableStoredMint is the regression test for the
// E750 incident: the wallet DB still holds a keyset (and a proof) for a mint
// that is currently unreachable with EOF. Wallet init must skip that keyset,
// keep its DB record and proof, and load the reachable current mint — instead
// of failing the whole wallet and putting the merchant in degraded mode.
func TestLoadWalletSkipsUnreachableStoredMint(t *testing.T) {
	// Healthy current mint.
	healthyKeys := selfhealTestKeys(t)
	healthyID := crypto.DeriveKeysetId(healthyKeys)
	healthy := rotatingMint(t, healthyKeys, healthyID, "0000000000000000")

	// Unreachable mint whose keyset/proof are still in the DB.
	dead := eofMint(t)
	deadKeys := selfhealTestKeys(t)
	deadID := crypto.DeriveKeysetId(deadKeys)

	dir := t.TempDir()
	db, err := InitStorage(dir)
	if err != nil {
		t.Fatalf("seed InitStorage: %v", err)
	}
	stale := crypto.WalletKeyset{Id: deadID, MintURL: dead.URL, Unit: "sat", Active: true}
	if err := db.SaveKeyset(&stale); err != nil {
		t.Fatalf("seed SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter(deadID, 3); err != nil {
		t.Fatalf("seed counter: %v", err)
	}
	proofs := cashu.Proofs{{Amount: 1, Secret: "offline-minibits-proof", C: "02" + deadID[:16], Id: deadID}}
	if err := db.SaveProofs(proofs); err != nil {
		t.Fatalf("seed SaveProofs: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: healthy.URL})
	if err != nil {
		t.Fatalf("LoadWallet must skip an EOF mint and keep its record, got: %v", err)
	}
	t.Cleanup(func() { _ = w.Shutdown() })

	// The reachable mint was loaded.
	if _, ok := w.mints[healthy.URL]; !ok {
		t.Fatal("healthy current mint was not loaded")
	}

	// Fund safety: the unreachable mint's keyset, counter and proof are intact.
	if got := w.db.GetKeyset(deadID); got == nil {
		t.Fatal("unreachable mint keyset record was lost")
	}
	if got := w.db.GetKeysetCounter(deadID); got != 3 {
		t.Fatalf("unreachable keyset counter must be preserved: want 3 got %d", got)
	}
	if got := len(w.db.GetProofsByKeysetId(deadID)); got != 1 {
		t.Fatalf("unreachable mint proof must survive: want 1 got %d", got)
	}
}
