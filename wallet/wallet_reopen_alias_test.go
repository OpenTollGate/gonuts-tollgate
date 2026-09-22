package wallet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
)

// TestReopenWithAliasSeededDB_NoOutputReplay is the #480 scenario end to end
// at the wallet layer: outputs derived pre-restart, the restart wipes the
// alias bucket's counter (the observed field failure), and the wallet is
// reopened. Without the alias merge the next derivation replays the
// pre-restart blinded messages ("Duplicate outputs" at the mint); with it,
// the maximum counter survives and derivation is disjoint.
func TestReopenWithAliasSeededDB_NoOutputReplay(t *testing.T) {
	const genKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	keysJSON := `{"keysets":[{"id":"` + v2FullID + `","unit":"sat","active":true,"input_fee_ppk":0,"keys":{`
	for i := 0; i <= 20; i++ {
		if i > 0 {
			keysJSON += ","
		}
		keysJSON += fmt.Sprintf(`"%d":"%s"`, 1<<i, genKey)
	}
	keysJSON += `}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, keysJSON)
	}))
	defer srv.Close()

	dir := t.TempDir()

	load := func() *Wallet {
		w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: srv.URL})
		if err != nil {
			t.Fatalf("LoadWallet: %v", err)
		}
		return w
	}
	proofsFor := func(n uint64) cashu.Proofs {
		return cashu.Proofs{{Id: v2FullID, Amount: n, Secret: fmt.Sprintf("s%d", n), C: "02ab"}}
	}

	// Phase 1: pre-restart wallet, derive a swap's outputs.
	w1 := load()
	m1, ok := w1.mints[srv.URL]
	if !ok {
		t.Fatalf("mint not in map")
	}
	req1, err := w1.createSwapRequest(proofsFor(64), &m1)
	if err != nil {
		t.Fatalf("derive #1: %v", err)
	}
	seen := map[string]bool{}
	for _, bm := range req1.outputs {
		seen[bm.B_] = true
	}
	if err := w1.db.IncrementKeysetCounter(v2FullID, uint32(len(req1.outputs))); err != nil {
		t.Fatalf("increment: %v", err)
	}
	w1.db.Close()

	// Phase 2: simulate the restart's alias wipe — the same keyset re-saved
	// fresh (Counter 0) under the trailing-slash alias bucket, exactly as the
	// forensics captured.
	dbRaw, err := storage.InitBolt(dir)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	alias := srv.URL + "/"
	if err := dbRaw.SaveKeysetRawForTests(alias, &crypto.WalletKeyset{
		Id: v2FullID, MintURL: alias, Unit: "sat", Active: true, Counter: 0,
	}); err != nil {
		t.Fatalf("alias wipe: %v", err)
	}
	dbRaw.Close()

	// Phase 3: reopen — the alias merge must keep the max counter, and the
	// next derivation must produce zero overlap with phase 1.
	w2 := load()
	defer w2.Shutdown()
	m2, ok := w2.mints[srv.URL]
	if !ok {
		t.Fatalf("mint not in map after reopen")
	}
	req2, err := w2.createSwapRequest(proofsFor(65), &m2)
	if err != nil {
		t.Fatalf("derive #2: %v", err)
	}
	overlap := 0
	for _, bm := range req2.outputs {
		if seen[bm.B_] {
			overlap++
		}
	}
	if overlap != 0 {
		t.Fatalf("#480 regression: %d/%d post-restart outputs replay pre-restart blinded messages", overlap, len(req2.outputs))
	}
}
