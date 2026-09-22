package wallet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
)

// TestAddMintRewriteNeverRewindsCounter is the #496 writer-audit pin for
// the riskiest keyset writer: AddMint re-registration re-fetches keysets
// from the mint and saves them as fresh records (Counter 0). Whatever the
// reason for the re-registration (restart, alias miss, manual call), the
// persisted derivation counter of an existing keyset must survive — the
// monotonic guard in SaveKeyset is what stands between this writer and a
// replay of already-exposed swap outputs (tollgate #480/#496).
func TestAddMintRewriteNeverRewindsCounter(t *testing.T) {
	const genKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	keysJSON := `{"keysets":[{"id":"` + v2FullID + `","unit":"sat","active":true,"input_fee_ppk":0,"keys":{`
	for i := 0; i <= 20; i++ {
		if i > 0 {
			keysJSON += ","
		}
		keysJSON += fmt.Sprintf(`"%d":"%s"`, 1<<i, genKey)
	}
	keysJSON += `}}]}`
	inactiveJSON := `{"keysets":[]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/keys":
			fmt.Fprint(w, keysJSON)
		case "/v1/keysets":
			fmt.Fprint(w, `{"keysets":[{"id":"`+v2FullID+`","unit":"sat","active":true,"input_fee_ppk":0}]}`)
		case "/v1/keysets/swaps":
			fmt.Fprint(w, inactiveJSON)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()

	w1, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: srv.URL})
	if err != nil {
		t.Fatalf("LoadWallet #1: %v", err)
	}
	if err := w1.db.IncrementKeysetCounter(v2FullID, 4242); err != nil {
		t.Fatalf("advance counter: %v", err)
	}
	w1.Shutdown()

	db, err := storage.InitBolt(dir)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	fresh := &crypto.WalletKeyset{
		Id: v2FullID, MintURL: srv.URL, Unit: "sat", Active: true, Counter: 0,
	}
	if err := db.SaveKeyset(fresh); err != nil {
		t.Fatalf("SaveKeyset fresh: %v", err)
	}
	db.Close()

	w2, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: srv.URL})
	if err != nil {
		t.Fatalf("LoadWallet #2: %v", err)
	}
	defer w2.Shutdown()

	if got := w2.counterForKeyset(v2FullID); got != 4242 {
		t.Fatalf("keyset rewrite rewound the derivation counter: got %d, want 4242", got)
	}
}
