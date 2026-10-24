package wallet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The tollgate #818 contract: a wallet whose DB caches keysets the mint has
// since retired (rotated out and dropped from the mint's keyset list) must
// still initialize against that same reachable mint — the retired records
// are skipped in memory while their DB records, derivation counters and any
// remaining proofs are retained untouched, and the mint's current keyset
// set (NUT-02) is fetched and registered. Before this fix, GetKeysetKeys'
// "Unknown Keyset" refusal was fatal to LoadWallet and bricked the wallet
// into degraded mode until an operator moved wallet.db aside.

func selfhealTestKeys(t *testing.T) crypto.PublicKeys {
	t.Helper()
	keys := make(crypto.PublicKeys, 4)
	for i := uint64(1); i <= 8; i *= 2 {
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		keys[i] = priv.PubKey()
	}
	return keys
}

// rotatingMint serves the #818 shape: the current keyset set no longer
// contains staleID at all, and the by-id endpoint answers NUT-19 12001.
func rotatingMint(t *testing.T, keys crypto.PublicKeys, activeID, staleID string) *httptest.Server {
	t.Helper()
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("marshal keys: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/keysets":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"keysets":[{"id":%q,"unit":"sat","active":true,"input_fee_ppk":0}]}`, activeID)
		case r.URL.Path == "/v1/keys":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"keysets":[{"id":%q,"unit":"sat","active":true,"input_fee_ppk":0,"keys":%s}]}`, activeID, keysJSON)
		case r.URL.Path == "/v1/keys/"+staleID:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"detail":"Unknown Keyset","code":12001}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestLoadWalletSelfHealsRetiredKeysets(t *testing.T) {
	keys := selfhealTestKeys(t)
	activeID := crypto.DeriveKeysetId(keys)
	staleID := crypto.DeriveKeysetId(selfhealTestKeys(t)) // honestly formed, mint no longer lists it
	srv := rotatingMint(t, keys, activeID, staleID)

	dir := t.TempDir()
	os.MkdirAll(dir, 0o700)
	db, err := InitStorage(dir)
	if err != nil {
		t.Fatalf("seed InitStorage: %v", err)
	}
	// A pre-rotation wallet: the stale keyset is the active one, its keys
	// were never cached in the record (inactive-keyset records are stored
	// without keys), it owns a nonzero derivation counter and a proof.
	stale := crypto.WalletKeyset{Id: staleID, MintURL: srv.URL, Unit: "sat", Active: true}
	if err := db.SaveKeyset(&stale); err != nil {
		t.Fatalf("seed SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter(staleID, 5); err != nil {
		t.Fatalf("seed counter: %v", err)
	}
	proofs := cashu.Proofs{{Amount: 4, Secret: "selfheal-stale-proof", C: "02" + staleID[:16], Id: staleID}}
	if err := db.SaveProofs(proofs); err != nil {
		t.Fatalf("seed SaveProofs: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: srv.URL})
	if err != nil {
		t.Fatalf("LoadWallet must self-heal past the retired keyset (tollgate #818), got: %v", err)
	}
	t.Cleanup(func() { _ = w.Shutdown() })

	// The mint's current keyset set was re-fetched and registered.
	mint, ok := w.mints[srv.URL]
	if !ok {
		t.Fatal("current mint not in wallet after self-heal")
	}
	if mint.activeKeyset.Id != activeID {
		t.Fatalf("active keyset not refreshed from the mint: want %s got %s", activeID, mint.activeKeyset.Id)
	}

	// Fund safety: the retired record was retained, not overwritten or
	// dropped — counter stays monotonic (#480), proofs stay in the wallet.
	if got := w.db.GetKeysetCounter(staleID); got != 5 {
		t.Fatalf("retired keyset counter must be preserved: want 5 got %d", got)
	}
	if got := len(w.db.GetProofsByKeysetId(staleID)); got != 1 {
		t.Fatalf("proof of the retired keyset must survive self-heal: want 1 got %d", got)
	}
	if got := w.db.GetKeyset(staleID); got == nil {
		t.Fatal("retired keyset record must remain in the DB")
	}
}

// The classification the tollgate init hook depends on: the typed NUT-19
// refusal (value and pointer forms), through fmt.Errorf wraps, from mints
// that spell the detail differently — and nothing else.
func TestIsUnknownKeysetError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"typed value", cashu.UnknownKeysetErr, true},
		{"typed pointer", &cashu.UnknownKeysetErr, true},
		{"wrapped", fmt.Errorf("error getting keyset from mint: %w", cashu.Error{Detail: "Unknown Keyset", Code: 12001}), true},
		{"detail without code", cashu.Error{Detail: "unknown keyset"}, true},
		{"message text only", fmt.Errorf("mint said: Unknown Keyset"), true},
		{"network error", fmt.Errorf("dial tcp 1.2.3.4:443: connection refused"), false},
		{"other mint error", cashu.StandardErr, false},
		{"other wrap", fmt.Errorf("error getting keyset from mint: %w", cashu.PaymentMethodNotSupportedErr), false},
	}
	for _, tc := range cases {
		if got := IsUnknownKeysetError(tc.err); got != tc.want {
			t.Errorf("%s: IsUnknownKeysetError=%v want %v", tc.name, got, tc.want)
		}
	}
}

// The DB a previous session leaves behind must not wedge the NEXT session
// either: heal once, close, heal again (the skip is idempotent across
// restarts — the retired record is still there and still skipped).
func TestLoadWalletSelfHealIsIdempotentAcrossRestart(t *testing.T) {
	keys := selfhealTestKeys(t)
	activeID := crypto.DeriveKeysetId(keys)
	staleID := crypto.DeriveKeysetId(selfhealTestKeys(t))
	srv := rotatingMint(t, keys, activeID, staleID)

	dir := t.TempDir()
	os.MkdirAll(dir, 0o700)
	db, err := InitStorage(dir)
	if err != nil {
		t.Fatalf("seed InitStorage: %v", err)
	}
	stale := crypto.WalletKeyset{Id: staleID, MintURL: srv.URL, Unit: "sat", Active: true}
	if err := db.SaveKeyset(&stale); err != nil {
		t.Fatalf("seed SaveKeyset: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	for i := 0; i < 2; i++ {
		w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: srv.URL})
		if err != nil {
			t.Fatalf("restart %d: LoadWallet must self-heal: %v", i, err)
		}
		if got := w.mints[srv.URL].activeKeyset.Id; got != activeID {
			t.Fatalf("restart %d: active keyset not refreshed: want %s got %s", i, activeID, got)
		}
		if err := w.Shutdown(); err != nil {
			t.Fatalf("restart %d: shutdown: %v", i, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "wallet.db")); err != nil {
		t.Fatalf("wallet.db must survive: %v", err)
	}
}
