package wallet

import (
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
)

// seededWalletForTest builds a wallet over a temp bolt DB that already
// holds a mint's keysets (with public keys, so LoadWallet populates the
// in-memory mint cache without any network traffic).
func seededWalletForTest(t *testing.T, mintURL string, active *crypto.WalletKeyset, inactive ...*crypto.WalletKeyset) *Wallet {
	t.Helper()
	dir := t.TempDir()
	db, err := InitStorage(dir)
	if err != nil {
		t.Fatalf("InitStorage: %v", err)
	}
	for _, ks := range append([]*crypto.WalletKeyset{active}, inactive...) {
		if err := db.SaveKeyset(ks); err != nil {
			t.Fatalf("SaveKeyset: %v", err)
		}
	}
	db.Close()

	w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: mintURL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	t.Cleanup(func() { w.Shutdown() })
	return w
}

func keysetWithFee(id, mintURL string, ppk uint, keys crypto.PublicKeys) *crypto.WalletKeyset {
	return &crypto.WalletKeyset{Id: id, MintURL: mintURL, Unit: "sat", Active: true, InputFeePpk: ppk, PublicKeys: keys}
}

// The fee map must be servable purely from the cached keysets — no
// network — for both the active and the inactive (rotated) keysets.
func TestKeysetFeesForMintServesCacheWithoutNetwork(t *testing.T) {
	mintURL := "http://127.0.0.1:1" // nothing listens; any fetch would fail the test
	keys := crypto.PublicKeys{}
	for i := 0; i < 2; i++ {
		h := sha256.Sum256([]byte("fee-test-" + strconv.Itoa(i)))
		_, pub := btcec.PrivKeyFromBytes(h[:])
		keys[uint64(1)<<uint(i)] = pub
	}
	active := keysetWithFee("00aa", mintURL, 100, keys)
	active.Active = true
	inactive := keysetWithFee("00bb", mintURL, 0, keys)
	inactive.Active = false

	w := seededWalletForTest(t, mintURL, active, inactive)

	fees, err := w.KeysetFeesForMint(mintURL)
	if err != nil {
		t.Fatalf("KeysetFeesForMint: %v", err)
	}
	if len(fees) != 2 {
		t.Fatalf("expected 2 keysets, got %v", fees)
	}
	if fees["00aa"] != 100 {
		t.Fatalf("active fee = %d, want 100", fees["00aa"])
	}
	if fees["00bb"] != 0 {
		t.Fatalf("rotated fee = %d, want 0", fees["00bb"])
	}
}

// An unregistered mint must be an explicit error, not a silently empty
// map — the caller uses the miss to decide whether to fall back to a
// bounded network fetch.
func TestKeysetFeesForMintUnknownMintErrors(t *testing.T) {
	mintURL := "http://127.0.0.1:1"
	keys := crypto.PublicKeys{}
	h := sha256.Sum256([]byte("fee-test-single"))
	_, pub := btcec.PrivKeyFromBytes(h[:])
	keys[1] = pub
	w := seededWalletForTest(t, mintURL, keysetWithFee("00a", mintURL, 0, keys))

	if _, err := w.KeysetFeesForMint("http://elsewhere.example"); err == nil {
		t.Fatal("expected an error for an unregistered mint, got none")
	}
}
