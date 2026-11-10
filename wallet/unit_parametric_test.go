package wallet

import (
	"crypto/sha256"
	"strconv"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/btcsuite/btcd/btcec/v2"
)

// keysetPubKeyForTest returns a well-formed public key so a keyset looks
// populated to LoadWallet's cache without any network traffic.
func keysetPubKeyForTest(t *testing.T) *btcec.PublicKey {
	t.Helper()
	h := sha256.Sum256([]byte("unit-parametric-test"))
	_, pub := btcec.PrivKeyFromBytes(h[:])
	return pub
}

// A wallet's unit is not decoration: it selects which keyset the wallet
// operates on at a mint that issues more than one. TollGate's operator mints
// issue custom units (a community mint issuing `mb` for metered access), and a
// wallet that assumes sat can neither see nor spend those keysets — the
// failure surfaces as "could not find an active keyset for the unit", far from
// the assumption that caused it.
func TestLoadWalletHonoursConfiguredUnit(t *testing.T) {
	dir := t.TempDir()
	mintURL := "http://127.0.0.1:1"

	db, err := InitStorage(dir)
	if err != nil {
		t.Fatalf("InitStorage: %v", err)
	}
	ks := &crypto.WalletKeyset{
		Id:         "00bb22",
		MintURL:    mintURL,
		Unit:       "mb",
		Active:     true,
		PublicKeys: crypto.PublicKeys{1: keysetPubKeyForTest(t)},
	}
	if err := db.SaveKeyset(ks); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	db.Close()

	w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: mintURL, Unit: "mb"})
	if err != nil {
		t.Fatalf("LoadWallet with Unit \"mb\": %v", err)
	}
	defer w.Shutdown()

	if got := w.Unit(); got != "mb" {
		t.Fatalf("wallet unit = %q, want %q", got, "mb")
	}
	if got := w.Unit(); got == cashu.Sat.String() {
		t.Fatalf("wallet unit fell back to %q despite Unit being configured", got)
	}
}

// An empty unit keeps the long-standing behaviour: sat. Every config written
// before custom units existed carries no unit field, and those wallets must
// keep working unchanged.
func TestLoadWalletDefaultsToSat(t *testing.T) {
	dir := t.TempDir()
	mintURL := "http://127.0.0.1:1"

	db, err := InitStorage(dir)
	if err != nil {
		t.Fatalf("InitStorage: %v", err)
	}
	ks := &crypto.WalletKeyset{
		Id:         "00aa11",
		MintURL:    mintURL,
		Unit:       "sat",
		Active:     true,
		PublicKeys: crypto.PublicKeys{1: keysetPubKeyForTest(t)},
	}
	if err := db.SaveKeyset(ks); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	db.Close()

	w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: mintURL})
	if err != nil {
		t.Fatalf("LoadWallet with no Unit: %v", err)
	}
	defer w.Shutdown()

	if got := w.Unit(); got != cashu.Sat.String() {
		t.Fatalf("wallet unit = %q, want %q (default)", got, cashu.Sat.String())
	}
}

// A balance is a number WITH a unit. Summing proofs across units reports a
// number that is not money: 10 sats plus 64 mb is not 74 of anything, and an
// operator reading that total would spend against funds that do not exist.
// GetBalance must count only the wallet's own unit.
func TestBalanceIsScopedToTheWalletsUnit(t *testing.T) {
	dir := t.TempDir()
	mintURL := "http://127.0.0.1:1"

	db, err := InitStorage(dir)
	if err != nil {
		t.Fatalf("InitStorage: %v", err)
	}
	for _, ks := range []*crypto.WalletKeyset{
		{Id: "00aa11", MintURL: mintURL, Unit: "sat", Active: true, PublicKeys: crypto.PublicKeys{1: keysetPubKeyForTest(t)}},
		{Id: "00bb22", MintURL: mintURL, Unit: "mb", Active: true, PublicKeys: crypto.PublicKeys{1: keysetPubKeyForTest(t)}},
	} {
		if err := db.SaveKeyset(ks); err != nil {
			t.Fatalf("SaveKeyset(%s): %v", ks.Id, err)
		}
	}

	// 5+5 sats and 32+32 mb: summing them would report 74.
	if err := db.SaveProofs(append(mkProofs("00aa11", 5, 5), mkProofs("00bb22", 32, 32)...)); err != nil {
		t.Fatalf("SaveProofs: %v", err)
	}
	db.Close()

	satWallet, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: mintURL, Unit: "sat"})
	if err != nil {
		t.Fatalf("LoadWallet(sat): %v", err)
	}
	if got, want := satWallet.GetBalance(), uint64(10); got != want {
		t.Errorf("sat wallet balance = %d, want %d (must not count mb proofs)", got, want)
	}
	satWallet.Shutdown()

	mbWallet, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: mintURL, Unit: "mb"})
	if err != nil {
		t.Fatalf("LoadWallet(mb): %v", err)
	}
	if got, want := mbWallet.GetBalance(), uint64(64); got != want {
		t.Errorf("mb wallet balance = %d, want %d (must not count sat proofs)", got, want)
	}
	mbWallet.Shutdown()
}

// mkProofs builds proofs with distinct secrets, which the bolt store keys on.
func mkProofs(keysetID string, amounts ...uint64) cashu.Proofs {
	proofs := make(cashu.Proofs, 0, len(amounts))
	for i, amt := range amounts {
		proofs = append(proofs, cashu.Proof{
			Amount: amt,
			Id:     keysetID,
			Secret: "secret-" + keysetID + "-" + strconv.Itoa(i),
			C:      "02" + strconv.FormatUint(uint64(i+1), 16),
		})
	}
	return proofs
}
