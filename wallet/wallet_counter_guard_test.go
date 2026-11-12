package wallet

import (
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	wstorage "github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

// Red-first behavioral matrix for the wallet-side checked allocation span.
//
// createBlindedMessages advances a local counter per deterministic output
// with no domain check; the guarded version must refuse the whole span
// BEFORE generating or exposing any output. These tests use the existing
// (unexported) wallet APIs and assert BEHAVIOR so they compile and fail
// against the unguarded base.

const walletHardenedDomainLimit = uint32(1) << 31

func guardTestWallet(t *testing.T) *Wallet {
	t.Helper()
	mnemonic := "half depart obvious quality work element tank gorilla view sugar picture humble"
	seed := bip39.NewSeed(mnemonic, "")
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewMaster: %v", err)
	}
	return &Wallet{masterKey: master}
}

// Last valid hardened index: a single output derived at 2^31-1 must keep
// working and advance the local counter onto the exhausted marker.
func TestCreateBlindedMessagesLastValidIndex(t *testing.T) {
	w := guardTestWallet(t)
	counter := walletHardenedDomainLimit - 1
	msgs, secrets, rs, err := w.createBlindedMessages([]uint64{1}, "01ab", &counter)
	if err != nil {
		t.Fatalf("single output at the last hardened index must stay valid: %v", err)
	}
	if len(msgs) != 1 || len(secrets) != 1 || len(rs) != 1 {
		t.Fatalf("expected 1 output, got %d/%d/%d", len(msgs), len(secrets), len(rs))
	}
	if counter != walletHardenedDomainLimit {
		t.Fatalf("local counter after last-index output = %d, want the exhausted marker %d", counter, walletHardenedDomainLimit)
	}
}

// First invalid index: deriving at the one-past-end marker must be refused.
func TestCreateBlindedMessagesFirstInvalidIndex(t *testing.T) {
	w := guardTestWallet(t)
	counter := walletHardenedDomainLimit
	if _, _, _, err := w.createBlindedMessages([]uint64{1}, "01ab", &counter); err == nil {
		t.Fatal("deriving at the exhausted marker must be refused: the hardened index wraps out of the hardened domain")
	}
	if counter != walletHardenedDomainLimit {
		t.Fatalf("refused derivation must not advance the counter, got %d", counter)
	}
}

// Multi-output span crossing the limit must be refused BEFORE any output
// is generated — no partial derivation, no counter movement.
func TestCreateBlindedMessagesMultiOutputCrossingRefused(t *testing.T) {
	w := guardTestWallet(t)
	counter := walletHardenedDomainLimit - 1
	msgs, _, _, err := w.createBlindedMessages([]uint64{1, 1, 1}, "01ab", &counter)
	if err == nil {
		t.Fatal("a 3-output span crossing the hardened domain limit must be refused before generation")
	}
	if len(msgs) != 0 {
		t.Fatalf("refused span must expose no outputs, got %d", len(msgs))
	}
	if counter != walletHardenedDomainLimit-1 {
		t.Fatalf("refused span must not advance the counter, got %d", counter)
	}
}

// Zero-length allocation with a non-nil counter is existing zero-output
// behavior (empty NUT-08 blank-output melts): no derivation, no counter
// movement, no error.
func TestCreateBlindedMessagesZeroLengthSemantics(t *testing.T) {
	w := guardTestWallet(t)
	counter := walletHardenedDomainLimit - 1 // even at the last valid index
	msgs, secrets, rs, err := w.createBlindedMessages([]uint64{}, "01ab", &counter)
	if err != nil {
		t.Fatalf("zero-length allocation must keep working: %v", err)
	}
	if len(msgs) != 0 || len(secrets) != 0 || len(rs) != 0 {
		t.Fatalf("zero-length allocation must produce no outputs, got %d/%d/%d", len(msgs), len(secrets), len(rs))
	}
	if counter != walletHardenedDomainLimit-1 {
		t.Fatalf("zero-length allocation must not move the counter, got %d", counter)
	}
}

// Nil counter keeps the random (non-deterministic) path: unaffected.
func TestCreateBlindedMessagesNilCounterStillRandom(t *testing.T) {
	w := guardTestWallet(t)
	msgs, secrets, rs, err := w.createBlindedMessages([]uint64{1, 1}, "01ab", nil)
	if err != nil {
		t.Fatalf("nil-counter random path must keep working: %v", err)
	}
	if len(msgs) != 2 || len(secrets) != 2 || len(rs) != 2 {
		t.Fatalf("expected 2 random outputs, got %d/%d/%d", len(msgs), len(secrets), len(rs))
	}
}

// A reservation refused inside the storage transaction must abort the
// swap BEFORE any network/provider call and leave no partial intent.
func TestSwapWithIntentRefusedBeforeNetworkCall(t *testing.T) {
	dir := t.TempDir()
	db, err := wstorage.InitBolt(dir)
	if err != nil {
		t.Fatalf("InitBolt: %v", err)
	}
	defer db.Close()
	if err := db.SaveKeyset(&crypto.WalletKeyset{Id: "01ab", MintURL: "http://127.0.0.1:1", Unit: "sat", Active: true, Counter: walletHardenedDomainLimit - 1}); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	w := &Wallet{db: db}

	swapCalls := 0
	origSwap := swap
	swap = func(mint string, req swapRequestPayload) (cashu.Proofs, error) {
		swapCalls++
		return nil, nil
	}
	defer func() { swap = origSwap }()

	req := swapRequestPayload{
		keyset:       &crypto.WalletKeyset{Id: "01ab", Unit: "sat"},
		counterStart: walletHardenedDomainLimit - 1,
		outputs:      make(cashu.BlindedMessages, 2),
	}
	_, _, err = w.swapWithIntent("http://127.0.0.1:1", req)
	if err == nil {
		t.Fatal("the refused reservation must surface an error")
	}

	if swapCalls != 0 {
		t.Fatalf("no swap/network call may happen after a refused reservation, got %d calls", swapCalls)
	}
	if len(db.GetPendingSwaps()) != 0 {
		t.Fatalf("refused reservation must leave no intent, pending swaps = %d", len(db.GetPendingSwaps()))
	}
	if got := db.GetKeysetCounter("01ab"); got != walletHardenedDomainLimit-1 {
		t.Fatalf("refused reservation must leave the counter unchanged, got %d", got)
	}
}
