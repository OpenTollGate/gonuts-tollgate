package wallet

import (
	"errors"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut13"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	wstorage "github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
)

// The wallet-level allocation refusal must carry
// nut13.ErrHardenedDomainExhausted up through its %w wrapper.
func TestWalletRefusalCarriesDomainSentinel(t *testing.T) {
	w := guardTestWallet(t)
	counter := walletHardenedDomainLimit
	_, _, _, err := w.createBlindedMessages([]uint64{1}, "01ab", &counter)
	if err == nil {
		t.Fatal("deriving at the exhausted marker must be refused")
	}
	if !errors.Is(err, nut13.ErrHardenedDomainExhausted) {
		t.Fatalf("wallet refusal must wrap nut13.ErrHardenedDomainExhausted, got: %v", err)
	}
}

// The swapWithIntent reservation refusal must surface the sentinel too.
func TestSwapWithIntentRefusalCarriesDomainSentinel(t *testing.T) {
	db, err := wstorage.InitBolt(t.TempDir())
	if err != nil {
		t.Fatalf("InitBolt: %v", err)
	}
	defer db.Close()
	if err := db.SaveKeyset(&crypto.WalletKeyset{Id: "01ab", MintURL: "http://127.0.0.1:1", Unit: "sat", Active: true, Counter: walletHardenedDomainLimit}); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	w := &Wallet{db: db}
	_, _, err = w.swapWithIntent("http://127.0.0.1:1", swapRequestPayload{
		keyset:       &crypto.WalletKeyset{Id: "01ab", Unit: "sat"},
		counterStart: walletHardenedDomainLimit,
		outputs:      make(cashu.BlindedMessages, 1),
	})
	if err == nil {
		t.Fatal("reserving from the exhausted marker must be refused")
	}
	if !errors.Is(err, nut13.ErrHardenedDomainExhausted) {
		t.Fatalf("swapWithIntent refusal must wrap nut13.ErrHardenedDomainExhausted, got: %v", err)
	}
}
