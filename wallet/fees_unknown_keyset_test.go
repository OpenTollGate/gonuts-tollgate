package wallet

// #832 (tollgate-module-basic-go): a proof on a keyset the wallet cannot
// price must refuse the swap, never silently cost 0 ppk — the zero
// understates the fee, the below-fee refusal never fires, and the swap
// consumes the whole note.

import (
	"strings"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
)

func TestFeesForProofsUnknownKeysetRefused(t *testing.T) {
	active := newSigningMint(t).keyset
	active.Id = "00active"
	inactive := active
	inactive.Id = "00inactive"

	mint := &walletMint{
		mintURL:         "http://stub",
		activeKeyset:    active,
		inactiveKeysets: map[string]crypto.WalletKeyset{"00inactive": inactive},
	}

	known := cashu.Proofs{
		{Id: "00active", Amount: 64},
		{Id: "00inactive", Amount: 32},
	}
	if _, err := feesForProofs(known, mint); err != nil {
		t.Fatalf("known keysets must still price: %v", err)
	}

	_, err := feesForProofs(cashu.Proofs{{Id: "00never-listed", Amount: 64}}, mint)
	if err == nil {
		t.Fatal("unknown-keyset proof priced without an error — the silent zero is back")
	}
	if !strings.Contains(err.Error(), "00never-listed") {
		t.Fatalf("refusal must name the unpriceable keyset, got: %v", err)
	}
}
