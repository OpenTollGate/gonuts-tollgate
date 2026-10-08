package wallet

import (
	"strings"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// verifyKeysetId's contract (the NUT-02 half of tollgate #705): a keyset ID
// must derive from the mint's published keys. The disclosure found no client
// enforcing it — a mint free to choose its ID is the first step of the
// NUT-13 residue-collision attack, and even an honestly-derived ID does not
// fix the residue flaw (the collision guard in wallet/storage does that
// half); this check refuses the casually-forged ID on every fetch path.

func verifyTestKeys(t *testing.T) crypto.PublicKeys {
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

func TestVerifyKeysetIdAcceptsHonestV1(t *testing.T) {
	keys := verifyTestKeys(t)
	id := crypto.DeriveKeysetId(keys)
	if err := verifyKeysetId(id, keys, "sat", 0); err != nil {
		t.Fatalf("an honestly derived V1 ID must be accepted: %v", err)
	}
}

func TestVerifyKeysetIdRejectsForgedV1(t *testing.T) {
	keys := verifyTestKeys(t)
	id := crypto.DeriveKeysetId(keys)
	forged := id[:15] + "f"
	if forged == id {
		t.Fatal("fixture must actually differ from the derived ID")
	}
	err := verifyKeysetId(forged, keys, "sat", 0)
	if err == nil {
		t.Fatal("an ID the keys do not derive to must be refused")
	}
	if !strings.Contains(err.Error(), forged) {
		t.Errorf("the refusal must name the advertised ID, got: %v", err)
	}
}

func TestVerifyKeysetIdAcceptsHonestV2(t *testing.T) {
	keys := verifyTestKeys(t)
	id := crypto.DeriveKeysetIdV2(keys, "sat", 100)
	if !crypto.IsKeysetIdV2(id) {
		t.Fatalf("fixture must be a V2 ID, got %q", id)
	}
	if err := verifyKeysetId(id, keys, "sat", 100); err != nil {
		t.Fatalf("an honestly derived V2 ID must be accepted: %v", err)
	}
}

func TestVerifyKeysetIdRejectsV2WithDifferentFee(t *testing.T) {
	keys := verifyTestKeys(t)
	id := crypto.DeriveKeysetIdV2(keys, "sat", 100)
	// The mint advertises the ID, but the fee metadata it reports no longer
	// derives it: same keys, different fee — a mismatched pair, refused.
	if err := verifyKeysetId(id, keys, "sat", 200); err == nil {
		t.Fatal("a V2 ID must be refused when the reported unit/fee does not derive it")
	}
}
