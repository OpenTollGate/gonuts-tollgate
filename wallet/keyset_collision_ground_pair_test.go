package wallet

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut13"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The ground NUT-13 residue pair (PRTA tests/conformance/fixtures/
// nut13-collision-pair.json, ground by the offline grinder using this
// fork's own DeriveKeysetId): two DIFFERENT keyset IDs whose residues mod
// 2^31-1 both equal 1818255859. The honest one is what a wallet has
// registered; the adversarial one is what a colliding mint announces.
// Registration of the second must be refused with ErrCollidingKeysetId
// — the exact attack of the 2026-01 conduition disclosure, in its
// non-exact (ground) shape rather than the trivial duplicate.
const groundPair = `{
  "honest_id": "00a8cee9eb0ec420",
  "adversarial_id": "00fa37066a6bf3e7",
  "adversarial_keys": {
    "keys": "{\"1\":\"0399cd4b569bcfb6634c1acdda4f9eea2d031e8e3e087329ff9cd525a3d186fa03\",\"16\":\"03773befeb2de3fdcfa434074ef97bbf1659e29a3e50ce0f141f202b69f05aabc6\",\"2\":\"025b3500604f54c8ee5f6dfa8a76d569bf9cb8ef23850fcbac944c3b52e101e942\",\"32\":\"03d03934e7a4a24e6072d7bd939663110314c5de87fdb44d3f829f95e65f4b6490\",\"4\":\"03707a2d9e80529a99d0f9f3215000dc45e2d6fcfb09ed9d4f26dd24c1bc7f49b8\",\"64\":\"03bcf8fc610df8b766968a409e6c69089eaeb5c5bd5d1f8ae4396281fdcb15d475\",\"8\":\"0207a0bbe5a134e68797930a3f0c81facf1e26729c0c1939fe3250833099976bd1\"}"
  }
}`

func TestGroundResiduePairCollidesAndIsRefused(t *testing.T) {
	var pair struct {
		HonestID        string `json:"honest_id"`
		AdversarialID   string `json:"adversarial_id"`
		AdversarialKeys struct {
			Keys string `json:"keys"`
		} `json:"adversarial_keys"`
	}
	if err := json.Unmarshal([]byte(groundPair), &pair); err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	if err := json.Unmarshal([]byte(pair.AdversarialKeys.Keys), &doc); err != nil {
		t.Fatal(err)
	}
	pubs := crypto.PublicKeys{}
	for amt, khex := range doc {
		var amtU uint64
		if _, err := fmt.Sscanf(amt, "%d", &amtU); err != nil {
			t.Fatalf("amount %q: %v", amt, err)
		}
		b, err := hex.DecodeString(khex)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := secp256k1.ParsePubKey(b)
		if err != nil {
			t.Fatal(err)
		}
		pubs[amtU] = pk
	}

	// The adversarial keys DERIVE to the claimed ID — an honest verifier
	// passes, which is what makes the attack shape real.
	derived := crypto.DeriveKeysetId(pubs)
	if derived != pair.AdversarialID {
		t.Fatalf("derived %s != claimed %s (fixture rot?)", derived, pair.AdversarialID)
	}
	if derived == pair.HonestID {
		t.Fatal("this is the exact-duplicate shape, not the residue shape")
	}

	// The residue collision is what the quarantine keys on.
	if err := nut13.CheckCollidingKeysets([]string{pair.HonestID}, []string{pair.AdversarialID}); err == nil {
		t.Fatal("residues do not collide — fixture rot")
	}

	// The guard itself, at its own layer (the same construction the bolt
	// collision tests use): a registered honest keyset + the adversarial
	// registration attempt must refuse with ErrCollidingKeysetId.
	db, err := InitStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	honest := crypto.WalletKeyset{Id: pair.HonestID, MintURL: "http://honest.example/", Unit: "sat", Active: true}
	if err := db.SaveKeyset(&honest); err != nil {
		t.Fatal(err)
	}
	adv := crypto.WalletKeyset{Id: pair.AdversarialID, MintURL: "http://adversarial.example/", Unit: "sat", Active: true}
	err = db.SaveKeyset(&adv)
	if err == nil {
		t.Fatal("the ground residue pair was ACCEPTED — the NUT-13 quarantine is unwired")
	}
	if !errors.Is(err, nut13.ErrCollidingKeysetId) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
