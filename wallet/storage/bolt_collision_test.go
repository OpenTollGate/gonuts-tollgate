package storage

import (
	"errors"
	"strings"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut13"
)

// The NUT-13 residue-collision guard at its choke point: SaveKeyset. The
// Conduition cashu disclosure's short-term fix — a wallet must refuse keysets
// whose 2^31-1 derivation residues collide — existed in nut13 as
// CheckCollidingKeysets but was never invoked (tollgate #705). These tests
// pin the wired contract: cross-mint collisions refused with both mints and
// both IDs named, same-mint rotation to a colliding ID refused, exact
// cross-mint duplicates refused, unrelated multi-mint registration untouched,
// a keyset's own re-saves exempt, and a refusal leaving no partial state.

// The colliding pair, constructed rather than inherited: the second ID is
// the first plus exactly (2^31 - 1), so their keysetIdToBigInt residues are
// equal by construction (nut13's own fixture pair was only conditionally
// asserted and does not actually collide).
const (
	collisionHonestID   = "009a1f293253e41e"
	collisionAttackerID = "009a1f29b253e41d"
	collisionOtherID    = "0039ff30789bc776"
)

func TestSaveKeysetRefusesResidueCollisionAcrossMints(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("https://honest.example", collisionHonestID, 5)); err != nil {
		t.Fatalf("seed honest keyset: %v", err)
	}

	err := db.SaveKeyset(keysetFor("https://attacker.example", collisionAttackerID, 0))
	if err == nil {
		t.Fatal("a keyset whose NUT-13 residue collides with a registered keyset of another mint must be refused")
	}
	if !errors.Is(err, nut13.ErrCollidingKeysetId) {
		t.Fatalf("the refusal must carry nut13.ErrCollidingKeysetId for callers to match on, got: %v", err)
	}
	for _, want := range []string{"https://attacker.example", collisionAttackerID, "https://honest.example", collisionHonestID} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q so an operator can act on it, got: %v", want, err)
		}
	}
}

func TestSaveKeysetRefusesExactDuplicateAcrossMints(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("https://a.example", collisionHonestID, 0)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := db.SaveKeyset(keysetFor("https://b.example", collisionHonestID, 0)); err == nil {
		t.Fatal("the same keyset ID registered at a second mint is the residue attack with k=0 and must be refused")
	}
}

func TestSaveKeysetRefusesSameMintRotationToCollidingId(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("https://mint.example", collisionHonestID, 5)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The disclosure's rotation shape: the same (attacker) mint rotates its
	// keyset onto an ID whose residue collides with a keyset already
	// registered — here the mint's own honest one, as when an attacker's ID
	// targets the inactive keyset of the honest mint it impersonates.
	err := db.SaveKeyset(keysetFor("https://mint.example", collisionAttackerID, 0))
	if err == nil {
		t.Fatal("rotation onto a residue-colliding ID must be refused, not only fresh cross-mint registration")
	}
	if !errors.Is(err, nut13.ErrCollidingKeysetId) {
		t.Fatalf("rotation refusal must carry nut13.ErrCollidingKeysetId, got: %v", err)
	}
}

func TestSaveKeysetAllowsUnrelatedMultiMintRegistration(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("https://a.example", collisionHonestID, 0)); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	if err := db.SaveKeyset(keysetFor("https://b.example", collisionOtherID, 0)); err != nil {
		t.Fatalf("a non-colliding keyset of a second mint must register: %v", err)
	}
	if got := len(db.mintBucketNames()); got != 2 {
		t.Fatalf("both mints must be registered, got %d bucket(s): %v", got, db.mintBucketNames())
	}
}

func TestSaveKeysetCollisionRefusalLeavesNoPartialState(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("https://honest.example", collisionHonestID, 5)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := db.SaveKeyset(keysetFor("https://attacker.example", collisionAttackerID, 7)); err == nil {
		t.Fatal("expected refusal")
	}

	// No row for the refused keyset, anywhere.
	if ks := db.GetKeyset(collisionAttackerID); ks != nil {
		t.Fatalf("a refused registration must leave no keyset record, got %+v", ks)
	}
	// No bucket for the refused mint: the guard runs before the transaction
	// creates anything, so a later honest save of that mint starts clean.
	for _, name := range db.mintBucketNames() {
		if strings.Contains(name, "attacker.example") {
			t.Fatalf("a refused registration must leave no mint bucket, found %q", name)
		}
	}
	// And the honest mint's counter state is untouched.
	if got := db.GetKeysetCounter(collisionHonestID); got != 5 {
		t.Fatalf("a refused registration must not touch other keysets' counters, got %d", got)
	}
}

func TestSaveKeysetResaveOfOwnRecordIsNotACollision(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("https://mint.example", collisionHonestID, 5)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Rotation-in-place, fee updates, counter merges and the startup loader
	// all re-save a keyset's own record; none of those may trip the guard.
	resave := keysetFor("https://mint.example", collisionHonestID, 5)
	resave.Active = false
	if err := db.SaveKeyset(resave); err != nil {
		t.Fatalf("re-saving a keyset's own record must not be a collision: %v", err)
	}
	resave.Counter = 9
	if err := db.SaveKeyset(resave); err != nil {
		t.Fatalf("counter advance on a keyset's own record must not be a collision: %v", err)
	}

	// A legacy alias bucket of the SAME mint holding the same ID (the
	// pre-canonicalization spelling) is the same keyset, not an attack.
	alias := keysetFor("https://mint.example/", collisionHonestID, 9)
	if err := db.SaveKeysetRawForTests("https://mint.example/", alias); err != nil {
		t.Fatalf("seed alias: %v", err)
	}
	if err := db.SaveKeyset(keysetFor("https://mint.example", collisionHonestID, 9)); err != nil {
		t.Fatalf("a same-mint alias row of the same keyset must be exempt from the collision guard: %v", err)
	}
}
