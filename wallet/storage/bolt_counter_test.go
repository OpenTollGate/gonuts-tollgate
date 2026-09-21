package storage

import (
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/crypto"
)

func newCounterTestDB(t *testing.T) *BoltDB {
	t.Helper()
	db, err := InitBolt(t.TempDir())
	if err != nil {
		t.Fatalf("InitBolt: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func keysetFor(id, mintURL string, counter uint32) *crypto.WalletKeyset {
	return &crypto.WalletKeyset{Id: id, MintURL: mintURL, Unit: "sat", Active: true, Counter: counter}
}

// The same keyset id can be stored under two spellings of the mint URL
// (the wallet registers the configured spelling; mint responses and boot
// re-saves use the mint's own spelling). Regression shape of the
// "Duplicate outputs after restart" bug: a freshly fetched keyset saved
// with Counter 0 must not rewind a copy that already advanced.
func TestKeysetCounterNotRewoundByFreshSave(t *testing.T) {
	db := newCounterTestDB(t)
	id := "01abc"

	if err := db.SaveKeyset(keysetFor(id, "http://mint.example", 0)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter(id, 14); err != nil {
		t.Fatalf("IncrementKeysetCounter: %v", err)
	}

	// Boot re-save path: same id, the mint's URL spelling, fresh Counter 0.
	if err := db.SaveKeyset(keysetFor(id, "http://mint.example/", 0)); err != nil {
		t.Fatalf("SaveKeyset (second spelling): %v", err)
	}

	if got := db.GetKeysetCounter(id); got != 14 {
		t.Fatalf("counter rewound by fresh save: got %d, want 14", got)
	}
}

// Reads take the maximum across copies, never an order-dependent one.
func TestGetKeysetCounterTakesMaxAcrossURLBuckets(t *testing.T) {
	db := newCounterTestDB(t)
	id := "01def"

	if err := db.SaveKeyset(keysetFor(id, "http://a.example", 3)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.SaveKeyset(keysetFor(id, "http://b.example/", 9)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}

	if got := db.GetKeysetCounter(id); got != 9 {
		t.Fatalf("GetKeysetCounter: got %d, want 9 (max across buckets)", got)
	}
}

// An increment derives from the highest copy and rewrites every copy, so
// drifted copies converge instead of staying split.
func TestIncrementKeysetCounterSyncsAllCopies(t *testing.T) {
	db := newCounterTestDB(t)
	id := "01ghi"

	if err := db.SaveKeyset(keysetFor(id, "http://a.example", 3)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.SaveKeyset(keysetFor(id, "http://b.example/", 9)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter(id, 4); err != nil {
		t.Fatalf("IncrementKeysetCounter: %v", err)
	}

	for _, mintURL := range []string{"http://a.example", "http://b.example/"} {
		ks := db.GetKeysets()[mintURL]
		if len(ks) != 1 {
			t.Fatalf("bucket %s: want 1 keyset, got %d", mintURL, len(ks))
		}
		for _, k := range ks {
			if k.Counter != 13 {
				t.Fatalf("bucket %s: counter %d, want 13 (max 9 + 4, synced)", mintURL, k.Counter)
			}
		}
	}
}

// Existing semantics preserved: a keyset that was never saved reads as an
// error-shaped 0 rather than panicking or silently succeeding.
func TestGetKeysetCounterMissingKeyset(t *testing.T) {
	db := newCounterTestDB(t)
	if got := db.GetKeysetCounter("does-not-exist"); got != 0 {
		t.Fatalf("missing keyset counter: got %d, want 0", got)
	}
}
