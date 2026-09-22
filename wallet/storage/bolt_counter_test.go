package storage

import (
	"testing"
)

func newIntentTestDB(t *testing.T) *BoltDB {
	t.Helper()
	db, err := InitBolt(t.TempDir())
	if err != nil {
		t.Fatalf("InitBolt: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// The combined reservation must advance the counter AND write the
// intent in one call — the atomicity is the #497 fund-safety invariant.
func TestReserveKeysetRangeWithIntentWritesBoth(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", 0)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}

	intent := &PendingSwapIntent{
		OpID: "op-1", MintURL: "http://m.example", KeysetID: "01ab",
		CounterStart: 0, CounterEnd: 3,
		RequestBytes: []byte(`{"inputs":[],"outputs":[]}`),
		Secrets:      []string{"a", "b", "c"},
		Rs:           [][]byte{make([]byte, 32), make([]byte, 32), make([]byte, 32)},
	}
	if err := db.ReserveKeysetRangeWithIntent("01ab", 3, intent); err != nil {
		t.Fatalf("ReserveKeysetRangeWithIntent: %v", err)
	}

	if got := db.GetKeysetCounter("01ab"); got != 3 {
		t.Fatalf("counter = %d, want 3", got)
	}
	intents := db.GetPendingSwaps()
	if len(intents) != 1 {
		t.Fatalf("pending swaps = %d, want 1", len(intents))
	}
	got := intents[0]
	if got.OpID != "op-1" || got.CounterStart != 0 || got.CounterEnd != 3 || len(got.Secrets) != 3 {
		t.Fatalf("intent roundtrip mismatch: %+v", got)
	}
	if string(got.RequestBytes) != string(intent.RequestBytes) {
		t.Fatalf("request bytes not preserved: %q", got.RequestBytes)
	}

	if err := db.DeletePendingSwap("op-1"); err != nil {
		t.Fatalf("DeletePendingSwap: %v", err)
	}
	if len(db.GetPendingSwaps()) != 0 {
		t.Fatal("intent must be gone after delete")
	}
	if got := db.GetKeysetCounter("01ab"); got != 3 {
		t.Fatalf("delete must not touch the counter, got %d", got)
	}
}

// A nil intent is refused loudly rather than reserving a range with no
// recovery record — the exact hole #497 exists to close.
func TestReserveKeysetRangeWithIntentRejectsNil(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01cd", 0)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.ReserveKeysetRangeWithIntent("01cd", 2, nil); err == nil {
		t.Fatal("nil intent must be rejected")
	}
}
