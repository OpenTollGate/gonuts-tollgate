package storage

import (
	"math"
	"testing"
)

// Red-first behavioral matrix for the storage-side checked counter range.
//
// IncrementKeysetCounter and ReserveKeysetRangeWithIntent currently do a
// plain uint32 `Counter += num` inside the bolt transaction: it wraps
// silently at MaxUint32 and never checks the NUT-13 hardened domain
// (0 <= counter < 2^31). These tests assert BEHAVIOR on the existing APIs:
// a span that would leave the domain must be refused inside the
// transaction, leaving the counter and the pending-intent rows unchanged.

const hardenedDomainLimit = uint32(1) << 31 // one past the last valid hardened counter

func guardIntent(opID string, start, end uint32) *PendingSwapIntent {
	return &PendingSwapIntent{
		OpID:         opID,
		MintURL:      "http://m.example",
		KeysetID:     "01ab",
		CounterStart: start,
		CounterEnd:   end,
		RequestBytes: []byte(`{"inputs":[],"outputs":[]}`),
		Secrets:      []string{},
		Rs:           [][]byte{},
	}
}

// Normal low counters must keep working (compatibility control).
func TestIncrementLowCounterStillWorks(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", 0)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter("01ab", 3); err != nil {
		t.Fatalf("IncrementKeysetCounter(3): %v", err)
	}
	if got := db.GetKeysetCounter("01ab"); got != 3 {
		t.Fatalf("counter = %d, want 3", got)
	}
}

// MaxUint32 increment must be refused, not wrapped: from counter 0 the
// span [0, MaxUint32) already leaves the hardened domain far behind.
func TestIncrementMaxUint32RefusedNotWrapped(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", 0)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter("01ab", math.MaxUint32); err == nil {
		t.Fatal("IncrementKeysetCounter(MaxUint32) must be refused: the span leaves the hardened derivation domain")
	}
	if got := db.GetKeysetCounter("01ab"); got != 0 {
		t.Fatalf("refused increment must leave the counter unchanged, got %d", got)
	}
}

// A legacy row already at MaxUint32 (wrapped by the old unchecked addition)
// must be preserved as-is and refuse further allocation — no clamp, no
// reset, no silent wrap back to small counters.
func TestIncrementLegacyMaxUint32RowPreservedAndRefused(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", math.MaxUint32)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter("01ab", 1); err == nil {
		t.Fatal("incrementing a MaxUint32 counter must be refused: it would wrap onto already-derived secrets")
	}
	if got := db.GetKeysetCounter("01ab"); got != math.MaxUint32 {
		t.Fatalf("legacy MaxUint32 row must be preserved unchanged, got %d", got)
	}
}

// Exact-end reservation: reserving the last hardened index lands the
// stored counter exactly on the one-past-end exhausted marker (2^31);
// that marker is a valid stored value but must never be derived from, so
// any follow-up allocation must be refused.
func TestReserveExactEndThenExhaustedFollowUpRefused(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", hardenedDomainLimit-1)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	intent := guardIntent("op-exact-end", hardenedDomainLimit-1, hardenedDomainLimit)
	if err := db.ReserveKeysetRangeWithIntent("01ab", 1, intent); err != nil {
		t.Fatalf("reserving the last hardened index must succeed: %v", err)
	}
	if got := db.GetKeysetCounter("01ab"); got != hardenedDomainLimit {
		t.Fatalf("counter = %d, want the exhausted marker %d", got, hardenedDomainLimit)
	}
	if len(db.GetPendingSwaps()) != 1 {
		t.Fatalf("pending swaps = %d, want 1", len(db.GetPendingSwaps()))
	}

	// Exhausted follow-up: refused, counter stays on the marker, no
	// second intent appears.
	if err := db.ReserveKeysetRangeWithIntent("01ab", 1, guardIntent("op-exhausted", hardenedDomainLimit, hardenedDomainLimit+1)); err == nil {
		t.Fatal("allocating past the exhausted marker must be refused")
	}
	if err := db.IncrementKeysetCounter("01ab", 1); err == nil {
		t.Fatal("incrementing past the exhausted marker must be refused")
	}
	if got := db.GetKeysetCounter("01ab"); got != hardenedDomainLimit {
		t.Fatalf("exhausted counter must stay on the marker, got %d", got)
	}
	if len(db.GetPendingSwaps()) != 1 {
		t.Fatalf("refused follow-up must not write an intent, pending swaps = %d", len(db.GetPendingSwaps()))
	}
}

// Multi-output span crossing the domain limit must be refused atomically:
// neither the counter nor the intent may be written.
func TestReserveMultiOutputSpanCrossingLimitRefused(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", hardenedDomainLimit-2)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	intent := guardIntent("op-cross", hardenedDomainLimit-2, hardenedDomainLimit+1)
	if err := db.ReserveKeysetRangeWithIntent("01ab", 3, intent); err == nil {
		t.Fatal("a 3-output span crossing the hardened domain limit must be refused")
	}
	if got := db.GetKeysetCounter("01ab"); got != hardenedDomainLimit-2 {
		t.Fatalf("refused reservation must leave the counter unchanged, got %d", got)
	}
	if len(db.GetPendingSwaps()) != 0 {
		t.Fatalf("refused reservation must not write an intent, pending swaps = %d", len(db.GetPendingSwaps()))
	}
}

// MaxUint32 reservation must be refused from any starting counter.
func TestReserveMaxUint32Refused(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", 0)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.ReserveKeysetRangeWithIntent("01ab", math.MaxUint32, guardIntent("op-max", 0, math.MaxUint32)); err == nil {
		t.Fatal("reserving MaxUint32 outputs must be refused: the span leaves the hardened derivation domain")
	}
	if got := db.GetKeysetCounter("01ab"); got != 0 {
		t.Fatalf("refused reservation must leave the counter unchanged, got %d", got)
	}
	if len(db.GetPendingSwaps()) != 0 {
		t.Fatalf("refused reservation must not write an intent, pending swaps = %d", len(db.GetPendingSwaps()))
	}
}

// Missing key: the existing "keyset does not exist" refusal must keep
// leaving no partial state (no intent row).
func TestReserveMissingKeysetRollsBackIntent(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", 0)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.ReserveKeysetRangeWithIntent("missing", 2, guardIntent("op-missing", 0, 2)); err == nil {
		t.Fatal("reserving on a missing keyset must fail")
	}
	if len(db.GetPendingSwaps()) != 0 {
		t.Fatalf("missing-keyset refusal must not write an intent, pending swaps = %d", len(db.GetPendingSwaps()))
	}
	if got := db.GetKeysetCounter("01ab"); got != 0 {
		t.Fatalf("missing-keyset refusal must not touch other keysets, counter = %d", got)
	}
}

// Zero-length reservation is existing zero-output behavior (empty NUT-08
// blank-output melts): it must keep writing its intent and keep the
// counter unchanged — nothing is derived from an empty span.
func TestReserveZeroLengthPreservesZeroOutputBehavior(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", 5)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.ReserveKeysetRangeWithIntent("01ab", 0, guardIntent("op-zero", 5, 5)); err != nil {
		t.Fatalf("zero-length reservation must keep working: %v", err)
	}
	if got := db.GetKeysetCounter("01ab"); got != 5 {
		t.Fatalf("zero-length reservation must not move the counter, got %d", got)
	}
	if len(db.GetPendingSwaps()) != 1 {
		t.Fatalf("zero-length reservation must still write its intent, pending swaps = %d", len(db.GetPendingSwaps()))
	}
	// Zero-length on the exhausted marker is equally safe: nothing derived.
	if err := db.SaveKeyset(keysetFor("http://m.example", "cdfe", hardenedDomainLimit)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.ReserveKeysetRangeWithIntent("cdfe", 0, guardIntent("op-zero-exh", hardenedDomainLimit, hardenedDomainLimit)); err != nil {
		t.Fatalf("zero-length reservation on the exhausted marker must keep working: %v", err)
	}
	if got := db.GetKeysetCounter("cdfe"); got != hardenedDomainLimit {
		t.Fatalf("zero-length reservation must not move the exhausted marker, got %d", got)
	}
}
