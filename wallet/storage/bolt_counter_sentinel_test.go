package storage

import (
	"errors"
	"math"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut13"
)

// The storage refusal must carry nut13.ErrHardenedDomainExhausted up
// through its %w wrapper so wallet callers can errors.Is it.
func TestStorageRefusalCarriesDomainSentinel(t *testing.T) {
	db := newIntentTestDB(t)
	if err := db.SaveKeyset(keysetFor("http://m.example", "01ab", math.MaxUint32)); err != nil {
		t.Fatalf("SaveKeyset: %v", err)
	}
	if err := db.IncrementKeysetCounter("01ab", 1); !errors.Is(err, nut13.ErrHardenedDomainExhausted) {
		t.Fatalf("increment refusal must wrap nut13.ErrHardenedDomainExhausted, got: %v", err)
	}
	if err := db.ReserveKeysetRangeWithIntent("01ab", 1, guardIntent("op-sentinel", math.MaxUint32, 0)); !errors.Is(err, nut13.ErrHardenedDomainExhausted) {
		t.Fatalf("reservation refusal must wrap nut13.ErrHardenedDomainExhausted, got: %v", err)
	}
}
