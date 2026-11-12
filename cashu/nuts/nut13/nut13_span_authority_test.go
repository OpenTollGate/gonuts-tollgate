package nut13

import (
	"errors"
	"testing"
)

// Sentinel identity for the domain refusal: callers up the stack must be
// able to detect exhaustion with errors.Is through every wrapper.
func TestDerivationDomainRefusalIsErrHardenedDomainExhausted(t *testing.T) {
	path := guardTestKeysetPath(t)
	_, err := DeriveSecret(path, 1<<31)
	if err == nil {
		t.Fatal("DeriveSecret(counter 2^31) must be refused")
	}
	if !errors.Is(err, ErrHardenedDomainExhausted) {
		t.Fatalf("refusal must wrap ErrHardenedDomainExhausted, got: %v", err)
	}
	if _, err := DeriveBlindingFactor(path, 1<<31); !errors.Is(err, ErrHardenedDomainExhausted) {
		t.Fatalf("DeriveBlindingFactor refusal must wrap ErrHardenedDomainExhausted, got: %v", err)
	}
}

// The span authority itself: first/last valid spans pass, one-past-end
// span is allowed (lands on the exhausted marker), anything beyond or
// out-of-domain is refused with the sentinel; zero-length always passes.
func TestCheckHardenedCounterSpanMatrix(t *testing.T) {
	cases := []struct {
		name    string
		start   uint32
		num     uint64
		wantErr bool
	}{
		{"first valid span", 0, 1, false},
		{"last valid span", HardenedCounterLimit - 1, 1, false},
		{"span ending exactly on the marker", HardenedCounterLimit - 3, 3, false},
		{"span ending one past the marker", HardenedCounterLimit - 3, 4, true},
		{"first invalid single counter", HardenedCounterLimit, 1, true},
		{"out-of-domain legacy start", 0xFFFFFFFF, 1, true},
		{"max uint64 count cannot wrap", 0, 0xFFFFFFFFFFFFFFFF, true},
		{"positive start plus max count cannot wrap", 1, 0xFFFFFFFFFFFFFFFF, true},
		{"last valid start plus max count cannot wrap", HardenedCounterLimit - 1, 0xFFFFFFFFFFFFFFFF, true},
		{"positive start plus near max count cannot wrap", 2, 0xFFFFFFFFFFFFFFFE, true},
		{"zero length at 0", 0, 0, false},
		{"zero length on the marker", HardenedCounterLimit, 0, false},
		{"zero length on legacy out-of-domain", 0xFFFFFFFF, 0, false},
	}
	for _, tc := range cases {
		err := CheckHardenedCounterSpan(tc.start, tc.num)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%s: expected refusal", tc.name)
			}
			if !errors.Is(err, ErrHardenedDomainExhausted) {
				t.Fatalf("%s: refusal must wrap ErrHardenedDomainExhausted, got: %v", tc.name, err)
			}
		} else if err != nil {
			t.Fatalf("%s: unexpected refusal: %v", tc.name, err)
		}
	}
}
