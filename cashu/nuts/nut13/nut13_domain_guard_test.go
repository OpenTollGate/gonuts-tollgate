package nut13

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

// Red-first behavioral matrix for the NUT-13 hardened derivation domain.
//
// The hardened index is HardenedKeyStart + counter (0x80000000 + counter),
// so the counter's valid domain is [0, 2^31). At counter == 2^31 the index
// wraps out of the hardened range entirely, and a persisted counter that
// wrapped past MaxUint32 re-derives earlier secrets. These tests use only
// the existing public derivation APIs and assert BEHAVIOR (an error must
// be returned), so they compile and fail against the unguarded base.

func guardTestKeysetPath(t *testing.T) *hdkeychain.ExtendedKey {
	t.Helper()
	mnemonic := "half depart obvious quality work element tank gorilla view sugar picture humble"
	seed := bip39.NewSeed(mnemonic, "")
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("NewMaster: %v", err)
	}
	path, err := DeriveKeysetPath(master, "009a1f293253e41e")
	if err != nil {
		t.Fatalf("DeriveKeysetPath: %v", err)
	}
	return path
}

// First valid hardened index: counter 0 must keep deriving.
func TestDerivationDomainFirstValidIndex(t *testing.T) {
	path := guardTestKeysetPath(t)
	if _, err := DeriveSecret(path, 0); err != nil {
		t.Fatalf("DeriveSecret(counter 0) must stay valid: %v", err)
	}
	if _, err := DeriveBlindingFactor(path, 0); err != nil {
		t.Fatalf("DeriveBlindingFactor(counter 0) must stay valid: %v", err)
	}
}

// Last valid hardened index: 2^31-1 maps to hardened index 0xFFFFFFFF and
// must keep deriving.
func TestDerivationDomainLastValidIndex(t *testing.T) {
	path := guardTestKeysetPath(t)
	if _, err := DeriveSecret(path, 1<<31-1); err != nil {
		t.Fatalf("DeriveSecret(counter 2^31-1) must stay valid: %v", err)
	}
	if _, err := DeriveBlindingFactor(path, 1<<31-1); err != nil {
		t.Fatalf("DeriveBlindingFactor(counter 2^31-1) must stay valid: %v", err)
	}
}

// First invalid index: the one-past-end exhausted marker (counter == 2^31)
// must never be derived — the hardened index wraps to a non-hardened path.
func TestDerivationDomainFirstInvalidIndex(t *testing.T) {
	path := guardTestKeysetPath(t)
	if _, err := DeriveSecret(path, 1<<31); err == nil {
		t.Fatal("DeriveSecret(counter 2^31) must be refused: the hardened index wraps out of the hardened domain")
	}
	if _, err := DeriveBlindingFactor(path, 1<<31); err == nil {
		t.Fatal("DeriveBlindingFactor(counter 2^31) must be refused: the hardened index wraps out of the hardened domain")
	}
}

// Out-of-domain high counters (legacy wrapped rows) must also be refused
// rather than silently derived on a colliding path.
func TestDerivationDomainRefusesHighOutOfDomainCounters(t *testing.T) {
	path := guardTestKeysetPath(t)
	for _, counter := range []uint32{1 << 31, 1<<31 + 5, 0xFFFFFFFF} {
		if _, err := DeriveSecret(path, counter); err == nil {
			t.Fatalf("DeriveSecret(counter %d) must be refused: outside the hardened domain", counter)
		}
		if _, err := DeriveBlindingFactor(path, counter); err == nil {
			t.Fatalf("DeriveBlindingFactor(counter %d) must be refused: outside the hardened domain", counter)
		}
	}
}
