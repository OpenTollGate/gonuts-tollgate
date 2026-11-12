package nut13

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	ErrCollidingKeysetId = errors.New("error: colliding keyset detected")
	// ErrHardenedDomainExhausted reports a refusal to derive from, or
	// allocate, a counter span at or past the end of the NUT-13 hardened
	// derivation domain. Wrap it with %w so callers can errors.Is it.
	ErrHardenedDomainExhausted = errors.New("error: hardened derivation counter domain exhausted")
)

// HardenedCounterLimit is one past the last counter valid for NUT-13
// hardened derivation. The wallet derivation path index is
// HardenedKeyStart + counter: at counter == HardenedCounterLimit the
// uint32 index wraps out of the hardened range onto non-hardened paths,
// and a persisted storage counter that wrapped past MaxUint32 re-derives
// secrets the mint has already seen. Valid derivation counters are
// therefore confined to [0, HardenedCounterLimit).
//
// HardenedCounterLimit itself is a valid STORED counter value — the
// documented one-past-end "exhausted" marker a reservation may land on
// after deriving the last valid index — but nothing may ever be derived
// from it or allocated past it.
const HardenedCounterLimit uint32 = hdkeychain.HardenedKeyStart

// CheckHardenedCounterSpan is the single checked domain/range authority
// shared by NUT-13 derivation, wallet output allocation and storage
// counter reservation. It validates that the half-open span
// [start, start+num) lies entirely within the hardened domain, using
// wide (uint64) arithmetic so neither the count nor the resulting end
// can truncate or wrap.
//
// A zero-length span derives nothing and moves no counter, so it is
// always allowed — preserving existing zero-output operations (empty
// NUT-08 change melts) — including on the exhausted marker or a legacy
// out-of-domain record, which are preserved, never clamped or reset.
//
// The span's exclusive end may land exactly on HardenedCounterLimit:
// that reserves the last valid hardened index and stores the exhausted
// marker. Any further non-zero allocation from there is refused.
func CheckHardenedCounterSpan(start uint32, num uint64) error {
	if num == 0 {
		return nil
	}
	if start >= HardenedCounterLimit {
		return fmt.Errorf("%w: counter %d is at or past the hardened domain limit %d", ErrHardenedDomainExhausted, start, HardenedCounterLimit)
	}
	// Compare the count to remaining capacity before adding: num itself
	// may be MaxUint64, so widening start alone cannot prevent overflow.
	if num > uint64(HardenedCounterLimit)-uint64(start) {
		return fmt.Errorf("%w: span starting at %d with %d outputs exceeds the hardened domain limit %d", ErrHardenedDomainExhausted, start, num, HardenedCounterLimit)
	}
	return nil
}

// checkHardenedCounter is the innermost derivation guard: a single
// counter at or past the domain limit — including the one-past-end
// exhausted marker — must never be derived.
func checkHardenedCounter(counter uint32) error {
	if counter >= HardenedCounterLimit {
		return fmt.Errorf("%w: refusing to derive counter %d at or past the hardened domain limit %d", ErrHardenedDomainExhausted, counter, HardenedCounterLimit)
	}
	return nil
}

// NUT #13: This value is then modulo reduced by `2^31 - 1` to arrive at an integer that is a unique identifier `keyset_id_int`.
func keysetIdToBigInt(id string) (*big.Int, error) {
	hexPattern := regexp.MustCompile("^[0-9a-fA-F]+$")

	var result *big.Int
	modulus := big.NewInt(2147483647) // 2^31 - 1

	if hexPattern.MatchString(id) {
		result = new(big.Int)
		result.SetString(id, 16)
	} else {
		decoded, err := base64.StdEncoding.DecodeString(id)
		if err != nil {
			return nil, err
		}

		hexStr := hex.EncodeToString(decoded)
		result = new(big.Int)
		result.SetString(hexStr, 16)
	}

	return result.Mod(result, modulus), nil
}

// NUT #13: Note that the coin type is always `0'`, independent of the unit of the ecash.
func DeriveKeysetPath(master *hdkeychain.ExtendedKey, keysetId string) (*hdkeychain.ExtendedKey, error) {
	keysetIdInt, err := keysetIdToBigInt(keysetId)
	if err != nil {
		return nil, err
	}

	// m/129372
	purpose, err := master.Derive(hdkeychain.HardenedKeyStart + 129372)
	if err != nil {
		return nil, err
	}

	// m/129372'/0'
	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, err
	}

	// m/129372'/0'/keyset_k_int'
	keysetPath, err := coinType.Derive(hdkeychain.HardenedKeyStart + uint32(keysetIdInt.Uint64()))
	if err != nil {
		return nil, err
	}

	return keysetPath, nil
}

// NUT #13: Here, we describe how wallets can deterministically generate the `secrets` and blinding factors `r` necessary to generate the signatures `C`.
func DeriveBlindingFactor(keysetPath *hdkeychain.ExtendedKey, counter uint32) (*secp256k1.PrivateKey, error) {
	if err := checkHardenedCounter(counter); err != nil {
		return nil, err
	}

	// m/129372'/0'/keyset_k_int'/counter'
	counterPath, err := keysetPath.Derive(hdkeychain.HardenedKeyStart + counter)
	if err != nil {
		return nil, err
	}

	// m/129372'/0'/keyset_k_int'/counter'/1
	rDerivationPath, err := counterPath.Derive(1)
	if err != nil {
		return nil, err
	}

	rkey, err := rDerivationPath.ECPrivKey()
	if err != nil {
		return nil, err
	}

	return rkey, nil
}

// NUT #13: The wallet uses the `seed`, to derive deterministic values for the `secret` and the blinding factors `r` for every new ecash token that it generates.
func DeriveSecret(keysetPath *hdkeychain.ExtendedKey, counter uint32) (string, error) {
	if err := checkHardenedCounter(counter); err != nil {
		return "", err
	}

	// m/129372'/0'/keyset_k_int'/counter'
	counterPath, err := keysetPath.Derive(hdkeychain.HardenedKeyStart + counter)
	if err != nil {
		return "", err
	}

	// m/129372'/0'/keyset_k_int'/counter'/0
	secretDerivationPath, err := counterPath.Derive(0)
	if err != nil {
		return "", err
	}

	secretKey, err := secretDerivationPath.ECPrivKey()
	if err != nil {
		return "", err
	}

	secretBytes := secretKey.Serialize()
	secret := hex.EncodeToString(secretBytes)

	return secret, nil
}

// NUT #13: The index `k` indicates that the wallet **MUST** keep track of a separate counter for each keyset `k` it uses.
func CheckCollidingKeysets(currentKeysetIds []string, newMintKeysetIds []string) error {
	for i := range currentKeysetIds {
		keysetIdInt, err := keysetIdToBigInt(currentKeysetIds[i])
		if err != nil {
			return err
		}

		for j := range newMintKeysetIds {
			if currentKeysetIds[i] == newMintKeysetIds[j] {
				return fmt.Errorf("%w. KeysetId: %+v. New KeysetId: %+v", ErrCollidingKeysetId, currentKeysetIds[i], newMintKeysetIds[j])
			}

			keysetIdIntToCompare, err := keysetIdToBigInt(newMintKeysetIds[j])
			if err != nil {
				return err
			}

			if keysetIdInt.Cmp(keysetIdIntToCompare) == 0 {
				return fmt.Errorf("%w. KeysetId: %+v. New KeysetId: %+v", ErrCollidingKeysetId, currentKeysetIds[i], newMintKeysetIds[j])
			}
		}
	}

	return nil
}
