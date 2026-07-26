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
)

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
