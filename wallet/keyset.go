package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/client"
)

// GetMintActiveKeyset gets the active keyset with the specified unit.
// Uses GET /v1/keys (single call) which returns active keysets WITH keys,
// instead of GET /v1/keysets + GET /v1/keys/{id} (two calls) where the
// second call fails with 400 "unknown keyset" on some mints.
func GetMintActiveKeyset(mintURL string, unit cashu.Unit) (*crypto.WalletKeyset, error) {
	keysets, err := client.GetActiveKeysets(mintURL)
	if err != nil {
		// Fallback: try the two-call approach if /v1/keys fails entirely
		return getMintActiveKeysetFallback(mintURL, unit)
	}

	for _, keyset := range keysets.Keysets {
		if keyset.Active && keyset.Unit == unit.String() {
			_, err := hex.DecodeString(keyset.Id)
			if err == nil {
				return &crypto.WalletKeyset{
					Id:          keyset.Id,
					MintURL:     mintURL,
					Unit:        keyset.Unit,
					Active:      true,
					PublicKeys:  keyset.Keys,
					InputFeePpk: keyset.InputFeePpk,
				}, nil
			}
		}
	}

	// No active keyset with keys found via /v1/keys, try two-call approach
	return getMintActiveKeysetFallback(mintURL, unit)
}

// getMintActiveKeysetFallback is the legacy two-call approach: GET /v1/keysets
// to discover the keyset ID, then GET /v1/keys/{id} to fetch keys. Used as a
// fallback when GetActiveKeysets (/v1/keys) doesn't return active keysets with keys.
func getMintActiveKeysetFallback(mintURL string, unit cashu.Unit) (*crypto.WalletKeyset, error) {
	keysets, err := client.GetAllKeysets(mintURL)
	if err != nil {
		return nil, fmt.Errorf("error getting active keysets from mint: %w", err)
	}

	for _, keyset := range keysets.Keysets {
		if keyset.Active && keyset.Unit == unit.String() {
			_, err := hex.DecodeString(keyset.Id)
			if err == nil {
				keys, err := GetKeysetKeys(mintURL, keyset.Id)
				if err != nil {
					return nil, fmt.Errorf("error getting keyset keys: %w", err)
				}
				return &crypto.WalletKeyset{
					Id:          keyset.Id,
					MintURL:     mintURL,
					Unit:        keyset.Unit,
					Active:      true,
					PublicKeys:  keys,
					InputFeePpk: keyset.InputFeePpk,
				}, nil
			}
		}
	}

	return nil, errors.New("could not find an active keyset for the unit")
}

func GetMintInactiveKeysets(mintURL string, unit cashu.Unit) (map[string]crypto.WalletKeyset, error) {
	keysetsResponse, err := client.GetAllKeysets(mintURL)
	if err != nil {
		return nil, fmt.Errorf("error getting keysets from mint: %w", err)
	}

	inactiveKeysets := make(map[string]crypto.WalletKeyset)
	for _, keysetRes := range keysetsResponse.Keysets {
		_, err := hex.DecodeString(keysetRes.Id)
		if !keysetRes.Active && keysetRes.Unit == unit.String() && err == nil {
			keyset := crypto.WalletKeyset{
				Id:          keysetRes.Id,
				MintURL:     mintURL,
				Unit:        keysetRes.Unit,
				Active:      keysetRes.Active,
				InputFeePpk: keysetRes.InputFeePpk,
			}
			inactiveKeysets[keyset.Id] = keyset
		}
	}
	return inactiveKeysets, nil
}

func GetKeysetKeys(mintURL, id string) (crypto.PublicKeys, error) {
	keysetsResponse, err := client.GetKeysetById(mintURL, id)
	if err != nil {
		// Fallback: GET /v1/keys returns all active keysets with keys.
		// Some mints return 400 "unknown keyset" for GET /v1/keys/{id}
		// even when the keyset is active and returned by GET /v1/keys.
		allKeys, fallbackErr := client.GetActiveKeysets(mintURL)
		if fallbackErr != nil {
			return nil, fmt.Errorf("error getting keyset from mint: %w", err)
		}
		for _, ks := range allKeys.Keysets {
			if ks.Id == id {
				return ks.Keys, nil
			}
		}
		return nil, fmt.Errorf("error getting keyset from mint: %w", err)
	}

	if len(keysetsResponse.Keysets) == 0 {
		return nil, fmt.Errorf("mint returned no keysets for id %s", id)
	}

	keyset := keysetsResponse.Keysets[0]

	var derivedId string
	if crypto.IsKeysetIdV2(id) {
		unit, inputFeePpk, err := getKeysetMetadata(mintURL, id)
		if err != nil {
			return nil, fmt.Errorf("error getting keyset metadata: %w", err)
		}
		derivedId = crypto.DeriveKeysetIdV2(keyset.Keys, unit, inputFeePpk)
	} else {
		derivedId = crypto.DeriveKeysetId(keyset.Keys)
	}

	if id != derivedId {
		return nil, fmt.Errorf("Got invalid keyset. Derived id: '%v' but got '%v' from mint", derivedId, keyset.Id)
	}

	return keyset.Keys, nil
}

func getKeysetMetadata(mintURL, id string) (string, uint, error) {
	allKeysets, err := client.GetAllKeysets(mintURL)
	if err != nil {
		return "", 0, fmt.Errorf("error getting keysets from mint: %v", err)
	}
	for _, ks := range allKeysets.Keysets {
		if ks.Id == id {
			return ks.Unit, ks.InputFeePpk, nil
		}
	}
	return "", 0, fmt.Errorf("keyset %s not found in mint keysets", id)
}

// getActiveKeyset returns the active keyset for the mint passed.
// if mint passed is known and the latest active keyset has changed,
// it will inactivate the previous active and save new active to db
func (w *Wallet) getActiveKeyset(mintURL string) (*crypto.WalletKeyset, error) {
	mint, ok := w.mints[mintURL]
	// if mint is not known, get active sat keyset from calling mint
	if !ok {
		activeKeyset, err := GetMintActiveKeyset(mintURL, w.unit)
		if err != nil {
			return nil, err
		}
		return activeKeyset, nil
	}

	activeKeyset := mint.activeKeyset

	allKeysets, err := client.GetAllKeysets(mintURL)
	if err != nil {
		if isNetworkError(err) {
			// Use cached keyset when offline
			return &activeKeyset, nil
		}
		return nil, err
	}
	var activeInputFeePpk uint
	// check if there is new active keyset
	activeChanged := true
	for _, keyset := range allKeysets.Keysets {
		if keyset.Active && keyset.Id == activeKeyset.Id {
			activeChanged = false
			activeInputFeePpk = keyset.InputFeePpk
			break
		}
	}

	// if new active, save it to db and inactivate previous
	if activeChanged {
		// inactivate previous active
		activeKeyset.Active = false
		mint.inactiveKeysets[activeKeyset.Id] = activeKeyset
		if err := w.db.SaveKeyset(&activeKeyset); err != nil {
			return nil, err
		}

		for _, keyset := range allKeysets.Keysets {
			_, err = hex.DecodeString(keyset.Id)
			if keyset.Active && keyset.Unit == w.unit.String() && err == nil {
				storedKeyset := w.db.GetKeyset(keyset.Id)
				if storedKeyset != nil {
					storedKeyset.Active = true
					storedKeyset.InputFeePpk = keyset.InputFeePpk
					if err := w.db.SaveKeyset(storedKeyset); err != nil {
						return nil, err
					}
					activeKeyset = *storedKeyset
					mint.activeKeyset = activeKeyset
					delete(mint.inactiveKeysets, storedKeyset.Id)
				} else {
					// Use GET /v1/keys (single call) to get keys, which returns
					// all active keysets WITH keys. This avoids the broken
					// GET /v1/keys/{id} endpoint that fails with 400 "unknown
					// keyset" on some mints (e.g. coinos). Falls back to
					// GetKeysetKeys only if GetActiveKeysets fails entirely.
					keys, err := func() (crypto.PublicKeys, error) {
						allKeys, gakErr := client.GetActiveKeysets(mintURL)
						if gakErr != nil {
							// Fallback to two-call approach
							return GetKeysetKeys(mintURL, keyset.Id)
						}
						for _, ks := range allKeys.Keysets {
							if ks.Id == keyset.Id && ks.Active {
								return ks.Keys, nil
							}
						}
						// Keyset not found in /v1/keys response, fall back
						return GetKeysetKeys(mintURL, keyset.Id)
					}()
					if err != nil {
						return nil, err
					}
					activeKeyset = crypto.WalletKeyset{
						Id:          keyset.Id,
						MintURL:     mintURL,
						Unit:        keyset.Unit,
						Active:      true,
						PublicKeys:  keys,
						InputFeePpk: keyset.InputFeePpk,
					}

					if err := w.db.SaveKeyset(&activeKeyset); err != nil {
						return nil, err
					}
					mint.activeKeyset = activeKeyset
				}
				w.mints[mintURL] = mint
			}
		}
	} else {
		// check if input_fee_ppk changed for current active
		if activeInputFeePpk != activeKeyset.InputFeePpk {
			activeKeyset.InputFeePpk = activeInputFeePpk
			if err := w.db.SaveKeyset(&activeKeyset); err != nil {
				return nil, err
			}
			mint.activeKeyset = activeKeyset
			w.mints[mintURL] = mint
		}
	}

	return &activeKeyset, nil
}
