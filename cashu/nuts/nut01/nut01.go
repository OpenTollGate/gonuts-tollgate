// Package nut01 contains structs as defined in [NUT-01]
//
// [NUT-01]: https://github.com/cashubtc/nuts/blob/main/01.md
package nut01

import (
	"encoding/json"

	"github.com/OpenTollGate/gonuts-tollgate/crypto"
)

type GetKeysResponse struct {
	// NUT #01: Wallet user `Alice` receives public keys from mint `Bob` via `GET /v1/keys`.
	Keysets []Keyset `json:"keysets"`
}

type Keyset struct {
	// NUT #01: Keys in Keysets are maps of the form `{<amount_1> : <mint_pubkey_1>, <amount_2> : <mint_pubkey_2>, ...}`
	Id   string            `json:"id"`
	Unit string            `json:"unit"`
	Keys crypto.PublicKeys `json:"keys"`
	// NUT #02: These fields are also present in GET /v1/keys responses
	// on NUT-01-compliant mints. Parsing them here lets us avoid a
	// separate GET /v1/keys/{id} call that fails with 400 on some mints.
	Active      bool `json:"active"`
	InputFeePpk uint `json:"input_fee_ppk"`
}

func (kr *GetKeysResponse) UnmarshalJSON(data []byte) error {
	var tempResponse struct {
		Keysets []json.RawMessage
	}
	if err := json.Unmarshal(data, &tempResponse); err != nil {
		return nil
	}

	keysets := make([]Keyset, len(tempResponse.Keysets))
	for i, k := range tempResponse.Keysets {
		var keyset Keyset
		if err := json.Unmarshal(k, &keyset); err != nil {
			return err
		}
		keysets[i] = keyset
	}
	kr.Keysets = keysets

	return nil
}

func (ks *Keyset) UnmarshalJSON(data []byte) error {
	var tempKeyset struct {
		Id          string
		Unit        string
		Keys        json.RawMessage
		Active      bool `json:"active"`
		InputFeePpk uint `json:"input_fee_ppk"`
	}

	if err := json.Unmarshal(data, &tempKeyset); err != nil {
		return err
	}

	ks.Id = tempKeyset.Id
	ks.Unit = tempKeyset.Unit
	ks.Active = tempKeyset.Active
	ks.InputFeePpk = tempKeyset.InputFeePpk

	publicKeys := make(crypto.PublicKeys, len(tempKeyset.Keys))
	if err := json.Unmarshal(tempKeyset.Keys, &publicKeys); err != nil {
		return err
	}
	ks.Keys = publicKeys

	return nil
}
