// Package nut02 contains structs as defined in [NUT-02]
//
// [NUT-02]: https://github.com/cashubtc/nuts/blob/main/02.md
package nut02

type GetKeysetsResponse struct {
	Keysets []Keyset `json:"keysets"`
}

type Keyset struct {
	// NUT #02: Mints can have multiple keysets at the same time but **MUST** have at least one `active` keyset (see [NUT-01][01]).
	Id          string `json:"id"`
	Unit        string `json:"unit"`
	Active      bool   `json:"active"`
	// NUT #02: Keysets indicate the fee `input_fee_ppk` that is charged when a `Proof` of that keyset is spent as an input to a transaction.
	InputFeePpk uint   `json:"input_fee_ppk"`
}
