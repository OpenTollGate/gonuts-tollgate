// Package nut03 contains structs as defined in [NUT-03]
//
// [NUT-03]: https://github.com/cashubtc/nuts/blob/main/03.md
package nut03

import "github.com/OpenTollGate/gonuts-tollgate/cashu"

// NUT #03: the client **SHOULD** ensure that the list requested outputs is ordered by amount in ascending order.

// NUT #03: A swap operation consists of multiple inputs (`Proofs`) and outputs (`BlindedMessages`).
type PostSwapRequest struct {
	Inputs  cashu.Proofs          `json:"inputs"`
	Outputs cashu.BlindedMessages `json:"outputs"`
}

// NUT #03: Mints verify and invalidate the inputs and issue new promises (`BlindSignatures`).
type PostSwapResponse struct {
	Signatures cashu.BlindedSignatures `json:"signatures"`
}
