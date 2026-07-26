package nut09

import "github.com/OpenTollGate/gonuts-tollgate/cashu"

// NUT #09: Mints must store the `BlindedMessage` and the corresponding `BlindSignature` in their database every time they issue a `BlindSignature`.
type PostRestoreRequest struct {
	// NUT #09: Wallets provide the `BlindedMessage` for which they request the `BlindSignature`.
	Outputs cashu.BlindedMessages `json:"outputs"`
}

// NUT #09: Mints only respond with a `BlindSignature`, if they have previously signed the `BlindedMessage`.
type PostRestoreResponse struct {
	Outputs    cashu.BlindedMessages   `json:"outputs"`
	// NUT #09: The returned arrays `outputs` and `signatures` are of the same length and for every entry `outputs[i]`, there is a corresponding entry `signatures[i]`.
	Signatures cashu.BlindedSignatures `json:"signatures"`
}
