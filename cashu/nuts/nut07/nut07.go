package nut07

import (
	"encoding/json"
	"errors"
)

type State int

const (
	// NUT #07: A proof is `UNSPENT` if it has not been spent yet
	Unspent State = iota
	// NUT #07: A proof is `PENDING` if it is being processed in a transaction (in an ongoing payment).
	Pending
	// NUT #07: A proof is `SPENT` if it has been redeemed and its secret is in the list of spent secrets of the mint.
	Spent
	Unknown
)

func (state State) String() string {
	switch state {
	case Unspent:
		return "UNSPENT"
	case Pending:
		return "PENDING"
	case Spent:
		return "SPENT"
	default:
		return "unknown"
	}
}

func StringToState(state string) State {
	switch state {
	case "UNSPENT":
		return Unspent
	case "PENDING":
		return Pending
	case "SPENT":
		return Spent
	}
	return Unknown
}

type PostCheckStateRequest struct {
	// NUT #07: the elements of the array in `Ys` are the hexadecimal representation of the compressed point `Y = hash_to_curve(secret)` of the `Proof` to check
	Ys []string `json:"Ys"`
}

type PostCheckStateResponse struct {
	// NUT #07: The elements of the `states` array MUST be returned in the same order as the corresponding `Ys` checked in the request.
	States []ProofState `json:"states"`
}

type ProofState struct {
	Y       string `json:"Y"`
	State   State  `json:"state"`
	Witness string `json:"witness,omitempty"`
}

type tempProofState struct {
	Y       string `json:"Y"`
	State   string `json:"state"`
	Witness string `json:"witness,omitempty"`
}

func (state *ProofState) MarshalJSON() ([]byte, error) {
	tempProof := tempProofState{
		Y:       state.Y,
		State:   state.State.String(),
		Witness: state.Witness,
	}
	return json.Marshal(tempProof)
}

func (state *ProofState) UnmarshalJSON(data []byte) error {
	var tempProof tempProofState

	if err := json.Unmarshal(data, &tempProof); err != nil {
		return err
	}

	state.Y = tempProof.Y
	stateVal := StringToState(tempProof.State)
	if stateVal == Unknown {
		return errors.New("invalid state")
	}
	state.State = stateVal
	state.Witness = tempProof.Witness

	return nil
}
