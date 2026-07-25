package nut12

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// VerifyProofsDLEQ will verify the DLEQ proofs if present. If the DLEQ proofs are not present
// it will continue and return true
func VerifyProofsDLEQ(proofs cashu.Proofs, keyset crypto.WalletKeyset) bool {
	for _, proof := range proofs {
		if proof.DLEQ == nil {
			continue
		} else {
			pubkey, ok := keyset.PublicKeys[proof.Amount]
			if !ok {
				return false
			}

			if !VerifyProofDLEQ(proof, pubkey) {
				return false
			}
		}
	}
	return true
}

// keysetFetcher is a function that returns the public keys for a given keyset ID.
type keysetFetcher func(keysetID string) (crypto.PublicKeys, error)

// VerifyProofsDLEQWithKeysets verifies DLEQ proofs using the correct keyset
// for each proof, looked up by proof.Id. This handles mints that have rotated
// keysets — the active keyset may differ from the keyset that signed the proof.
// If a proof has no DLEQ proof, it is skipped (returns true for that proof).
// If keysetFetcher is nil, falls back to verifying all proofs against the
// provided activeKeyset (legacy behavior).
func VerifyProofsDLEQWithKeysets(proofs cashu.Proofs, activeKeyset crypto.WalletKeyset, fetcher keysetFetcher) (bool, error) {
	if fetcher == nil {
		return VerifyProofsDLEQ(proofs, activeKeyset), nil
	}

	// Group proofs by keyset ID to minimize mint API calls.
	proofsByKeyset := make(map[string]cashu.Proofs)
	for _, proof := range proofs {
		if proof.DLEQ == nil {
			continue
		}
		proofsByKeyset[proof.Id] = append(proofsByKeyset[proof.Id], proof)
	}

	// No DLEQ proofs to verify.
	if len(proofsByKeyset) == 0 {
		return true, nil
	}

	// Fetch keysets and verify concurrently.
	type result struct {
		valid bool
		err   error
	}

	var mu sync.Mutex
	var firstErr error
	allValid := true

	var wg sync.WaitGroup
	for keysetID, keysetProofs := range proofsByKeyset {
		wg.Add(1)
		go func(id string, prfs cashu.Proofs) {
			defer wg.Done()

			var pubkeys crypto.PublicKeys
			var err error

			if id == activeKeyset.Id {
				// Use the active keyset we already have.
				pubkeys = activeKeyset.PublicKeys
			} else {
				// Fetch the historical keyset that signed these proofs.
				pubkeys, err = fetcher(id)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("failed to fetch keyset %s: %v", id, err)
					}
					allValid = false
					mu.Unlock()
					return
				}
			}

			valid := VerifyProofsDLEQ(prfs, crypto.WalletKeyset{
				Id:         id,
				PublicKeys: pubkeys,
			})

			if !valid {
				mu.Lock()
				allValid = false
				mu.Unlock()
			}
		}(keysetID, keysetProofs)
	}
	wg.Wait()

	if firstErr != nil {
		return false, firstErr
	}
	return allValid, nil
}

func VerifyProofDLEQ(
	proof cashu.Proof,
	A *secp256k1.PublicKey,
) bool {
	e, s, r, err := ParseDLEQ(*proof.DLEQ)
	if err != nil || r == nil {
		return false
	}

	B_, _, err := crypto.BlindMessage(proof.Secret, r)
	if err != nil {
		return false
	}

	CBytes, err := hex.DecodeString(proof.C)
	if err != nil {
		return false
	}

	C, err := secp256k1.ParsePubKey(CBytes)
	if err != nil {
		return false
	}

	var CPoint, APoint secp256k1.JacobianPoint
	C.AsJacobian(&CPoint)
	A.AsJacobian(&APoint)

	// C' = C + r*A
	var C_Point, rAPoint secp256k1.JacobianPoint
	secp256k1.ScalarMultNonConst(&r.Key, &APoint, &rAPoint)
	rAPoint.ToAffine()
	secp256k1.AddNonConst(&CPoint, &rAPoint, &C_Point)
	C_Point.ToAffine()
	C_ := secp256k1.NewPublicKey(&C_Point.X, &C_Point.Y)

	return crypto.VerifyDLEQ(e, s, A, B_, C_)
}

func VerifyBlindSignatureDLEQ(
	dleq cashu.DLEQProof,
	A *secp256k1.PublicKey,
	B_str string,
	C_str string,
) bool {
	e, s, _, err := ParseDLEQ(dleq)
	if err != nil {
		return false
	}

	B_bytes, err := hex.DecodeString(B_str)
	if err != nil {
		return false
	}
	B_, err := secp256k1.ParsePubKey(B_bytes)
	if err != nil {
		return false
	}

	C_bytes, err := hex.DecodeString(C_str)
	if err != nil {
		return false
	}
	C_, err := secp256k1.ParsePubKey(C_bytes)
	if err != nil {
		return false
	}

	return crypto.VerifyDLEQ(e, s, A, B_, C_)
}

func ParseDLEQ(dleq cashu.DLEQProof) (
	*secp256k1.PrivateKey,
	*secp256k1.PrivateKey,
	*secp256k1.PrivateKey,
	error,
) {
	ebytes, err := hex.DecodeString(dleq.E)
	if err != nil {
		return nil, nil, nil, err
	}
	e := secp256k1.PrivKeyFromBytes(ebytes)

	sbytes, err := hex.DecodeString(dleq.S)
	if err != nil {
		return nil, nil, nil, err
	}
	s := secp256k1.PrivKeyFromBytes(sbytes)

	if dleq.R == "" {
		return e, s, nil, nil
	}

	rbytes, err := hex.DecodeString(dleq.R)
	if err != nil {
		return nil, nil, nil, err
	}
	r := secp256k1.PrivKeyFromBytes(rbytes)

	return e, s, r, nil
}
