package nut14

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut11"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	NUT14ErrCode cashu.CashuErrCode = 30004
)

// NUT-14: specific errors
var (
	InvalidPreimageErr = cashu.Error{Detail: "Invalid preimage for HTLC", Code: NUT14ErrCode}
	InvalidHashErr     = cashu.Error{Detail: "Invalid hash in secret", Code: NUT14ErrCode}
)

// NUT #14: `HTLCWitness` is a serialized JSON string of the form
type HTLCWitness struct {
	Preimage   string   `json:"preimage"`
	Signatures []string `json:"signatures"`
}

// AddWitnessHTLC will add the preimage to the HTLCWitness.
// It will also read the tags in the secret and add the signatures
// if needed.
// NUT #14: To successfully spend a Proof via the **Receiver Pathway**, the spender must present the matching `preimage_bytes`, encoded as a 64-character lowercase hexadecimal string in the `Proof.witness.preimage`.
func AddWitnessHTLC(
	proofs cashu.Proofs,
	secret nut10.WellKnownSecret,
	preimage string,
	signingKey *btcec.PrivateKey,
) (cashu.Proofs, error) {
	tags, err := nut11.ParseP2PKTags(secret.Data.Tags)
	if err != nil {
		return nil, err
	}

	signatureNeeded := false
	if tags.NSigs > 0 {
		// return error if it requires more than 1 signature
		if tags.NSigs > 1 {
			return nil, errors.New("unable to provide enough signatures")
		}

		publicKey := signingKey.PubKey().SerializeCompressed()
		canSign := false
		// read pubkeys and check signingKey can sign
		for _, pk := range tags.Pubkeys {
			if slices.Equal(pk.SerializeCompressed(), publicKey) {
				canSign = true
				break
			}
		}
		if !canSign {
			return nil, errors.New("signing key is not part of public keys list that can provide signatures")
		}

		// if it gets to here, signature is needed in the witness
		signatureNeeded = true
	}

	for i, proof := range proofs {
		htlcWitness := HTLCWitness{Preimage: preimage}
		if signatureNeeded {
			hash := sha256.Sum256([]byte(proof.Secret))
			signature, err := schnorr.Sign(signingKey, hash[:])
			if err != nil {
				return nil, err
			}
			htlcWitness.Signatures = []string{hex.EncodeToString(signature.Serialize())}
		}

		witness, err := json.Marshal(htlcWitness)
		if err != nil {
			return nil, err
		}
		proof.Witness = string(witness)
		proofs[i] = proof
	}

	return proofs, nil
}

// NUT #14: The hash lock in `Secret.data` and the preimage in `Proof.witness.preimage` are treated as 32-byte data, encoded as 64-character hexadecimal strings.
func AddWitnessHTLCToOutputs(
	outputs cashu.BlindedMessages,
	preimage string,
	signingKey *btcec.PrivateKey,
) (cashu.BlindedMessages, error) {
	for i, output := range outputs {
		hash := sha256.Sum256([]byte(output.B_))
		signature, err := schnorr.Sign(signingKey, hash[:])
		if err != nil {
			return nil, err
		}

		htlcWitness := HTLCWitness{
			Preimage:   preimage,
			Signatures: []string{hex.EncodeToString(signature.Serialize())},
		}

		witness, err := json.Marshal(htlcWitness)
		if err != nil {
			return nil, err
		}
		output.Witness = string(witness)
		outputs[i] = output
	}

	return outputs, nil
}

// NUT #14: Aligned with Bitcoin's HTLC construction, the hash lock in `Secret.data` represents the **SHA-256 hash** of a 32-byte preimage.
func VerifyHTLCProof(proof cashu.Proof, proofSecret nut10.WellKnownSecret) error {
	var htlcWitness HTLCWitness
	json.Unmarshal([]byte(proof.Witness), &htlcWitness)

	p2pkTags, err := nut11.ParseP2PKTags(proofSecret.Data.Tags)
	if err != nil {
		return err
	}

	// if locktime is expired and there is no refund pubkey, treat as anyone can spend
	// if refund pubkey present, check signature
	if p2pkTags.Locktime > 0 && time.Now().Local().Unix() > p2pkTags.Locktime {
		if len(p2pkTags.Refund) == 0 {
			return nil
		} else {
			hash := sha256.Sum256([]byte(proof.Secret))
			if len(htlcWitness.Signatures) < 1 {
				return nut11.InvalidWitness
			}
			if !nut11.HasValidSignatures(hash[:], htlcWitness.Signatures, 1, p2pkTags.Refund) {
				return nut11.NotEnoughSignaturesErr
			}
		}
		return nil
	}

	// verify valid preimage
	preimageBytes, err := hex.DecodeString(htlcWitness.Preimage)
	if err != nil {
		return InvalidPreimageErr
	}
	hashBytes := sha256.Sum256(preimageBytes)
	hash := hex.EncodeToString(hashBytes[:])

	if len(proofSecret.Data.Data) != 64 {
		return InvalidHashErr
	}
	if hash != proofSecret.Data.Data {
		return InvalidPreimageErr
	}

	// if n_sigs flag present, verify signatures
	if p2pkTags.NSigs > 0 {
		if len(htlcWitness.Signatures) < 1 {
			return nut11.NoSignaturesErr
		}

		hash := sha256.Sum256([]byte(proof.Secret))

		if nut11.DuplicateSignatures(htlcWitness.Signatures) {
			return nut11.DuplicateSignaturesErr
		}

		if !nut11.HasValidSignatures(hash[:], htlcWitness.Signatures, p2pkTags.NSigs, p2pkTags.Pubkeys) {
			return nut11.NotEnoughSignaturesErr
		}
	}

	return nil
}
