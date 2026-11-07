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
	// Error code: HTLC preimage/hash failures have no error_codes.md
	// class, and the 3xxxx range they previously squatted is
	// spec-allocated to NUT-21/22 auth — emitted from the private 41xxx
	// block instead (cashu-audit #68 item A).
	NUT14ErrCode cashu.CashuErrCode = 41014
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

	requiredSigs := tags.NSigs
	if requiredSigs == 0 && len(tags.Pubkeys) > 0 {
		requiredSigs = 1
	}

	signatureNeeded := false
	if requiredSigs > 0 {
		if requiredSigs > 1 {
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
	// NUT-11/14: locktime expiry ADDS the refund keys as an alternative
	// path — it does NOT revoke the receiver (preimage + primary) path
	// (cashu-audit #59: receiver-path-after-locktime must still verify;
	// cdk and nutshell >=0.20.3 accept both).
	if p2pkTags.Locktime > 0 && time.Now().Local().Unix() > p2pkTags.Locktime {
		if len(p2pkTags.Refund) == 0 {
			// no refund keys: anyone can spend after expiry
			return nil
		}
		if len(htlcWitness.Signatures) >= 1 {
			hash := sha256.Sum256([]byte(proof.Secret))
			refundRequired := 1
			if p2pkTags.NSigsRefund > 0 {
				refundRequired = p2pkTags.NSigsRefund
			}
			if nut11.HasValidSignatures(hash[:], htlcWitness.Signatures, refundRequired, p2pkTags.Refund) {
				return nil
			}
		}
		// refund path did not verify — fall through to the receiver path
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

	verifySigs := p2pkTags.NSigs
	if verifySigs == 0 && len(p2pkTags.Pubkeys) > 0 {
		verifySigs = 1
	}

	if verifySigs > 0 {
		if len(htlcWitness.Signatures) < 1 {
			return nut11.NoSignaturesErr
		}

		hash := sha256.Sum256([]byte(proof.Secret))

		if nut11.DuplicateSignatures(htlcWitness.Signatures) {
			return nut11.DuplicateSignaturesErr
		}

		// NUT-11: signable set = primary key (secret.data is the hash for
		// HTLC, so the primary SIGNING key rides the pubkeys tag; data-key
		// union semantics preserved for the P2PK verifier) — keys as-is here.
		if !nut11.HasValidSignatures(hash[:], htlcWitness.Signatures, verifySigs, p2pkTags.Pubkeys) {
			return nut11.NotEnoughSignaturesErr
		}
	}

	return nil
}

// VerifySigAllHTLCProofs verifies a spec-conformant HTLC SIG_ALL
// transaction: the witness lives ONLY in the first input (HTLCWitness:
// preimage + signatures) and the signatures are Schnorr signatures over
// sha256(nut11.SigAllMessage(inputs, outputs, quoteId)) — the same
// aggregate as P2PK SIG_ALL (tollgate #809 / cashu-audit #59: the HTLC
// arm of the spec alignment).
//
// Semantics mirror VerifyHTLCProof: locktime expiry is additive (refund
// keys over the aggregate accepted, receiver path still accepted, no
// refund keys = anyone-can-spend); the receiver path requires a preimage
// hashing to Secret.data, plus aggregate signatures when the pubkeys tag
// (or n_sigs) demands them.
func VerifySigAllHTLCProofs(inputs cashu.Proofs, outputs cashu.BlindedMessages, quoteId string) error {
	if len(inputs) == 0 {
		return cashu.NoProofsProvided
	}

	firstSecret, err := nut10.DeserializeSecret(inputs[0].Secret)
	if err != nil {
		return err
	}
	if firstSecret.Kind != nut10.HTLC {
		errmsg := "VerifySigAllHTLCProofs requires HTLC conditions"
		return cashu.BuildCashuError(errmsg, NUT14ErrCode)
	}

	// NUT-11: if one input is SIG_ALL, all inputs MUST share the same
	// Secret.data and Secret.tags.
	for _, proof := range inputs {
		secret, err := nut10.DeserializeSecret(proof.Secret)
		if err != nil {
			return err
		}
		if secret.Kind != nut10.HTLC || !nut11.IsSigAll(secret) {
			return nut11.AllSigAllFlagsErr
		}
		if secret.Data.Data != firstSecret.Data.Data || len(secret.Data.Tags) != len(firstSecret.Data.Tags) {
			return nut11.SigAllInputsNotUniformErr
		}
		for i := range secret.Data.Tags {
			if !slices.Equal(secret.Data.Tags[i], firstSecret.Data.Tags[i]) {
				return nut11.SigAllInputsNotUniformErr
			}
		}
	}

	p2pkTags, err := nut11.ParseP2PKTags(firstSecret.Data.Tags)
	if err != nil {
		return err
	}

	var witness HTLCWitness
	if inputs[0].Witness != "" {
		if err := json.Unmarshal([]byte(inputs[0].Witness), &witness); err != nil {
			return nut11.InvalidWitness
		}
	}

	msgHash := sha256.Sum256(nut11.SigAllMessage(inputs, outputs, quoteId))

	// Locktime semantics: expiry ADDS the refund pathway.
	if p2pkTags.Locktime > 0 && time.Now().Unix() > p2pkTags.Locktime {
		if len(p2pkTags.Refund) == 0 {
			// no refund keys: unlocked after expiry, spendable by anyone
			return nil
		}
		if nut11.HasDuplicateKeys(p2pkTags.Refund) {
			return nut11.DuplicatePubkeysErr
		}
		if len(witness.Signatures) >= 1 && !nut11.DuplicateSignatures(witness.Signatures) {
			refundRequired := 1
			if p2pkTags.NSigsRefund > 0 {
				refundRequired = p2pkTags.NSigsRefund
			}
			if nut11.HasValidSignatures(msgHash[:], witness.Signatures, refundRequired, p2pkTags.Refund) {
				return nil
			}
		}
		// refund path did not verify — fall through to the receiver path
	}

	// Receiver path: the preimage must hash to Secret.data.
	preimageBytes, err := hex.DecodeString(witness.Preimage)
	if err != nil {
		return InvalidPreimageErr
	}
	hashBytes := sha256.Sum256(preimageBytes)
	hash := hex.EncodeToString(hashBytes[:])
	if len(firstSecret.Data.Data) != 64 {
		return InvalidHashErr
	}
	if hash != firstSecret.Data.Data {
		return InvalidPreimageErr
	}

	// Aggregate signatures when the pubkeys tag (or n_sigs) demands them.
	verifySigs := p2pkTags.NSigs
	if verifySigs == 0 && len(p2pkTags.Pubkeys) > 0 {
		verifySigs = 1
	}
	if verifySigs > 0 {
		if nut11.HasDuplicateKeys(p2pkTags.Pubkeys) {
			return nut11.DuplicatePubkeysErr
		}
		if len(witness.Signatures) < 1 {
			return nut11.NoSignaturesErr
		}
		if nut11.DuplicateSignatures(witness.Signatures) {
			return nut11.DuplicateSignaturesErr
		}
		if !nut11.HasValidSignatures(msgHash[:], witness.Signatures, verifySigs, p2pkTags.Pubkeys) {
			return nut11.NotEnoughSignaturesErr
		}
	}

	return nil
}

// AddSigAllHTLCToFirstInput produces the spec-conformant HTLC SIG_ALL
// witness: the preimage and the aggregate signatures go ONLY in the
// first input's witness (tollgate #809: gonuts previously signed each
// output's B_ — a construction no other implementation accepts).
func AddSigAllHTLCToFirstInput(
	inputs cashu.Proofs,
	outputs cashu.BlindedMessages,
	quoteId string,
	preimage string,
	signingKeys ...*btcec.PrivateKey,
) (cashu.Proofs, error) {
	if len(inputs) == 0 {
		return nil, cashu.NoProofsProvided
	}
	msgHash := sha256.Sum256(nut11.SigAllMessage(inputs, outputs, quoteId))

	signatures := make([]string, 0, len(signingKeys))
	for _, key := range signingKeys {
		signature, err := schnorr.Sign(key, msgHash[:])
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, hex.EncodeToString(signature.Serialize()))
	}

	witness, err := json.Marshal(HTLCWitness{Preimage: preimage, Signatures: signatures})
	if err != nil {
		return nil, err
	}
	inputs[0].Witness = string(witness)
	for i := 1; i < len(inputs); i++ {
		inputs[i].Witness = ""
	}
	return inputs, nil
}
