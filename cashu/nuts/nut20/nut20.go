package nut20

import (
	"crypto/sha256"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// NUT #20: This NUT defines signature-based authentication for mint quote redemption.
func SignMintQuote(
	privateKey *secp256k1.PrivateKey,
	quoteId string,
	blindedMessages cashu.BlindedMessages,
) (*schnorr.Signature, error) {
	msg := quoteId
	for _, bm := range blindedMessages {
		msg += bm.B_
	}

	// NUT #20: To mint a quote where a public key was provided, the wallet includes a signature on `msg_to_sign` in the `PostMintBolt11Request`.
	hash := sha256.Sum256([]byte(msg))
	sig, err := schnorr.Sign(privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// NUT #20: `pubkey` is the compressed secp256k1 public key (33 bytes, hex-encoded) that will be required for signature verification during the minting operation.
func VerifyMintQuoteSignature(
	signature *schnorr.Signature,
	quoteId string,
	blindedMessages cashu.BlindedMessages,
	publicKey *secp256k1.PublicKey,
) bool {
	msg := quoteId
	for _, bm := range blindedMessages {
		msg += bm.B_
	}
	hash := sha256.Sum256([]byte(msg))

	// NUT #20: If the wallet user `Alice` does not include a signature on the `PostMintBolt11Request` but did include a `pubkey` in the `PostMintBolt11QuoteRequest` then `Bob` **MUST** respond with an error.
	return signature.Verify(hash[:], publicKey)
}
