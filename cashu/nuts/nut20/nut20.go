package nut20

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// NUT #20: This NUT defines signature-based authentication for mint quote redemption.

// buildMessageToSign constructs the NUT-20 spec message:
// quote_id || hex(B_) of each output, concatenated in request order.
//
// This is the format cdk mints verify (cashubtc/cdk nut20.rs
// legacy_mint_quote_msg_to_sign), accepted both by cdk versions that predate
// the domain-separated variant and by newer ones via their legacy fallback.
// The domain-separated "Cashu_MintQuoteSig_v1" framing is NOT understood by
// cdk mints currently deployed (verified against testnut.cashu.space:
// spec format mints, domain-separated is rejected with
// "Signature missing or invalid").
func buildMessageToSign(quoteId string, blindedMessages cashu.BlindedMessages) []byte {
	var msg []byte
	msg = append(msg, quoteId...)
	for _, bm := range blindedMessages {
		msg = append(msg, bm.B_...)
	}
	return msg
}

func SignMintQuote(
	privateKey *secp256k1.PrivateKey,
	quoteId string,
	blindedMessages cashu.BlindedMessages,
) (*schnorr.Signature, error) {
	msg := buildMessageToSign(quoteId, blindedMessages)
	hash := sha256.Sum256(msg)
	sig, err := schnorr.Sign(privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// NUT #20: `pubkey` is the compressed secp256k1 public key (33 bytes, hex-encoded) that will be required for signature verification during the minting operation.
// Dual-accept: the legacy cdk framing first (deployed-mint compatibility,
// see buildMessageToSign), then the spec's domain-separated
// `Cashu_MintQuoteSig_v1` framing (nuts/20.md:106-124) — tag ||
// len32(quote) || quote || per output len32(amount)||amount ||
// len32(B_)||B_, amounts as canonical minimal big-endian (0 -> empty),
// B_ decoded from hex to raw bytes.
func VerifyMintQuoteSignature(
	signature *schnorr.Signature,
	quoteId string,
	blindedMessages cashu.BlindedMessages,
	publicKey *secp256k1.PublicKey,
) bool {
	legacyMsg := buildMessageToSign(quoteId, blindedMessages)
	legacyHash := sha256.Sum256(legacyMsg)
	if signature.Verify(legacyHash[:], publicKey) {
		return true
	}

	specHash := sha256.Sum256(buildSpecMessage(quoteId, blindedMessages))
	return signature.Verify(specHash[:], publicKey)
}

// buildSpecMessage constructs the NUT-20 spec message
// (nuts/20.md "Message to sign"): domain-separation tag, then
// length-prefixed quote id and per-output amount and B_ fields.
func buildSpecMessage(quoteId string, blindedMessages cashu.BlindedMessages) []byte {
	var msg []byte
	msg = append(msg, "Cashu_MintQuoteSig_v1"...)

	quoteBytes := []byte(quoteId)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(quoteBytes)))
	msg = append(msg, quoteBytes...)

	for _, bm := range blindedMessages {
		amountBytes := canonicalAmountBytes(bm.Amount)
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(amountBytes)))
		msg = append(msg, amountBytes...)

		bBytes, err := hex.DecodeString(bm.B_)
		if err != nil {
			// a non-hex B_ can never match a spec-format signature; keep
			// the message well-formed by appending nothing after its
			// zero length prefix
			msg = binary.BigEndian.AppendUint32(msg, 0)
			continue
		}
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(bBytes)))
		msg = append(msg, bBytes...)
	}
	return msg
}

// canonicalAmountBytes encodes an amount as minimal big-endian bytes
// (nuts/20.md: 0 -> empty, 1 -> 0x01, 256 -> 0x0100).
func canonicalAmountBytes(amount uint64) []byte {
	if amount == 0 {
		return nil
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, amount)
	i := 0
	for i < len(buf) && buf[i] == 0 {
		i++
	}
	return buf[i:]
}
