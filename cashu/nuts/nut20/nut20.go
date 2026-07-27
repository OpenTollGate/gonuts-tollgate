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

// buildMessageToSign constructs the NUT-20 binary message format:
// b"Cashu_MintQuoteSig_v1" || len32(quote) || quote || for each output: len32(amount) || amount || len32(B) || B
func buildMessageToSign(quoteId string, blindedMessages cashu.BlindedMessages) []byte {
	var msg []byte
	msg = append(msg, []byte("Cashu_MintQuoteSig_v1")...)

	quoteBytes := []byte(quoteId)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(quoteBytes)))
	msg = append(msg, lenBuf[:]...)
	msg = append(msg, quoteBytes...)

	for _, bm := range blindedMessages {
		amountBytes := canonicalAmountBytes(bm.Amount)
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(amountBytes)))
		msg = append(msg, lenBuf[:]...)
		msg = append(msg, amountBytes...)

		bBytes, err := hex.DecodeString(bm.B_)
		if err != nil {
			bBytes = []byte(bm.B_)
		}
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(bBytes)))
		msg = append(msg, lenBuf[:]...)
		msg = append(msg, bBytes...)
	}

	return msg
}

// canonicalAmountBytes converts an amount to minimal big-endian bytes (NUT-20 spec).
func canonicalAmountBytes(amount uint64) []byte {
	if amount == 0 {
		return []byte{}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], amount)
	for i := 0; i < 8; i++ {
		if buf[i] != 0 {
			return buf[i:]
		}
	}
	return buf[:]
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
func VerifyMintQuoteSignature(
	signature *schnorr.Signature,
	quoteId string,
	blindedMessages cashu.BlindedMessages,
	publicKey *secp256k1.PublicKey,
) bool {
	msg := buildMessageToSign(quoteId, blindedMessages)
	hash := sha256.Sum256(msg)
	return signature.Verify(hash[:], publicKey)
}
