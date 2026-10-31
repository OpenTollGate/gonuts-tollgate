package nut20

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestVerifyMintQuoteSignatureDualAccept: a legacy-format signature (cdk
// quote_id||hex(B_)) AND a spec-format signature (domain-separated
// Cashu_MintQuoteSig_v1, nuts/20.md) must both verify.
func TestVerifyMintQuoteSignatureDualAccept(t *testing.T) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	quoteId := "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8"
	outputs := cashu.BlindedMessages{
		{Amount: 4, B_: "02" + hex.EncodeToString(make([]byte, 31)) + "aa"},
		{Amount: 1, B_: "03" + hex.EncodeToString(make([]byte, 31)) + "bb"},
	}

	// legacy signature (SignMintQuote = quote_id || hex(B_))
	legacySig, err := SignMintQuote(key, quoteId, outputs)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyMintQuoteSignature(legacySig, quoteId, outputs, key.PubKey()) {
		t.Fatal("legacy-format signature must verify")
	}

	// spec signature: mirror the nuts/20.md message construction
	var msg []byte
	msg = append(msg, "Cashu_MintQuoteSig_v1"...)
	quoteBytes := []byte(quoteId)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(quoteBytes)))
	msg = append(msg, quoteBytes...)
	for _, o := range outputs {
		ab := canonicalAmountBytes(o.Amount)
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(ab)))
		msg = append(msg, ab...)
		bBytes, _ := hex.DecodeString(o.B_)
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(bBytes)))
		msg = append(msg, bBytes...)
	}
	specHash := sha256.Sum256(msg)
	specSig, err := schnorr.Sign(key, specHash[:])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyMintQuoteSignature(specSig, quoteId, outputs, key.PubKey()) {
		t.Fatal("spec-format (Cashu_MintQuoteSig_v1) signature must verify")
	}

	// a spec signature over DIFFERENT outputs must not verify
	tampered := cashu.BlindedMessages{
		{Amount: 4, B_: "02" + hex.EncodeToString(make([]byte, 31)) + "cc"},
	}
	if VerifyMintQuoteSignature(specSig, quoteId, tampered, key.PubKey()) {
		t.Fatal("spec signature over different outputs must be rejected")
	}

	// canonicalAmountBytes: 0 -> empty, 1 -> 0x01, 256 -> 0x0100
	if len(canonicalAmountBytes(0)) != 0 {
		t.Fatal("amount 0 must encode as empty")
	}
	if got := canonicalAmountBytes(1); len(got) != 1 || got[0] != 0x01 {
		t.Fatalf("amount 1 must encode as 0x01, got %x", got)
	}
	if got := canonicalAmountBytes(256); len(got) != 2 || got[0] != 0x01 || got[1] != 0x00 {
		t.Fatalf("amount 256 must encode as 0x0100, got %x", got)
	}
}
