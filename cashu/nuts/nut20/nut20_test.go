package nut20

import (
	"encoding/hex"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestSignMintQuote(t *testing.T) {
	privateKey, _ := secp256k1.GeneratePrivateKey()

	tests := []struct {
		quoteId    string
		outputs    cashu.BlindedMessages
		privateKey *secp256k1.PrivateKey
	}{
		{
			quoteId: "9d745270-1405-46de-b5c5-e2762b4f5e00",
			outputs: cashu.BlindedMessages{
				cashu.BlindedMessage{
					Amount: 1,
					Id:     "00456a94ab4e1c46",
					B_:     "0342e5bcc77f5b2a3c2afb40bb591a1e27da83cddc968abdc0ec4904201a201834",
				},
				cashu.BlindedMessage{
					Amount: 1,
					Id:     "00456a94ab4e1c46",
					B_:     "032fd3c4dc49a2844a89998d5e9d5b0f0b00dde9310063acb8a92e2fdafa4126d4",
				},
				cashu.BlindedMessage{
					Amount: 1,
					Id:     "00456a94ab4e1c46",
					B_:     "033b6fde50b6a0dfe61ad148fff167ad9cf8308ded5f6f6b2fe000a036c464c311",
				},
				cashu.BlindedMessage{
					Amount: 1,
					Id:     "00456a94ab4e1c46",
					B_:     "02be5a55f03e5c0aaea77595d574bce92c6d57a2a0fb2b5955c0b87e4520e06b53",
				},
				cashu.BlindedMessage{
					Amount: 1,
					Id:     "00456a94ab4e1c46",
					B_:     "02209fc2873f28521cbdde7f7b3bb1521002463f5979686fd156f23fe6a8aa2b79",
				},
			},
			privateKey: privateKey,
		},
	}

	for _, test := range tests {
		sig, err := SignMintQuote(test.privateKey, test.quoteId, test.outputs)
		if err != nil {
			t.Fatalf("got unexpected error signing mint quote: %v", err)
		}

		if !VerifyMintQuoteSignature(sig, test.quoteId, test.outputs, test.privateKey.PubKey()) {
			t.Fatal("generated invalid signature on mint quote")
		}
	}
}

func TestVerifyMintQuoteSignature(t *testing.T) {
	outputs := cashu.BlindedMessages{
		cashu.BlindedMessage{
			Amount: 1,
			Id:     "00456a94ab4e1c46",
			B_:     "0342e5bcc77f5b2a3c2afb40bb591a1e27da83cddc968abdc0ec4904201a201834",
		},
		cashu.BlindedMessage{
			Amount: 1,
			Id:     "00456a94ab4e1c46",
			B_:     "032fd3c4dc49a2844a89998d5e9d5b0f0b00dde9310063acb8a92e2fdafa4126d4",
		},
	}
	quoteId := "9d745270-1405-46de-b5c5-e2762b4f5e00"

	privKey, _ := secp256k1.GeneratePrivateKey()

	sig, err := SignMintQuote(privKey, quoteId, outputs)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	if !VerifyMintQuoteSignature(sig, quoteId, outputs, privKey.PubKey()) {
		t.Fatal("valid signature rejected")
	}

	otherPrivKey, _ := secp256k1.GeneratePrivateKey()
	if VerifyMintQuoteSignature(sig, quoteId, outputs, otherPrivKey.PubKey()) {
		t.Fatal("invalid signature accepted (wrong key)")
	}

	sigHex := hex.EncodeToString(sig.Serialize())
	pubHex := hex.EncodeToString(privKey.PubKey().SerializeCompressed())
	if len(sigHex) != 128 {
		t.Fatalf("signature hex length = %d, want 128", len(sigHex))
	}
	if len(pubHex) != 66 {
		t.Fatalf("pubkey hex length = %d, want 66", len(pubHex))
	}
}

func TestBuildMessageToSign(t *testing.T) {
	msg := buildMessageToSign("test", cashu.BlindedMessages{})
	expected := []byte("Cashu_MintQuoteSig_v1")
	if string(msg[:len(expected)]) != string(expected) {
		t.Fatalf("domain separator wrong: got %q", string(msg[:len(expected)]))
	}
}

func TestCanonicalAmountBytes(t *testing.T) {
	tests := []struct {
		amount uint64
		want   int
	}{
		{0, 0},
		{1, 1},
		{255, 1},
		{256, 2},
		{65535, 2},
		{65536, 3},
	}
	for _, tt := range tests {
		got := canonicalAmountBytes(tt.amount)
		if len(got) != tt.want {
			t.Errorf("canonicalAmountBytes(%d) length = %d, want %d", tt.amount, len(got), tt.want)
		}
	}
}
