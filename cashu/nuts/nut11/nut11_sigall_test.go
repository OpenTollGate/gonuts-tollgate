package nut11

import (
	"encoding/hex"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
	"github.com/btcsuite/btcd/btcec/v2"
)

// sigAllTestProofs builds n SIG_ALL-locked proofs sharing the same secret
// data and tags, with a fixed deterministic C for message-vector tests.
func sigAllTestProofs(t *testing.T, n int, tags [][]string, dataKey *btcec.PublicKey) cashu.Proofs {
	t.Helper()
	secretStr, err := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.P2PK,
		Data: nut10.SecretData{
			Nonce: "nonce",
			Data:  hex.EncodeToString(dataKey.SerializeCompressed()),
			Tags:  tags,
		},
	})
	if err != nil {
		t.Fatalf("error serializing secret: %v", err)
	}
	proofs := make(cashu.Proofs, n)
	for i := range proofs {
		proofs[i] = cashu.Proof{
			Id:     "testkeyset",
			Amount: 4,
			Secret: secretStr,
			C:      "c" + string(rune('a'+i)) + "fe",
		}
	}
	return proofs
}

func TestSigAllMessageVector(t *testing.T) {
	dataKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	proofs := sigAllTestProofs(t, 2, [][]string{{SIGFLAG, SIGALL}}, dataKey.PubKey())
	// override for a deterministic vector
	proofs[0].Secret = "secret0"
	proofs[0].C = "CAFE"
	proofs[1].Secret = "secret1"
	proofs[1].C = "BEEF"
	outputs := cashu.BlindedMessages{
		{Amount: 4, B_: "02aa"},
		{Amount: 2, B_: "03bb"},
	}

	got := string(SigAllMessage(proofs, outputs, "quote123"))
	want := "secret0" + "CAFE" + "secret1" + "BEEF" + "4" + "02aa" + "2" + "03bb" + "quote123"
	if got != want {
		t.Fatalf("SigAllMessage mismatch:\n got %q\nwant %q", got, want)
	}

	gotSwap := string(SigAllMessage(proofs, outputs, ""))
	wantSwap := "secret0" + "CAFE" + "secret1" + "BEEF" + "4" + "02aa" + "2" + "03bb"
	if gotSwap != wantSwap {
		t.Fatalf("SigAllMessage (swap, no quote) mismatch:\n got %q\nwant %q", gotSwap, wantSwap)
	}
}

func TestSigAllRoundTrip(t *testing.T) {
	dataKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	proofs := sigAllTestProofs(t, 3, [][]string{{SIGFLAG, SIGALL}}, dataKey.PubKey())
	outputs := cashu.BlindedMessages{{Amount: 8, B_: "02ab"}}

	signed, err := AddSigAllSignatureToFirstInput(proofs, outputs, "", dataKey)
	if err != nil {
		t.Fatalf("error signing: %v", err)
	}
	if signed[0].Witness == "" {
		t.Fatal("witness must be on the FIRST input")
	}
	for i := 1; i < len(signed); i++ {
		if signed[i].Witness != "" {
			t.Fatalf("input %d must not carry a witness in SIG_ALL", i)
		}
	}
	if err := VerifySigAllProofs(signed, outputs, ""); err != nil {
		t.Fatalf("valid SIG_ALL swap must verify: %v", err)
	}
}

func TestSigAllRejectsTampering(t *testing.T) {
	dataKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputs := cashu.BlindedMessages{{Amount: 8, B_: "02ab"}}

	signed, err := AddSigAllSignatureToFirstInput(
		sigAllTestProofs(t, 2, [][]string{{SIGFLAG, SIGALL}}, dataKey.PubKey()),
		outputs, "", dataKey)
	if err != nil {
		t.Fatal(err)
	}

	// tampered output must invalidate the aggregate signature
	tamperedOutputs := cashu.BlindedMessages{{Amount: 8, B_: "02cd"}}
	if err := VerifySigAllProofs(signed, tamperedOutputs, ""); err == nil {
		t.Fatal("signature over a different output set must be rejected")
	}

	// wrong quote id must invalidate a melt signature
	meltSigned, err := AddSigAllSignatureToFirstInput(
		sigAllTestProofs(t, 2, [][]string{{SIGFLAG, SIGALL}}, dataKey.PubKey()),
		outputs, "quoteAAA", dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(meltSigned, outputs, "quoteBBB"); err == nil {
		t.Fatal("signature over a different quote id must be rejected")
	}
	if err := VerifySigAllProofs(meltSigned, outputs, "quoteAAA"); err != nil {
		t.Fatalf("signature over the correct quote id must verify: %v", err)
	}

	// witness on the second input only must be rejected (first input carries it)
	misplaced := sigAllTestProofs(t, 2, [][]string{{SIGFLAG, SIGALL}}, dataKey.PubKey())
	misplaced[0].Witness = ""
	misplaced[1].Witness = signed[0].Witness
	if err := VerifySigAllProofs(misplaced, outputs, ""); err == nil {
		t.Fatal("witness on a non-first input must be rejected")
	}
}

func TestSigAllRejectsNonUniformInputs(t *testing.T) {
	dataKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputs := cashu.BlindedMessages{{Amount: 8, B_: "02ab"}}

	// same data key, different tags → non-uniform
	tagsA := [][]string{{SIGFLAG, SIGALL}}
	tagsB := [][]string{{SIGFLAG, SIGALL}, {LOCKTIME, "1"}}
	secretA, _ := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.P2PK,
		Data: nut10.SecretData{Nonce: "n", Data: hex.EncodeToString(dataKey.PubKey().SerializeCompressed()), Tags: tagsA},
	})
	secretB, _ := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.P2PK,
		Data: nut10.SecretData{Nonce: "n", Data: hex.EncodeToString(dataKey.PubKey().SerializeCompressed()), Tags: tagsB},
	})
	proofs := cashu.Proofs{{Secret: secretA, C: "aa"}, {Secret: secretB, C: "bb"}}
	signed, err := AddSigAllSignatureToFirstInput(proofs, outputs, "", dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(signed, outputs, ""); err == nil {
		t.Fatal("inputs with differing tags must be rejected")
	}

	// a SIG_INPUTS input mixed in → all-must-be-SIG_ALL
	mixed := sigAllTestProofs(t, 2, [][]string{}, dataKey.PubKey())
	mixedSecret, _ := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.P2PK,
		Data: nut10.SecretData{Nonce: "n", Data: hex.EncodeToString(dataKey.PubKey().SerializeCompressed()), Tags: [][]string{}},
	})
	mixed[1].Secret = mixedSecret
	signedMixed, err := AddSigAllSignatureToFirstInput(mixed, outputs, "", dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(signedMixed, outputs, ""); err == nil {
		t.Fatal("non-SIG_ALL input in a SIG_ALL group must be rejected")
	}
}

func TestSigAllTagValidation(t *testing.T) {
	// n_sigs=0 present → malformed, MUST reject (previously treated as absent)
	if _, err := ParseP2PKTags([][]string{{NSIGS, "0"}}); err == nil {
		t.Fatal("n_sigs=0 must be rejected as malformed")
	}
	if _, err := ParseP2PKTags([][]string{{NSIGSREFUND, "0"}}); err == nil {
		t.Fatal("n_sigs_refund=0 must be rejected as malformed")
	}
	if _, err := ParseP2PKTags([][]string{{NSIGS, "2"}}); err != nil {
		t.Fatalf("positive n_sigs must parse: %v", err)
	}

	// duplicate key within one pathway → malformed
	keyDup, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyOther, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	dupKey := hex.EncodeToString(keyDup.PubKey().SerializeCompressed())
	if _, err := ParseP2PKTags([][]string{{PUBKEYS, dupKey, dupKey}}); err != nil {
		t.Fatalf("parse of duplicate pubkeys tag: %v", err)
	}
	pkDup := keyDup.PubKey()
	pkOther := keyOther.PubKey()
	if !HasDuplicateKeys([]*btcec.PublicKey{pkDup, pkDup}) {
		t.Fatal("HasDuplicateKeys must detect duplicates")
	}
	if HasDuplicateKeys([]*btcec.PublicKey{pkDup, pkOther}) {
		t.Fatal("HasDuplicateKeys must not flag distinct keys")
	}

	// duplicate keys per pathway rejected at verify time
	dataKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputs := cashu.BlindedMessages{{Amount: 8, B_: "02ab"}}
	proofs := sigAllTestProofs(t, 2,
		[][]string{{SIGFLAG, SIGALL}, {PUBKEYS, dupKey, dupKey}}, dataKey.PubKey())
	signed, err := AddSigAllSignatureToFirstInput(proofs, outputs, "", dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(signed, outputs, ""); err == nil {
		t.Fatal("duplicate keys in the primary pathway must be rejected")
	}
}

func TestSigAllLocktimeAdditive(t *testing.T) {
	dataKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	refundKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	outputs := cashu.BlindedMessages{{Amount: 8, B_: "02ab"}}
	expired := [][]string{{SIGFLAG, SIGALL}, {LOCKTIME, "1"}} // long past

	// expired + no refund keys → anyone-can-spend: accepts with NO witness
	unlocked := sigAllTestProofs(t, 2, expired, dataKey.PubKey())
	if err := VerifySigAllProofs(unlocked, outputs, ""); err != nil {
		t.Fatalf("expired lock without refund keys must be anyone-can-spend: %v", err)
	}

	// expired + refund keys → refund path verifies (primary signer NOT needed)
	expiredRefund := [][]string{
		{SIGFLAG, SIGALL},
		{LOCKTIME, "1"},
		{REFUND, hex.EncodeToString(refundKey.PubKey().SerializeCompressed())},
	}
	refundSigned, err := AddSigAllSignatureToFirstInput(
		sigAllTestProofs(t, 2, expiredRefund, dataKey.PubKey()), outputs, "", refundKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(refundSigned, outputs, ""); err != nil {
		t.Fatalf("refund path after expiry must verify: %v", err)
	}

	// expired + refund keys → PRIMARY path still works (expiry is additive)
	primarySigned, err := AddSigAllSignatureToFirstInput(
		sigAllTestProofs(t, 2, expiredRefund, dataKey.PubKey()), outputs, "", dataKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(primarySigned, outputs, ""); err != nil {
		t.Fatalf("primary path after expiry must still verify (additive, not revoking): %v", err)
	}
}

func TestSigAllMultisigThreshold(t *testing.T) {
	keyA, _ := btcec.NewPrivateKey()
	keyB, _ := btcec.NewPrivateKey()
	keyC, _ := btcec.NewPrivateKey()
	outputs := cashu.BlindedMessages{{Amount: 8, B_: "02ab"}}

	tags := [][]string{
		{SIGFLAG, SIGALL},
		{NSIGS, "2"},
		{PUBKEYS,
			hex.EncodeToString(keyB.PubKey().SerializeCompressed()),
			hex.EncodeToString(keyC.PubKey().SerializeCompressed())},
	}

	// data key A + pubkeys B,C; 2-of-3
	oneSig, err := AddSigAllSignatureToFirstInput(
		sigAllTestProofs(t, 2, tags, keyA.PubKey()), outputs, "", keyA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(oneSig, outputs, ""); err == nil {
		t.Fatal("1-of-3 must NOT satisfy n_sigs=2")
	}

	twoSig, err := AddSigAllSignatureToFirstInput(
		sigAllTestProofs(t, 2, tags, keyA.PubKey()), outputs, "", keyA, keyC)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllProofs(twoSig, outputs, ""); err != nil {
		t.Fatalf("2-of-3 (data key + one pubkeys key) must verify: %v", err)
	}
}
