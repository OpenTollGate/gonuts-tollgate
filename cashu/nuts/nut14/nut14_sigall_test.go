package nut14

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut11"
	"github.com/btcsuite/btcd/btcec/v2"
)

// htlcSigAllProofs builds n HTLC SIG_ALL-locked proofs (fixed C values —
// the group verifier only reads C as part of the aggregate message).
func htlcSigAllProofs(t *testing.T, n int, hashHex string, tags [][]string) cashu.Proofs {
	t.Helper()
	secretStr, err := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.HTLC,
		Data: nut10.SecretData{Nonce: "nonce", Data: hashHex, Tags: tags},
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
			C:      "cafe",
		}
	}
	return proofs
}

func htlcPreimage(t *testing.T) (string, string) {
	t.Helper()
	preimage := make([]byte, 32)
	if _, err := rand.Read(preimage); err != nil {
		t.Fatal(err)
	}
	preimageHex := hex.EncodeToString(preimage)
	hash := sha256Hex(preimage)
	return preimageHex, hash
}

func TestSigAllHTLCPreimageOnlySpends(t *testing.T) {
	preimage, hash := htlcPreimage(t)
	outputs := cashu.BlindedMessages{{Amount: 4, B_: "02ab"}}
	tags := [][]string{{"sigflag", "SIG_ALL"}}
	proofs := htlcSigAllProofs(t, 2, hash, tags)

	signed, err := AddSigAllHTLCToFirstInput(proofs, outputs, "", preimage)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(signed, outputs, ""); err != nil {
		t.Fatalf("preimage-only HTLC SIG_ALL (no pubkeys) must spend: %v", err)
	}

	// wrong preimage rejected
	wrongPreimage := make([]byte, 32)
	rand.Read(wrongPreimage)
	badSigned, err := AddSigAllHTLCToFirstInput(
		htlcSigAllProofs(t, 2, hash, tags), outputs, "",
		hex.EncodeToString(wrongPreimage))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(badSigned, outputs, ""); err == nil {
		t.Fatal("wrong preimage must be rejected")
	}

	// witness on a non-first input rejected
	misplaced := htlcSigAllProofs(t, 2, hash, tags)
	misplaced[0].Witness = ""
	misplaced[1].Witness = signed[0].Witness
	if err := VerifySigAllHTLCProofs(misplaced, outputs, ""); err == nil {
		t.Fatal("witness on a non-first input must be rejected")
	}
}

func TestSigAllHTLCPreimageAndSignatures(t *testing.T) {
	preimage, hash := htlcPreimage(t)
	signer, _ := btcec.NewPrivateKey()
	wrongKey, _ := btcec.NewPrivateKey()
	outputs := cashu.BlindedMessages{{Amount: 4, B_: "02ab"}}
	tags := [][]string{
		{"sigflag", "SIG_ALL"},
		{"pubkeys", hex.EncodeToString(signer.PubKey().SerializeCompressed())},
	}

	signed, err := AddSigAllHTLCToFirstInput(
		htlcSigAllProofs(t, 2, hash, tags), outputs, "", preimage, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(signed, outputs, ""); err != nil {
		t.Fatalf("preimage + signature must verify: %v", err)
	}

	// wrong signer rejected
	badSigned, err := AddSigAllHTLCToFirstInput(
		htlcSigAllProofs(t, 2, hash, tags), outputs, "", preimage, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(badSigned, outputs, ""); err == nil {
		t.Fatal("wrong signer must be rejected")
	}

	// tampered outputs rejected (aggregate covers them)
	tamperedOutputs := cashu.BlindedMessages{{Amount: 4, B_: "02cd"}}
	if err := VerifySigAllHTLCProofs(signed, tamperedOutputs, ""); err == nil {
		t.Fatal("signature over different outputs must be rejected")
	}
}

func TestSigAllHTLCMultisig2of3(t *testing.T) {
	preimage, hash := htlcPreimage(t)
	keyA, _ := btcec.NewPrivateKey()
	keyB, _ := btcec.NewPrivateKey()
	keyC, _ := btcec.NewPrivateKey()
	outputs := cashu.BlindedMessages{{Amount: 4, B_: "02ab"}}
	tags := [][]string{
		{"sigflag", "SIG_ALL"},
		{"n_sigs", "2"},
		{"pubkeys",
			hex.EncodeToString(keyA.PubKey().SerializeCompressed()),
			hex.EncodeToString(keyB.PubKey().SerializeCompressed()),
			hex.EncodeToString(keyC.PubKey().SerializeCompressed())},
	}

	oneSig, err := AddSigAllHTLCToFirstInput(
		htlcSigAllProofs(t, 2, hash, tags), outputs, "", preimage, keyA)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(oneSig, outputs, ""); err == nil {
		t.Fatal("1-of-3 must NOT satisfy n_sigs=2")
	}

	twoSig, err := AddSigAllHTLCToFirstInput(
		htlcSigAllProofs(t, 2, hash, tags), outputs, "", preimage, keyB, keyC)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(twoSig, outputs, ""); err != nil {
		t.Fatalf("2-of-3 must verify: %v", err)
	}
}

func TestSigAllHTLCLocktimeAdditive(t *testing.T) {
	preimage, hash := htlcPreimage(t)
	primary, _ := btcec.NewPrivateKey()
	refundKey, _ := btcec.NewPrivateKey()
	outputs := cashu.BlindedMessages{{Amount: 4, B_: "02ab"}}

	// expired + no refund keys → anyone-can-spend
	expired := [][]string{{"sigflag", "SIG_ALL"}, {"locktime", "1"}}
	bare := htlcSigAllProofs(t, 2, hash, expired)
	if err := VerifySigAllHTLCProofs(bare, outputs, ""); err != nil {
		t.Fatalf("expired lock without refund keys must be anyone-can-spend: %v", err)
	}

	// expired + refund keys → refund path (aggregate sigs) verifies
	expiredRefund := [][]string{
		{"sigflag", "SIG_ALL"},
		{"locktime", "1"},
		{"pubkeys", hex.EncodeToString(primary.PubKey().SerializeCompressed())},
		{"refund", hex.EncodeToString(refundKey.PubKey().SerializeCompressed())},
	}
	refundSigned, err := AddSigAllHTLCToFirstInput(
		htlcSigAllProofs(t, 2, hash, expiredRefund), outputs, "", "00", refundKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(refundSigned, outputs, ""); err != nil {
		t.Fatalf("refund path after expiry must verify (preimage may be absent): %v", err)
	}

	// expired + refund keys → receiver path STILL works (additive)
	receiverSigned, err := AddSigAllHTLCToFirstInput(
		htlcSigAllProofs(t, 2, hash, expiredRefund), outputs, "", preimage, primary)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(receiverSigned, outputs, ""); err != nil {
		t.Fatalf("receiver path after expiry must still verify: %v", err)
	}
}

func TestSigAllHTLCRejectsNonUniformInputs(t *testing.T) {
	preimage, hash := htlcPreimage(t)
	outputs := cashu.BlindedMessages{{Amount: 4, B_: "02ab"}}
	signer, _ := btcec.NewPrivateKey()

	tagsA := [][]string{{"sigflag", "SIG_ALL"}}
	tagsB := [][]string{{"sigflag", "SIG_ALL"}, {"locktime", "1"}}
	secretA, _ := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.HTLC,
		Data: nut10.SecretData{Nonce: "n", Data: hash, Tags: tagsA},
	})
	secretB, _ := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.HTLC,
		Data: nut10.SecretData{Nonce: "n", Data: hash, Tags: tagsB},
	})
	proofs := cashu.Proofs{{Secret: secretA, C: "aa"}, {Secret: secretB, C: "bb"}}
	signed, err := AddSigAllHTLCToFirstInput(proofs, outputs, "", preimage, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(signed, outputs, ""); err == nil {
		t.Fatal("inputs with differing tags must be rejected")
	}

	// a P2PK SIG_ALL input mixed in → kind-uniformity rejection
	p2pkSecret, _ := nut10.SerializeSecret(nut10.WellKnownSecret{
		Kind: nut10.P2PK,
		Data: nut10.SecretData{
			Nonce: "n",
			Data:  hex.EncodeToString(signer.PubKey().SerializeCompressed()),
			Tags:  [][]string{{"sigflag", "SIG_ALL"}},
		},
	})
	mixed := htlcSigAllProofs(t, 2, hash, tagsA)
	mixed[1].Secret = p2pkSecret
	mixedSigned, err := AddSigAllHTLCToFirstInput(mixed, outputs, "", preimage, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySigAllHTLCProofs(mixedSigned, outputs, ""); err == nil {
		t.Fatal("mixed-kind inputs must be rejected by the HTLC verifier")
	}
	if err := nut11.VerifySigAllProofs(mixedSigned, outputs, ""); err == nil {
		t.Fatal("mixed-kind inputs must be rejected by the P2PK verifier too")
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
