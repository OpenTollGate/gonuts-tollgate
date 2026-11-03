package mint

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// internalTestOutputs builds n 8-sat blinded messages directly (no
// testutils dependency — it cannot be imported from package mint) and
// returns the secrets/blinding factors for proof construction.
func internalTestOutputs(keysetId string, n int) (cashu.BlindedMessages, []string, []*secp256k1.PrivateKey) {
	outputs := make(cashu.BlindedMessages, n)
	secrets := make([]string, n)
	rs := make([]*secp256k1.PrivateKey, n)
	for i := 0; i < n; i++ {
		secretBytes := make([]byte, 32)
		rand.Read(secretBytes)
		secrets[i] = hex.EncodeToString(secretBytes)
		r, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			panic(err)
		}
		rs[i] = r
		B_, _, err := crypto.BlindMessage(secrets[i], r)
		if err != nil {
			panic(err)
		}
		outputs[i] = cashu.NewBlindedMessage(keysetId, 8, B_)
	}
	return outputs, secrets, rs
}

// internalTestProofs mints n valid 8-sat proofs (unblinds with
// crypto.UnblindSignature against the active keyset).
func internalTestProofs(t *testing.T, m *Mint, n int) cashu.Proofs {
	t.Helper()
	quote, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{
		Amount: uint64(8 * n),
		Unit:   cashu.Sat.String(),
	})
	if err != nil {
		t.Fatalf("error requesting mint quote: %v", err)
	}
	keyset := m.GetActiveKeyset()
	outputs, secrets, rs := internalTestOutputs(keyset.Id, n)
	sigs, err := m.MintTokens(nut04.PostMintBolt11Request{Quote: quote.Id, Outputs: outputs})
	if err != nil {
		t.Fatalf("error minting tokens: %v", err)
	}
	proofs := make(cashu.Proofs, len(sigs))
	for i, sig := range sigs {
		C_bytes, err := hex.DecodeString(sig.C_)
		if err != nil {
			t.Fatal(err)
		}
		C_, err := secp256k1.ParsePubKey(C_bytes)
		if err != nil {
			t.Fatal(err)
		}
		A := keyset.Keys[outputs[i].Amount]
		C := crypto.UnblindSignature(C_, rs[i], A)
		proofs[i] = cashu.Proof{
			Id:     keyset.Id,
			Amount: outputs[i].Amount,
			Secret: secrets[i],
			C:      hex.EncodeToString(C.SerializeCompressed()),
		}
	}
	return proofs
}

// TestMintQuoteConcurrentDoubleIssuance stages the double-issuance race
// DETERMINISTICALLY: the mintQuoteClaimBarrier seam holds both callers
// between their quote read and the Paid->Pending CAS claim, so both have
// read Paid before either claims — exactly the interleaving where only
// the CAS (not the advisory read-check) prevents double issuance.
// cashu-audit #59: the mutant that ignores the CAS verdict fails with
// two issuances.
func TestMintQuoteConcurrentDoubleIssuance(t *testing.T) {
	m, err := LoadMint(Config{
		MintPath:        t.TempDir(),
		LightningClient: &lightning.FakeBackend{},
		LogLevel:        Disable,
	})
	if err != nil {
		t.Fatalf("error loading mint: %v", err)
	}
	const rounds = 10

	for round := 0; round < rounds; round++ {
		quote, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{
			Amount: 8,
			Unit:   cashu.Sat.String(),
		})
		if err != nil {
			t.Fatalf("error requesting mint quote: %v", err)
		}

		keyset := m.GetActiveKeyset()
		outsA, _, _ := internalTestOutputs(keyset.Id, 1)
		outsB, _, _ := internalTestOutputs(keyset.Id, 1)

		// two-party barrier: both callers pass the quote read, then wait
		// for each other, then race to the claim.
		var barrier sync.WaitGroup
		barrier.Add(2)
		prevBarrier := mintQuoteClaimBarrier
		mintQuoteClaimBarrier = func() {
			barrier.Done()
			barrier.Wait()
		}

		errs := make([]error, 2)
		sigs := make([]cashu.BlindedSignatures, 2)
		var wg sync.WaitGroup
		for i, outs := range []cashu.BlindedMessages{outsA, outsB} {
			wg.Add(1)
			go func(i int, outs cashu.BlindedMessages) {
				defer wg.Done()
				s, err := m.MintTokens(nut04.PostMintBolt11Request{Quote: quote.Id, Outputs: outs})
				errs[i] = err
				sigs[i] = s
			}(i, outs)
		}
		wg.Wait()
		mintQuoteClaimBarrier = prevBarrier

		winners := 0
		for _, err := range errs {
			if err == nil {
				winners++
			}
		}
		if winners != 1 {
			q, _ := m.GetMintQuoteState(quote.Id)
			t.Fatalf("round %d: exactly one mint must issue, got %d (errs: %v / %v; sigs: %d / %d; finalState: %v)",
				round, winners, errs[0], errs[1], len(sigs[0]), len(sigs[1]), q.State)
		}

		finalQuote, err := m.GetMintQuoteState(quote.Id)
		if err != nil {
			t.Fatal(err)
		}
		if finalQuote.State != nut04.Issued {
			t.Fatalf("round %d: quote must end Issued, got %v", round, finalQuote.State)
		}
	}
}

// TestSwapSameProofsConcurrentDoubleSpend stages the swap-side race
// deterministically: the swapClaimBarrier seam holds both callers between
// their read-checks and the proof claim, so both verified before either
// claims — the interleaving where only the claim (not the read-checks)
// prevents signing the same proofs twice (cashu-audit #59).
func TestSwapSameProofsConcurrentDoubleSpend(t *testing.T) {
	m, err := LoadMint(Config{
		MintPath:        t.TempDir(),
		LightningClient: &lightning.FakeBackend{},
		LogLevel:        Disable,
	})
	if err != nil {
		t.Fatalf("error loading mint: %v", err)
	}
	const rounds = 10

	for round := 0; round < rounds; round++ {
		proofs := internalTestProofs(t, m, 1)
		keyset := m.GetActiveKeyset()
		outsA, _, _ := internalTestOutputs(keyset.Id, 1)
		outsB, _, _ := internalTestOutputs(keyset.Id, 1)

		var barrier sync.WaitGroup
		barrier.Add(2)
		prevBarrier := swapClaimBarrier
		swapClaimBarrier = func() {
			barrier.Done()
			barrier.Wait()
		}

		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, outs := range []cashu.BlindedMessages{outsA, outsB} {
			wg.Add(1)
			go func(i int, outs cashu.BlindedMessages) {
				defer wg.Done()
				_, err := m.Swap(proofs, outs)
				errs[i] = err
			}(i, outs)
		}
		wg.Wait()
		swapClaimBarrier = prevBarrier

		winners := 0
		for _, err := range errs {
			if err == nil {
				winners++
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: exactly one swap must sign, got %d (errs: %v / %v)",
				round, winners, errs[0], errs[1])
		}

		// the proofs must end spent, with no pending residue
		if _, err := m.Swap(proofs, outsB); err == nil {
			t.Fatalf("round %d: the spent proofs must not swap again", round)
		}
	}
}

// internalTestOutputsAmounts builds one output per requested amount.
func internalTestOutputsAmounts(keysetId string, amounts []uint64) (cashu.BlindedMessages, []string, []*secp256k1.PrivateKey) {
	outputs := make(cashu.BlindedMessages, len(amounts))
	secrets := make([]string, len(amounts))
	rs := make([]*secp256k1.PrivateKey, len(amounts))
	for i, amt := range amounts {
		secretBytes := make([]byte, 32)
		rand.Read(secretBytes)
		secrets[i] = hex.EncodeToString(secretBytes)
		r, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			panic(err)
		}
		rs[i] = r
		B_, _, err := crypto.BlindMessage(secrets[i], r)
		if err != nil {
			panic(err)
		}
		outputs[i] = cashu.NewBlindedMessage(keysetId, amt, B_)
	}
	return outputs, secrets, rs
}
