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

// internalTestOutputs builds n zero-amount blinded messages directly (no
// testutils dependency — it cannot be imported from package mint).
func internalTestOutputs(keysetId string, n int) cashu.BlindedMessages {
	outputs := make(cashu.BlindedMessages, n)
	for i := 0; i < n; i++ {
		secretBytes := make([]byte, 32)
		rand.Read(secretBytes)
		secret := hex.EncodeToString(secretBytes)
		r, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			panic(err)
		}
		B_, _, err := crypto.BlindMessage(secret, r)
		if err != nil {
			panic(err)
		}
		outputs[i] = cashu.NewBlindedMessage(keysetId, 8, B_)
	}
	return outputs
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
		outsA := internalTestOutputs(keyset.Id, 1)
		outsB := internalTestOutputs(keyset.Id, 1)

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
