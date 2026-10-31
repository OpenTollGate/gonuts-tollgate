package mint_test

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut11"
	"github.com/OpenTollGate/gonuts-tollgate/mint"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/OpenTollGate/gonuts-tollgate/mint/storage"
	"github.com/OpenTollGate/gonuts-tollgate/testutils"
	"github.com/btcsuite/btcd/btcec/v2"
)

// Regression tests for the melt-quote settlement races (cashu-audit #59 P0):
//
//  1. TestMeltQuoteConcurrentDoubleSettlement — two concurrent melts on ONE
//     quote with DISJOINT proof sets must settle exactly once. On the
//     unfixed code (unconditional Pending write after a read-check) both
//     melts paid — the TOCTOU found by the PR #58 conformance run.
//  2. TestMeltSameProofsTwoQuotesNoStrand — the same proofs raced across
//     TWO quotes must leave the losing quote retryable (Unpaid), never
//     stranded PENDING with no payment behind it (the AddPendingProofs
//     failure path after the CAS claim).

func newRaceTestMint(t *testing.T) (*mint.Mint, *lightning.FakeBackend) {
	t.Helper()
	fakeBackend := &lightning.FakeBackend{}
	m, err := mint.LoadMint(mint.Config{
		MintPath:        t.TempDir(),
		LightningClient: fakeBackend,
		LogLevel:        mint.Disable,
	})
	if err != nil {
		t.Fatalf("error loading mint: %v", err)
	}
	return m, fakeBackend
}

// raceTestProofs mints `amount` sats of valid proofs through the normal
// nut-04 flow. FakeBackend invoices are created settled, so no external
// payment step is needed.
func raceTestProofs(t *testing.T, m *mint.Mint, amount uint64) cashu.Proofs {
	t.Helper()
	quote, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{
		Amount: amount,
		Unit:   cashu.Sat.String(),
	})
	if err != nil {
		t.Fatalf("error requesting mint quote: %v", err)
	}
	keyset := m.GetActiveKeyset()
	blindedMessages, secrets, rs, err := testutils.CreateBlindedMessages(amount, keyset.Id)
	if err != nil {
		t.Fatalf("error creating blinded messages: %v", err)
	}
	signatures, err := m.MintTokens(nut04.PostMintBolt11Request{
		Quote:   quote.Id,
		Outputs: blindedMessages,
	})
	if err != nil {
		t.Fatalf("error minting tokens: %v", err)
	}
	proofs, err := testutils.ConstructProofs(signatures, secrets, rs, keyset)
	if err != nil {
		t.Fatalf("error constructing proofs: %v", err)
	}
	return proofs
}

func raceTestMeltQuote(t *testing.T, m *mint.Mint, backend *lightning.FakeBackend, amount uint64) storage.MeltQuote {
	t.Helper()
	invoice, err := backend.CreateInvoice(amount)
	if err != nil {
		t.Fatalf("error creating invoice: %v", err)
	}
	quote, err := m.RequestMeltQuote(nut05.PostMeltQuoteBolt11Request{
		Request: invoice.PaymentRequest,
		Unit:    cashu.Sat.String(),
	})
	if err != nil {
		t.Fatalf("error requesting melt quote: %v", err)
	}
	return quote
}

// runConcurrentMelts fires n melt attempts at `quote` concurrently (barrier
// start) and returns each attempt's error in submission order.
func runConcurrentMelts(t *testing.T, m *mint.Mint, inputsByAttempt []cashu.Proofs, quotes []storage.MeltQuote) []error {
	t.Helper()
	ctx := context.Background()
	attempts := len(inputsByAttempt)
	errs := make([]error, attempts)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		quote := quotes[i%len(quotes)]
		inputs := inputsByAttempt[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := m.MeltTokens(ctx, nut05.PostMeltBolt11Request{
				Quote:  quote.Id,
				Inputs: inputs,
			})
			errs[i] = err
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

func TestMeltQuoteConcurrentDoubleSettlement(t *testing.T) {
	m, backend := newRaceTestMint(t)
	const amount uint64 = 1000
	const rounds = 30

	for round := 0; round < rounds; round++ {
		quote := raceTestMeltQuote(t, m, backend, amount)
		setA := raceTestProofs(t, m, amount)
		setB := raceTestProofs(t, m, amount)

		errs := runConcurrentMelts(t, m, []cashu.Proofs{setA, setB}, []storage.MeltQuote{quote})

		winners := 0
		for _, err := range errs {
			if err == nil {
				winners++
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: exactly one melt must settle, got %d (errs: %v / %v)",
				round, winners, errs[0], errs[1])
		}

		finalQuote, err := m.GetMeltQuoteState(context.Background(), quote.Id)
		if err != nil {
			t.Fatalf("round %d: error getting melt quote state: %v", round, err)
		}
		if finalQuote.State != nut05.Paid {
			t.Fatalf("round %d: quote must end Paid, got %v", round, finalQuote.State)
		}
	}
}

func TestMeltSameProofsTwoQuotesNoStrand(t *testing.T) {
	m, backend := newRaceTestMint(t)
	const amount uint64 = 1000
	const rounds = 30

	for round := 0; round < rounds; round++ {
		quoteA := raceTestMeltQuote(t, m, backend, amount)
		quoteB := raceTestMeltQuote(t, m, backend, amount)
		proofs := raceTestProofs(t, m, amount)

		errs := runConcurrentMelts(t, m, []cashu.Proofs{proofs, proofs}, []storage.MeltQuote{quoteA, quoteB})

		winners := 0
		for _, err := range errs {
			if err == nil {
				winners++
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: same proofs must settle exactly one quote, got %d winners (errs: %v / %v)",
				round, winners, errs[0], errs[1])
		}

		// FakeBackend settles synchronously, so after both attempts return
		// every quote must have converged to Paid or Unpaid. A quote left
		// PENDING here is the stranded-claim signature: the quote was CAS'd,
		// AddPendingProofs then lost the secret-unique race, and no payment
		// ever happened behind it.
		for _, q := range []storage.MeltQuote{quoteA, quoteB} {
			finalQuote, err := m.GetMeltQuoteState(context.Background(), q.Id)
			if err != nil {
				t.Fatalf("round %d: error getting melt quote state: %v", round, err)
			}
			if finalQuote.State == nut05.Pending {
				t.Fatalf("round %d: quote %v stranded PENDING with no payment behind it "+
					"(AddPendingProofs failure path must roll the claim back to Unpaid)", round, q.Id)
			}
		}

		paidQuotes := 0
		for _, q := range []storage.MeltQuote{quoteA, quoteB} {
			finalQuote, err := m.GetMeltQuoteState(context.Background(), q.Id)
			if err != nil {
				t.Fatalf("round %d: error getting melt quote state: %v", round, err)
			}
			if finalQuote.State == nut05.Paid {
				paidQuotes++
			}
		}
		if paidQuotes != 1 {
			t.Fatalf("round %d: exactly one quote must be Paid, got %d", round, paidQuotes)
		}
	}
}

// TestMeltQuoteSequentialDoubleMelt: after a settled melt, a second melt on
// the same quote is rejected (the advisory read-check path, no race needed).
func TestMeltQuoteSequentialDoubleMelt(t *testing.T) {
	m, backend := newRaceTestMint(t)
	const amount uint64 = 1000

	quote := raceTestMeltQuote(t, m, backend, amount)
	proofs := raceTestProofs(t, m, amount)

	if _, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote:  quote.Id,
		Inputs: proofs,
	}); err != nil {
		t.Fatalf("first melt must succeed: %v", err)
	}

	secondProofs := raceTestProofs(t, m, amount)
	_, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote:  quote.Id,
		Inputs: secondProofs,
	})
	if !errors.Is(err, cashu.MeltQuoteAlreadyPaid) {
		t.Fatalf("sequential double melt must be rejected with MeltQuoteAlreadyPaid, got %v", err)
	}
}

// sigAllLockedProofs mints proofs locked to a SIG_ALL P2PK condition.
func sigAllLockedProofs(t *testing.T, m *mint.Mint, amount uint64, lockKey *btcec.PrivateKey) cashu.Proofs {
	t.Helper()
	condition := nut10.SpendingCondition{
		Kind: nut10.P2PK,
		Data: hex.EncodeToString(lockKey.PubKey().SerializeCompressed()),
		Tags: [][]string{{"sigflag", "SIG_ALL"}},
	}
	quote, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{Amount: amount, Unit: cashu.Sat.String()})
	if err != nil {
		t.Fatalf("error requesting mint quote: %v", err)
	}
	keyset := m.GetActiveKeyset()
	blindedMessages, secrets, rs, err := testutils.BlindedMessagesFromSpendingCondition(
		cashu.AmountSplit(amount), keyset.Id, condition)
	if err != nil {
		t.Fatalf("error creating locked blinded messages: %v", err)
	}
	signatures, err := m.MintTokens(nut04.PostMintBolt11Request{Quote: quote.Id, Outputs: blindedMessages})
	if err != nil {
		t.Fatalf("error minting locked tokens: %v", err)
	}
	proofs, err := testutils.ConstructProofs(signatures, secrets, rs, keyset)
	if err != nil {
		t.Fatalf("error constructing proofs: %v", err)
	}
	return proofs
}

func blankOutputs(t *testing.T, m *mint.Mint, n int) cashu.BlindedMessages {
	t.Helper()
	keyset := m.GetActiveKeyset()
	outputs, _, _, err := testutils.BlindedMessagesFromSpendingCondition(
		make([]uint64, n), keyset.Id, nut10.SpendingCondition{Kind: nut10.P2PK, Data: "00", Tags: nil})
	if err != nil {
		t.Fatalf("error creating blank outputs: %v", err)
	}
	return outputs
}

// TestSigAllSpecConstructionMeltAndSwap: spec-conformant SIG_ALL spends
// (first-input witness over the aggregated message) must be accepted by
// BOTH the melt and swap paths — pre-fix, melts were rejected outright
// (SigAllOnlySwap) and swaps demanded non-spec per-output witnesses
// (tollgate #809).
func TestSigAllSpecConstructionMeltAndSwap(t *testing.T) {
	m, backend := newRaceTestMint(t)
	const amount uint64 = 1000
	lockKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// --- melt ---
	quote := raceTestMeltQuote(t, m, backend, amount)
	proofs := sigAllLockedProofs(t, m, amount, lockKey)
	outputs := blankOutputs(t, m, 4)

	signed, err := nut11.AddSigAllSignatureToFirstInput(proofs, outputs, quote.Id, lockKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote:   quote.Id,
		Inputs:  signed,
		Outputs: outputs,
	}); err != nil {
		t.Fatalf("spec-conformant SIG_ALL melt must succeed: %v", err)
	}
	finalQuote, err := m.GetMeltQuoteState(context.Background(), quote.Id)
	if err != nil {
		t.Fatal(err)
	}
	if finalQuote.State != nut05.Paid {
		t.Fatalf("SIG_ALL melt quote must end Paid, got %v", finalQuote.State)
	}

	// wrong signer's witness must be rejected — and must NOT pay or claim
	quote2 := raceTestMeltQuote(t, m, backend, amount)
	proofs2 := sigAllLockedProofs(t, m, amount, lockKey)
	badSigned, err := nut11.AddSigAllSignatureToFirstInput(proofs2, outputs, quote2.Id, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote:   quote2.Id,
		Inputs:  badSigned,
		Outputs: outputs,
	}); err == nil {
		t.Fatal("SIG_ALL melt with a non-signer's witness must be rejected")
	}
	finalQuote2, err := m.GetMeltQuoteState(context.Background(), quote2.Id)
	if err != nil {
		t.Fatal(err)
	}
	if finalQuote2.State != nut05.Unpaid {
		t.Fatalf("rejected SIG_ALL melt must leave the quote Unpaid (retryable), got %v", finalQuote2.State)
	}

	// --- swap ---
	proofs3 := sigAllLockedProofs(t, m, amount, lockKey)
	swapOutputs, _, _, err := testutils.CreateBlindedMessages(amount, m.GetActiveKeyset().Id)
	if err != nil {
		t.Fatal(err)
	}
	swapSigned, err := nut11.AddSigAllSignatureToFirstInput(proofs3, swapOutputs, "", lockKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Swap(swapSigned, swapOutputs); err != nil {
		t.Fatalf("spec-conformant SIG_ALL swap must succeed: %v", err)
	}
}
