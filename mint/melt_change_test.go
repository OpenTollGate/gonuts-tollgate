package mint_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut12"
	"github.com/OpenTollGate/gonuts-tollgate/mint"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/OpenTollGate/gonuts-tollgate/mint/storage"
)

// NUT-08 melt change (cashu-audit #68 B3, the "gonuts never returns melt
// change" divergence): a melt that overpays — the fee reserve the backend
// did not spend, plus any over-funding — must return as blind signatures
// for the request's blank outputs, persist before the Paid write, and
// replay identically for a lost response.

func newMeltChangeMint(t *testing.T, backend lightning.Client, dbpath string) *mint.Mint {
	t.Helper()
	if dbpath == "" {
		dbpath = t.TempDir()
	}
	m, err := mint.LoadMint(mint.Config{
		MintPath:        dbpath,
		LightningClient: backend,
		LogLevel:        mint.Disable,
	})
	if err != nil {
		t.Fatalf("error loading mint: %v", err)
	}
	return m
}

// blankOutputs (shared with the CAS suite in melt_cas_test.go) creates n
// NUT-08 blank outputs (amount 0).

// partialFeeBackend wraps the FakeBackend so successful payments report a
// chosen fee actually spent (FeeSpentKnown) — the partial-fee e2e shape.
type partialFeeBackend struct {
	*lightning.FakeBackend
	feeSpent uint64
}

func (p *partialFeeBackend) SendPayment(ctx context.Context, request string, maxFee uint64) (lightning.PaymentStatus, error) {
	status, err := p.FakeBackend.SendPayment(ctx, request, maxFee)
	if err == nil && status.PaymentStatus == lightning.Succeeded {
		status.FeeSpent, status.FeeSpentKnown = p.feeSpent, true
	}
	return status, err
}

func (p *partialFeeBackend) OutgoingPaymentStatus(ctx context.Context, hash string) (lightning.PaymentStatus, error) {
	status, err := p.FakeBackend.OutgoingPaymentStatus(ctx, hash)
	if err == nil && status.PaymentStatus == lightning.Succeeded {
		status.FeeSpent, status.FeeSpentKnown = p.feeSpent, true
	}
	return status, err
}

// --- unit: the fee math ---

func TestMeltChangeTargetFeeMath(t *testing.T) {
	const amount, reserve uint64 = 21, 4
	const fees uint64 = 2
	quote := storage.MeltQuote{Amount: amount, FeeReserve: reserve}
	const inputs uint64 = amount + reserve + fees // exactly funded

	cases := []struct {
		name    string
		inputs  uint64
		payment lightning.PaymentStatus
		want    uint64
	}{
		// backend spent nothing: the whole reserve is overpaid
		{"fake backend spends nothing", inputs, lightning.PaymentStatus{FeeSpentKnown: true}, reserve},
		// partial fee: part of the reserve returns
		{"partial fee", inputs, lightning.PaymentStatus{FeeSpent: 1, FeeSpentKnown: true}, reserve - 1},
		// full fee: nothing of the reserve returns
		{"full fee consumed", inputs, lightning.PaymentStatus{FeeSpent: reserve, FeeSpentKnown: true}, 0},
		// backend cannot report: the reserve is never returned (operator
		// fund-safety), only over-funding beyond amount+reserve+fees
		{"unknown fee keeps the reserve", inputs, lightning.PaymentStatus{}, 0},
		// over-funding returns for every backend shape
		{"overfunded, fee unknown", inputs + 5, lightning.PaymentStatus{}, 5},
		{"overfunded, fee known zero", inputs + 5, lightning.PaymentStatus{FeeSpentKnown: true}, reserve + 5},
		// backend spent more than the reserve: saturates, never negative
		{"fee over reserve saturates", inputs, lightning.PaymentStatus{FeeSpent: reserve + 3, FeeSpentKnown: true}, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mint.MeltChangeTargetForTest(tc.inputs, fees, quote, tc.payment)
			if got != tc.want {
				t.Fatalf("change target = %d, want %d", got, tc.want)
			}
		})
	}
}

// --- unit: denomination split ---

func TestMeltChangeSplitAmounts(t *testing.T) {
	m := newMeltChangeMint(t, &lightning.FakeBackend{}, "")

	amounts, shortfall := m.SplitChangeAmountsForTest(7)
	if len(amounts) != 3 || amounts[0] != 4 || amounts[1] != 2 || amounts[2] != 1 || shortfall != 0 {
		t.Fatalf("split(7) = %v (shortfall %d), want [4 2 1]", amounts, shortfall)
	}
	if _, shortfall := m.SplitChangeAmountsForTest(0); shortfall != 0 {
		t.Fatal("split(0) must be empty with no shortfall")
	}
}

// --- e2e: overpaid reserve returns as change ---

func meltChangeE2E(t *testing.T, paymentBackend lightning.Client, invoiceBackend *lightning.FakeBackend, inputsAmount, invoiceAmount uint64, numBlanks int) (cashu.BlindedSignatures, cashu.BlindedMessages, storage.MeltQuote, *mint.Mint) {
	t.Helper()
	m := newMeltChangeMint(t, paymentBackend, "")

	proofs := raceTestProofs(t, m, inputsAmount)
	quote := raceTestMeltQuote(t, m, invoiceBackend, invoiceAmount)

	outputs := blankOutputs(t, m, numBlanks)
	meltQuote, change, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote:   quote.Id,
		Inputs:  proofs,
		Outputs: outputs,
	})
	if err != nil {
		t.Fatalf("melt with blank outputs failed: %v", err)
	}
	if meltQuote.State != nut05.Paid {
		t.Fatalf("melt state = %v, want PAID", meltQuote.State)
	}
	return change, outputs, quote, m
}

func verifyChangeSignatures(t *testing.T, m *mint.Mint, change cashu.BlindedSignatures, outputs cashu.BlindedMessages) {
	t.Helper()
	keyset := m.GetActiveKeyset()
	for i, sig := range change {
		if i >= len(outputs) {
			t.Fatalf("change carries more signatures (%d+) than blank outputs sent", i)
		}
		if sig.Id != outputs[i].Id {
			t.Fatalf("change signature %d answers keyset %s, blank output asked %s", i, sig.Id, outputs[i].Id)
		}
		if sig.Amount == 0 {
			t.Fatalf("change signature %d carries amount 0 (NUT-08: value signatures only)", i)
		}
		if sig.DLEQ == nil {
			t.Fatalf("change signature %d carries no DLEQ proof", i)
		}
		pubkey, ok := keyset.Keys[sig.Amount]
		if !ok {
			t.Fatalf("change amount %d has no key in the active keyset", sig.Amount)
		}
		if !nut12.VerifyBlindSignatureDLEQ(*sig.DLEQ, pubkey, outputs[i].B_, sig.C_) {
			t.Fatalf("change signature %d fails DLEQ verification against the keyset", i)
		}
	}
}

func TestMeltChangeReturnedForOverpaidReserve(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}

	// inputs 24, invoice 21, reserve 2, fake payment costs nothing:
	// change = 24 − 0 fees − 21 − 0 fee_spent = 3 → [2, 1]
	change, outputs, quote, m := meltChangeE2E(t, backend, backend, 24, 21, 2)

	if len(change) != 2 || change[0].Amount != 2 || change[1].Amount != 1 {
		t.Fatalf("change = %v, want [2 1] (3 sats overpay)", amountsOf(change))
	}
	if change.Amount() != 3 {
		t.Fatalf("change sum = %d, want 3", change.Amount())
	}
	verifyChangeSignatures(t, m, change, outputs)

	// the quote-state endpoint surfaces the same stored change
	if got := m.MeltQuoteChange(quote.Id); got.Amount() != 3 {
		t.Fatalf("MeltQuoteChange sum = %d, want 3", got.Amount())
	}
}

func TestMeltChangePartialFeeReturnsRemainder(t *testing.T) {
	backend := &partialFeeBackend{FakeBackend: &lightning.FakeBackend{FeeReserveSats: 4}, feeSpent: 1}

	// inputs 25, invoice 21, reserve 4, fee actually spent 1:
	// change = 25 − 21 − 1 = 3
	change, outputs, _, m := meltChangeE2E(t, backend, backend.FakeBackend, 25, 21, 2)
	if change.Amount() != 3 {
		t.Fatalf("change sum = %d, want 3 (reserve 4 − fee spent 1)", change.Amount())
	}
	verifyChangeSignatures(t, m, change, outputs)
}

func TestMeltChangeUnknownFeeKeepsReserve(t *testing.T) {
	// the raw FakeBackend reports its fee; a backend that does NOT is
	// modeled by clearing FeeSpentKnown on the wire result
	backend := &unknownFeeBackend{FakeBackend: &lightning.FakeBackend{FeeReserveSats: 2}}

	// inputs 24, invoice 21, reserve 2 unknown fee: only the over-funding
	// (24 − 21 − 2 = 1) returns; the unaccounted reserve stays
	change, outputs, _, m := meltChangeE2E(t, backend, backend.FakeBackend, 24, 21, 2)
	if change.Amount() != 1 {
		t.Fatalf("change sum = %d, want 1 (over-funding only; unknown fee keeps the reserve)", change.Amount())
	}
	verifyChangeSignatures(t, m, change, outputs)
}

type unknownFeeBackend struct {
	*lightning.FakeBackend
}

func (u *unknownFeeBackend) SendPayment(ctx context.Context, request string, maxFee uint64) (lightning.PaymentStatus, error) {
	status, err := u.FakeBackend.SendPayment(ctx, request, maxFee)
	status.FeeSpent, status.FeeSpentKnown = 0, false
	return status, err
}

func (u *unknownFeeBackend) OutgoingPaymentStatus(ctx context.Context, hash string) (lightning.PaymentStatus, error) {
	status, err := u.FakeBackend.OutgoingPaymentStatus(ctx, hash)
	status.FeeSpent, status.FeeSpentKnown = 0, false
	return status, err
}

func TestMeltChangeNoOutputsNoChange(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}
	m := newMeltChangeMint(t, backend, "")

	proofs := raceTestProofs(t, m, 24)
	quote := raceTestMeltQuote(t, m, backend, 21)

	meltQuote, change, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote:  quote.Id,
		Inputs: proofs,
	})
	if err != nil {
		t.Fatalf("melt without outputs failed: %v", err)
	}
	if meltQuote.State != nut05.Paid {
		t.Fatalf("melt state = %v, want PAID", meltQuote.State)
	}
	if len(change) != 0 {
		t.Fatalf("change without blank outputs = %v, want none (NUT-08: change only if outputs provided)", amountsOf(change))
	}
	if got := m.MeltQuoteChange(quote.Id); len(got) != 0 {
		t.Fatalf("MeltQuoteChange without outputs = %v, want none", amountsOf(got))
	}
}

func TestMeltChangeMoreDenominationsThanOutputsKeepsLargest(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}

	// change 7 = [4,2,1] but only 2 blank outputs: the two LARGEST return
	// ([4,2] = 6); the 1-sat remainder stays with the mint (reference
	// behavior: sort descending, sign what fits)
	change, outputs, _, m := meltChangeE2E(t, backend, backend, 28, 21, 2)
	if len(change) != 2 || change[0].Amount != 4 || change[1].Amount != 2 {
		t.Fatalf("change = %v, want [4 2] (largest two of [4 2 1])", amountsOf(change))
	}
	verifyChangeSignatures(t, m, change, outputs)
}

// --- replay: a lost response recovers identical change ---

func TestMeltChangeReplayIdenticalRequest(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}
	m := newMeltChangeMint(t, backend, "")

	proofs := raceTestProofs(t, m, 24)
	quote := raceTestMeltQuote(t, m, backend, 21)
	outputs := blankOutputs(t, m, 2)

	request := nut05.PostMeltBolt11Request{Quote: quote.Id, Inputs: proofs, Outputs: outputs}
	_, firstChange, err := m.MeltTokens(context.Background(), request)
	if err != nil {
		t.Fatalf("first melt: %v", err)
	}
	if firstChange.Amount() != 3 {
		t.Fatalf("first change = %d, want 3", firstChange.Amount())
	}

	// identical re-POST (the wallet-side crash-recovery replay): PAID with
	// the SAME change — not MeltQuoteAlreadyPaid
	replayQuote, replayChange, err := m.MeltTokens(context.Background(), request)
	if err != nil {
		t.Fatalf("identical replay of a paid melt must answer idempotently, got: %v", err)
	}
	if replayQuote.State != nut05.Paid {
		t.Fatalf("replay state = %v, want PAID", replayQuote.State)
	}
	if !sameChange(replayChange, firstChange) {
		t.Fatalf("replay change %+v differs from first %+v", replayChange, firstChange)
	}

	// a different output set on the PAID quote is NOT this melt: refused
	otherOutputs := blankOutputs(t, m, 2)
	_, _, err = m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote: quote.Id, Inputs: proofs, Outputs: otherOutputs,
	})
	if !errors.Is(err, cashu.MeltQuoteAlreadyPaid) {
		t.Fatalf("re-POST with foreign outputs must be refused with MeltQuoteAlreadyPaid, got %v", err)
	}
}

func TestMeltChangeSurvivesMintRestart(t *testing.T) {
	dbpath := t.TempDir()
	backend := &lightning.FakeBackend{FeeReserveSats: 2}
	m := newMeltChangeMint(t, backend, dbpath)

	proofs := raceTestProofs(t, m, 24)
	quote := raceTestMeltQuote(t, m, backend, 21)
	outputs := blankOutputs(t, m, 2)

	request := nut05.PostMeltBolt11Request{Quote: quote.Id, Inputs: proofs, Outputs: outputs}
	_, firstChange, err := m.MeltTokens(context.Background(), request)
	if err != nil {
		t.Fatalf("first melt: %v", err)
	}

	// "restart": a fresh mint process on the same database — no in-memory
	// state, no NUT-19 cache, keyset re-derived from the stored seed
	restarted := newMeltChangeMint(t, backend, dbpath)
	replayQuote, replayChange, err := restarted.MeltTokens(context.Background(), request)
	if err != nil {
		t.Fatalf("post-restart replay of a paid melt must answer idempotently, got: %v", err)
	}
	if replayQuote.State != nut05.Paid {
		t.Fatalf("post-restart replay state = %v, want PAID", replayQuote.State)
	}
	if !sameChange(replayChange, firstChange) {
		t.Fatalf("post-restart change %+v differs from first %+v", replayChange, firstChange)
	}
	if got := restarted.MeltQuoteChange(quote.Id); got.Amount() != firstChange.Amount() {
		t.Fatalf("post-restart MeltQuoteChange = %d, want %d", got.Amount(), firstChange.Amount())
	}
}

// --- the poll-path reconciler signs change for pending-settling payments ---

func TestMeltChangePollPathReconciliation(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2, PaymentDelay: 2}
	m := newMeltChangeMint(t, backend, "")

	proofs := raceTestProofs(t, m, 24)
	quote := raceTestMeltQuote(t, m, backend, 21)
	outputs := blankOutputs(t, m, 2)

	pendingQuote, change, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote: quote.Id, Inputs: proofs, Outputs: outputs,
	})
	if err != nil {
		t.Fatalf("melt against delayed payment failed: %v", err)
	}
	if pendingQuote.State != nut05.Pending || len(change) != 0 {
		t.Fatalf("delayed melt must return PENDING with no change, got %v/%v", pendingQuote.State, amountsOf(change))
	}

	// the payment settles behind the mint's back; the poll reconciler must
	// settle the quote AND sign the change from the journaled outputs
	time.Sleep(3 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	settled, err := m.GetMeltQuoteState(ctx, quote.Id)
	if err != nil {
		t.Fatalf("poll reconciliation failed: %v", err)
	}
	if settled.State != nut05.Paid {
		t.Fatalf("reconciled state = %v, want PAID", settled.State)
	}
	if got := m.MeltQuoteChange(quote.Id); got.Amount() != 3 {
		t.Fatalf("poll-path change = %d, want 3 (signed by the reconciler)", got.Amount())
	}
}

// --- validation: bad blank outputs are refused BEFORE the quote claim ---

func TestMeltChangeValidationRefusedBeforeClaim(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}
	m := newMeltChangeMint(t, backend, "")

	cases := []struct {
		name    string
		outputs cashu.BlindedMessages
		want    error
	}{
		{"foreign keyset", withKeyset(blankOutputs(t, m, 1), "00deadbeef"), cashu.InactiveKeysetSignatureRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proofs := raceTestProofs(t, m, 24)
			quote := raceTestMeltQuote(t, m, backend, 21)
			_, _, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
				Quote: quote.Id, Inputs: proofs, Outputs: tc.outputs,
			})
			if !errors.Is(err, tc.want) {
				t.Fatalf("%s must be refused with %v, got %v", tc.name, tc.want, err)
			}
			// the claim was never taken: the quote is still retryable
			fresh, err := m.GetMeltQuoteState(context.Background(), quote.Id)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.State != nut05.Unpaid {
				t.Fatalf("refused %s must leave the quote UNPAID (retryable), got %v", tc.name, fresh.State)
			}
		})
	}

	// duplicate B_ values
	proofs := raceTestProofs(t, m, 24)
	quote := raceTestMeltQuote(t, m, backend, 21)
	dup := blankOutputs(t, m, 1)
	dups := cashu.BlindedMessages{dup[0], dup[0]}
	_, _, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote: quote.Id, Inputs: proofs, Outputs: dups,
	})
	if !errors.Is(err, cashu.DuplicateOutputs) {
		t.Fatalf("duplicate blank outputs must be refused with DuplicateOutputs, got %v", err)
	}
}

// NUT-08: "Alice MUST set the amount of each blank output to 0, and Bob
// MUST ignore it" — wallets legitimately send nonzero amounts on melt
// outputs (the conformance corpus carries such melts; the reference
// families accept them), and the mint imprints its own change amounts
// regardless.
func TestMeltChangeIgnoresNonzeroBlankAmounts(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}
	m := newMeltChangeMint(t, backend, "")

	proofs := raceTestProofs(t, m, 24)
	quote := raceTestMeltQuote(t, m, backend, 21)
	outputs := blankOutputs(t, m, 2)
	outputs[0].Amount = 16 // the "amount" wallets send — ignored
	outputs[1].Amount = 8

	_, change, err := m.MeltTokens(context.Background(), nut05.PostMeltBolt11Request{
		Quote: quote.Id, Inputs: proofs, Outputs: outputs,
	})
	if err != nil {
		t.Fatalf("melt with nonzero-amount blank outputs must succeed (NUT-08: Bob MUST ignore): %v", err)
	}
	// the change is the mint's own math (24 − 21 − 0 fee = 3 → [2,1]),
	// never the wallet-sent amounts
	if change.Amount() != 3 || len(change) != 2 || change[0].Amount != 2 || change[1].Amount != 1 {
		t.Fatalf("change = %v, want [2 1] (mint-imprinted, wallet amounts ignored)", amountsOf(change))
	}
}

func withKeyset(outputs cashu.BlindedMessages, id string) cashu.BlindedMessages {
	outputs[0].Id = id
	return outputs
}

func amountsOf(sigs cashu.BlindedSignatures) []uint64 {
	amounts := make([]uint64, len(sigs))
	for i, sig := range sigs {
		amounts[i] = sig.Amount
	}
	return amounts
}

// sameChange compares two change sets value-wise (DLEQ is a pointer —
// addresses differ, e/s must not).
func sameChange(a, b cashu.BlindedSignatures) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Amount != b[i].Amount || a[i].C_ != b[i].C_ || a[i].Id != b[i].Id {
			return false
		}
		if (a[i].DLEQ == nil) != (b[i].DLEQ == nil) {
			return false
		}
		if a[i].DLEQ != nil && *a[i].DLEQ != *b[i].DLEQ {
			return false
		}
	}
	return true
}
