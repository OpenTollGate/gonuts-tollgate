package wallet

import (
	"errors"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut13"
)

// The pre-POST reservation is the only counter advance for a mint. Advancing
// again after saving proofs can report a failure for a successful payment at
// the domain tail and leaves its local quote unissued.
func TestMintTokensAdvancesReservedRangeOnce(t *testing.T) {
	for _, tc := range []struct {
		name string
		tail bool
	}{
		{name: "low-counter"},
		{name: "exact-end", tail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newSigningMint(t)
			dir := t.TempDir()
			w, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: m.server.URL})
			if err != nil {
				t.Fatal("load synthetic wallet failed")
			}
			t.Cleanup(func() { _ = w.Shutdown() })
			n := uint32(len(w.splitWalletTarget(64, m.server.URL)))
			if n == 0 {
				t.Fatal("fixture requires nonempty mint outputs")
			}
			var start uint32
			if tc.tail {
				start = nut13.HardenedCounterLimit - n
			}
			if err := w.db.IncrementKeysetCounter(m.keyset.Id, start); err != nil {
				t.Fatal("setting synthetic counter failed")
			}
			quote, err := w.RequestMint(64, m.server.URL)
			if err != nil {
				t.Fatal("requesting synthetic quote failed")
			}
			orig := postMintBolt11
			t.Cleanup(func() { postMintBolt11 = orig })
			calls := 0
			postMintBolt11 = func(mint string, req nut04.PostMintBolt11Request) (*nut04.PostMintBolt11Response, error) {
				calls++
				if w.db.GetKeysetCounter(m.keyset.Id) != start+n {
					t.Fatal("counter range was not reserved before the mint POST")
				}
				if len(w.db.GetPendingSwaps()) != 1 {
					t.Fatal("mint intent was not durable before the POST")
				}
				return orig(mint, req)
			}
			amount, err := w.MintTokens(quote.Quote)
			if err != nil || amount != 64 {
				t.Errorf("successful mint misreported: amount=%d error=%v", amount, err != nil)
			}
			if calls != 1 || m.mints != 1 || w.GetBalance() != 64 {
				t.Fatal("expected one mint POST and the full credited balance")
			}
			if got := w.db.GetKeysetCounter(m.keyset.Id); got != start+n {
				t.Errorf("counter=%d, want the single reserved end %d", got, start+n)
			}
			saved := w.db.GetMintQuoteById(quote.Quote)
			if saved == nil || saved.State != nut04.Issued || saved.SettledAt == 0 {
				t.Error("successful mint did not persist its issued quote")
			}
			if len(w.db.GetPendingSwaps()) != 0 {
				t.Error("successful mint retained its intent")
			}

			// An already-issued local quote must not generate another POST or
			// advance the counter, including when that counter is exhausted.
			if _, err := w.MintTokens(quote.Quote); err == nil {
				t.Error("an issued quote was minted again")
			}
			if calls != 1 || w.db.GetKeysetCounter(m.keyset.Id) != start+n || len(w.db.GetPendingSwaps()) != 0 {
				t.Error("duplicate mint changed counter, intent or POST count")
			}
			w.Shutdown()
			reopened, err := LoadWallet(Config{WalletPath: dir, CurrentMintURL: m.server.URL})
			if err != nil {
				t.Fatal("reopening synthetic wallet failed")
			}
			t.Cleanup(func() { _ = reopened.Shutdown() })
			saved = reopened.db.GetMintQuoteById(quote.Quote)
			if reopened.GetBalance() != 64 || reopened.db.GetKeysetCounter(m.keyset.Id) != start+n || saved == nil || saved.State != nut04.Issued || len(reopened.db.GetPendingSwaps()) != 0 {
				t.Error("credited mint state did not survive reopen")
			}
		})
	}
}

func TestMintTokensRefusesCrossingRangeBeforePOST(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatal("load synthetic wallet failed")
	}
	t.Cleanup(func() { _ = w.Shutdown() })
	n := uint32(len(w.splitWalletTarget(64, m.server.URL)))
	if n < 2 {
		t.Fatal("fixture requires multiple mint outputs")
	}
	start := nut13.HardenedCounterLimit - n + 1
	if err := w.db.IncrementKeysetCounter(m.keyset.Id, start); err != nil {
		t.Fatal("setting synthetic counter failed")
	}
	quote, err := w.RequestMint(64, m.server.URL)
	if err != nil {
		t.Fatal("requesting synthetic quote failed")
	}
	amount, err := w.MintTokens(quote.Quote)
	if amount != 0 || !errors.Is(err, nut13.ErrHardenedDomainExhausted) {
		t.Fatal("crossing mint must return the domain refusal")
	}
	if m.mints != 0 || w.GetBalance() != 0 || w.db.GetKeysetCounter(m.keyset.Id) != start || len(w.db.GetPendingSwaps()) != 0 {
		t.Error("refused mint exposed outputs or changed durable value/counter/intent")
	}
}
