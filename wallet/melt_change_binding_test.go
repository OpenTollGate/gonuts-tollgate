package wallet

import (
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
)

func TestMeltChangeAssignsBlankAmountAndPreservesBinding(t *testing.T) {
	m, _, req := newBindingTestWallet(t)
	sigs := postSwapToStubMint(t, m, req).Signatures
	blanks := append(cashu.BlindedMessages(nil), req.outputs...)
	for i := range blanks {
		blanks[i].Amount = 0
	}
	proofs, err := constructMeltChangeProofs(sigs, blanks, req.secrets, req.rs, req.keyset)
	if err != nil || proofs.Amount() != 8 {
		t.Fatalf("NUT-08 change rejected: %v %d", err, proofs.Amount())
	}
	if blanks[0].Amount != 0 {
		t.Fatal("durable blank outputs mutated")
	}
	if _, err := constructProofs(sigs, blanks, req.secrets, req.rs, req.keyset); err == nil {
		t.Fatal("swap binding was weakened")
	}
	sigs[0].Id = "00deadbeef"
	if _, err := constructMeltChangeProofs(sigs, blanks, req.secrets, req.rs, req.keyset); err == nil {
		t.Fatal("foreign change keyset accepted")
	}
}

func TestMeltChangeAllowsPrefixButRejectsExcessSignatures(t *testing.T) {
	m, _, req := newBindingTestWallet(t)
	sigs := postSwapToStubMint(t, m, req).Signatures
	blanks := append(cashu.BlindedMessages(nil), req.outputs...)
	for i := range blanks {
		blanks[i].Amount = 0
	}
	blanks = append(blanks, blanks[0])
	secrets := append(append([]string(nil), req.secrets...), req.secrets[0])
	rs := append(req.rs[:len(req.rs):len(req.rs)], req.rs[0])
	if proofs, err := constructMeltChangeProofs(sigs, blanks, secrets, rs, req.keyset); err != nil || proofs.Amount() != 8 {
		t.Fatalf("prefix change rejected: %v", err)
	}
	excess := append(append(cashu.BlindedSignatures(nil), sigs...), sigs[0])
	if _, err := constructMeltChangeProofs(excess, blanks[:1], secrets[:1], rs[:1], req.keyset); err == nil {
		t.Fatal("excess signatures accepted")
	}
}

func TestMeltStoresPositiveFeeChange(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Shutdown()
	q, err := w.RequestMint(64, m.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.MintTokens(q.Quote); err != nil {
		t.Fatal(err)
	}
	mq, err := w.RequestMeltQuote(fakeMeltInvoice, m.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Melt(mq.Quote); err != nil {
		t.Fatal(err)
	}
	if w.GetBalance() != 43 || w.PendingBalance() != 0 || len(w.db.GetPendingSwaps()) != 0 {
		t.Fatalf("settled change not saved: balance=%d pending=%d intents=%d", w.GetBalance(), w.PendingBalance(), len(w.db.GetPendingSwaps()))
	}
}

func TestMeltRecoveryAfterRestartDoesNotResubmitSettledPayment(t *testing.T) {
	for _, tc := range []struct {
		name                                                      string
		pending, quoteError, omitChange, restoreError, zeroChange bool
		wantRecovered                                             uint64
		wantFailure                                               bool
	}{
		{name: "paid change", wantRecovered: 1},
		{name: "pending", pending: true, wantFailure: true},
		{name: "quote failure", quoteError: true, wantFailure: true},
		{name: "paid missing change uses restore", omitChange: true, wantRecovered: 1},
		{name: "restore failure retains intent", omitChange: true, restoreError: true, wantFailure: true},
		{name: "explicit empty change", zeroChange: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newSigningMint(t)
			path := t.TempDir()
			w, err := LoadWallet(Config{WalletPath: path, CurrentMintURL: m.server.URL})
			if err != nil {
				t.Fatal(err)
			}
			q, err := w.RequestMint(64, m.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = w.MintTokens(q.Quote); err != nil {
				t.Fatal(err)
			}
			mq, err := w.RequestMeltQuote(fakeMeltInvoice, m.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			m.zeroMeltChange = tc.zeroChange
			original := postMeltBolt11
			postMeltBolt11 = func(mint string, request nut05.PostMeltBolt11Request) (*nut05.PostMeltQuoteBolt11Response, error) {
				if _, err := original(mint, request); err != nil {
					return nil, err
				}
				return nil, errSimulatedCrash
			}
			_, meltErr := w.Melt(mq.Quote)
			postMeltBolt11 = original
			if meltErr == nil {
				t.Fatal("crash not simulated")
			}
			counter := w.counterForKeyset(m.keyset.Id)
			before := w.GetBalance()
			if len(w.db.GetPendingSwaps()) != 1 {
				t.Fatal("crashed melt not journaled")
			}
			if err := w.Shutdown(); err != nil {
				t.Fatal(err)
			}
			w, err = LoadWallet(Config{WalletPath: path, CurrentMintURL: m.server.URL})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Shutdown()
			m.omitMeltChange = tc.omitChange
			m.restoreErr = tc.restoreError
			m.meltQuoteHTTPError = tc.quoteError
			if tc.pending {
				m.meltQuoteState = "PENDING"
			}
			recovered, failed, err := w.ResumePendingOperations()
			if tc.wantFailure {
				if err == nil || failed != 1 || recovered != 0 || len(w.db.GetPendingSwaps()) != 1 || w.GetBalance() != before {
					t.Fatalf("unresolved operation changed funds: recovered=%d failed=%d err=%v", recovered, failed, err)
				}
			} else {
				if err != nil || failed != 0 || recovered != tc.wantRecovered || w.GetBalance() != before+tc.wantRecovered || w.PendingBalance() != 0 || len(w.db.GetPendingSwaps()) != 0 {
					t.Fatalf("change not recovered: recovered=%d failed=%d err=%v", recovered, failed, err)
				}
				if w.db.GetMeltQuoteById(mq.Quote).State != nut05.Paid {
					t.Fatal("settlement not persisted")
				}
				if n, f, e := w.ResumePendingOperations(); n != 0 || f != 0 || e != nil {
					t.Fatal("second resume was not idempotent")
				}
			}
			if m.melts != 1 {
				t.Fatalf("settled/pending melt resubmitted: %d POSTs", m.melts)
			}
			if w.counterForKeyset(m.keyset.Id) != counter {
				t.Fatal("recovery changed the reserved derivation range")
			}
			if tc.omitChange && !tc.quoteError && !tc.pending && m.restoreCalls != 1 {
				t.Fatalf("restore calls=%d", m.restoreCalls)
			}
		})
	}
}
