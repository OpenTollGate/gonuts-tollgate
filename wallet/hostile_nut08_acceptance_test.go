package wallet

// ACCEPTANCE tests for the #46 melt-recovery contract (ratified on the PR
// thread, issuecomment-6808181529 + issuecomment-6824400305; gates per
// cashu-audit #67 §10-11 plus murdawkmedia's two regression conditions).
//
// Red-first: these tests assert the GUARDED behavior and are expected to
// FAIL on heads without the guards (they compile regardless — assertions
// are state-based, not error-identity-based). Mapping:
//
//	ACC-V1/V1b  quote-id echo binding (GAP-A) — foreign PAID must refuse
//	ACC-V2      pairing/ceiling on injected foreign signatures (GAP-A+B)
//	ACC-V3      total-change ceiling vs stored fee_reserve (GAP-B)
//	ACC-V4      "change":[] = absence ⇒ NUT-09 consulted, never silent zero
//	ACC-V5      honest control (must keep passing — anti-over-blocking)
//	ACC-V6/V6b  interactive path: foreign PAID refused; honest PAID persisted
//	ACC-HoldEmpty  PAID + reserve>0 + no change obtainable ⇒ hold, no retire
//	ACC-Layer3     explicit-UNPAID bounded replay gate (layer 3 commit)
//
// Harness: identical wire-level mutation front as the original repro
// (hostile_nut08_recovery_test.go in cashu-audit research/), plus one knob:
// restoreEmpty rewrites POST /v1/restore answers to an empty result set.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

const foreignQuoteID = "e771b3ac-1234-4000-8000-00000000046x" // deliberately not our quote id

// hostileProxy fronts the honest stub mint and rewrites melt-quote GET
// answers (plus optionally the melt POST response state) on the wire.
type hostileProxy struct {
	t        *testing.T
	server   *httptest.Server
	upstream *url.URL
	mint     *signingMint

	// GET /v1/melt/quote/bolt11/* knobs
	quoteIDOverride string // rewrite the "quote" field
	forceState      string // force the "state" field
	changeMode      string // "passthrough" (default) | "remove" | "empty" | "inject"
	injectSigs      []cashu.BlindedSignature

	// POST /v1/melt/bolt11 knob
	meltPOSTState string // rewrite the melt response "state" (V6)

	// evidence
	lastGETBody  []byte
	meltOutputs  cashu.BlindedMessages // blank outputs captured from the melt POST
	getsServed   int
	restoreSeen  int
	restoreEmpty bool // rewrite POST /v1/restore answers to an empty result set (hold-on-empty gate)
}

func newHostileProxy(t *testing.T, m *signingMint) *hostileProxy {
	t.Helper()
	up, err := url.Parse(m.server.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	p := &hostileProxy{t: t, upstream: up, mint: m, changeMode: "passthrough"}
	proxy := httputil.NewSingleHostReverseProxy(up)
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/melt/bolt11") {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req struct {
				Outputs cashu.BlindedMessages `json:"outputs"`
			}
			if json.Unmarshal(body, &req) == nil && len(req.Outputs) > 0 {
				p.meltOutputs = req.Outputs
			}
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/restore") {
			p.restoreSeen++
			if p.restoreEmpty {
				_, _ = w.Write([]byte(`{"outputs":[],"signatures":[]}`))
				return
			}
		}

		isQuoteGet := r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v1/melt/quote/bolt11/")
		if isQuoteGet {
			p.getsServed++
		}
		if !isQuoteGet && p.meltPOSTState == "" {
			proxy.ServeHTTP(w, r)
			return
		}

		// Capture the upstream answer, then rewrite it on the wire.
		req, err := http.NewRequest(r.Method, p.upstream.String()+r.URL.Path, r.Body)
		if err != nil {
			t.Fatalf("build upstream request: %v", err)
		}
		req.Header = r.Header
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		doc := map[string]any{}
		if err := json.Unmarshal(body, &doc); err != nil {
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			return
		}
		if isQuoteGet {
			if p.quoteIDOverride != "" {
				doc["quote"] = p.quoteIDOverride
			}
			if p.forceState != "" {
				doc["state"] = p.forceState
			}
			switch p.changeMode {
			case "remove":
				delete(doc, "change")
			case "empty":
				doc["change"] = []cashu.BlindedSignature{}
			case "inject":
				doc["change"] = p.injectSigs
			}
			p.lastGETBody, _ = json.Marshal(doc)
			_, _ = w.Write(p.lastGETBody)
			return
		}
		// melt POST response rewrite (V6): forced state never carries change.
		doc["state"] = p.meltPOSTState
		delete(doc, "change")
		rewritten, _ := json.Marshal(doc)
		_, _ = w.Write(rewritten)
	}))
	t.Cleanup(p.server.Close)
	return p
}

// fundAndMelt mints 64 sats, takes a melt quote (amount 21, fee_reserve
// 1, one blank output) and starts Melt(). crashMode:
//
//	"after"  – the melt POST reaches the mint, the answer is dropped
//	           (the crash shape the PR recovers from);
//	"before" – the POST never leaves the wallet (network failure); the
//	           intent and pending inputs stay journaled, the mint never
//	           sees the melt.
func fundAndMelt(t *testing.T, mintURL string, crashMode string) (*Wallet, string) {
	t.Helper()
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: mintURL})
	if err != nil {
		t.Fatal(err)
	}
	q, err := w.RequestMint(64, mintURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.MintTokens(q.Quote); err != nil {
		t.Fatal(err)
	}
	mq, err := w.RequestMeltQuote(fakeMeltInvoice, mintURL)
	if err != nil {
		t.Fatal(err)
	}
	original := postMeltBolt11
	postMeltBolt11 = func(mint string, request nut05.PostMeltBolt11Request) (*nut05.PostMeltQuoteBolt11Response, error) {
		if crashMode == "after" {
			if _, err := original(mint, request); err != nil {
				return nil, err
			}
		}
		return nil, errors.New("connection reset by peer")
	}
	_, meltErr := w.Melt(mq.Quote)
	postMeltBolt11 = original
	if meltErr == nil {
		t.Fatal("melt must surface the simulated failure")
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("crashed melt not journaled: %d intents", len(w.db.GetPendingSwaps()))
	}
	return w, mq.Quote
}

// ACC-V1 — foreign quote PAID must be refused before any state acceptance.
func TestAccV1ForeignQuotePaidRefused(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, quoteID := fundAndMelt(t, p.server.URL, "after")
	before := w.GetBalance()

	p.quoteIDOverride = foreignQuoteID
	p.changeMode = "remove"

	recovered, _, err := w.ResumePendingOperations()

	q := w.db.GetMeltQuoteById(quoteID)
	if q == nil || q.State == nut05.Paid {
		t.Fatalf("GUARD MISSING (V1): our quote marked PAID from a FOREIGN id answer (q=%+v)", q)
	}
	if recovered != 0 || w.GetBalance() != before {
		t.Fatalf("GUARD MISSING (V1): value moved (recovered=%d balance %d want %d)", recovered, w.GetBalance(), before)
	}
	if err == nil {
		t.Fatal("GUARD MISSING (V1): resume reported success on an id-mismatch answer")
	}
	if len(w.db.GetPendingSwaps()) != 1 || m.restoreCalls != 0 || p.restoreSeen != 0 {
		t.Fatalf("GUARD MISSING (V1): intents=%d restoreCalls=%d proxyRestores=%d (want 1/0/0 — no NUT-09, no retirement)",
			len(w.db.GetPendingSwaps()), m.restoreCalls, p.restoreSeen)
	}
	t.Logf("V1 guarded: foreign id refused, intent retained, nothing credited")
}

// ACC-V1b — the fund-loss shape: melt never reached the mint; nothing may
// be destroyed on a foreign PAID.
func TestAccV1bForeignPaidNeverDestroysInputs(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, quoteID := fundAndMelt(t, p.server.URL, "before")

	p.quoteIDOverride = foreignQuoteID
	p.forceState = "PAID"
	p.changeMode = "remove"

	_, _, err := w.ResumePendingOperations()

	if err == nil {
		t.Fatal("GUARD MISSING (V1b): resume succeeded on a foreign answer")
	}
	if w.PendingBalance() != 22 || len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("GUARD MISSING (V1b): records destroyed (pending=%d intents=%d want 22/1)", w.PendingBalance(), len(w.db.GetPendingSwaps()))
	}
	if q := w.db.GetMeltQuoteById(quoteID); q == nil || q.State == nut05.Paid {
		t.Fatalf("GUARD MISSING (V1b): quote settled from foreign answer (%+v)", q)
	}
	if m.melts != 0 {
		t.Fatalf("harness drift: %d melt POSTs", m.melts)
	}
	t.Logf("V1b guarded: unspent inputs and intent survive the foreign PAID lie")
}

// ACC-V2 — a cryptographically valid signature over a foreign point must
// never become stored balance.
func TestAccV2ForeignSignatureRefused(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, _ := fundAndMelt(t, p.server.URL, "after")
	before := w.GetBalance()

	foreignB := randPrivKey(t).PubKey()
	C_ := crypto.SignBlindedMessage(foreignB, m.privs[64])
	p.quoteIDOverride = foreignQuoteID
	p.forceState = "PAID"
	p.changeMode = "inject"
	p.injectSigs = []cashu.BlindedSignature{{
		Amount: 64,
		Id:     m.keyset.Id,
		C_:     hex.EncodeToString(C_.SerializeCompressed()),
	}}

	_, _, err := w.ResumePendingOperations()

	if err == nil {
		t.Fatal("GUARD MISSING (V2): foreign signature accepted")
	}
	if w.GetBalance() != before {
		t.Fatalf("GUARD MISSING (V2): balance moved %d -> %d", before, w.GetBalance())
	}
	for _, pr := range w.db.GetProofs() {
		if pr.Amount == 64 {
			t.Fatalf("GUARD MISSING (V2): phantom 64-sat proof stored (C=%s)", pr.C)
		}
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("GUARD MISSING (V2): intent retired (intents=%d)", len(w.db.GetPendingSwaps()))
	}
	t.Logf("V2 guarded: signature over a foreign point refused")
}

// ACC-V3 — total change vs the stored quote's fee reserve (ceiling gate).
func TestAccV3OverCeilingChangeRefused(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, quoteID := fundAndMelt(t, p.server.URL, "after")
	before := w.GetBalance()
	stored := w.db.GetMeltQuoteById(quoteID)
	if stored == nil || stored.FeeReserve != 1 {
		t.Fatalf("harness drift: stored fee_reserve=%+v", stored)
	}

	B_bytes, err := hex.DecodeString(p.meltOutputs[0].B_)
	if err != nil {
		t.Fatal(err)
	}
	BPub, err := secp256k1.ParsePubKey(B_bytes)
	if err != nil {
		t.Fatal(err)
	}
	C_ := crypto.SignBlindedMessage(BPub, m.privs[64])
	p.forceState = "PAID" // our id; only the amount is hostile
	p.changeMode = "inject"
	p.injectSigs = []cashu.BlindedSignature{{
		Amount: 64,
		Id:     m.keyset.Id,
		C_:     hex.EncodeToString(C_.SerializeCompressed()),
	}}

	_, _, err = w.ResumePendingOperations()

	if err == nil {
		t.Fatal("GUARD MISSING (V3): over-ceiling change accepted")
	}
	if w.GetBalance() != before {
		t.Fatalf("GUARD MISSING (V3): balance moved %d -> %d", before, w.GetBalance())
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("GUARD MISSING (V3): intent retired on refused change")
	}
	t.Logf("V3 guarded: change 64 refused against fee_reserve=1")
}

// ACC-V4 — "change":[] is absence, not zero: NUT-09 must be consulted.
func TestAccV4EmptyChangeConsultsRestore(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, _ := fundAndMelt(t, p.server.URL, "after")
	before := w.GetBalance()

	p.changeMode = "empty" // our id, honest PAID, real 1-sat change in restore

	_, _, err := w.ResumePendingOperations()

	if m.restoreCalls == 0 && p.restoreSeen == 0 {
		t.Fatalf("GUARD MISSING (V4): restore never consulted on change:[] (err=%v)", err)
	}
	recovered := before != w.GetBalance()
	if !recovered && len(w.db.GetPendingSwaps()) == 0 {
		t.Fatal("GUARD MISSING (V4): neither recovered via restore nor retained the intent")
	}
	if recovered && w.GetBalance() != before+1 {
		t.Fatalf("GUARD MISSING (V4): wrong recovery amount (balance %d want %d)", w.GetBalance(), before+1)
	}
	t.Logf("V4 guarded: empty array treated as absence — restore consulted (recovered=%v)", recovered)
}

// ACC-V5 — honest control, unchanged: guards must not over-block.
func TestAccV5HonestControl(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, _ := fundAndMelt(t, p.server.URL, "after")
	before := w.GetBalance()

	recovered, failed, err := w.ResumePendingOperations()

	if err != nil || failed != 0 || recovered != 1 || w.GetBalance() != before+1 {
		t.Fatalf("V5 CONTROL FAILED (guards over-blocking): recovered=%d failed=%d err=%v balance=%d", recovered, failed, err, w.GetBalance())
	}
	if m.melts != 1 {
		t.Fatalf("V5 CONTROL: melt POSTs=%d want 1", m.melts)
	}
	t.Logf("V5 control: honest recovery intact through the proxy")
}

// ACC-V6 — interactive path: a foreign PAID must be refused and must not
// settle or destroy pending inputs.
func TestAccV6InteractiveForeignPaidRefused(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: p.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	q, err := w.RequestMint(64, p.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.MintTokens(q.Quote); err != nil {
		t.Fatal(err)
	}
	mq, err := w.RequestMeltQuote(fakeMeltInvoice, p.server.URL)
	if err != nil {
		t.Fatal(err)
	}

	p.meltPOSTState = "PENDING"
	if _, err = w.Melt(mq.Quote); err != nil {
		t.Fatal(err)
	}
	p.meltPOSTState = ""
	p.quoteIDOverride = foreignQuoteID
	p.forceState = "PAID"

	if _, err := w.CheckMeltQuoteState(mq.Quote); err == nil {
		t.Fatal("GUARD MISSING (V6): interactive path accepted a foreign PAID")
	}
	stored := w.db.GetMeltQuoteById(mq.Quote)
	if stored == nil || stored.SettledAt != 0 {
		t.Fatalf("GUARD MISSING (V6): foreign PAID settled the quote (%+v)", stored)
	}
	if w.PendingBalance() != 22 {
		t.Fatalf("GUARD MISSING (V6): pending inputs destroyed (=%d want 22)", w.PendingBalance())
	}
	t.Logf("V6 guarded: interactive foreign PAID refused, inputs intact")
}

// ACC-V6b — interactive path: an HONEST PAID must persist State=Paid.
func TestAccV6bInteractiveHonestPaidPersisted(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: p.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	q, err := w.RequestMint(64, p.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.MintTokens(q.Quote); err != nil {
		t.Fatal(err)
	}
	mq, err := w.RequestMeltQuote(fakeMeltInvoice, p.server.URL)
	if err != nil {
		t.Fatal(err)
	}

	p.meltPOSTState = "PENDING"
	if _, err = w.Melt(mq.Quote); err != nil {
		t.Fatal(err)
	}
	p.meltPOSTState = "" // honest PAID from here

	if _, err := w.CheckMeltQuoteState(mq.Quote); err != nil {
		t.Fatalf("V6b: honest PAID rejected: %v", err)
	}
	stored := w.db.GetMeltQuoteById(mq.Quote)
	if stored == nil || stored.State != nut05.Paid || stored.SettledAt == 0 {
		t.Fatalf("GUARD MISSING (V6b): honest PAID not persisted (%+v)", stored)
	}
	if w.PendingBalance() != 0 {
		t.Fatalf("GUARD MISSING (V6b): pending inputs not settled (=%d)", w.PendingBalance())
	}
	t.Logf("V6b guarded: honest interactive PAID persisted (State=Paid)")
}

// ACC-HoldEmpty — PAID (our id), change unobtainable from GET and restore,
// fee_reserve > 0: hold the intent; never retire as zero-change.
func TestAccHoldOnEmptyRetainsIntent(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, _ := fundAndMelt(t, p.server.URL, "after")
	before := w.GetBalance()

	p.forceState = "PAID" // our id, honest settlement
	p.changeMode = "remove"
	p.restoreEmpty = true // restore genuinely has nothing

	_, _, err := w.ResumePendingOperations()

	if p.restoreSeen == 0 {
		t.Fatalf("GUARD MISSING (HoldEmpty): restore never consulted (err=%v)", err)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("GUARD MISSING (HoldEmpty): intent retired with reserve>0 and change unobtainable (intents=%d err=%v)", len(w.db.GetPendingSwaps()), err)
	}
	if w.GetBalance() != before {
		t.Fatalf("GUARD MISSING (HoldEmpty): balance moved %d -> %d without signatures", before, w.GetBalance())
	}
	t.Logf("HoldEmpty guarded: PAID + reserve>0 + empty GET/restore => intent held")
}

// ACC-Layer3 — explicit UNPAID gate (separate layer-3 commit): a journaled
// melt whose quote is honestly UNPAID is completed by exactly one bounded
// replay of the saved request; change recovered under the same ceiling.
// Red until layer 3 lands; see the contract's landing order.
func TestAccLayer3UnpaidBoundedReplayCompletes(t *testing.T) {
	m := newSigningMint(t)
	p := newHostileProxy(t, m)
	w, quoteID := fundAndMelt(t, p.server.URL, "before") // melt never sent
	before := w.GetBalance()

	p.forceState = "UNPAID" // mint honestly unpaid at resume time

	_, _, err := w.ResumePendingOperations()

	q := w.db.GetMeltQuoteById(quoteID)
	if err != nil || q == nil || q.State != nut05.Paid {
		t.Fatalf("LAYER3 GATE (red until implemented): quote not completed (q=%+v err=%v)", q, err)
	}
	if w.GetBalance() != before+1 {
		t.Fatalf("LAYER3 GATE: change not recovered (balance %d want %d)", w.GetBalance(), before+1)
	}
	if m.melts != 1 {
		t.Fatalf("LAYER3 GATE: melt POSTs=%d want exactly 1 (the bounded replay)", m.melts)
	}
	t.Logf("Layer3: explicit-UNPAID journaled melt completed by one bounded replay")
}
