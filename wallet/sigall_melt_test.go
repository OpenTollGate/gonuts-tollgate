package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut11"
	"github.com/OpenTollGate/gonuts-tollgate/mint"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// cashu-audit #68 B1: the wallet must PRODUCE the melt witness for
// spending-condition inputs — the mint side (MeltTokens → verifySigAllGroup)
// has accepted spec SIG_ALL melts since the #809 alignment, but until this
// fix the wallet never signed them, so melting locked tokens was impossible
// end-to-end.

// lockAllToCondition swaps the wallet's entire balance into proofs locked
// to the given spending condition. Leaving no unlocked change behind keeps
// the melt's proof selection deterministic (getProofsForAmount only
// returns stored proofs unchanged when they cover the amount exactly —
// any shortfall would go through a swap that unlocks).
func lockAllToCondition(t *testing.T, w *Wallet, mintURL string, cond nut10.SpendingCondition) cashu.Proofs {
	t.Helper()
	wm, ok := w.mints[mintURL]
	if !ok {
		t.Fatalf("mint %s not registered", mintURL)
	}
	amount := w.GetBalance()
	if amount == 0 {
		t.Fatal("wallet has no balance to lock")
	}
	locked, err := w.swapToSend(amount, &wm, &cond, true)
	if err != nil {
		t.Fatalf("swapToSend with condition: %v", err)
	}
	if err := w.db.SaveProofs(locked); err != nil {
		t.Fatalf("SaveProofs(locked): %v", err)
	}
	return locked
}

func sigAllSelfCondition(w *Wallet) nut10.SpendingCondition {
	return nut10.SpendingCondition{
		Kind: nut10.P2PK,
		Data: hex.EncodeToString(w.privateKey.PubKey().SerializeCompressed()),
		Tags: [][]string{{"sigflag", "SIG_ALL"}},
	}
}

// fundWallet mints `amount` through the normal nut-04 flow (FakeBackend
// invoices are created settled).
func fundWallet(t *testing.T, w *Wallet, mintURL string, amount uint64) {
	t.Helper()
	quote, err := w.RequestMint(amount, mintURL)
	if err != nil {
		t.Fatalf("RequestMint: %v", err)
	}
	if _, err := w.MintTokens(quote.Quote); err != nil {
		t.Fatalf("MintTokens: %v", err)
	}
}

// TestMeltSigAllWitnessShapeAndBinding (unit): the melt request for
// SIG_ALL-locked inputs carries the spec witness — Schnorr signature over
// sha256(SigAllMessage(inputs, blank outputs, quote id)) in the FIRST
// input only — and the persisted melt intent replays byte-identical bytes.
func TestMeltSigAllWitnessShapeAndBinding(t *testing.T) {
	m := newSigningMint(t)
	m.meltAmount, m.meltFeeReserve = 62, 1

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	// fund 63 (split 1+2+4+8+16+32), then lock the entire balance to
	// the wallet's own key under SIG_ALL — six locked inputs.
	fundWallet(t, w, m.server.URL, 63)
	quote, err := w.RequestMeltQuote(fakeMeltInvoice, m.server.URL)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}
	if quote.Amount != 62 || quote.FeeReserve != 1 {
		t.Fatalf("fixture requires melt amount 62 + fee reserve 1 (= the locked 63), got %d+%d", quote.Amount, quote.FeeReserve)
	}

	var captured nut05.PostMeltBolt11Request
	var capturedIntentBytes []byte
	origMelt := postMeltBolt11
	defer func() { postMeltBolt11 = origMelt }()
	postMeltBolt11 = func(mintURL string, req nut05.PostMeltBolt11Request) (*nut05.PostMeltQuoteBolt11Response, error) {
		captured = req
		for _, intent := range w.db.GetPendingSwaps() {
			if intent.OpType == storagePendingOpMelt {
				capturedIntentBytes = intent.RequestBytes
			}
		}
		return &nut05.PostMeltQuoteBolt11Response{State: nut05.Paid, Preimage: "aa"}, nil
	}

	locked := lockAllToCondition(t, w, m.server.URL, sigAllSelfCondition(w))
	if len(locked) < 2 {
		t.Fatalf("fixture must lock multiple inputs, got %d", len(locked))
	}

	resp, err := w.Melt(quote.Quote)
	if err != nil {
		t.Fatalf("Melt: %v", err)
	}
	if resp.State != nut05.Paid {
		t.Fatalf("melt state = %v, want PAID", resp.State)
	}

	// --- witness shape: first input only, one signature, no per-input sigs ---
	if len(captured.Outputs) == 0 {
		t.Fatal("melt must carry NUT-08 blank outputs so the SIG_ALL aggregate binds them")
	}
	if captured.Inputs[0].Witness == "" {
		t.Fatal("first input must carry the SIG_ALL witness")
	}
	for i, in := range captured.Inputs[1:] {
		if in.Witness != "" {
			t.Fatalf("input %d must have an empty witness (SIG_ALL lives in the first input only)", i+1)
		}
	}
	var witness nut11.P2PKWitness
	if err := json.Unmarshal([]byte(captured.Inputs[0].Witness), &witness); err != nil {
		t.Fatalf("first-input witness is not a P2PKWitness: %v", err)
	}
	if len(witness.Signatures) != 1 {
		t.Fatalf("witness carries %d signatures, want 1", len(witness.Signatures))
	}

	sigBytes, err := hex.DecodeString(witness.Signatures[0])
	if err != nil {
		t.Fatalf("witness signature is not hex: %v", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		t.Fatalf("witness signature does not parse as schnorr: %v", err)
	}

	// --- binding: the signature verifies over the aggregate WITH the
	// quote id, and NOT over aggregates with a wrong quote id or
	// missing outputs (the mutation checks for the binding itself).
	good := sha256.Sum256(nut11.SigAllMessage(captured.Inputs, captured.Outputs, quote.Quote))
	if !sig.Verify(good[:], w.privateKey.PubKey()) {
		t.Fatal("witness signature must verify over sha256(SigAllMessage(inputs, outputs, quote_id))")
	}
	noQuote := sha256.Sum256(nut11.SigAllMessage(captured.Inputs, captured.Outputs, ""))
	if sig.Verify(noQuote[:], w.privateKey.PubKey()) {
		t.Fatal("witness must be bound to the quote id — it must NOT verify without it")
	}
	otherQuote := sha256.Sum256(nut11.SigAllMessage(captured.Inputs, captured.Outputs, "not-the-quote"))
	if sig.Verify(otherQuote[:], w.privateKey.PubKey()) {
		t.Fatal("witness must be bound to THIS quote id — it must not verify over another")
	}
	noOutputs := sha256.Sum256(nut11.SigAllMessage(captured.Inputs, captured.Outputs[:len(captured.Outputs)-1], quote.Quote))
	if sig.Verify(noOutputs[:], w.privateKey.PubKey()) {
		t.Fatal("witness must be bound to the blank outputs — it must not verify without one")
	}

	// --- replay parity: the persisted intent carries the exact wire bytes
	if capturedIntentBytes == nil {
		t.Fatal("melt intent must exist when the request fires")
	}
	want, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	if string(capturedIntentBytes) != string(want) {
		t.Fatalf("intent bytes must equal the request bytes (crash-recovery replays byte-identical melts):\nintent:    %s\nrequest: %s", capturedIntentBytes, want)
	}
}

// --- real-mint e2e (mint.Mint + FakeBackend + MintServer) ---

// feeBackend makes the FakeBackend reserve a nonzero melt fee so the melt
// carries NUT-08 blank outputs (with a zero reserve the aggregate binds
// inputs + quote id only).
type feeBackend struct {
	*lightning.FakeBackend
}

func (f *feeBackend) FeeReserve(uint64) uint64 { return 1 }

func freePort(t *testing.T) int {
	t.Helper()
	for p := 4400; p < 4440; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln.Close()
			return p
		}
	}
	t.Fatal("no free port in 4400-4439")
	return 0
}

// startRealMint boots the production mint + HTTP server on a free port.
func startRealMint(t *testing.T) (*mint.MintServer, string, *feeBackend) {
	t.Helper()
	backend := &feeBackend{&lightning.FakeBackend{}}
	port := freePort(t)
	cfg := mint.Config{
		MintPath:        t.TempDir(),
		LightningClient: backend,
		LogLevel:        mint.Disable,
		Port:            port,
	}
	m, err := mint.LoadMint(cfg)
	if err != nil {
		t.Fatalf("LoadMint: %v", err)
	}
	server := mint.SetupMintServer(m, mint.ServerConfig{Port: port})
	go func() { _ = server.Start() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	// wait for the listener
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + "/v1/info")
		if err == nil {
			resp.Body.Close()
			return server, url, backend
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("mint server did not come up")
	return nil, "", nil
}

// meltLockedE2E funds a fresh wallet, locks its whole balance to cond,
// and melts it against the REAL mint (full MeltTokens verification:
// verifySigAllGroup over inputs + blank outputs + quote id).
func meltLockedE2E(t *testing.T, cond func(w *Wallet) nut10.SpendingCondition) (*nut05.PostMeltQuoteBolt11Response, error) {
	t.Helper()
	_, mintURL, backend := startRealMint(t)

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: mintURL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	fundWallet(t, w, mintURL, 63)
	lockAllToCondition(t, w, mintURL, cond(w))

	// melt quote: amount 62 + fee reserve 1 = the exact 63 locked
	invoice, err := backend.CreateInvoice(62)
	if err != nil {
		t.Fatalf("CreateInvoice: %v", err)
	}
	meltQuote, err := w.RequestMeltQuote(invoice.PaymentRequest, mintURL)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}
	if meltQuote.FeeReserve != 1 {
		t.Fatalf("fixture requires fee_reserve 1 (blank outputs in the melt), got %d", meltQuote.FeeReserve)
	}
	if meltQuote.Amount != 62 {
		t.Fatalf("fixture requires melt amount 62, got %d", meltQuote.Amount)
	}
	return w.Melt(meltQuote.Quote)
}

// TestMeltSigAllEndToEndRealMint: SIG_ALL proofs locked to the wallet's
// own key melt successfully against the production mint — witness
// production (wallet) meets witness verification (mint) over the wire.
func TestMeltSigAllEndToEndRealMint(t *testing.T) {
	resp, err := meltLockedE2E(t, sigAllSelfCondition)
	if err != nil {
		t.Fatalf("SIG_ALL melt must succeed end-to-end: %v", err)
	}
	if resp.State != nut05.Paid {
		t.Fatalf("melt state = %v, want PAID", resp.State)
	}
	if resp.Preimage == "" {
		t.Fatal("paid melt must return the preimage")
	}
}

// TestMeltPlainP2PKEndToEndRealMint: the non-SIG_ALL P2PK arm — per-input
// witnesses from AddSignatureToInputs must satisfy the mint's per-proof
// VerifyP2PKLockedProof on the melt path.
func TestMeltPlainP2PKEndToEndRealMint(t *testing.T) {
	cond := func(w *Wallet) nut10.SpendingCondition {
		return nut10.SpendingCondition{
			Kind: nut10.P2PK,
			Data: hex.EncodeToString(w.privateKey.PubKey().SerializeCompressed()),
		}
	}
	resp, err := meltLockedE2E(t, cond)
	if err != nil {
		t.Fatalf("plain P2PK melt must succeed end-to-end: %v", err)
	}
	if resp.State != nut05.Paid {
		t.Fatalf("melt state = %v, want PAID", resp.State)
	}
}

// TestMeltSigAllWrongKeyRefusesLocally: proofs locked to a key the wallet
// does not hold must be refused locally, with the inputs released back to
// spendable — never stranded as pending.
func TestMeltSigAllWrongKeyRefusesLocally(t *testing.T) {
	_, mintURL, _ := startRealMint(t)

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: mintURL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	fundWallet(t, w, mintURL, 63)
	otherKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	lockAllToCondition(t, w, mintURL, nut10.SpendingCondition{
		Kind: nut10.P2PK,
		Data: hex.EncodeToString(otherKey.PubKey().SerializeCompressed()),
		Tags: [][]string{{"sigflag", "SIG_ALL"}},
	})

	backend := &lightning.FakeBackend{}
	invoice, err := backend.CreateInvoice(62)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := w.RequestMeltQuote(invoice.PaymentRequest, mintURL)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}

	_, err = w.Melt(quote.Quote)
	if err == nil || !strings.Contains(err.Error(), "cannot sign locked proofs") {
		t.Fatalf("melt of proofs locked to another key must refuse locally, got: %v", err)
	}
	if got := len(w.db.GetPendingProofsByQuoteId(quote.Quote)); got != 0 {
		t.Fatalf("refused melt must release its inputs, %d still pending", got)
	}
	if w.GetBalance() != 63 {
		t.Fatalf("balance after local refusal = %d, want 63 (inputs released)", w.GetBalance())
	}
}

// TestMeltHTLCLockedRefusesLocally: HTLC-locked proofs need a preimage
// which Melt carries none of — refuse locally (clear error, inputs
// released) instead of firing a request the mint must reject.
func TestMeltHTLCLockedRefusesLocally(t *testing.T) {
	_, mintURL, _ := startRealMint(t)

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: mintURL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	fundWallet(t, w, mintURL, 63)
	paymentHash := sha256.Sum256([]byte("htlc-melt-test"))
	lockAllToCondition(t, w, mintURL, nut10.SpendingCondition{
		Kind: nut10.HTLC,
		Data: hex.EncodeToString(paymentHash[:]),
	})

	backend := &lightning.FakeBackend{}
	invoice, err := backend.CreateInvoice(62)
	if err != nil {
		t.Fatal(err)
	}
	// quote for the same total so selection returns the locked proofs
	// unchanged (62 + 1 fee reserve = 63)
	quote, err := w.RequestMeltQuote(invoice.PaymentRequest, mintURL)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}

	_, err = w.Melt(quote.Quote)
	if err == nil || !strings.Contains(err.Error(), "without a preimage") {
		t.Fatalf("melt of HTLC-locked proofs must refuse locally with a preimage error, got: %v", err)
	}
	if got := len(w.db.GetPendingProofsByQuoteId(quote.Quote)); got != 0 {
		t.Fatalf("refused melt must release its inputs, %d still pending", got)
	}
	if w.GetBalance() != 63 {
		t.Fatalf("balance after local refusal = %d, want 63 (inputs released)", w.GetBalance())
	}
}
