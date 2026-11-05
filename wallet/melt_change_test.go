package wallet

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/OpenTollGate/gonuts-tollgate/mint"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// NUT-08 melt change, wallet side (cashu-audit #68 B3): the mint imprints
// change amounts on the wallet's blank outputs; the wallet consumes them
// with the binding disciplines intact — index/keyset binding, the overpay
// ceiling, crash recovery replaying the identical melt.

// --- unit: the binding disciplines on constructMeltChangeProofs ---

type changeFixture struct {
	blanks  cashu.BlindedMessages
	secrets []string
	rs      []*secp256k1.PrivateKey
	keyset  crypto.WalletKeyset
	privs   map[uint64]*secp256k1.PrivateKey
	sigs    cashu.BlindedSignatures
}

// newChangeFixture builds n blank outputs against a local keyset and
// signs them at the given amounts (the honest-mint shape: signature i
// answers blank i, mint-assigned amount).
func newChangeFixture(t *testing.T, n int, amounts []uint64) *changeFixture {
	t.Helper()
	f := &changeFixture{
		privs: map[uint64]*secp256k1.PrivateKey{},
	}
	pubs := crypto.PublicKeys{}
	for _, a := range []uint64{1, 2, 4, 8, 16, 32, 64} {
		priv, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		f.privs[a] = priv
		pubs[a] = priv.PubKey()
	}
	f.keyset = crypto.WalletKeyset{
		Id:         crypto.DeriveKeysetId(pubs),
		MintURL:    "placeholder",
		Unit:       "sat",
		Active:     true,
		PublicKeys: pubs,
	}

	f.blanks = make(cashu.BlindedMessages, n)
	f.secrets = make([]string, n)
	f.rs = make([]*secp256k1.PrivateKey, n)
	for i := 0; i < n; i++ {
		secret, r, err := generateRandomSecret()
		if err != nil {
			t.Fatal(err)
		}
		B_, r, err := crypto.BlindMessage(secret, r)
		if err != nil {
			t.Fatal(err)
		}
		f.blanks[i] = cashu.NewBlindedMessage(f.keyset.Id, 0, B_)
		f.secrets[i] = secret
		f.rs[i] = r
	}

	if amounts != nil {
		f.sigs = f.signAt(t, amounts)
	}
	return f
}

func (f *changeFixture) signAt(t *testing.T, amounts []uint64) cashu.BlindedSignatures {
	t.Helper()
	sigs := make(cashu.BlindedSignatures, len(amounts))
	for i, amount := range amounts {
		if amount == 0 {
			t.Fatal("fixture: change amounts must be positive")
		}
		BBytes, err := hex.DecodeString(f.blanks[i].B_)
		if err != nil {
			t.Fatal(err)
		}
		BPub, err := secp256k1.ParsePubKey(BBytes)
		if err != nil {
			t.Fatal(err)
		}
		C_ := crypto.SignBlindedMessage(BPub, f.privs[amount])
		e, s := crypto.GenerateDLEQ(f.privs[amount], BPub, C_)
		sigs[i] = cashu.BlindedSignature{
			Amount: amount,
			C_:     hex.EncodeToString(C_.SerializeCompressed()),
			Id:     f.keyset.Id,
			DLEQ: &cashu.DLEQProof{
				E: hex.EncodeToString(e.Serialize()),
				S: hex.EncodeToString(s.Serialize()),
			},
		}
	}
	return sigs
}

func TestMeltChangeProofsAcceptMintAssignedAmounts(t *testing.T) {
	f := newChangeFixture(t, 3, []uint64{2, 1})
	proofs, err := constructMeltChangeProofs(f.sigs, f.blanks, f.secrets, f.rs, &f.keyset, 3)
	if err != nil {
		t.Fatalf("honest change (2+1, bound 3) must unblind: %v", err)
	}
	if proofs.Amount() != 3 {
		t.Fatalf("change proofs sum = %d, want 3", proofs.Amount())
	}
	// partial change: fewer signatures than blanks is the spec shape
	// (zero-value signatures are omitted by the mint)
	f2 := newChangeFixture(t, 3, []uint64{4})
	proofs, err = constructMeltChangeProofs(f2.sigs, f2.blanks, f2.secrets, f2.rs, &f2.keyset, 5)
	if err != nil || proofs.Amount() != 4 {
		t.Fatalf("partial change must unblind: %v %d", err, proofs.Amount())
	}
}

func TestMeltChangeProofsRejectOversizedChange(t *testing.T) {
	f := newChangeFixture(t, 3, []uint64{2, 2})
	// bound 3, mint returns 4: hostile or broken — refused
	if _, err := constructMeltChangeProofs(f.sigs, f.blanks, f.secrets, f.rs, &f.keyset, 3); err == nil {
		t.Fatal("change exceeding the overpay bound must be rejected")
	}
}

func TestMeltChangeProofsRejectExcessSignatures(t *testing.T) {
	f := newChangeFixture(t, 2, []uint64{2, 1})
	// hand over only ONE blank: two signatures for one output is not a
	// shape to guess value from
	if _, err := constructMeltChangeProofs(f.sigs, f.blanks[:1], f.secrets[:1], f.rs[:1], &f.keyset, 3); err == nil {
		t.Fatal("more change signatures than blank outputs must be rejected")
	}
}

func TestMeltChangeProofsRejectForeignKeyset(t *testing.T) {
	f := newChangeFixture(t, 2, []uint64{2, 1})
	sigs := append(cashu.BlindedSignatures{}, f.sigs...)
	sigs[0].Id = "00deadbeef"
	if _, err := constructMeltChangeProofs(sigs, f.blanks, f.secrets, f.rs, &f.keyset, 3); err == nil {
		t.Fatal("change signature answering a foreign keyset must be rejected")
	}
	// case-insensitive id comparison (mint-supplied spelling) stays legal
	sigs[0].Id = f.keyset.Id
	upper := []byte(f.keyset.Id)
	for i, c := range upper {
		if c >= 'a' && c <= 'f' {
			upper[i] = c - 'a' + 'A'
		}
	}
	sigs[0].Id = string(upper)
	if _, err := constructMeltChangeProofs(sigs, f.blanks, f.secrets, f.rs, &f.keyset, 3); err != nil {
		t.Fatalf("keyset id differing only in case must be accepted: %v", err)
	}
}

func TestMeltChangeProofsRejectUnknownDenomination(t *testing.T) {
	f := newChangeFixture(t, 3, []uint64{2})
	// relabel the amount onto one the keyset cannot sign (3 is not a
	// denomination of the 2^n keyset): a tampered answer, refused
	sigs := append(cashu.BlindedSignatures{}, f.sigs...)
	sigs[0].Amount = 3
	if _, err := constructMeltChangeProofs(sigs, f.blanks, f.secrets, f.rs, &f.keyset, 5); err == nil {
		t.Fatal("change amount that is not a keyset denomination must be rejected")
	}
}

// --- real-mint e2e (production mint + FakeBackend over HTTP) ---

type realMintArm struct {
	server  *mint.MintServer
	m       *mint.Mint
	url     string
	port    int
	backend *lightning.FakeBackend
	dbpath  string
}

func freePort(t *testing.T) int {
	t.Helper()
	for p := 4450; p < 4490; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln.Close()
			return p
		}
	}
	t.Fatal("no free port in 4450-4489")
	return 0
}

func startRealMintArm(t *testing.T, dbpath string, backend *lightning.FakeBackend, port int) *realMintArm {
	t.Helper()
	m, err := mint.LoadMint(mint.Config{
		MintPath:        dbpath,
		LightningClient: backend,
		LogLevel:        mint.Disable,
		Port:            port,
	})
	if err != nil {
		t.Fatalf("LoadMint: %v", err)
	}
	server := mint.SetupMintServer(m, mint.ServerConfig{Port: port})
	go func() { _ = server.Start() }()
	arm := &realMintArm{server: server, m: m, url: fmt.Sprintf("http://127.0.0.1:%d", port), port: port, backend: backend, dbpath: dbpath}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(arm.url + "/v1/info")
		if err == nil {
			resp.Body.Close()
			return arm
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("mint server did not come up")
	return nil
}

// restartRealMintArm models a mint process restart on the same database:
// fresh in-memory state (no NUT-19 response cache), keyset re-derived
// from the stored seed. The cleanup stays with the test.
func restartRealMintArm(t *testing.T, arm *realMintArm) *realMintArm {
	t.Helper()
	arm.server.Shutdown()
	return startRealMintArm(t, arm.dbpath, arm.backend, arm.port)
}

func fundWalletAtMint(t *testing.T, w *Wallet, mintURL string, amount uint64) {
	t.Helper()
	quote, err := w.RequestMint(amount, mintURL)
	if err != nil {
		t.Fatalf("RequestMint: %v", err)
	}
	if _, err := w.MintTokens(quote.Quote); err != nil {
		t.Fatalf("MintTokens: %v", err)
	}
}

func TestMeltChangeEndToEndRealMint(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}
	arm := startRealMintArm(t, t.TempDir(), backend, freePort(t))
	defer arm.server.Shutdown()

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: arm.url})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	fundWalletAtMint(t, w, arm.url, 64)

	invoice, err := backend.CreateInvoice(21)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := w.RequestMeltQuote(invoice.PaymentRequest, arm.url)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}
	if quote.FeeReserve != 2 {
		t.Fatalf("fixture requires fee reserve 2, got %d", quote.FeeReserve)
	}

	var captured nut05.PostMeltBolt11Request
	origMelt := postMeltBolt11
	defer func() { postMeltBolt11 = origMelt }()
	postMeltBolt11 = func(mintURL string, req nut05.PostMeltBolt11Request) (*nut05.PostMeltQuoteBolt11Response, error) {
		captured = req
		return origMelt(mintURL, req)
	}

	resp, err := w.Melt(quote.Quote)
	if err != nil {
		t.Fatalf("Melt: %v", err)
	}
	if resp.State != nut05.Paid {
		t.Fatalf("melt state = %v, want PAID", resp.State)
	}

	inputs := captured.Inputs.Amount()
	wantChange := inputs - 21 // fake payment costs nothing: the whole overpay returns
	if resp.Change.Amount() != wantChange {
		t.Fatalf("change = %d, want %d (inputs %d − amount 21)", resp.Change.Amount(), wantChange, inputs)
	}
	if got := w.GetBalance(); got != 64-inputs+wantChange {
		t.Fatalf("balance = %d, want %d (64 − %d inputs + %d change)", got, 64-inputs+wantChange, inputs, wantChange)
	}
	if n := len(w.db.GetPendingSwaps()); n != 0 {
		t.Fatalf("melt intent must retire on success, %d remain", n)
	}
}

// TestMeltChangeCrashRecoveryReplaysIdentically: the response is lost
// after the mint settled (crash between PAID and the change save). The
// intent replays the exact request bytes against a RESTARTED mint (no
// NUT-19 cache) and must recover the identical change — no re-derivation,
// no counter movement.
func TestMeltChangeCrashRecoveryReplaysIdentically(t *testing.T) {
	backend := &lightning.FakeBackend{FeeReserveSats: 2}
	arm := startRealMintArm(t, t.TempDir(), backend, freePort(t))

	walletPath := t.TempDir()
	w, err := LoadWallet(Config{WalletPath: walletPath, CurrentMintURL: arm.url})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}

	fundWalletAtMint(t, w, arm.url, 64)
	invoice, err := backend.CreateInvoice(21)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := w.RequestMeltQuote(invoice.PaymentRequest, arm.url)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}

	var firstChange cashu.BlindedSignatures
	origMelt := postMeltBolt11
	postMeltBolt11 = func(mintURL string, req nut05.PostMeltBolt11Request) (*nut05.PostMeltQuoteBolt11Response, error) {
		resp, err := origMelt(mintURL, req)
		if err == nil && resp.State == nut05.Paid {
			firstChange = resp.Change // the response the crash eats
			return nil, errors.New("simulated crash after settlement")
		}
		return resp, err
	}
	_, meltErr := w.Melt(quote.Quote)
	postMeltBolt11 = origMelt
	if meltErr == nil {
		t.Fatal("crash not simulated")
	}
	if firstChange.Amount() == 0 {
		t.Fatal("fixture requires positive change")
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatal("crashed melt must leave exactly one intent")
	}
	counterBefore := w.counterForKeyset(w.db.GetKeysets()[arm.url][0].Id)
	balanceBefore := w.GetBalance()

	// restart the mint: fresh process, same database — the replay cannot
	// be served from any cache, it must come from the paid-quote replay
	// path (stored outputs + stored signatures)
	arm = restartRealMintArm(t, arm)
	defer arm.server.Shutdown()

	recovered, failed, err := w.ResumePendingOperations()
	if err != nil || failed != 0 {
		t.Fatalf("resume must recover the crashed melt: recovered=%d failed=%d err=%v", recovered, failed, err)
	}
	if recovered != firstChange.Amount() {
		t.Fatalf("recovered %d sats, want the identical change %d", recovered, firstChange.Amount())
	}
	if got := w.GetBalance(); got != balanceBefore+firstChange.Amount() {
		t.Fatalf("balance = %d, want %d", got, balanceBefore+firstChange.Amount())
	}
	if n := len(w.db.GetPendingSwaps()); n != 0 {
		t.Fatalf("intent must retire after recovery, %d remain", n)
	}
	keysetId := ""
	for _, ks := range w.db.GetKeysets()[arm.url] {
		if ks.Active {
			keysetId = ks.Id
		}
	}
	if w.counterForKeyset(keysetId) != counterBefore {
		t.Fatalf("recovery moved the derivation counter: %d → %d (never rewind, never double-advance)",
			counterBefore, w.counterForKeyset(keysetId))
	}
}

// TestMeltChangeHostileOversizedRefused: a mint answering with change
// beyond the wallet's own overpay is refused — the melt is PAID, the
// intent stays, the value is never booked.
func TestMeltChangeHostileOversizedRefused(t *testing.T) {
	m := newSigningMint(t)
	m.meltChangeAmounts = []uint64{8} // hostile: 8 sats where ≤1 is honest

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	fundWalletAtMint(t, w, m.server.URL, 64)
	quote, err := w.RequestMeltQuote(fakeMeltInvoice, m.server.URL)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}
	// stub quote: amount 21, fee_reserve 1 → inputs 22, overpay bound 1
	balanceBefore := w.GetBalance()

	_, err = w.Melt(quote.Quote)
	if err == nil {
		t.Fatal("oversized change must be refused")
	}
	if got := w.GetBalance(); got != balanceBefore-22 {
		t.Fatalf("balance = %d, want %d (inputs spent, no change booked)", got, balanceBefore-22)
	}
	var meltIntents int
	for _, intent := range w.db.GetPendingSwaps() {
		if intent.OpType == storagePendingOpMelt {
			meltIntents++
		}
	}
	if meltIntents != 1 {
		t.Fatalf("hostile-change melt must keep its intent journaled, got %d", meltIntents)
	}
}
