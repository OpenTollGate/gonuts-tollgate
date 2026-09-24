package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// signingMint is a stub mint that actually signs swaps (deterministic
// DhKE), so the resume path can be exercised end to end offline. It
// keeps the private keys the wallet never sees.
type signingMint struct {
	t           *testing.T
	server      *httptest.Server
	privs       map[uint64]*secp256k1.PrivateKey
	keyset      crypto.WalletKeyset
	swaps       int
	mints       int
	lastReq     []byte
	lastQuoteID string
}

func newSigningMint(t *testing.T) *signingMint {
	t.Helper()
	m := &signingMint{t: t, privs: map[uint64]*secp256k1.PrivateKey{}}
	pubs := crypto.PublicKeys{}
	for _, a := range []uint64{1, 2, 4, 8, 16, 32, 64} {
		h := randPrivKey(t)
		m.privs[a] = h
		pubs[a] = h.PubKey()
	}
	m.keyset = crypto.WalletKeyset{
		Id:         "00" + hex.EncodeToString([]byte("feetest")),
		MintURL:    "placeholder",
		Unit:       "sat",
		Active:     true,
		PublicKeys: pubs,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mint/quote/bolt11/", func(w http.ResponseWriter, r *http.Request) {
		// subtree match covers both POST /v1/mint/quote/bolt11 and GET /{id}
		if r.Method == http.MethodGet {
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			id := parts[len(parts)-1]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"quote": id, "request": "lntb", "amount": 64, "unit": "sat",
				"state": "PAID", "expiry": 0, "amount_paid": 64, "amount_issued": 0, "updated_at": 0,
			})
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := fmt.Sprintf("quote-%d", time.Now().UnixNano())
		m.lastQuoteID = id
		_ = json.NewEncoder(w).Encode(map[string]any{
			"quote": id, "request": "lntb", "amount": req["amount"], "unit": "sat",
			"state": "PAID", "expiry": 0, "amount_paid": req["amount"], "amount_issued": 0, "updated_at": 0,
		})
	})
	mux.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keysets": []map[string]any{{
			"id": m.keyset.Id, "unit": "sat", "active": true, "keys": pubs,
		}}})
	})
	mux.HandleFunc("/v1/mint/bolt11", func(w http.ResponseWriter, r *http.Request) {
		var req nut04.PostMintBolt11Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		m.mints++
		sigs := []cashu.BlindedSignature{}
		for _, out := range req.Outputs {
			B_, err := hex.DecodeString(out.B_)
			if err != nil {
				http.Error(w, "bad B_", 400)
				return
			}
			BPub, err := secp256k1.ParsePubKey(B_)
			if err != nil {
				http.Error(w, "bad point", 400)
				return
			}
			C_ := crypto.SignBlindedMessage(BPub, m.privs[out.Amount])
			sigs = append(sigs, cashu.BlindedSignature{
				Amount: out.Amount,
				Id:     m.keyset.Id,
				C_:     hex.EncodeToString(C_.SerializeCompressed()),
			})
		}
		_ = json.NewEncoder(w).Encode(nut04.PostMintBolt11Response{Signatures: cashu.BlindedSignatures(sigs)})
	})
	mux.HandleFunc("/v1/keysets", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keysets": []map[string]any{{
			"id": m.keyset.Id, "unit": "sat", "active": true, "input_fee_ppk": 0,
		}}})
	})
	mux.HandleFunc("/v1/swap", func(w http.ResponseWriter, r *http.Request) {
		var req nut03.PostSwapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		m.swaps++
		raw, _ := json.Marshal(req)
		m.lastReq = raw
		sigs := cashu.BlindedSignatures{}
		for _, out := range req.Outputs {
			B_, err := hex.DecodeString(out.B_)
			if err != nil {
				http.Error(w, "bad B_", 400)
				return
			}
			BPub, err := secp256k1.ParsePubKey(B_)
			if err != nil {
				http.Error(w, "bad point", 400)
				return
			}
			C_ := crypto.SignBlindedMessage(BPub, m.privs[out.Amount])
			sigs = append(sigs, cashu.BlindedSignature{
				Amount: out.Amount,
				Id:     m.keyset.Id,
				C_:     hex.EncodeToString(C_.SerializeCompressed()),
			})
		}
		_ = json.NewEncoder(w).Encode(nut03.PostSwapResponse{Signatures: sigs})
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

var storagePendingOpMint = "mint" // mirrors storage.PendingOpMint without an extra import cycle in this test file

var errSimulatedCrash = errors.New("simulated crash after the mint accepted the swap")

func (m *signingMint) newSwapRequest(t *testing.T, w *Wallet, amount uint64) swapRequestPayload {
	t.Helper()
	mint, ok := w.mints[m.server.URL]
	if !ok {
		t.Fatalf("stub mint not registered")
	}
	proofs := cashu.Proofs{{Id: m.keyset.Id, Amount: amount, Secret: "input-secret", C: "02ab"}}
	req, err := w.createSwapRequest(proofs, &mint)
	if err != nil {
		t.Fatalf("createSwapRequest: %v", err)
	}
	return req
}

// The #497 acceptance shape: the mint accepted and signed the swap, the
// wallet "died" before unblinding or saving. The intent must let
// ResumePendingSwaps recover the full amount by replaying the exact
// request bytes.
func TestResumePendingSwapsRecoversCrashedSwap(t *testing.T) {
	m := newSigningMint(t)

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	// Simulate the crash: the POST reaches the mint (it signs), but the
	// wallet never processes the response. swapWithIntent recorded the
	// intent before the POST, so it survives.
	origSwap := swap
	defer func() { swap = origSwap }()
	swap = func(mintURL string, req swapRequestPayload) (cashu.Proofs, error) {
		body, _ := json.Marshal(nut03.PostSwapRequest{Inputs: req.inputs, Outputs: req.outputs})
		resp, err := http.Post(mintURL+"/v1/swap", "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		return nil, errSimulatedCrash
	}

	req := m.newSwapRequest(t, w, 64)
	if _, _, recErr := w.swapWithIntent(m.server.URL, req); recErr == nil {
		t.Fatal("simulated crash must surface an error")
	}
	if m.swaps != 1 {
		t.Fatalf("mint should have signed exactly once, signed %d", m.swaps)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("intent must survive the crash, have %d", len(w.db.GetPendingSwaps()))
	}

	// Boot again: real swap path restored; resume replays and recovers.
	swap = origSwap
	recovered, failed, err := w.ResumePendingSwaps()
	if err != nil || failed != 0 {
		t.Fatalf("resume: recovered=%d failed=%d err=%v", recovered, failed, err)
	}
	if recovered != 64 {
		t.Fatalf("recovered %d, want 64", recovered)
	}
	if len(w.db.GetPendingSwaps()) != 0 {
		t.Fatal("intent must be deleted after recovery")
	}
	if w.GetBalance() != 64 {
		t.Fatalf("balance after recovery = %d, want 64", w.GetBalance())
	}
	if m.swaps != 2 {
		t.Fatalf("mint should have signed exactly twice (original + replay), signed %d", m.swaps)
	}
}

// A successful swap leaves no intent behind once its caller completes
// the Receive sequence: swap, SaveProofs, delete intent.
func TestSuccessfulSwapDeletesItsIntent(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	proofs, opID, err := w.swapWithIntent(m.server.URL, m.newSwapRequest(t, w, 8))
	if err != nil {
		t.Fatalf("swapWithIntent: %v", err)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatal("intent must exist between POST and SaveProofs")
	}
	if err := w.db.SaveProofs(proofs); err != nil {
		t.Fatalf("SaveProofs: %v", err)
	}
	if err := w.db.DeletePendingSwap(opID); err != nil {
		t.Fatalf("DeletePendingSwap: %v", err)
	}
	if len(w.db.GetPendingSwaps()) != 0 {
		t.Fatal("completed swap must have no lingering intent")
	}
	if w.GetBalance() != 8 {
		t.Fatalf("balance = %d, want 8", w.GetBalance())
	}
}

// A mint that cannot answer keeps its intent: never delete what was not
// recovered.
func TestResumePendingSwapsKeepsIntentWhenMintDown(t *testing.T) {
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origSwap := swap
	swap = func(mintURL string, req swapRequestPayload) (cashu.Proofs, error) {
		return nil, errSimulatedCrash
	}
	_, _, _ = w.swapWithIntent(m.server.URL, m.newSwapRequest(t, w, 16))
	swap = origSwap

	m.server.Close()

	_, failed, _ := w.ResumePendingSwaps()
	if failed != 1 {
		t.Fatalf("failed = %d, want 1", failed)
	}
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatal("intent must survive an unrecoverable pass")
	}
}

func randPrivKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1 + len(t.Name()))
	}
	return secp256k1.PrivKeyFromBytes(b)
}

// The #497 acceptance shape for the mint path: the mint signed the mint
// request, the wallet "died" before unblinding/saving; the intent must
// let ResumePendingOperations recover by replaying the exact bytes.
func TestResumePendingOperationsRecoversCrashedMint(t *testing.T) {
	m := newSigningMint(t)

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	origPost := postMintBolt11
	defer func() { postMintBolt11 = origPost }()
	postMintBolt11 = func(mintURL string, req nut04.PostMintBolt11Request) (*nut04.PostMintBolt11Response, error) {
		// the POST reaches the mint (it signs)…
		body, _ := json.Marshal(req)
		resp, err := http.Post(mintURL+"/v1/mint/bolt11", "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		resp.Body.Close()
		// …and the wallet dies before processing the response.
		return nil, errSimulatedCrash
	}

	quote, err := w.RequestMint(64, m.server.URL)
	if err != nil {
		t.Fatalf("RequestMint: %v", err)
	}
	if _, err := w.MintTokens(quote.Quote); err == nil {
		t.Fatal("simulated crash must surface an error")
	}
	intents := w.db.GetPendingSwaps()
	if len(intents) != 1 {
		t.Fatalf("mint intent must survive the crash, have %d", len(intents))
	}
	if intents[0].OpType != storagePendingOpMint {
		t.Fatalf("op type = %q, want mint", intents[0].OpType)
	}

	// Boot again: the real mint path is restored; resume replays.
	postMintBolt11 = origPost
	recovered, failed, err := w.ResumePendingOperations()
	if err != nil || failed != 0 {
		t.Fatalf("resume: recovered=%d failed=%d err=%v", recovered, failed, err)
	}
	if recovered != 64 {
		t.Fatalf("recovered %d, want 64", recovered)
	}
	if len(w.db.GetPendingSwaps()) != 0 {
		t.Fatal("mint intent must be deleted after recovery")
	}
	if w.GetBalance() != 64 {
		t.Fatalf("balance after recovery = %d, want 64", w.GetBalance())
	}
}
