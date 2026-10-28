package wallet

// Regression tests for the swap-response binding (audit #831/#833, tracked
// in tollgate-module-basic-go): every signature in a swap response must
// answer the blinded message this wallet sent at the same index — same
// amount, same keyset id — and the arrays must be length-matched, or the
// response is refused. A tampered or hostile relabel must never re-price a
// proof with the mint's own label.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
)

// postSwapToStubMint drives the honest stub mint so the tests tamper with a
// real, well-formed response rather than hand-building one.
func postSwapToStubMint(t *testing.T, m *signingMint, req swapRequestPayload) nut03.PostSwapResponse {
	t.Helper()
	body, _ := json.Marshal(nut03.PostSwapRequest{Inputs: req.inputs, Outputs: req.outputs})
	resp, err := http.Post(m.server.URL+"/v1/swap", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post swap: %v", err)
	}
	defer resp.Body.Close()
	var swapResp nut03.PostSwapResponse
	if err := json.NewDecoder(resp.Body).Decode(&swapResp); err != nil {
		t.Fatalf("decode swap response: %v", err)
	}
	return swapResp
}

func newBindingTestWallet(t *testing.T) (*signingMint, *Wallet, swapRequestPayload) {
	t.Helper()
	m := newSigningMint(t)
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: m.server.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	t.Cleanup(func() { _ = w.Shutdown() })
	return m, w, m.newSwapRequest(t, w, 8)
}

// The honest answer still passes: the binding must not break real swaps.
func TestSwapResponseBindingAcceptsHonestAnswer(t *testing.T) {
	m, _, req := newBindingTestWallet(t)
	swapResp := postSwapToStubMint(t, m, req)
	proofs, err := constructProofs(swapResp.Signatures, req.outputs, req.secrets, req.rs, req.keyset)
	if err != nil {
		t.Fatalf("honest answer rejected: %v", err)
	}
	if proofs.Amount() != req.inputs.Amount() {
		t.Fatalf("honest answer produced %d sat, inputs were %d", proofs.Amount(), req.inputs.Amount())
	}
}

// #831: a relabeled Amount must be refused, not minted into a proof.
func TestSwapResponseRelabeledAmountRefused(t *testing.T) {
	m, _, req := newBindingTestWallet(t)
	swapResp := postSwapToStubMint(t, m, req)
	if len(swapResp.Signatures) == 0 {
		t.Fatal("stub mint returned no signatures")
	}
	swapResp.Signatures[0].Amount = 64
	if _, err := constructProofs(swapResp.Signatures, req.outputs, req.secrets, req.rs, req.keyset); err == nil {
		t.Fatal("relabeled amount accepted: a tampered response re-priced the proof")
	}
}

// #831: a foreign keyset id on a signature must be refused.
func TestSwapResponseForeignKeysetIdRefused(t *testing.T) {
	m, _, req := newBindingTestWallet(t)
	swapResp := postSwapToStubMint(t, m, req)
	swapResp.Signatures[0].Id = "00" + "deadbeef"
	if _, err := constructProofs(swapResp.Signatures, req.outputs, req.secrets, req.rs, req.keyset); err == nil {
		t.Fatal("foreign keyset id accepted")
	}
}

// #833: a response with more signatures than blinded messages must be an
// error, never an index-out-of-range panic.
func TestSwapResponseLengthMismatchIsErrorNotPanic(t *testing.T) {
	m, _, req := newBindingTestWallet(t)
	swapResp := postSwapToStubMint(t, m, req)
	extended := append(swapResp.Signatures, swapResp.Signatures[0])
	if _, err := constructProofs(extended, req.outputs, req.secrets, req.rs, req.keyset); err == nil {
		t.Fatal("length mismatch accepted")
	}
}
