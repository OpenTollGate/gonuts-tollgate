package wallet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
)

// TestSwapWithRetryReservesRetryRange pins the invariant behind tollgate
// #495: when the mint rejects the first swap range with 10002 and
// swapWithRetry regenerates fresh outputs, the retry's derivation range
// must be persisted (counter incremented) before it is sent. Without it
// the counter trails the last exposed range and every later first attempt
// re-derives it.
func TestSwapWithRetryReservesRetryRange(t *testing.T) {
	const genKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	keysJSON := `{"keysets":[{"id":"` + v2FullID + `","unit":"sat","active":true,"input_fee_ppk":0,"keys":{`
	for i := 0; i <= 20; i++ {
		if i > 0 {
			keysJSON += ","
		}
		keysJSON += fmt.Sprintf(`"%d":"%s"`, 1<<i, genKey)
	}
	keysJSON += `}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, keysJSON)
	}))
	defer srv.Close()

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: srv.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	mint, ok := w.mints[srv.URL]
	if !ok {
		t.Fatalf("mint not registered")
	}

	proofs := cashu.Proofs{{Id: v2FullID, Amount: 64, Secret: "s64", C: "02ab"}}
	req, err := w.createSwapRequest(proofs, &mint)
	if err != nil {
		t.Fatalf("createSwapRequest: %v", err)
	}
	// swapWithIntent (inside swapWithRetry) now reserves the first
	// attempt's range atomically with its intent — no manual pre-increment.
	counterAfterFirst := req.counterStart + uint32(len(req.outputs))

	firstOutputs := map[string]bool{}
	for _, bm := range req.outputs {
		firstOutputs[bm.B_] = true
	}

	swapCalls := 0
	var retrySeen []string
	swap = func(mintURL string, swapRequest swapRequestPayload) (cashu.Proofs, error) {
		swapCalls++
		if swapCalls == 1 {
			return nil, cashu.BlindedMessageAlreadySigned
		}
		for _, bm := range swapRequest.outputs {
			retrySeen = append(retrySeen, bm.B_)
		}
		return cashu.Proofs{{Id: v2FullID, Amount: 63, Secret: "retry", C: "02cd"}}, nil
	}
	defer func() { swap = nil }()

	got, _, err := w.swapWithRetry(srv.URL, req, proofs, &mint, nut10.WellKnownSecret{})
	if err != nil {
		t.Fatalf("swapWithRetry: %v", err)
	}
	if got.Amount() != 63 {
		t.Fatalf("unexpected retry result amount %d", got.Amount())
	}

	if swapCalls != 2 {
		t.Fatalf("expected exactly 2 swap calls, got %d", swapCalls)
	}

	counterAfterRetry := w.counterForKeyset(v2FullID)
	want := counterAfterFirst + uint32(len(retrySeen))
	if counterAfterRetry != want {
		t.Fatalf("counter must cover the retry range: got %d, want %d (first %d + retry %d)",
			counterAfterRetry, want, counterAfterFirst, len(retrySeen))
	}

	overlap := 0
	for _, b := range retrySeen {
		if firstOutputs[b] {
			overlap++
		}
	}
	if overlap != 0 {
		t.Fatalf("retry re-derived %d output(s) from the rejected range", overlap)
	}
}
