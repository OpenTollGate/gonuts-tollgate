package wallet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/storage"
)

// TestMeltReservesBlankOutputRangeBeforeSending pins the invariant behind
// tollgate #494: the melt's blank (NUT-08 fee-change) outputs are exposed
// to the mint with the melt request, so their derivation range must be
// persisted BEFORE the request is sent — even when the mint's response is
// lost. A retried melt with a fresh quote must then derive a disjoint
// range instead of replaying the exposed one ("outputs already signed").
func TestMeltReservesBlankOutputRangeBeforeSending(t *testing.T) {
	const genKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	keysJSON := `{"keysets":[{"id":"` + v2FullID + `","unit":"sat","active":true,"input_fee_ppk":0,"keys":{`
	for i := 0; i <= 20; i++ {
		if i > 0 {
			keysJSON += ","
		}
		keysJSON += fmt.Sprintf(`"%d":"%s"`, 1<<i, genKey)
	}
	keysJSON += `}}]}`

	var mu sync.Mutex
	meltOutputs := []map[string]bool{}
	meltFailFirst := true

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, keysJSON)
	})
	mux.HandleFunc("/v1/keysets", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"keysets":[{"id":"`+v2FullID+`","unit":"sat","active":true,"input_fee_ppk":0}]}`)
	})
	mux.HandleFunc("/v1/melt/bolt11", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Outputs cashu.BlindedMessages `json:"outputs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		mu.Lock()
		seen := map[string]bool{}
		for _, bm := range req.Outputs {
			seen[bm.B_] = true
		}
		meltOutputs = append(meltOutputs, seen)
		first := len(meltOutputs) == 1 && meltFailFirst
		mu.Unlock()

		if first {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "upstream lightning backend unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"quote":"q","state":"PAID","payment_preimage":"00"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: srv.URL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()

	fundExact := func(tag string) {
		t.Helper()
		exact := cashu.Proofs{
			{Id: v2FullID, Amount: 64, Secret: tag + "-64", C: "02ab"},
			{Id: v2FullID, Amount: 4, Secret: tag + "-4", C: "02cd"},
		}
		if err := w.db.SaveProofs(exact); err != nil {
			t.Fatalf("SaveProofs(%s): %v", tag, err)
		}
	}
	fundExact("melt1")

	newQuote := func(id string) storage.MeltQuote {
		return storage.MeltQuote{
			QuoteId:        id,
			Mint:           srv.URL,
			Method:         cashu.BOLT11_METHOD,
			Unit:           "sat",
			State:          nut05.Unpaid,
			PaymentRequest: "lnbcrt64u1p_TEST_INVOICE",
			Amount:         64,
			FeeReserve:     4, // calculateBlankOutputs(4) == 2 blank outputs
		}
	}
	for _, id := range []string{"q1", "q2"} {
		if err := w.db.SaveMeltQuote(newQuote(id)); err != nil {
			t.Fatalf("SaveMeltQuote(%s): %v", id, err)
		}
	}

	counter0 := w.counterForKeyset(v2FullID)

	if _, err := w.Melt("q1"); err == nil {
		t.Fatalf("first melt against a 500ing mint should fail")
	}

	mu.Lock()
	firstOutputs := meltOutputs[0]
	mu.Unlock()
	if len(firstOutputs) == 0 {
		t.Fatalf("mint saw no blank outputs in the melt request")
	}

	counter1 := w.counterForKeyset(v2FullID)
	if counter1 != counter0+uint32(len(firstOutputs)) {
		t.Fatalf("failed melt must still reserve its exposed range: counter %d -> %d, expected +%d",
			counter0, counter1, len(firstOutputs))
	}

	fundExact("melt2")
	if _, err := w.Melt("q2"); err != nil {
		t.Fatalf("second melt (fresh quote, mint healthy): %v", err)
	}

	mu.Lock()
	secondOutputs := meltOutputs[1]
	mu.Unlock()

	replayed := 0
	for b := range secondOutputs {
		if firstOutputs[b] {
			replayed++
		}
	}
	if replayed != 0 {
		t.Fatalf("retried melt re-derived %d output(s) from the failed melt's exposed range", replayed)
	}
	counter2 := w.counterForKeyset(v2FullID)
	if counter2 != counter0+uint32(len(firstOutputs))+uint32(len(secondOutputs)) {
		t.Fatalf("counter must cover both exposed ranges exactly: %d, want %d",
			counter2, counter0+uint32(len(firstOutputs))+uint32(len(secondOutputs)))
	}
}
