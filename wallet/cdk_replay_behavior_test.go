package wallet

// The #31 evidence gap, settled empirically: does a REAL cdk-mintd answer an
// identical re-POST of an already-consumed swap with 200 + signatures (the
// PR's recovery premise), or with the spent-inputs refusal the fork's own
// client.go documents? Gated on CDK_MINT_URL — skipped everywhere else, so
// it costs the offline suites nothing.
//
// Run against the cloud-lab mint (cdk-mintd, FakeWallet):
//
//	docker run -d --network host \
//	  -e CDK_MINTD_URL=http://127.0.0.1:8085 \
//	  -e CDK_MINTD_LN_BACKEND=fakewallet \
//	  -e CDK_MINTD_LISTEN_HOST=0.0.0.0 -e CDK_MINTD_LISTEN_PORT=8085 \
//	  -e CDK_MINTD_MNEMONIC='abandon abandon ... about' \
//	  -e CDK_MINTD_DATABASE=sqlite -e CDK_MINTD_DATABASE_PATH=data/mint \
//	  -e CDK_MINTD_CACHE_BACKEND=memory  <mint-image>
//	CDK_MINT_URL=http://127.0.0.1:8085 go test ./wallet/ -run TestCdkMintSwapReplayBehavior -v -count=1
import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
)

func TestCdkMintSwapReplayBehavior(t *testing.T) {
	mintURL := os.Getenv("CDK_MINT_URL")
	if mintURL == "" {
		t.Skip("CDK_MINT_URL not set — replay behavior against a real cdk-mintd is opt-in")
	}

	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: mintURL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	defer w.Shutdown()
	if _, err := w.AddMint(mintURL); err != nil {
		t.Fatalf("AddMint: %v", err)
	}

	quote, err := w.RequestMint(64, mintURL)
	if err != nil {
		t.Fatalf("RequestMint: %v", err)
	}
	paid := false
	for i := 0; i < 30; i++ {
		st, sErr := w.MintQuoteState(quote.Quote)
		if sErr == nil && st.State == nut04.Paid {
			paid = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !paid {
		t.Fatalf("FakeWallet never settled the quote (state polls exhausted)")
	}
	if _, err := w.MintTokens(quote.Quote); err != nil {
		t.Fatalf("MintTokens: %v", err)
	}

	// Build the swap exactly as the wallet would: fresh outputs from the
	// deterministic derivation, inputs = the minted proofs.
	m, ok := w.mints[mintURL]
	if !ok {
		t.Fatalf("mint %s not in wallet cache", mintURL)
	}
	proofs := w.db.GetProofs()
	if len(proofs) == 0 {
		t.Fatal("no proofs after minting")
	}
	req, err := w.createSwapRequest(proofs, &m)
	if err != nil {
		t.Fatalf("createSwapRequest: %v", err)
	}
	body, _ := json.Marshal(nut03.PostSwapRequest{Inputs: req.inputs, Outputs: req.outputs})

	post := func(label string) (int, []byte) {
		resp, pErr := http.Post(mintURL+"/v1/swap", "application/json", bytes.NewReader(body))
		if pErr != nil {
			t.Fatalf("%s POST: %v", label, pErr)
		}
		defer resp.Body.Close()
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}

	s1, b1 := post("first")
	if s1 != 200 {
		t.Fatalf("first swap should succeed, got %d: %s", s1, truncateForLog(b1, 200))
	}
	t.Logf("first swap: 200, %d-byte signature set", len(b1))

	s2, b2 := post("replay")
	t.Logf("REPLAY VERDICT: HTTP %d, body: %s", s2, truncateForLog(b2, 300))
	if s2 == 200 && bytes.Equal(b1, b2) {
		t.Logf("RESULT: cdk-mintd answers identical replay with 200 + byte-identical signatures — #31's premise HOLDS")
	} else if s2 != 200 {
		t.Logf("RESULT: cdk-mintd REFUSES the replay (HTTP %d) — #31's recovery premise FAILS on cdk; the intent is a tombstone, not a recovery", s2)
	} else {
		t.Logf("RESULT: replay is 200 but signatures differ from the first answer — inspect before concluding")
	}
}
