package wallet

// Finding 1 of the #33 review, settled empirically: does a REAL cdk-mintd
// answer an identical re-POST of an already-completed MELT with 200 + Paid +
// the change signatures (#33's recovery premise), or with a refusal? Same
// gating as the swap experiment on #31 — CDK_MINT_URL unset means skip.
//
// Driver: mint via a settled FakeWallet quote, build a melt quote from the
// fixture invoice, drive w.Melt with postMeltBolt11 wrapped so the exact
// request object is captured (its marshal IS the wire body), then re-POST
// the identical bytes with a plain http client and print the verdict.
import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/client"
)

func TestCdkMintMeltReplayBehavior(t *testing.T) {
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

	quote, err := w.RequestMint(128, mintURL)
	if err != nil {
		t.Fatalf("RequestMint: %v", err)
	}
	for i := 0; i < 30; i++ {
		if st, sErr := w.MintQuoteState(quote.Quote); sErr == nil && st.State == nut04.Paid {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if _, err := w.MintTokens(quote.Quote); err != nil {
		t.Fatalf("MintTokens: %v", err)
	}

	meltQuote, err := w.RequestMeltQuote(fakeMeltInvoice, mintURL)
	if err != nil {
		t.Fatalf("RequestMeltQuote: %v", err)
	}

	var captured []byte
	orig := postMeltBolt11
	defer func() { postMeltBolt11 = orig }()
	postMeltBolt11 = func(m string, req nut05.PostMeltBolt11Request) (*nut05.PostMeltQuoteBolt11Response, error) {
		captured, _ = json.Marshal(req)
		return orig(m, req)
	}

	if _, err := w.Melt(meltQuote.Quote); err != nil {
		t.Fatalf("Melt (first, must succeed for the experiment): %v", err)
	}
	if len(captured) == 0 {
		t.Fatal("melt request bytes were not captured")
	}
	t.Logf("first melt: completed, %d-byte request", len(captured))

	resp, err := http.Post(mintURL+"/v1/melt/bolt11", "application/json", bytes.NewReader(captured))
	if err != nil {
		t.Fatalf("replay POST: %v", err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	t.Logf("REPLAY VERDICT: HTTP %d, body: %s", resp.StatusCode, truncateForLog(buf.Bytes(), 400))

	if resp.StatusCode == http.StatusOK {
		var replay nut05.PostMeltQuoteBolt11Response
		if jErr := json.Unmarshal(buf.Bytes(), &replay); jErr == nil && replay.State == nut05.Paid {
			t.Logf("RESULT: cdk-mintd answers the completed-melt replay with 200 + Paid (+change len %d) — #33's melt premise HOLDS", len(replay.Change))
		} else {
			t.Logf("RESULT: replay is 200 but not the Paid shape — inspect body above")
		}
	} else {
		t.Logf("RESULT: cdk-mintd REFUSES the completed-melt replay (HTTP %d) — #33's melt recovery premise FAILS on cdk; the melt intent is a tombstone, not a recovery", resp.StatusCode)
	}
	_ = client.PostMeltBolt11
}
