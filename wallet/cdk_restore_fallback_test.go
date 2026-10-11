package wallet

// The #866 live lane, run against a real cdk-mintd (the same opt-in
// shape as TestCdkMintSwapReplayBehavior): the boot-resume path must
// recover a beyond-window 11001-stuck swap intent via NUT-09 /restore —
// the wallet "dies" after the mint accepted the swap, the mint is
// restarted (its in-memory NUT-19 cache dies with the process while the
// sqlite blind-signature store persists), so the journaled replay is
// refused {"code":11001,"detail":"Token Already Spent"} and only the
// restore fallback can complete the recovery. Gated on CDK_MINT_URL —
// skipped everywhere else, so it costs the offline suites nothing.
//
//	docker run -d --name probe-mint --network host \
//	  -e CDK_MINTD_URL=http://127.0.0.1:8085 \
//	  -e CDK_MINTD_LN_BACKEND=fakewallet \
//	  -e CDK_MINTD_LISTEN_HOST=127.0.0.1 -e CDK_MINTD_LISTEN_PORT=8085 \
//	  -e CDK_MINTD_MNEMONIC='abandon abandon ... about' \
//	  -e CDK_MINTD_DATABASE=sqlite -e CDK_MINTD_DATABASE_PATH=/data/mint \
//	  -e CDK_MINTD_CACHE_BACKEND=memory -v $PWD/mint-data:/data \
//	  cdk-replay-mint:latest
//	CDK_MINT_URL=http://127.0.0.1:8085 CDK_MINT_CONTAINER=probe-mint \
//	  go test ./wallet/ -run TestCdkResumeRecoversViaRestoreAfterMintRestart -v -count=1
import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
)

func restoreProbeGet(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b
}

func restoreProbeWaitHealthy(t *testing.T, mintURL string, seconds int) {
	t.Helper()
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := restoreProbeGet(t, mintURL+"/v1/info"); s == 200 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("mint %s did not become healthy within %ds", mintURL, seconds)
}

func TestCdkResumeRecoversViaRestoreAfterMintRestart(t *testing.T) {
	mintURL := os.Getenv("CDK_MINT_URL")
	if mintURL == "" {
		t.Skip("CDK_MINT_URL not set — restore recovery against a real cdk-mintd is opt-in")
	}
	container := os.Getenv("CDK_MINT_CONTAINER")
	if container == "" {
		t.Skip("CDK_MINT_CONTAINER not set — the restart variant needs the mint's container name")
	}

	_, infoBody := restoreProbeGet(t, mintURL+"/v1/info")
	var infoRaw map[string]json.RawMessage
	if err := json.Unmarshal(infoBody, &infoRaw); err != nil {
		t.Fatalf("parse /v1/info: %v", err)
	}
	var nutsRaw map[string]json.RawMessage
	if err := json.Unmarshal(infoRaw["nuts"], &nutsRaw); err != nil {
		t.Fatalf("parse nuts: %v", err)
	}
	t.Logf("mint /v1/info nuts[9]  = %s", string(nutsRaw["9"]))
	t.Logf("mint /v1/info nuts[19] = %s", string(nutsRaw["19"]))

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
	mint, ok := w.mints[mintURL]
	if !ok {
		t.Fatalf("mint %s not in wallet cache", mintURL)
	}

	origSwap := swap
	defer func() { swap = origSwap }()
	swap = func(mint string, req swapRequestPayload) (cashu.Proofs, error) {
		body, _ := json.Marshal(nut03.PostSwapRequest{Inputs: req.inputs, Outputs: req.outputs})
		resp, pErr := http.Post(mint+"/v1/swap", "application/json", bytes.NewReader(body)) //nolint:noctx
		if pErr != nil {
			return nil, pErr
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("crash-window swap unexpectedly refused: HTTP %d", resp.StatusCode)
		}
		return nil, errSimulatedCrash
	}

	proofs := w.db.GetProofs()
	if len(proofs) == 0 {
		t.Fatal("no proofs after minting")
	}
	req, err := w.createSwapRequest(proofs, &mint)
	if err != nil {
		t.Fatalf("createSwapRequest: %v", err)
	}
	if _, _, recErr := w.swapWithIntent(mintURL, req); recErr == nil {
		t.Fatal("simulated crash must surface an error")
	}
	swap = origSwap
	if len(w.db.GetPendingSwaps()) != 1 {
		t.Fatalf("intent must survive the crash, have %d", len(w.db.GetPendingSwaps()))
	}
	t.Logf("(2) crash window: mint accepted and signed, wallet died with the response on the wire")

	t.Logf("(4) docker restart %s — wipes the in-memory NUT-19 cache; sqlite persists", container)
	if out, rErr := exec.Command("docker", "restart", container).CombinedOutput(); rErr != nil {
		t.Fatalf("docker restart: %v: %s", rErr, out)
	}
	restoreProbeWaitHealthy(t, mintURL, 60)

	recovered, failed, err := w.ResumePendingSwaps()
	if err != nil || failed != 0 {
		t.Fatalf("(5) resume: recovered=%d failed=%d err=%v — want the restore fallback to complete recovery", recovered, failed, err)
	}
	if recovered != 64 {
		t.Fatalf("(5) recovered %d, want 64", recovered)
	}
	if len(w.db.GetPendingSwaps()) != 0 {
		t.Fatal("(5) intent must be retired after restore recovery")
	}
	if w.GetBalance() != 64 {
		t.Fatalf("(5) balance after restore = %d, want 64", w.GetBalance())
	}
	t.Logf("(5) replay refused beyond the window (mint log carries the 11001) and the boot-resume recovered %d sats via NUT-09 restore", recovered)

	proofs = w.db.GetProofs()
	req2, err := w.createSwapRequest(proofs, &mint)
	if err != nil {
		t.Fatalf("(6) createSwapRequest(restored): %v", err)
	}
	proofs2, opID, err := w.swapWithIntent(mintURL, req2)
	if err != nil {
		t.Fatalf("(6) spending the restored proofs failed: %v", err)
	}
	if err := w.db.SaveProofs(proofs2); err != nil {
		t.Fatalf("(6) SaveProofs: %v", err)
	}
	// the caller contract: retire the consumed inputs once the swap landed
	for _, p := range proofs {
		w.db.DeleteProof(p.Secret) //nolint:errcheck
	}
	if err := w.db.DeletePendingSwap(opID); err != nil {
		t.Fatalf("(6) DeletePendingSwap: %v", err)
	}
	if w.GetBalance() != 64 {
		t.Fatalf("(6) balance after re-swap = %d, want 64", w.GetBalance())
	}
	t.Logf("VERDICT: boot-resume recovered a beyond-window 11001-stuck intent via NUT-09 restore and the restored value re-spent cleanly")
}
