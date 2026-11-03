//go:build killtest

// Kill/restart crash-boundary harness (cashu-audit #59): spawns the REAL
// mint server binary as a subprocess, drives a melt over HTTP, kills it
// with SIGKILL while its payment settles at the backend, restarts on the
// same database, and asserts the poll reconciler converges the quote to
// PAID with preimage and the proofs spent. The doctrine-literal form of
// the db-staged crash tests: process death, disk state, real HTTP.
//
// Run: go test ./mint/ -tags killtest -run TestKill -count=1 -v
package mint_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type killMint struct {
	t       *testing.T
	workdir string
	port    int
	baseURL string
	proc    *exec.Cmd
	logFile *os.File
}

// dumpDiagnostics prints the mint log tail and the backend state file —
// called on assertion failures so crash-window debugging does not need
// a manual repro.
func (km *killMint) dumpDiagnostics(context string) {
	km.t.Logf("=== diagnostics: %s", context)
	if km.logFile != nil {
		km.logFile.Close()
	}
	if data, err := os.ReadFile(km.workdir + "/mint.log"); err == nil {
		lines := strings.Split(string(data), "\n")
		start := len(lines) - 40
		if start < 0 {
			start = 0
		}
		km.t.Logf("=== mint.log tail:\n%s", strings.Join(lines[start:], "\n"))
	}
	if data, err := os.ReadFile(km.workdir + "/fakebackend-state.json"); err == nil {
		km.t.Logf("=== fakebackend-state.json: %s", data)
	} else {
		km.t.Logf("=== fakebackend-state.json: %v", err)
	}
}

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

func newKillMint(t *testing.T, paymentDelaySec int64) *killMint {
	t.Helper()

	binOnce.Do(func() {
		out, err := os.CreateTemp("", "gonuts-mint-killtest-*")
		if err != nil {
			binErr = err
			return
		}
		out.Close()
		cmd := exec.Command("go", "build", "-o", out.Name(), "../cmd/mint")
		if combined, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("go build ./cmd/mint: %v: %s", err, combined)
			return
		}
		binPath = out.Name()
	})
	if binErr != nil {
		t.Fatalf("cannot build mint binary: %v", binErr)
	}

	workdir := t.TempDir()
	dbPath := workdir + "/db"
	if err := os.MkdirAll(dbPath, 0o755); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	env := fmt.Sprintf("MINT_PATH=%s\nMINT_PORT=%d\nLIGHTNING_BACKEND=FAKEBACKEND\nMINT_FAKE_PAYMENT_DELAY=%d\nMINT_FAKE_BACKEND_STATE=%s\n",
		dbPath, port, paymentDelaySec, workdir+"/fakebackend-state.json")
	if err := os.WriteFile(workdir+"/.env", []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}

	km := &killMint{t: t, workdir: workdir, port: port, baseURL: fmt.Sprintf("http://127.0.0.1:%d", port)}
	km.start()
	return km
}

func (km *killMint) start() {
	km.t.Helper()
	cmd := exec.Command(binPath)
	cmd.Dir = km.workdir
	km.logFile, _ = os.OpenFile(km.workdir+"/mint.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	cmd.Stdout = io.Discard
	cmd.Stderr = km.logFile
	if err := cmd.Start(); err != nil {
		km.t.Fatalf("start mint: %v", err)
	}
	km.proc = cmd
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(km.baseURL + "/v1/keys")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	km.t.Fatal("mint did not become healthy within 20s")
}

func (km *killMint) kill() {
	km.t.Helper()
	if km.proc == nil || km.proc.Process == nil {
		return
	}
	km.proc.Process.Signal(syscall.SIGKILL)
	km.proc.Wait()
	km.proc = nil
}

func (km *killMint) post(path string, body any) (int, []byte) {
	km.t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(km.baseURL+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		km.t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func (km *killMint) get(path string) (int, []byte) {
	km.t.Helper()
	resp, err := http.Get(km.baseURL + path)
	if err != nil {
		km.t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

type keysResponse struct {
	Keysets []struct {
		Id   string            `json:"id"`
		Keys map[string]string `json:"keys"`
	} `json:"keysets"`
}

func (km *killMint) activeKeyset() (string, map[string]string) {
	km.t.Helper()
	_, body := km.get("/v1/keys")
	var kr keysResponse
	if err := json.Unmarshal(body, &kr); err != nil || len(kr.Keysets) == 0 {
		km.t.Fatalf("bad /v1/keys: %v (%s)", err, body)
	}
	return kr.Keysets[0].Id, kr.Keysets[0].Keys
}

type apiOutput struct {
	Amount uint64 `json:"amount"`
	Id     string `json:"id"`
	B_     string `json:"B_"`
}

type apiProof struct {
	Amount uint64 `json:"amount"`
	Id     string `json:"id"`
	Secret string `json:"secret"`
	C      string `json:"C"`
}

// mintOverHttp mints `amount` sats through the real endpoints and returns
// spendable proofs.
func (km *killMint) mintOverHttp(amount uint64) []apiProof {
	km.t.Helper()
	keysetId, keyMap := km.activeKeyset()

	_, quoteBody := km.post("/v1/mint/quote/bolt11", map[string]any{"amount": amount, "unit": "sat"})
	var quote nut04.PostMintQuoteBolt11Response
	json.Unmarshal(quoteBody, &quote)

	amounts := cashu.AmountSplit(amount)
	outputs := make([]apiOutput, len(amounts))
	secrets := make([]string, len(amounts))
	rs := make([]*secp256k1.PrivateKey, len(amounts))
	for i, amt := range amounts {
		secretBytes := make([]byte, 32)
		rand.Read(secretBytes)
		secrets[i] = hex.EncodeToString(secretBytes)
		r, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			km.t.Fatal(err)
		}
		rs[i] = r
		B_, _, err := crypto.BlindMessage(secrets[i], r)
		if err != nil {
			km.t.Fatal(err)
		}
		outputs[i] = apiOutput{Amount: amt, Id: keysetId, B_: hex.EncodeToString(B_.SerializeCompressed())}
	}

	// FakeBackend invoices settle on first status check — poll until PAID
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, s := km.get("/v1/mint/quote/bolt11/" + quote.Quote)
		var st nut04.PostMintQuoteBolt11Response
		json.Unmarshal(s, &st)
		if st.State == nut04.Paid {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	status, mintBody := km.post("/v1/mint/bolt11", map[string]any{"quote": quote.Quote, "outputs": outputs})
	if status != 200 {
		km.t.Fatalf("mint failed (%d): %s", status, mintBody)
	}
	var sigs struct {
		Signatures []struct {
			Amount uint64 `json:"amount"`
			C_     string `json:"C_"`
			Id     string `json:"id"`
		} `json:"signatures"`
	}
	json.Unmarshal(mintBody, &sigs)

	proofs := make([]apiProof, len(sigs.Signatures))
	for i, sig := range sigs.Signatures {
		C_bytes, err := hex.DecodeString(sig.C_)
		if err != nil {
			km.t.Fatal(err)
		}
		A_hex, ok := keyMap[strconv.FormatUint(sig.Amount, 10)]
		if !ok {
			km.t.Fatalf("no key for amount %d", sig.Amount)
		}
		A_bytes, err := hex.DecodeString(A_hex)
		if err != nil {
			km.t.Fatal(err)
		}
		A, err := secp256k1.ParsePubKey(A_bytes)
		if err != nil {
			km.t.Fatal(err)
		}
		C_, err := secp256k1.ParsePubKey(C_bytes)
		if err != nil {
			km.t.Fatal(err)
		}
		C := crypto.UnblindSignature(C_, rs[i], A)
		proofs[i] = apiProof{
			Amount: sig.Amount,
			Id:     sig.Id,
			Secret: secrets[i],
			C:      hex.EncodeToString(C.SerializeCompressed()),
		}
	}
	return proofs
}

// TestKillDuringMeltRecovers: delayed payment -> melt returns PENDING ->
// SIGKILL -> the payment settles during downtime -> restart on the same
// db -> the poll reconciles to PAID with preimage and the proofs spent.
func TestKillDuringMeltRecovers(t *testing.T) {
	km := newKillMint(t, 2)
	defer km.kill()

	proofs := km.mintOverHttp(8)

	// an external invoice the fake backend can decode
	request, _, _, err := lightning.CreateFakeInvoice(8, false)
	if err != nil {
		t.Fatal(err)
	}
	_, meltQuoteBody := km.post("/v1/melt/quote/bolt11", map[string]any{"request": request, "unit": "sat"})
	var meltQuote nut05.PostMeltQuoteBolt11Response
	json.Unmarshal(meltQuoteBody, &meltQuote)

	status, meltBody := km.post("/v1/melt/bolt11", map[string]any{"quote": meltQuote.Quote, "inputs": proofs})
	var meltState nut05.PostMeltQuoteBolt11Response
	json.Unmarshal(meltBody, &meltState)
	if status != 200 || meltState.State != nut05.Pending {
		t.Fatalf("delayed melt must return PENDING, got (%d) %s", status, meltBody)
	}

	// CRASH while the payment settles at the backend
	km.kill()

	// the delay elapses during downtime: the payment settles
	time.Sleep(3 * time.Second)

	// RESTART on the same database
	km.start()

	var final nut05.PostMeltQuoteBolt11Response
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, body := km.get("/v1/melt/quote/bolt11/" + meltQuote.Quote)
		final = nut05.PostMeltQuoteBolt11Response{}
		json.Unmarshal(body, &final)
		if final.State == nut05.Paid {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if final.State != nut05.Paid {
		km.dumpDiagnostics("reconciliation did not reach PAID")
		t.Fatalf("quote must reconcile to PAID after restart, got %v", final.State)
	}
	if final.Preimage == "" {
		t.Fatal("reconciled quote must carry the preimage")
	}

	// the proofs must be spent after reconciliation: re-melt rejected
	request2, _, _, err := lightning.CreateFakeInvoice(8, false)
	if err != nil {
		t.Fatal(err)
	}
	_, q2body := km.post("/v1/melt/quote/bolt11", map[string]any{"request": request2, "unit": "sat"})
	var q2 nut05.PostMeltQuoteBolt11Response
	json.Unmarshal(q2body, &q2)
	status, body := km.post("/v1/melt/bolt11", map[string]any{"quote": q2.Quote, "inputs": proofs})
	if status == 200 {
		t.Fatalf("spent proofs must be rejected after restart reconciliation, got 200: %s", body)
	}
}
