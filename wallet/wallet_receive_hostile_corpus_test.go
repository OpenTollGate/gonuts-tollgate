//go:build !integration

package wallet

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
)

// Hostile-token corpus for Receive: every case is an unauthenticated,
// remotely-deliverable token shape. The assertions are (1) Receive never
// panics — callers run it in goroutines, so a panic is a process kill — and
// (2) each shape fails with a controlled error where one exists. The corpus
// comes from the cross-implementation cashu audit learnings (empty arrays,
// foreign-key locks, spent-secret reuse, fee/amount mismatch) applied to this
// wallet's actual check sequence: short-ID resolution → active keyset → DLEQ
// → empty-guard (#23) → P2PK CanSign on proofs[0] only → swap.

const (
	corpusKeysetID = "009a1f293253e41e"
	// compressed secp256k1 generator point — a valid "02"-prefixed pubkey
	corpusAmount1Key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	// compressed G/2 — a *different* valid pubkey, used as the attacker's lock key
	corpusAttackerKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)

// corpusMint serves a mint whose active keyset optionally carries
// input_fee_ppk, and whose /v1/swap always rejects — standing in for a mint
// that refuses whatever hostile input the wallet sends it (spent secrets,
// invalid signatures). Swap rejection is the correct mint-side backstop; the
// point of the corpus is that the wallet reaches it in a controlled way.
func corpusMint(t *testing.T, inputFeePpk int) *httptest.Server {
	t.Helper()
	keysetsJSON := `{"keysets":[{"id":"` + corpusKeysetID + `","unit":"sat","active":true,` +
		`"input_fee_ppk":` + fmt.Sprint(inputFeePpk) + `,` +
		`"keys":{"1":"` + corpusAmount1Key + `"}}]}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/keys", "/v1/keysets":
			fmt.Fprint(w, keysetsJSON)
		case "/v1/swap":
			http.Error(w, `{"code":3,"detail":"inputs have already been spent"}`, http.StatusBadRequest)
		default:
			t.Errorf("unexpected mint request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func corpusWallet(t *testing.T, mintURL string) *Wallet {
	t.Helper()
	w, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: mintURL})
	if err != nil {
		t.Fatalf("LoadWallet: %v", err)
	}
	t.Cleanup(func() { w.Shutdown() })
	return w
}

// noPanic converts a panic inside Receive into a test failure with the panic
// value, so a regression from controlled error to crash is loud.
func noPanic(t *testing.T, name string) {
	t.Helper()
	if rec := recover(); rec != nil {
		t.Errorf("%s: Receive panicked (process-kill class for goroutine callers): %v", name, rec)
	}
}

func corpusProof(amount uint64, secret string) cashu.Proof {
	return cashu.Proof{Amount: amount, Id: corpusKeysetID, Secret: secret, C: corpusAmount1Key}
}

func TestReceive_HostileTokenCorpus(t *testing.T) {
	plainSecret := "hostile-corpus-secret"

	t.Run("empty proofs rejects without panic (#23)", func(t *testing.T) {
		mint := corpusMint(t, 0)
		defer mint.Close()
		w := corpusWallet(t, mint.URL)

		token, err := cashu.NewTokenV3(cashu.Proofs{}, mint.URL, cashu.Sat, false)
		if err != nil {
			t.Fatal(err)
		}
		defer noPanic(t, t.Name())
		if _, err := w.Receive(token, true); err == nil || !strings.Contains(err.Error(), "no proofs in token") {
			t.Fatalf("want 'no proofs in token' error, got %v", err)
		}
	})

	t.Run("P2PK locked to a foreign key rejects", func(t *testing.T) {
		mint := corpusMint(t, 0)
		defer mint.Close()
		w := corpusWallet(t, mint.URL)

		locked := `["P2PK",{"nonce":"attacker","data":"` + corpusAttackerKey + `"}]`
		token, err := cashu.NewTokenV3(cashu.Proofs{corpusProof(1, locked)}, mint.URL, cashu.Sat, false)
		if err != nil {
			t.Fatal(err)
		}
		defer noPanic(t, t.Name())
		if _, err := w.Receive(token, true); err == nil || !strings.Contains(err.Error(), "cannot sign locked proofs") {
			t.Fatalf("want 'cannot sign locked proofs', got %v", err)
		}
	})

	t.Run("amount below the keyset fee errors instead of underflowing", func(t *testing.T) {
		// input_fee_ppk 2000 => feesForProofs rounds up to 2 sats; a 1-sat
		// token makes Amount()-fees underflow toward 2^64 without the guard,
		// and the split of a near-max value is the hang/OOM.
		mint := corpusMint(t, 2000)
		defer mint.Close()
		w := corpusWallet(t, mint.URL)

		token, err := cashu.NewTokenV3(cashu.Proofs{corpusProof(1, plainSecret)}, mint.URL, cashu.Sat, false)
		if err != nil {
			t.Fatal(err)
		}
		defer noPanic(t, t.Name())
		_, err = w.Receive(token, true)
		if err == nil || !strings.Contains(err.Error(), "below the mint's swap fees") {
			t.Fatalf("want 'below the mint's swap fees' error, got %v", err)
		}
	})

	t.Run("duplicate proofs fail at the mint without panicking", func(t *testing.T) {
		mint := corpusMint(t, 0)
		defer mint.Close()
		w := corpusWallet(t, mint.URL)

		p := corpusProof(2, plainSecret)
		token, err := cashu.NewTokenV3(cashu.Proofs{p, p}, mint.URL, cashu.Sat, false)
		if err != nil {
			t.Fatal(err)
		}
		defer noPanic(t, t.Name())
		// No local duplicate detection: the mint's spent-secret check is
		// the backstop, and its rejection must SURFACE — the corpus fails
		// this assertion if the client regresses to swallowing NUT error
		// bodies (empty "could not swap proofs: " errors).
		_, swapErr := w.Receive(token, true)
		if swapErr == nil || !strings.Contains(swapErr.Error(), "inputs have already been spent") {
			t.Fatalf("want the mint's rejection to surface, got %v", swapErr)
		}
	})

	t.Run("mixed plain and locked proofs do not panic", func(t *testing.T) {
		// The P2PK gate inspects proofs[0] only; a locked proof later in the
		// array skips CanSign locally and is only stopped by the mint's
		// signature check on swap. Documented gap — mint-side enforcement is
		// the backstop; the wallet must still fail controlled.
		mint := corpusMint(t, 0)
		defer mint.Close()
		w := corpusWallet(t, mint.URL)

		locked := `["P2PK",{"nonce":"attacker","data":"` + corpusAttackerKey + `"}]`
		token, err := cashu.NewTokenV3(
			cashu.Proofs{corpusProof(1, plainSecret), corpusProof(1, locked)},
			mint.URL, cashu.Sat, false)
		if err != nil {
			t.Fatal(err)
		}
		defer noPanic(t, t.Name())
		if _, err := w.Receive(token, true); err == nil || !strings.Contains(err.Error(), "inputs have already been spent") {
			t.Fatalf("want mint-side rejection to surface for the locked proof, got %v", err)
		}
	})

	t.Run("unknown keyset id fails in keyset resolution", func(t *testing.T) {
		mint := corpusMint(t, 0)
		defer mint.Close()
		w := corpusWallet(t, mint.URL)

		p := corpusProof(1, plainSecret)
		p.Id = "ffffffffffffffff"
		token, err := cashu.NewTokenV3(cashu.Proofs{p}, mint.URL, cashu.Sat, false)
		if err != nil {
			t.Fatal(err)
		}
		defer noPanic(t, t.Name())
		if _, err := w.Receive(token, true); err == nil {
			t.Fatalf("unknown-keyset token unexpectedly succeeded")
		}
	})
}
