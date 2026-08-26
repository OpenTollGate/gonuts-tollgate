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

// TestReceiveEmptyProofsToken verifies that Receive rejects a token whose
// proofs array is empty instead of panicking. An empty-proofs token passes
// the DLEQ verification gate (nothing to verify) and used to reach
// proofsToSwap[0] unchecked, panicking with index-out-of-range. Callers run
// Receive in goroutines, so the panic crashed the whole process for an
// unauthenticated remotely-delivered token.
func TestReceiveEmptyProofsToken(t *testing.T) {
	const keysetID = "009a1f293253e41e"
	// compressed secp256k1 generator point: valid "02"-prefixed public key
	const amount1Key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	keysetsJSON := `{"keysets":[{"id":"` + keysetID + `","unit":"sat","active":true,` +
		`"keys":{"1":"` + amount1Key + `"}}]}`

	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/keys", "/v1/keysets":
			fmt.Fprint(w, keysetsJSON)
		default:
			t.Errorf("unexpected mint request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer mint.Close()

	testWallet, err := LoadWallet(Config{WalletPath: t.TempDir(), CurrentMintURL: mint.URL})
	if err != nil {
		t.Fatalf("error loading wallet: %v", err)
	}
	defer testWallet.Shutdown()

	token, err := cashu.NewTokenV3(cashu.Proofs{}, mint.URL, cashu.Sat, false)
	if err != nil {
		t.Fatalf("error creating token: %v", err)
	}
	tokenStr, err := token.Serialize()
	if err != nil {
		t.Fatalf("error serializing token: %v", err)
	}

	decoded, err := cashu.DecodeToken(tokenStr)
	if err != nil {
		t.Fatalf("error decoding token: %v", err)
	}

	amount, err := testWallet.Receive(*decoded.(*cashu.TokenV3), false)
	if err == nil {
		t.Fatalf("expected error for empty-proofs token, got nil (amount %v)", amount)
	}
	if !strings.Contains(err.Error(), "no proofs") {
		t.Errorf("expected 'no proofs' error, got: %v", err)
	}
}
