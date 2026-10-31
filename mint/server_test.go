package mint

import (
	"bytes"
	"encoding/json"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut01"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut02"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/gorilla/mux"
)

func TestActiveKeysetsHandler(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/v1/keys", nil)
	if err != nil {
		t.Fatalf("error creating request: %v", err)
	}

	seed, _ := hdkeychain.GenerateSeed(32)
	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	activeKeyset, _ := crypto.GenerateKeyset(master, 0, 0, true)

	mint := &Mint{
		activeKeyset: activeKeyset,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	mintServer := MintServer{
		mint:  mint,
		cache: NewCache(),
	}

	w := httptest.NewRecorder()
	mintServer.getActiveKeysets(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d but got %d", http.StatusOK, w.Code)
	}

	expectedKeysetResponse := nut01.GetKeysResponse{
		Keysets: []nut01.Keyset{
			{
				Id:   activeKeyset.Id,
				Unit: cashu.Sat.String(),
				Keys: activeKeyset.PublicKeys(),
			},
		},
	}

	expectedJson, _ := json.Marshal(expectedKeysetResponse)
	if !bytes.Equal(expectedJson, w.Body.Bytes()) {
		t.Fatal("responses do not match")
	}
}

func TestGetKeysetsHandler(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "/v1/keysets", nil)
	if err != nil {
		t.Fatalf("error creating request: %v", err)
	}

	seed, _ := hdkeychain.GenerateSeed(32)
	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	activeKeyset, _ := crypto.GenerateKeyset(master, 0, 150, true)
	inactiveKeyset, _ := crypto.GenerateKeyset(master, 1, 200, false)

	mint := &Mint{
		activeKeyset: activeKeyset,
		keysets: map[string]crypto.MintKeyset{
			activeKeyset.Id:   *activeKeyset,
			inactiveKeyset.Id: *inactiveKeyset,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	mintServer := MintServer{mint: mint}

	w := httptest.NewRecorder()
	mintServer.getKeysetsList(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status code %d but got %d", http.StatusOK, w.Code)
	}

	expectedKeysetsResponse := nut02.GetKeysetsResponse{
		Keysets: []nut02.Keyset{
			{
				Id:          activeKeyset.Id,
				Unit:        cashu.Sat.String(),
				Active:      true,
				InputFeePpk: 150,
			},
			{
				Id:          inactiveKeyset.Id,
				Unit:        cashu.Sat.String(),
				Active:      false,
				InputFeePpk: 200,
			},
		},
	}

	var keysetsResponse nut02.GetKeysetsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &keysetsResponse); err != nil {
		t.Fatal(err)
	}

	keysets := keysetsResponse.Keysets
	sort.Slice(keysets, func(i, j int) bool {
		return keysets[i].InputFeePpk < keysets[j].InputFeePpk
	})
	keysetsResponse.Keysets = keysets

	if !reflect.DeepEqual(expectedKeysetsResponse, keysetsResponse) {
		t.Fatalf("keyset responses do not match. Expected '%+v' but got '%+v'",
			expectedKeysetsResponse, keysetsResponse)
	}
}

func TestGetKeysetByIdHandler(t *testing.T) {
	seed, _ := hdkeychain.GenerateSeed(32)
	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	activeKeyset, _ := crypto.GenerateKeyset(master, 0, 150, true)
	expectedActiveKeyset := nut01.GetKeysResponse{
		Keysets: []nut01.Keyset{
			{
				Id:   activeKeyset.Id,
				Unit: activeKeyset.Unit,
				Keys: activeKeyset.PublicKeys(),
			},
		},
	}
	expectedActiveJson, _ := json.Marshal(expectedActiveKeyset)

	inactiveKeyset, _ := crypto.GenerateKeyset(master, 1, 200, false)
	expectedInactiveKeyset := nut01.GetKeysResponse{
		Keysets: []nut01.Keyset{
			{
				Id:   inactiveKeyset.Id,
				Unit: inactiveKeyset.Unit,
				Keys: inactiveKeyset.PublicKeys(),
			},
		},
	}
	expectedInactiveJson, _ := json.Marshal(expectedInactiveKeyset)
	expectedKeysetNotFound, _ := json.Marshal(cashu.UnknownKeysetErr)

	mint := &Mint{
		activeKeyset: activeKeyset,
		keysets: map[string]crypto.MintKeyset{
			activeKeyset.Id:   *activeKeyset,
			inactiveKeyset.Id: *inactiveKeyset,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	mintServer := MintServer{
		mint:  mint,
		cache: NewCache(),
	}
	r := mux.NewRouter()
	r.HandleFunc("/v1/keys/{id}", mintServer.getKeysetById)

	tests := []struct {
		name               string
		id                 string
		expectedStatusCode int
		expectedJson       []byte
	}{
		{
			name:               "active keyset",
			id:                 activeKeyset.Id,
			expectedStatusCode: http.StatusOK,
			expectedJson:       expectedActiveJson,
		},
		{
			name:               "inactive keyset",
			id:                 inactiveKeyset.Id,
			expectedStatusCode: http.StatusOK,
			expectedJson:       expectedInactiveJson,
		},
		{
			name:               "non existent keyset",
			id:                 "non-existent-id",
			expectedStatusCode: http.StatusBadRequest,
			expectedJson:       expectedKeysetNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/v1/keys/"+test.id, nil)
			if err != nil {
				t.Fatalf("error creating request: %v", err)
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != test.expectedStatusCode {
				t.Errorf("expected status code %d but got %d", test.expectedStatusCode, w.Code)
			}

			if !bytes.Equal(test.expectedJson, w.Body.Bytes()) {
				t.Fatal("responses do not match")
			}
		})
	}
}

func TestMeltTokensReplayCache(t *testing.T) {
	fakeBackend := &lightning.FakeBackend{}
	m, err := LoadMint(Config{
		MintPath:        t.TempDir(),
		LightningClient: fakeBackend,
		LogLevel:        Disable,
	})
	if err != nil {
		t.Fatalf("error loading mint: %v", err)
	}
	ms := MintServer{mint: m, cache: NewCache()}

	// one melt quote + proofs covering it
	invoice, err := fakeBackend.CreateInvoice(8)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := m.RequestMeltQuote(nut05.PostMeltQuoteBolt11Request{
		Request: invoice.PaymentRequest,
		Unit:    cashu.Sat.String(),
	})
	if err != nil {
		t.Fatal(err)
	}

	spendable := internalTestProofs(t, m, 2)
	requestBody, err := json.Marshal(nut05.PostMeltBolt11Request{
		Quote:  quote.Id,
		Inputs: spendable,
	})
	if err != nil {
		t.Fatal(err)
	}

	doPost := func() *httptest.ResponseRecorder {
		req, err := http.NewRequest(http.MethodPost, "/v1/melt/bolt11", bytes.NewReader(requestBody))
		if err != nil {
			t.Fatal(err)
		}
		req = mux.SetURLVars(req, map[string]string{"method": cashu.BOLT11_METHOD})
		w := httptest.NewRecorder()
		ms.meltTokens(w, req)
		return w
	}

	w1 := doPost()
	if w1.Code != http.StatusOK {
		t.Fatalf("first melt must succeed, got %d: %s", w1.Code, w1.Body.String())
	}

	// replay: byte-identical cached response, not MELT_ALREADY_PAID
	w2 := doPost()
	if w2.Code != http.StatusOK {
		t.Fatalf("replayed melt must return the cached 200, got %d: %s", w2.Code, w2.Body.String())
	}
	if !bytes.Equal(w1.Body.Bytes(), w2.Body.Bytes()) {
		t.Fatalf("replayed melt must be byte-identical:\nfirst:  %s\nreplay: %s", w1.Body.String(), w2.Body.String())
	}
}
