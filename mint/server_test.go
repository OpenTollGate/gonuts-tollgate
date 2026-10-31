package mint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/OpenTollGate/gonuts-tollgate/mint/storage"
	"github.com/btcsuite/btcd/btcec/v2"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
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

// TestMintQuoteBatchCheck: valid batch returns states in order; unknown id
// rejects the whole request; >limit rejects.
func TestMintQuoteBatchCheck(t *testing.T) {
	fakeBackend := &lightning.FakeBackend{}
	m, err := LoadMint(Config{
		MintPath:        t.TempDir(),
		LightningClient: fakeBackend,
		LogLevel:        Disable,
	})
	if err != nil {
		t.Fatal(err)
	}
	q1, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{Amount: 8, Unit: cashu.Sat.String()})
	if err != nil {
		t.Fatal(err)
	}
	q2, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{Amount: 16, Unit: cashu.Sat.String()})
	if err != nil {
		t.Fatal(err)
	}

	// valid batch via the Mint core (state assertions)
	quotes, err := m.CheckMintQuotesBatch([]string{q1.Id, q2.Id})
	if err != nil {
		t.Fatalf("valid batch must succeed: %v", err)
	}
	if quotes[0].Id != q1.Id || quotes[1].Id != q2.Id {
		t.Fatal("batch check must preserve request order")
	}

	// unknown id rejects the entire batch
	if _, err := m.CheckMintQuotesBatch([]string{q1.Id, "00000000-0000-7000-8000-00000000dead"}); err == nil {
		t.Fatal("unknown quote id must reject the whole batch")
	}

	// over the limit rejects
	many := make([]string, BatchCheckLimit+1)
	for i := range many {
		many[i] = q1.Id
	}
	if _, err := m.CheckMintQuotesBatch(many); err == nil {
		t.Fatal("batch over the limit must be rejected")
	}
}

// TestMintTokensBatchAtomic: two paid quotes + consolidated outputs mint
// once; a batch containing a not-paid quote signs nothing and rolls every
// claim back; over-limit outputs rejected.
func TestMintTokensBatchAtomic(t *testing.T) {
	fakeBackend := &lightning.FakeBackend{}
	m, err := LoadMint(Config{
		MintPath:        t.TempDir(),
		LightningClient: fakeBackend,
		LogLevel:        Disable,
	})
	if err != nil {
		t.Fatal(err)
	}

	payQuote := func(amount uint64) storage.MintQuote {
		quote, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{Amount: amount, Unit: cashu.Sat.String()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.GetMintQuoteState(quote.Id); err != nil {
			t.Fatal(err)
		}
		return quote
	}

	// happy path: two paid quotes (8 + 16), consolidated outputs summing to 24
	q1 := payQuote(8)
	q2 := payQuote(16)
	keyset := m.GetActiveKeyset()
	outputs, _, _ := internalTestOutputsAmounts(keyset.Id, []uint64{16, 8})
	sigs, err := m.MintTokensBatch([]string{q1.Id, q2.Id}, outputs, nil)
	if err != nil {
		t.Fatalf("atomic batch mint must succeed: %v", err)
	}
	if len(sigs) != len(outputs) {
		t.Fatalf("expected %d signatures, got %d", len(outputs), len(sigs))
	}
	for _, q := range []storage.MintQuote{q1, q2} {
		final, err := m.GetMintQuoteState(q.Id)
		if err != nil {
			t.Fatal(err)
		}
		if final.State != nut04.Issued {
			t.Fatalf("quote %v must end Issued, got %v", q.Id, final.State)
		}
	}

	// atomicity: one paid + one non-mintable quote signs NOTHING and
	// leaves the paid quote retryable (rolled back to PAID). FakeBackend
	// invoices are born settled so a genuinely-unpaid quote cannot be
	// staged; forcing ISSUED exercises the same all-or-nothing property.
	q3 := payQuote(8)
	q4, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{Amount: 8, Unit: cashu.Sat.String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.db.UpdateMintQuoteState(q4.Id, nut04.Issued); err != nil {
		t.Fatal(err)
	}
	outs2, _, _ := internalTestOutputsAmounts(keyset.Id, []uint64{8, 8})
	if _, err := m.MintTokensBatch([]string{q3.Id, q4.Id}, outs2, nil); err == nil {
		t.Fatal("batch with a non-mintable quote must fail")
	}
	q3Final, err := m.GetMintQuoteState(q3.Id)
	if err != nil {
		t.Fatal(err)
	}
	if q3Final.State != nut04.Paid {
		t.Fatalf("failed batch must roll its claims back to PAID, got %v", q3Final.State)
	}

	// duplicate quotes rejected
	if _, err := m.MintTokensBatch([]string{q3.Id, q3.Id}, outputs, nil); err == nil {
		t.Fatal("duplicate quote ids must be rejected")
	}

	// over-limit outputs rejected — every output UNIQUE so no earlier
	// duplicate check can shadow the limit verdict (mutation-check
	// discipline: the test must fail on the limit's absence)
	amounts := make([]uint64, BatchMaxOutputs+1)
	for i := range amounts {
		amounts[i] = 1
	}
	tooMany, _, _ := internalTestOutputsAmounts(keyset.Id, amounts)
	_, batchErr := m.MintTokensBatch([]string{q3.Id}, tooMany, nil)
	if batchErr == nil || !strings.Contains(batchErr.Error(), "too many outputs") {
		t.Fatalf("over-limit outputs must be rejected with the limit verdict (mutation-checkable), got: %v", batchErr)
	}

	// rollback exercised AFTER a claim: a locked quote with an invalid
	// NUT-20 signature fails inside the claim loop, after the earlier
	// quote was already claimed — the rollback must release it
	signer, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	q5 := payQuote(8)
	q5locked := payQuoteLocked(t, m, 8, signer.PubKey())
	outs3, _, _ := internalTestOutputsAmounts(keyset.Id, []uint64{8, 8})
	if _, err := m.MintTokensBatch([]string{q5.Id, q5locked.Id}, outs3, []string{"", "deadbeef"}); err == nil {
		t.Fatal("locked quote with invalid signature must fail the batch")
	}
	q5Final, err := m.GetMintQuoteState(q5.Id)
	if err != nil {
		t.Fatal(err)
	}
	if q5Final.State != nut04.Paid {
		t.Fatalf("claimed quote must be rolled back to PAID, got %v", q5Final.State)
	}
}

// payQuoteLocked creates a paid mint quote locked to a NUT-20 pubkey.
func payQuoteLocked(t *testing.T, m *Mint, amount uint64, pubkey *btcec.PublicKey) storage.MintQuote {
	t.Helper()
	quote, err := m.RequestMintQuote(nut04.PostMintQuoteBolt11Request{
		Amount: amount,
		Unit:   cashu.Sat.String(),
		Pubkey: hex.EncodeToString(pubkey.SerializeCompressed()),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetMintQuoteState(quote.Id); err != nil {
		t.Fatal(err)
	}
	return quote
}
