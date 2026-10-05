package client

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut07"
)

// The retry policy is a fund-safety boundary, not a convenience: a POST whose
// response never arrived may have been processed by the mint, and re-sending
// the same derivation outputs is the duplicate-output brick class
// (TollGate #257/#266/#480, measured live by the #535 conformance lane as
// swap-timeout-retry / no-output-reuse=fail). These tests pin the split:
//
//   - state-changing POSTs (swap here, the representative) are sent exactly
//     once when no answer arrives, and the error says the outcome is
//     ambiguous so the caller reconciles instead of retrying;
//   - a 429 IS an answer (nothing was processed), so the same body may be
//     re-sent after the mint's backoff — a rate-limited mint stays usable;
//   - a 5xx is terminal for POSTs, never retried (a gateway 502/504 after
//     processing has the transport error's ambiguity);
//   - checkstate is read-only, so it keeps its transport-error retry — it is
//     the reconciliation primitive and must survive the same outage that
//     made the money-moving call ambiguous.

// dropFirstResponse processes the first request and closes the connection
// without answering: the request reached the server, no response ever comes
// back — the ambiguous-outcome shape.
func dropFirstResponse(succeed func(w http.ResponseWriter)) http.HandlerFunc {
	var hits int32
	return func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			hj := w.(http.Hijacker)
			conn, _, err := hj.Hijack()
			if err != nil {
				panic(err)
			}
			conn.Close()
			return
		}
		succeed(w)
	}
}

func TestPostSwapDoesNotResendTheBodyWhenNoAnswerArrives(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(dropFirstResponse(func(w http.ResponseWriter) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := PostSwap(srv.URL, nut03.PostSwapRequest{})
	if err == nil {
		t.Fatal("a request whose response was dropped must surface an error, not a success")
	}
	var ambiguous *AmbiguousOutcomeError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("the error must be an AmbiguousOutcomeError so the caller reconciles instead of retrying; got %T: %v", err, err)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("the swap body was re-sent after the dropped response: %d further request(s) reached the mint", got)
	}
}

func TestPostSwapRetriesTheSameBodyOnRateLimit(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"signatures":[]}`))
	}))
	defer srv.Close()

	resp, err := PostSwap(srv.URL, nut03.PostSwapRequest{})
	if err != nil {
		t.Fatalf("a 429 answer must be retried with the same body, not failed: %v", err)
	}
	if resp == nil {
		t.Fatal("a successful retry must return a parsed response")
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("expected the 429 to be retried exactly once, saw %d requests", got)
	}
}

func TestPostSwapReturnsServerErrorWithoutRetryOn5xx(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := PostSwap(srv.URL, nut03.PostSwapRequest{})
	var serverErr *ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("a 5xx must surface as ServerError; got %T: %v", err, err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("a 5xx must not be retried for a state-changing POST; saw %d requests", got)
	}
}

func TestPostCheckStateKeepsItsTransportErrorRetry(t *testing.T) {
	srv := httptest.NewServer(dropFirstResponse(func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"states":[]}`))
	}))
	defer srv.Close()

	_, err := PostCheckProofState(srv.URL, nut07.PostCheckStateRequest{
		Ys: []string{"02"},
	})
	if err != nil {
		t.Fatalf("checkstate is read-only and must retry through a dropped response: %v", err)
	}
}
