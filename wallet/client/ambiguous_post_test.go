package client

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut03"
)

// The swap-timeout brick class (tollgate #640, the #257/#266/#480 family): a
// mint that processes a swap and whose response is dropped leaves the request
// UNKNOWN, and the client must never re-send the same blinded messages — a
// strict mint answers 10002 and the derivation range is dead. The fault proxy
// of the #535 conformance lane measured exactly this on main: the same output
// digests sighted twice on swap routes after a dropped response.

// dropAfterProcessing returns a handler that fully reads and records every
// request body (the fault proxy's observation log), then closes the connection
// without writing a response — the processed-then-dropped fault.
func dropAfterProcessing(sightings *recorder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		if _, err := readFull(r, buf); err != nil {
			return
		}
		sightings.add(string(buf))
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func readFull(r *http.Request, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Body.Read(buf[total:])
		total += n
		if err != nil {
			if total == len(buf) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}

type recorder struct {
	mu     sync.Mutex
	bodies []string
}

func (r *recorder) add(body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bodies = append(r.bodies, body)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

func ambiguousSwapRequest() nut03.PostSwapRequest {
	return nut03.PostSwapRequest{
		Inputs: cashu.Proofs{
			{Amount: 8, Id: "00", Secret: "ambiguous-swap-input", C: "02ab"},
		},
		Outputs: cashu.BlindedMessages{
			{Amount: 8, Id: "00", B_: "ambiguous-swap-output-0"},
			{Amount: 0, Id: "00", B_: "ambiguous-swap-output-1"},
		},
	}
}

// TestPostSwapDoesNotReSendOutputsAfterDroppedResponse is the #640
// reproducer: the mint (here: the fault proxy's stand-in) accepts and
// processes the first swap, the response is dropped, and the client must not
// re-expose the same outputs. Before the fix the client re-sent the identical
// body up to maxRetries times, and a duplicate-tolerant lab mint let the
// retry succeed — which is precisely how the violation stayed invisible.
func TestPostSwapDoesNotReSendOutputsAfterDroppedResponse(t *testing.T) {
	var sightings recorder
	srv := httptest.NewServer(dropAfterProcessing(&sightings))
	defer srv.Close()

	_, err := PostSwap(srv.URL, ambiguousSwapRequest())
	if err == nil {
		t.Fatal("expected an error from a dropped response, got none")
	}

	var ambiguous *AmbiguousResponseError
	if !asAmbiguous(err, &ambiguous) {
		t.Fatalf("expected *AmbiguousResponseError, got %T: %v", err, err)
	}

	bodies := sightings.snapshot()
	if len(bodies) != 1 {
		t.Fatalf("the swap body must reach the mint exactly once; got %d sightings: %q", len(bodies), bodies)
	}
	if ambiguous.MintURL != srv.URL+"/v1/swap" {
		t.Fatalf("error must name the mint endpoint; got %q", ambiguous.MintURL)
	}
}

func asAmbiguous(err error, target **AmbiguousResponseError) bool {
	for err != nil {
		if a, ok := err.(*AmbiguousResponseError); ok {
			*target = a
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestPostSwapStaysUsableAfterAmbiguousOutcome pins the recovery half: the
// next request after an ambiguous outcome is ordinary traffic. A fresh swap
// with fresh outputs must succeed against the same mint — the client carries
// no poisoned state from the dropped response.
func TestPostSwapStaysUsableAfterAmbiguousOutcome(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"signatures":[{"amount":8,"C_":"02ab","id":"00"}]}`))
	}))
	defer srv.Close()

	if _, err := PostSwap(srv.URL, ambiguousSwapRequest()); err == nil {
		t.Fatal("expected the first, dropped swap to fail")
	}

	resp, err := PostSwap(srv.URL, ambiguousSwapRequest())
	if err != nil {
		t.Fatalf("the follow-up swap must succeed after an ambiguous outcome: %v", err)
	}
	if resp == nil || len(resp.Signatures) != 1 {
		t.Fatalf("unexpected follow-up response: %+v", resp)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected exactly two mint round trips, got %d", got)
	}
}

// TestPostRetries429WithSameBody pins the one same-body retry that must
// survive: a 429 is the mint answering before processing, so the body was
// never exposed and re-sending it is the documented rate-limit handshake.
func TestPostRetries429WithSameBody(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if posts.Add(1) <= 2 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"signatures":[]}`))
	}))
	defer srv.Close()

	if _, err := PostSwap(srv.URL, nut03.PostSwapRequest{}); err != nil {
		t.Fatalf("expected the rate-limited swap to succeed after Retry-After: %v", err)
	}
	if got := posts.Load(); got != 3 {
		t.Fatalf("expected 3 POSTs (429, 429, 200), got %d", got)
	}
}

// TestAmbiguousResponseErrorCarriesTheUnderlyingCause keeps the type
// wrappable: callers reconcile on the class of the transport error.
func TestAmbiguousResponseErrorCarriesTheUnderlyingCause(t *testing.T) {
	inner := &netTimeoutError{}
	wrapped := &AmbiguousResponseError{MintURL: "https://mint.example.com", Err: inner}
	if wrapped.Unwrap() != inner {
		t.Fatal("Unwrap must return the transport error")
	}
	if wrapped.Error() == "" {
		t.Fatal("Error() must not be empty")
	}
}

type netTimeoutError struct{}

func (*netTimeoutError) Error() string { return "timeout awaiting response" }

// TestPostSwapTimeoutDoesNotResend is the timeout shape of the same fault:
// the mint processes the swap but never answers within the client deadline.
// The client must surface the ambiguity instead of re-sending the outputs.
func TestPostSwapTimeoutDoesNotResend(t *testing.T) {
	var sightings recorder
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = readFull(r, buf)
		sightings.add(string(buf))
		<-release // hold the response past the client's deadline
	}))
	defer srv.Close()
	defer close(release)

	prevTimeout := httpClient.Timeout
	httpClient.Timeout = 300 * time.Millisecond
	t.Cleanup(func() { httpClient.Timeout = prevTimeout })

	_, err := PostSwap(srv.URL, nut03.PostSwapRequest{
		Outputs: cashu.BlindedMessages{{Amount: 8, Id: "00", B_: "timeout-output-0"}},
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	var ambiguous *AmbiguousResponseError
	if !asAmbiguous(err, &ambiguous) {
		t.Fatalf("expected *AmbiguousResponseError, got %T: %v", err, err)
	}
	if n := len(sightings.snapshot()); n != 1 {
		t.Fatalf("the timed-out swap body must be sent exactly once; got %d sightings", n)
	}
}
