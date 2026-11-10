package wallet

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"
)

// TestIsNetworkErrorEOF is the regression test for the stale-mint failure:
// a mint that accepts a connection and closes it (EOF) must be classified as
// a network error, including when the error is wrapped by the keyset loader.
// loadWalletMints relies on this to skip the keyset and retain its DB record
// (and proofs) instead of aborting wallet initialization.
func TestIsNetworkErrorEOF(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"io.EOF", io.EOF, true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"wrapped EOF", fmt.Errorf("error getting keyset from mint: %w", io.EOF), true},
		{"url.Error EOF", &url.Error{Op: "Get", URL: "https://mint.example/v1/keys/00", Err: io.EOF}, true},
		{"wrapped url.Error", fmt.Errorf("outer: %w", &url.Error{Op: "Get", URL: "https://mint.example", Err: io.EOF}), true},
		{"net.OpError", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, true},
		{"non-network", errors.New("invalid signature"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNetworkError(tc.err); got != tc.want {
				t.Fatalf("isNetworkError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
