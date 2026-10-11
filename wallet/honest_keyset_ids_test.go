package wallet

import (
	"encoding/hex"

	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The honest keyset IDs for the two static-keyset shapes the fake mints in
// the tests serve: computed from the very keys the fixtures publish, never
// chosen — a fabricated ID over honest keys is the shape the wallet's keyset
// verification refuses (tollgate #705), and the fixtures must model honest
// mints. Shape A maps every amount 1<<0..1<<20 to the generator point and
// advertises sat/fee-0; shape B maps only amount 1.
//
// Untagged on purpose: consumers live both in !integration files and in
// always-compiled tests, so these fixtures must exist in every build —
// defining them inside wallet_test.go's !integration tag hid them from
// `go test --tags=integration ./wallet` and broke that build entirely.
var (
	honestV2FullID = func() string {
		const genKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
		pk, err := secp256k1.ParsePubKey(mustHex(genKey))
		if err != nil {
			panic(err)
		}
		pubs := crypto.PublicKeys{}
		for i := 0; i <= 20; i++ {
			pubs[1<<i] = pk
		}
		return crypto.DeriveKeysetIdV2(pubs, "sat", 0)
	}()
	honestV1SingleKeyID = func() string {
		const genKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
		pk, err := secp256k1.ParsePubKey(mustHex(genKey))
		if err != nil {
			panic(err)
		}
		return crypto.DeriveKeysetId(crypto.PublicKeys{1: pk})
	}()
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
