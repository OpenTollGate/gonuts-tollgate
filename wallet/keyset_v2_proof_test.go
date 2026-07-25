//go:build proof

package wallet

import (
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/client"
)

// This test demonstrates the V1/V2 keyset ID incompatibility.
//
// Run on main branch (V1 only):
//   go test -tags proof -run TestV1V2KeysetProof -v ./wallet/
//   → V1 passes, V2 fails with "Got invalid keyset"
//
// Run on feature/v2-keyset-ids branch:
//   go test -tags proof -run TestV1V2KeysetProof -v ./wallet/
//   → Both pass
//
// The issue: GetKeysetKeys() on main always uses DeriveKeysetId (V1 algorithm).
// V2 keyset IDs (01-prefix, 66 hex chars) require DeriveKeysetIdV2 which doesn't
// exist on main. When the wallet fetches keys from a V2 mint like testnut.cashu.space,
// it derives a V1 ID from the V2 pubkeys → ID mismatch → "Got invalid keyset" error.
//
// This is the crash that kills the TollGate Go backend on startup when configured
// with a V2 mint (e.g., a local CDK mint or testnut.cashu.space).

func TestV1V2KeysetProof(t *testing.T) {
	v1Mint := "https://testnut.cashu.exchange"
	v2Mint := "https://testnut.cashu.space"

	t.Run("V1_keyset_from_testnut_cashu_exchange", func(t *testing.T) {
		keysets, err := client.GetAllKeysets(v1Mint)
		if err != nil {
			t.Fatalf("GetAllKeysets failed: %v", err)
		}

		var v1ID string
		for _, ks := range keysets.Keysets {
			if ks.Active && ks.Unit == "sat" {
				v1ID = ks.Id
				break
			}
		}
		if v1ID == "" {
			t.Fatal("no active sat keyset on V1 mint")
		}

		t.Logf("V1 keyset ID: %s (len=%d)", v1ID, len(v1ID))
		if v1ID[:2] != "00" {
			t.Fatalf("expected V1 keyset ID to start with '00', got: %s", v1ID[:2])
		}

		keys, err := GetKeysetKeys(v1Mint, v1ID)
		if err != nil {
			t.Fatalf("GetKeysetKeys FAILED for V1 mint — this should always work: %v", err)
		}
		t.Logf("V1 OK: %d keys loaded", len(keys))
	})

	t.Run("V2_keyset_from_testnut_cashu_space", func(t *testing.T) {
		keysets, err := client.GetAllKeysets(v2Mint)
		if err != nil {
			t.Fatalf("GetAllKeysets failed: %v", err)
		}

		var v2ID string
		for _, ks := range keysets.Keysets {
			if ks.Active && ks.Unit == "sat" {
				v2ID = ks.Id
				break
			}
		}
		if v2ID == "" {
			t.Fatal("no active sat keyset on V2 mint")
		}

		t.Logf("V2 keyset ID: %s (len=%d)", v2ID, len(v2ID))
		if v2ID[:2] != "01" {
			t.Fatalf("expected V2 keyset ID to start with '01', got: %s", v2ID[:2])
		}

		keys, err := GetKeysetKeys(v2Mint, v2ID)
		if err != nil {
			t.Errorf("GetKeysetKeys FAILED for V2 mint: %v", err)
			t.Logf("This confirms the bug: main branch only supports V1 keyset derivation.")
			t.Logf("The fix (feature/v2-keyset-ids branch) adds DeriveKeysetIdV2() for 01-prefix IDs.")
			return
		}
		t.Logf("V2 OK: %d keys loaded — V2 keyset support is working!", len(keys))
	})

	t.Run("GetMintActiveKeyset_V2_end_to_end", func(t *testing.T) {
		keyset, err := GetMintActiveKeyset(v2Mint, cashu.Sat)
		if err != nil {
			t.Errorf("GetMintActiveKeyset FAILED for V2 mint: %v", err)
			t.Logf("This is the exact error the TollGate backend hits on startup.")
			return
		}
		t.Logf("V2 active keyset loaded: id=%s unit=%s keys=%d", keyset.Id, keyset.Unit, len(keyset.PublicKeys))
	})
}
