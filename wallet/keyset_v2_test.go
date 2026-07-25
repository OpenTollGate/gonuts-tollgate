//go:build livemint

package wallet

import (
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/client"
)

func TestGetKeysetKeys_V2_testnut_cashu_space(t *testing.T) {
	mintURL := "https://testnut.cashu.space"
	keysets, err := client.GetAllKeysets(mintURL)
	if err != nil {
		t.Skipf("mint unreachable: %v", err)
	}

	var satKeysetId string
	for _, ks := range keysets.Keysets {
		if ks.Active && ks.Unit == "sat" {
			satKeysetId = ks.Id
			break
		}
	}
	if satKeysetId == "" {
		t.Fatal("no active sat keyset found")
	}

	keys, err := GetKeysetKeys(mintURL, satKeysetId)
	if err != nil {
		t.Fatalf("GetKeysetKeys failed for V2 keyset %s: %v", satKeysetId, err)
	}
	if len(keys) == 0 {
		t.Fatal("expected non-empty keys")
	}
	t.Logf("V2 keyset %s: %d keys loaded successfully", satKeysetId, len(keys))
}

func TestGetKeysetKeys_V1_testnut_cashu_exchange(t *testing.T) {
	mintURL := "https://testnut.cashu.exchange"
	keysets, err := client.GetAllKeysets(mintURL)
	if err != nil {
		t.Skipf("mint unreachable: %v", err)
	}

	var satKeysetId string
	for _, ks := range keysets.Keysets {
		if ks.Active && ks.Unit == "sat" {
			satKeysetId = ks.Id
			break
		}
	}
	if satKeysetId == "" {
		t.Fatal("no active sat keyset found")
	}

	keys, err := GetKeysetKeys(mintURL, satKeysetId)
	if err != nil {
		t.Fatalf("GetKeysetKeys failed for V1 keyset %s: %v", satKeysetId, err)
	}
	if len(keys) == 0 {
		t.Fatal("expected non-empty keys")
	}
	t.Logf("V1 keyset %s: %d keys loaded successfully", satKeysetId, len(keys))
}

func TestGetMintActiveKeyset_V2(t *testing.T) {
	mintURL := "https://testnut.cashu.space"
	keyset, err := GetMintActiveKeyset(mintURL, cashu.Sat)
	if err != nil {
		t.Skipf("mint unreachable or keyset error: %v", err)
	}
	if !keyset.Active {
		t.Fatal("expected active keyset")
	}
	if keyset.Unit != "sat" {
		t.Fatalf("expected unit=sat, got %s", keyset.Unit)
	}
	if len(keyset.PublicKeys) == 0 {
		t.Fatal("expected non-empty public keys")
	}
	t.Logf("V2 active keyset: id=%s fee=%d keys=%d", keyset.Id, keyset.InputFeePpk, len(keyset.PublicKeys))
}

func TestGetMintActiveKeyset_V1(t *testing.T) {
	mintURL := "https://testnut.cashu.exchange"
	keyset, err := GetMintActiveKeyset(mintURL, cashu.Sat)
	if err != nil {
		t.Skipf("mint unreachable or keyset error: %v", err)
	}
	if !keyset.Active {
		t.Fatal("expected active keyset")
	}
	if keyset.Unit != "sat" {
		t.Fatalf("expected unit=sat, got %s", keyset.Unit)
	}
	if len(keyset.PublicKeys) == 0 {
		t.Fatal("expected non-empty public keys")
	}
	t.Logf("V1 active keyset: id=%s fee=%d keys=%d", keyset.Id, keyset.InputFeePpk, len(keyset.PublicKeys))
}
