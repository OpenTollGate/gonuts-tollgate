package storage

import (
	"testing"

	"github.com/OpenTollGate/gonuts-tollgate/crypto"
)

func TestCanonicalMintURL(t *testing.T) {
	cases := map[string]string{
		"http://mint-fees:8085":        "http://mint-fees:8085",
		"http://mint-fees:8085/":       "http://mint-fees:8085",
		"http://mint-fees:8085//":      "http://mint-fees:8085",
		"HTTP://Mint-Example:8085/":    "http://mint-example:8085",
		"http://mint.example:80/":      "http://mint.example",
		"https://mint.example:443/x/":  "https://mint.example/x",
		"http://mint.example:8085/p/":  "http://mint.example:8085/p",
		"http://user:pw@mint.example/": "http://mint.example",
		"http://mint.example/?a=b":     "http://mint.example",
		"not a url":                    "not a url",
	}
	for in, want := range cases {
		if got := canonicalMintURL(in); got != want {
			t.Errorf("canonicalMintURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// keysetFor builds a keyset record as the wallet would persist it.
func keysetFor(mintURL, id string, counter uint32) *crypto.WalletKeyset {
	return &crypto.WalletKeyset{Id: id, MintURL: mintURL, Unit: "sat", Active: true, Counter: counter}
}

// TestMergeMintURLAliases_HealsDivergentCounters replays the exact wallet.db
// state the #480 forensics captured: one keyset under two mint-URL bucket
// spellings with divergent counters (the alias copy wiped to 0 by a restart's
// fresh re-save). Opening the DB must collapse to ONE canonical bucket whose
// counter is the MAXIMUM — a lower counter would re-derive blinded messages
// the mint has already registered.
func TestMergeMintURLAliases_HealsDivergentCounters(t *testing.T) {
	dir := t.TempDir()

	db, err := InitBolt(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	const id = "01df97b6fb8a572a718d7df7fcbf4387e2d455134ea8004c9c8c51e1b3391f909e"
	// pre-#480 state: both spellings agree at 15…
	if err := db.SaveKeyset(keysetFor("http://mint:8085", id, 15)); err != nil {
		t.Fatalf("save no-slash: %v", err)
	}
	// …simulate the restart wipe on the slash alias: write raw via the alias key
	if err := db.saveKeysetRaw("http://mint:8085/", keysetFor("http://mint:8085/", id, 0)); err != nil {
		t.Fatalf("save slash alias (wiped): %v", err)
	}
	db.Close()

	healed, err := InitBolt(dir) // merge runs here
	if err != nil {
		t.Fatalf("reopen with merge: %v", err)
	}
	defer healed.Close()

	if got := healed.GetKeysetCounter(id); got != 15 {
		t.Fatalf("counter after merge = %d, want 15 (max of {15, 0}) — a lower value replays registered outputs", got)
	}
	ks := healed.GetKeyset(id)
	if ks == nil {
		t.Fatalf("keyset missing after merge")
	}
	// exactly one mint bucket remains, and it is canonical
	names := healed.mintBucketNames()
	if len(names) != 1 || names[0] != "http://mint:8085" {
		t.Fatalf("mint buckets after merge = %v, want exactly [http://mint:8085]", names)
	}
}

// TestSaveKeyset_CreatesNoAliases: writing the same keyset through both URL
// spellings must land in ONE canonical bucket.
func TestSaveKeyset_CreatesNoAliases(t *testing.T) {
	dir := t.TempDir()
	db, err := InitBolt(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer db.Close()
	const id = "01df97b6fb8a572a718d7df7fcbf4387e2d455134ea8004c9c8c51e1b3391f909e"
	for _, spelling := range []string{"http://mint:8085", "http://mint:8085/", "HTTP://Mint:8085"} {
		if err := db.SaveKeyset(keysetFor(spelling, id, 3)); err != nil {
			t.Fatalf("save %q: %v", spelling, err)
		}
	}
	names := db.mintBucketNames()
	if len(names) != 1 || names[0] != "http://mint:8085" {
		t.Fatalf("mint buckets = %v, want exactly [http://mint:8085]", names)
	}
}

// TestSaveKeyset_NeverLowersCounter pins the monotonic-counter invariant:
// a fresh keyset fetch (Counter 0) — exactly what the restart path's AddMint
// constructs — must not rewind a persisted counter, or post-restart swaps
// re-derive blinded messages the mint has already signed.
func TestSaveKeyset_NeverLowersCounter(t *testing.T) {
	dir := t.TempDir()
	db, err := InitBolt(dir)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer db.Close()
	const id = "01df97b6fb8a572a718d7df7fcbf4387e2d455134ea8004c9c8c51e1b3391f909e"

	if err := db.SaveKeyset(keysetFor("http://mint:8085", id, 8)); err != nil {
		t.Fatalf("save 8: %v", err)
	}
	// the wipe attempt: same keyset, fresh record, counter 0
	if err := db.SaveKeyset(keysetFor("http://mint:8085", id, 0)); err != nil {
		t.Fatalf("save 0: %v", err)
	}
	if got := db.GetKeysetCounter(id); got != 8 {
		t.Fatalf("counter after fresh-save = %d, want 8 (monotonic — a rewind replays registered outputs)", got)
	}
	// a genuine advance still writes through
	if err := db.SaveKeyset(keysetFor("http://mint:8085", id, 12)); err != nil {
		t.Fatalf("save 12: %v", err)
	}
	if got := db.GetKeysetCounter(id); got != 12 {
		t.Fatalf("counter after advance = %d, want 12", got)
	}
}
