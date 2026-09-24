package storage

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	bolt "go.etcd.io/bbolt"
)

const (
	KEYSETS_BUCKET        = "keysets"
	PROOFS_BUCKET         = "proofs"
	PENDING_PROOFS_BUCKET = "pending_proofs"
	PENDING_SWAPS_BUCKET  = "pending_swaps"
	MINT_QUOTES_BUCKET    = "mint_quotes"
	MELT_QUOTES_BUCKET    = "melt_quotes"
	INVOICES_BUCKET       = "invoices"
	SEED_BUCKET           = "seed"
	MNEMONIC_KEY          = "mnemonic"
)

var (
	ProofNotFound         = errors.New("proof not found")
	KeysetMintURLNotFound = errors.New("keyset with mint url not found")
)

type BoltDB struct {
	bolt *bolt.DB
}

// ErrDBLocked is returned when wallet.db cannot be opened because another
// wallet instance — in this process or another — still holds it. Without
// the open timeout, bolt.Open blocked forever on the file lock, which made
// a second in-process LoadWallet deadlock instead of failing.
var ErrDBLocked = errors.New("wallet database is locked")

// boltOpenTimeout bounds how long InitBolt waits for the database file lock
// before returning ErrDBLocked.
const boltOpenTimeout = 5 * time.Second

// canonicalMintURL returns the canonical bucket-key form of a mint URL:
// scheme and host lowercased, default ports dropped, trailing slashes
// stripped from the path. The wallet DB nests keyset records under buckets
// keyed by the mint URL as passed; two spellings of one mint (with and
// without a trailing slash — the cdk token form carries one) created two
// divergent copies of each keyset's derivation counter, and a restart that
// re-saved a fresh keyset under one alias replayed already-registered swap
// outputs at the mint ("Duplicate outputs", #480 in tollgate-module-basic-go).
// Every write keys by this canonical form so no new aliases can appear.
func canonicalMintURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.TrimSpace(raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "http" && strings.HasSuffix(u.Host, ":80")) ||
		(u.Scheme == "https" && strings.HasSuffix(u.Host, ":443")) {
		u.Host = u.Host[:strings.LastIndex(u.Host, ":")]
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// mergeMintURLAliases heals wallets written before canonicalization: for
// every keyset id that exists under more than one mint-URL bucket spelling,
// the copy with the HIGHEST derivation counter wins (the safe direction —
// a lower counter would re-derive already-registered blinded messages),
// all copies are rewritten under the canonical bucket, and alias buckets
// are deleted. Idempotent: a canonical DB is rewritten to itself.
func (db *BoltDB) mergeMintURLAliases() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))
		if keysetsb == nil {
			return nil
		}

		type best struct {
			json    []byte
			counter uint32
		}
		winners := map[string]*best{} // keyset id -> surviving record

		if err := keysetsb.ForEach(func(mintURL, _ []byte) error {
			mintBucket := keysetsb.Bucket(mintURL)
			if mintBucket == nil {
				return nil
			}
			return mintBucket.ForEach(func(id, v []byte) error {
				if v == nil {
					return nil
				}
				var ks crypto.WalletKeyset
				if err := json.Unmarshal(v, &ks); err != nil {
					return nil // not a keyset record; leave it alone
				}
				w, ok := winners[ks.Id]
				if !ok || ks.Counter > w.counter {
					cp := make([]byte, len(v))
					copy(cp, v)
					winners[ks.Id] = &best{json: cp, counter: ks.Counter}
				}
				return nil
			})
		}); err != nil {
			return err
		}

		// delete every non-canonical mint bucket
		var toDelete [][]byte
		if err := keysetsb.ForEach(func(mintURL, _ []byte) error {
			if string(mintURL) != canonicalMintURL(string(mintURL)) {
				toDelete = append(toDelete, append([]byte(nil), mintURL...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, m := range toDelete {
			if err := keysetsb.DeleteBucket(m); err != nil && err != bolt.ErrBucketNotFound {
				return err
			}
		}

		// rewrite winners under their canonical bucket, dropping empty
		// canonical buckets of aliases along the way
		for _, w := range winners {
			var ks crypto.WalletKeyset
			if err := json.Unmarshal(w.json, &ks); err != nil {
				continue
			}
			bucketName := canonicalMintURL(ks.MintURL)
			mintBucket, err := keysetsb.CreateBucketIfNotExists([]byte(bucketName))
			if err != nil {
				return err
			}
			if err := mintBucket.Put([]byte(ks.Id), w.json); err != nil {
				return err
			}
		}

		// remove canonical buckets left empty by the rewrite
		var empty [][]byte
		if err := keysetsb.ForEach(func(mintURL, _ []byte) error {
			b := keysetsb.Bucket(mintURL)
			if b != nil && b.Stats().KeyN == 0 {
				empty = append(empty, append([]byte(nil), mintURL...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, m := range empty {
			if err := keysetsb.DeleteBucket(m); err != nil && err != bolt.ErrBucketNotFound {
				return err
			}
		}
		return nil
	})
}

func InitBolt(path string) (*BoltDB, error) {
	db, err := bolt.Open(filepath.Join(path, "wallet.db"), 0600, &bolt.Options{Timeout: boltOpenTimeout})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("%w: another wallet still holds %s — Shutdown the previous wallet before loading again: %w",
				ErrDBLocked, filepath.Join(path, "wallet.db"), err)
		}
		return nil, fmt.Errorf("error setting bolt db: %v", err)
	}

	boltdb := &BoltDB{bolt: db}
	err = boltdb.initWalletBuckets()
	if err != nil {
		return nil, fmt.Errorf("error setting bolt db: %v", err)
	}

	if err := boltdb.MigrateInvoicesToQuotes(); err != nil {
		return nil, fmt.Errorf("error migrating db: %v", err)
	}

	if err := boltdb.mergeMintURLAliases(); err != nil {
		return nil, fmt.Errorf("error merging mint-url alias buckets: %v", err)
	}

	return boltdb, nil
}

func (db *BoltDB) Close() error {
	return db.bolt.Close()
}

func (db *BoltDB) initWalletBuckets() error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(KEYSETS_BUCKET))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(PROOFS_BUCKET))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(PENDING_PROOFS_BUCKET))
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists([]byte(PENDING_SWAPS_BUCKET))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(MINT_QUOTES_BUCKET))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(MELT_QUOTES_BUCKET))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(SEED_BUCKET))
		if err != nil {
			return err
		}

		return nil
	})
}

func (db *BoltDB) SaveMnemonicSeed(mnemonic string, seed []byte) {
	db.bolt.Update(func(tx *bolt.Tx) error {
		seedb := tx.Bucket([]byte(SEED_BUCKET))
		seedb.Put([]byte(SEED_BUCKET), seed)
		seedb.Put([]byte(MNEMONIC_KEY), []byte(mnemonic))
		return nil
	})
}

func (db *BoltDB) GetMnemonic() string {
	var mnemonic string
	db.bolt.View(func(tx *bolt.Tx) error {
		seedb := tx.Bucket([]byte(SEED_BUCKET))
		mnemonic = string(seedb.Get([]byte(MNEMONIC_KEY)))
		return nil
	})
	return mnemonic
}

func (db *BoltDB) GetSeed() []byte {
	var seed []byte
	db.bolt.View(func(tx *bolt.Tx) error {
		seedb := tx.Bucket([]byte(SEED_BUCKET))
		seed = seedb.Get([]byte(SEED_BUCKET))
		return nil
	})
	return seed
}

func (db *BoltDB) SaveProofs(proofs cashu.Proofs) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		proofsb := tx.Bucket([]byte(PROOFS_BUCKET))
		for _, proof := range proofs {
			key := []byte(proof.Secret)
			jsonProof, err := json.Marshal(proof)
			if err != nil {
				return fmt.Errorf("invalid proof: %v", err)
			}
			if err := proofsb.Put(key, jsonProof); err != nil {
				return err
			}
		}
		return nil
	})
}

// return all proofs from db
func (db *BoltDB) GetProofs() cashu.Proofs {
	proofs := cashu.Proofs{}

	db.bolt.View(func(tx *bolt.Tx) error {
		proofsb := tx.Bucket([]byte(PROOFS_BUCKET))

		c := proofsb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var proof cashu.Proof
			if err := json.Unmarshal(v, &proof); err != nil {
				continue
			}
			proofs = append(proofs, proof)
		}
		return nil
	})
	return proofs
}

func (db *BoltDB) GetProofsByKeysetId(id string) cashu.Proofs {
	proofs := cashu.Proofs{}

	if err := db.bolt.View(func(tx *bolt.Tx) error {
		proofsb := tx.Bucket([]byte(PROOFS_BUCKET))

		c := proofsb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var proof cashu.Proof
			if err := json.Unmarshal(v, &proof); err != nil {
				return err
			}

			if proof.Id == id {
				proofs = append(proofs, proof)
			}
		}
		return nil
	}); err != nil {
		return cashu.Proofs{}
	}

	return proofs
}

func (db *BoltDB) DeleteProof(secret string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		proofsb := tx.Bucket([]byte(PROOFS_BUCKET))
		val := proofsb.Get([]byte(secret))
		if val == nil {
			return ProofNotFound
		}
		return proofsb.Delete([]byte(secret))
	})
}

func (db *BoltDB) AddPendingProofs(proofs cashu.Proofs) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		pendingProofsb := tx.Bucket([]byte(PENDING_PROOFS_BUCKET))
		for _, proof := range proofs {
			Y, err := crypto.HashToCurve([]byte(proof.Secret))
			if err != nil {
				return err
			}
			Yhex := hex.EncodeToString(Y.SerializeCompressed())

			dbProof := DBProof{
				Y:      Yhex,
				Amount: proof.Amount,
				Id:     proof.Id,
				Secret: proof.Secret,
				C:      proof.C,
				DLEQ:   proof.DLEQ,
			}

			jsonProof, err := json.Marshal(dbProof)
			if err != nil {
				return fmt.Errorf("invalid proof: %v", err)
			}
			if err := pendingProofsb.Put(Y.SerializeCompressed(), jsonProof); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *BoltDB) AddPendingProofsByQuoteId(proofs cashu.Proofs, quoteId string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		pendingProofsb := tx.Bucket([]byte(PENDING_PROOFS_BUCKET))
		for _, proof := range proofs {
			Y, err := crypto.HashToCurve([]byte(proof.Secret))
			if err != nil {
				return err
			}
			Yhex := hex.EncodeToString(Y.SerializeCompressed())

			dbProof := DBProof{
				Y:           Yhex,
				Amount:      proof.Amount,
				Id:          proof.Id,
				Secret:      proof.Secret,
				C:           proof.C,
				DLEQ:        proof.DLEQ,
				MeltQuoteId: quoteId,
			}

			jsonProof, err := json.Marshal(dbProof)
			if err != nil {
				return fmt.Errorf("invalid proof: %v", err)
			}
			if err := pendingProofsb.Put(Y.SerializeCompressed(), jsonProof); err != nil {
				return err
			}
		}
		return nil
	})
}

func (db *BoltDB) GetPendingProofs() []DBProof {
	proofs := []DBProof{}

	db.bolt.View(func(tx *bolt.Tx) error {
		proofsb := tx.Bucket([]byte(PENDING_PROOFS_BUCKET))
		c := proofsb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var proof DBProof
			if err := json.Unmarshal(v, &proof); err != nil {
				continue
			}
			proofs = append(proofs, proof)
		}
		return nil
	})
	return proofs
}

func (db *BoltDB) GetPendingProofsByQuoteId(quoteId string) []DBProof {
	proofs := []DBProof{}

	if err := db.bolt.View(func(tx *bolt.Tx) error {
		pendingProofsb := tx.Bucket([]byte(PENDING_PROOFS_BUCKET))

		c := pendingProofsb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var proof DBProof
			if err := json.Unmarshal(v, &proof); err != nil {
				return err
			}

			if proof.MeltQuoteId == quoteId {
				proofs = append(proofs, proof)
			}
		}
		return nil
	}); err != nil {
		return []DBProof{}
	}

	return proofs
}

func (db *BoltDB) DeletePendingProofs(Ys []string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		pendingProofsb := tx.Bucket([]byte(PENDING_PROOFS_BUCKET))

		for _, v := range Ys {
			y, err := hex.DecodeString(v)
			if err != nil {
				return fmt.Errorf("invalid Y: %v", err)
			}
			if err := pendingProofsb.Delete(y); err != nil {
				return err
			}
		}

		return nil
	})
}

func (db *BoltDB) DeletePendingProofsByQuoteId(quoteId string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		pendingProofsb := tx.Bucket([]byte(PENDING_PROOFS_BUCKET))

		c := pendingProofsb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var proof DBProof
			if err := json.Unmarshal(v, &proof); err != nil {
				return err
			}

			if proof.MeltQuoteId == quoteId {
				y, err := hex.DecodeString(proof.Y)
				if err != nil {
					return err
				}
				if err := pendingProofsb.Delete(y); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// NOTE: Keysets are stored in nested buckets by mint URL. I.e a keyset with mint URL
// http://mint.com will create a bucket inside the KEYSETS_BUCKET named by the mint URL
// and inside this bucket, save the keysets by keyset id
func (db *BoltDB) SaveKeyset(keyset *crypto.WalletKeyset) error {
	jsonKeyset, err := json.Marshal(keyset)
	if err != nil {
		return fmt.Errorf("invalid keyset format: %v", err)
	}

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))
		mintBucket, err := keysetsb.CreateBucketIfNotExists([]byte(canonicalMintURL(keyset.MintURL)))
		if err != nil {
			return err
		}
		// The derivation counter is monotonic: it names output indices the
		// mint may already have registered. Writers re-fetching a keyset from
		// its mint construct a fresh record (Counter 0) — e.g. the restart
		// path's AddMint — and saving that unconditionally rewound the
		// counter, so post-restart swaps re-derived already-signed blinded
		// messages ("Duplicate outputs", tollgate #480). Never lower a
		// persisted counter on write.
		if existing := mintBucket.Get([]byte(keyset.Id)); existing != nil {
			var prev crypto.WalletKeyset
			if err := json.Unmarshal(existing, &prev); err == nil && prev.Counter > keyset.Counter {
				keyset.Counter = prev.Counter
				jsonKeyset, err = json.Marshal(keyset)
				if err != nil {
					return fmt.Errorf("invalid keyset format: %v", err)
				}
			}
		}
		return mintBucket.Put([]byte(keyset.Id), jsonKeyset)
	}); err != nil {
		return fmt.Errorf("error saving keyset: %v", err)
	}
	return nil
}

// saveKeysetRaw writes a keyset record under an arbitrary bucket key,
// emulating the pre-canonicalization writer so tests can seed legacy alias
// buckets exactly as old wallets had them.
// SaveKeysetRawForTests writes a keyset under an arbitrary bucket key,
// emulating the pre-canonicalization writer (exported for cross-package
// tests that seed legacy alias buckets).
func (db *BoltDB) SaveKeysetRawForTests(bucketKey string, keyset *crypto.WalletKeyset) error {
	return db.saveKeysetRaw(bucketKey, keyset)
}

// mintBucketNames lists the mint-URL bucket keys under the keysets bucket
// (test/diagnostic helper).
func (db *BoltDB) mintBucketNames() []string {
	var names []string
	db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(KEYSETS_BUCKET))
		if b == nil {
			return nil
		}
		return b.ForEach(func(mintURL, _ []byte) error {
			names = append(names, string(mintURL))
			return nil
		})
	})
	return names
}

func (db *BoltDB) saveKeysetRaw(bucketKey string, keyset *crypto.WalletKeyset) error {
	jsonKeyset, err := json.Marshal(keyset)
	if err != nil {
		return err
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))
		mintBucket, err := keysetsb.CreateBucketIfNotExists([]byte(bucketKey))
		if err != nil {
			return err
		}
		return mintBucket.Put([]byte(keyset.Id), jsonKeyset)
	})
}

func (db *BoltDB) GetKeysets() crypto.KeysetsMap {
	keysets := make(crypto.KeysetsMap)

	if err := db.bolt.View(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))

		return keysetsb.ForEach(func(mintURL, v []byte) error {
			mintKeysets := []crypto.WalletKeyset{}
			mintBucket := keysetsb.Bucket(mintURL)
			c := mintBucket.Cursor()

			for k, v := c.First(); k != nil; k, v = c.Next() {
				var keyset crypto.WalletKeyset
				if err := json.Unmarshal(v, &keyset); err != nil {
					return err
				}
				mintKeysets = append(mintKeysets, keyset)
			}
			keysets[string(mintURL)] = mintKeysets
			return nil
		})
	}); err != nil {
		return nil
	}

	return keysets
}

func (db *BoltDB) GetKeyset(keysetId string) *crypto.WalletKeyset {
	var keyset *crypto.WalletKeyset

	db.bolt.View(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))

		return keysetsb.ForEach(func(mintURL, v []byte) error {
			mintBucket := keysetsb.Bucket(mintURL)
			keysetBytes := mintBucket.Get([]byte(keysetId))
			if keysetBytes != nil {
				err := json.Unmarshal(keysetBytes, &keyset)
				if err != nil {
					return err
				}
			}
			return nil
		})
	})

	return keyset
}

func (db *BoltDB) IncrementKeysetCounter(keysetId string, num uint32) error {
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))
		var keyset *crypto.WalletKeyset
		keysetFound := false

		err := keysetsb.ForEach(func(mintURL, v []byte) error {
			mintBucket := keysetsb.Bucket(mintURL)

			keysetBytes := mintBucket.Get([]byte(keysetId))
			if keysetBytes != nil {
				err := json.Unmarshal(keysetBytes, &keyset)
				if err != nil {
					return fmt.Errorf("error reading keyset from db: %v", err)
				}
				keyset.Counter += num

				jsonBytes, err := json.Marshal(keyset)
				if err != nil {
					return err
				}
				keysetFound = true
				return mintBucket.Put([]byte(keysetId), jsonBytes)
			}

			return nil
		})

		if !keysetFound {
			return errors.New("keyset does not exist")
		}

		return err
	}); err != nil {
		return err
	}

	return nil
}

// ReserveKeysetRangeWithIntent advances the keyset counter and stores
// the swap intent in the same transaction: an intent always has its
// reserved range, and an exposed range always has its intent. The
// counter semantics match IncrementKeysetCounter exactly.
func (db *BoltDB) ReserveKeysetRangeWithIntent(keysetId string, num uint32, intent *PendingSwapIntent) error {
	if intent == nil {
		return errors.New("intent must not be nil")
	}
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))
		var keyset *crypto.WalletKeyset
		keysetFound := false

		err := keysetsb.ForEach(func(mintURL, v []byte) error {
			mintBucket := keysetsb.Bucket(mintURL)

			keysetBytes := mintBucket.Get([]byte(keysetId))
			if keysetBytes != nil {
				err := json.Unmarshal(keysetBytes, &keyset)
				if err != nil {
					return fmt.Errorf("error reading keyset from db: %v", err)
				}
				keyset.Counter += num

				jsonBytes, err := json.Marshal(keyset)
				if err != nil {
					return err
				}
				keysetFound = true
				return mintBucket.Put([]byte(keysetId), jsonBytes)
			}

			return nil
		})

		if !keysetFound {
			return errors.New("keyset does not exist")
		}
		if err != nil {
			return err
		}

		jsonIntent, err := json.Marshal(intent)
		if err != nil {
			return fmt.Errorf("invalid swap intent: %v", err)
		}
		return tx.Bucket([]byte(PENDING_SWAPS_BUCKET)).Put([]byte(intent.OpID), jsonIntent)
	}); err != nil {
		return err
	}

	return nil
}

// PutPendingSwap overwrites an existing intent by its OpID without
// touching counters — used when a retry re-signs the same derivation
// range (e.g. the NUT-20 legacy-signature retry) and the persisted
// request bytes must follow the bytes actually sent.
func (db *BoltDB) PutPendingSwap(intent *PendingSwapIntent) error {
	if intent == nil {
		return errors.New("intent must not be nil")
	}
	jsonIntent, err := json.Marshal(intent)
	if err != nil {
		return fmt.Errorf("invalid swap intent: %v", err)
	}
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(PENDING_SWAPS_BUCKET)).Put([]byte(intent.OpID), jsonIntent)
	})
}

func (db *BoltDB) GetPendingSwaps() []*PendingSwapIntent {
	intents := []*PendingSwapIntent{}
	_ = db.bolt.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(PENDING_SWAPS_BUCKET))
		if b == nil {
			return nil
		}
		return b.ForEach(func(k, v []byte) error {
			var intent PendingSwapIntent
			if err := json.Unmarshal(v, &intent); err != nil {
				return nil // skip corrupt entries, never abort recovery
			}
			intents = append(intents, &intent)
			return nil
		})
	})
	return intents
}

func (db *BoltDB) DeletePendingSwap(opId string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(PENDING_SWAPS_BUCKET)).Delete([]byte(opId))
	})
}

func (db *BoltDB) GetKeysetCounter(keysetId string) uint32 {
	var counter uint32 = 0

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))
		var keyset *crypto.WalletKeyset
		keysetFound := false

		err := keysetsb.ForEach(func(mintURL, v []byte) error {
			mintBucket := keysetsb.Bucket(mintURL)

			keysetBytes := mintBucket.Get([]byte(keysetId))
			if keysetBytes != nil {
				err := json.Unmarshal(keysetBytes, &keyset)
				if err != nil {
					return err
				}
				counter = keyset.Counter
				keysetFound = true
				return nil
			}
			return nil
		})

		if !keysetFound {
			return errors.New("keyset does not exist")
		}

		return err
	}); err != nil {
		return 0
	}

	return counter
}

// UpdateKeysetMintURL creates a new bucket named with newURL. It will then
// iterate over all the keysets that were stored in the oldURL bucket and copy
// them over to the new bucket with newURL. It also needs to change the MintURL
// field for each keyset.
func (db *BoltDB) UpdateKeysetMintURL(oldURL, newURL string) error {
	return db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))

		oldBucket := keysetsb.Bucket([]byte(oldURL))
		if oldBucket == nil {
			return KeysetMintURLNotFound
		}

		// create new bucket with new URL
		newBucket, err := keysetsb.CreateBucketIfNotExists([]byte(newURL))
		if err != nil {
			return err
		}

		// iterate and update each keyset's MintURL field with the newURL
		c := oldBucket.Cursor()
		for keysetId, v := c.First(); keysetId != nil; keysetId, v = c.Next() {
			var keyset crypto.WalletKeyset
			if err := json.Unmarshal(v, &keyset); err != nil {
				return err
			}

			keyset.MintURL = newURL

			updatedKeyset, err := json.Marshal(&keyset)
			if err != nil {
				return err
			}
			if err = newBucket.Put(keysetId, updatedKeyset); err != nil {
				return fmt.Errorf("error saving updated keyset: %v", err)
			}
		}

		// delete bucket with oldURL if update was successful
		if err := keysetsb.DeleteBucket([]byte(oldURL)); err != nil {
			return fmt.Errorf("failed to delete old mint URL bucket: %v", err)
		}

		return nil
	})
}

func (db *BoltDB) SaveMintQuote(quote MintQuote) error {
	jsonbytes, err := json.Marshal(&quote)
	if err != nil {
		return fmt.Errorf("invalid mint quote: %v", err)
	}

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		quotesb := tx.Bucket([]byte(MINT_QUOTES_BUCKET))
		key := []byte(quote.QuoteId)
		return quotesb.Put(key, jsonbytes)
	}); err != nil {
		return err
	}
	return nil
}

func (db *BoltDB) GetMintQuotes() []MintQuote {
	var mintQuotes []MintQuote

	db.bolt.View(func(tx *bolt.Tx) error {
		quotesb := tx.Bucket([]byte(MINT_QUOTES_BUCKET))
		c := quotesb.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var quote MintQuote
			if err := json.Unmarshal(v, &quote); err != nil {
				continue
			}
			mintQuotes = append(mintQuotes, quote)
		}
		return nil
	})

	return mintQuotes
}

func (db *BoltDB) GetMintQuoteById(id string) *MintQuote {
	var quote MintQuote
	if err := db.bolt.View(func(tx *bolt.Tx) error {
		quotesb := tx.Bucket([]byte(MINT_QUOTES_BUCKET))
		quoteBytes := quotesb.Get([]byte(id))
		if err := json.Unmarshal(quoteBytes, &quote); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil
	}

	return &quote
}

func (db *BoltDB) SaveMeltQuote(quote MeltQuote) error {
	jsonbytes, err := json.Marshal(quote)
	if err != nil {
		return fmt.Errorf("invalid melt quote: %v", err)
	}

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		quotesb := tx.Bucket([]byte(MELT_QUOTES_BUCKET))
		key := []byte(quote.QuoteId)
		return quotesb.Put(key, jsonbytes)
	}); err != nil {
		return err
	}
	return nil
}

func (db *BoltDB) GetMeltQuotes() []MeltQuote {
	var meltQuotes []MeltQuote

	db.bolt.View(func(tx *bolt.Tx) error {
		quotesb := tx.Bucket([]byte(MELT_QUOTES_BUCKET))
		c := quotesb.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var quote MeltQuote
			if err := json.Unmarshal(v, &quote); err != nil {
				continue
			}
			meltQuotes = append(meltQuotes, quote)
		}
		return nil
	})

	return meltQuotes
}

func (db *BoltDB) GetMeltQuoteById(id string) *MeltQuote {
	var quote *MeltQuote
	db.bolt.View(func(tx *bolt.Tx) error {
		quotesb := tx.Bucket([]byte(MELT_QUOTES_BUCKET))
		quoteBytes := quotesb.Get([]byte(id))
		if err := json.Unmarshal(quoteBytes, &quote); err != nil {
			quote = nil
		}
		return nil
	})
	return quote
}

func (db *BoltDB) MigrateInvoicesToQuotes() error {
	invoices := db.GetInvoices()

	for _, invoice := range invoices {
		switch invoice.TransactionType {
		case Mint:
			state := nut04.Unpaid
			if invoice.Paid {
				state = nut04.Paid
			}

			mintQuote := MintQuote{
				QuoteId:        invoice.Id,
				Mint:           invoice.Mint,
				Method:         cashu.BOLT11_METHOD,
				State:          state,
				Unit:           cashu.Sat.String(),
				Amount:         invoice.QuoteAmount,
				PaymentRequest: invoice.PaymentRequest,
				CreatedAt:      invoice.CreatedAt,
				QuoteExpiry:    invoice.QuoteExpiry,
			}
			if err := db.SaveMintQuote(mintQuote); err != nil {
				return fmt.Errorf("error saving mint quote: %v", err)
			}

		case Melt:
			state := nut05.Unpaid
			if invoice.Paid {
				state = nut05.Paid
			}

			meltQuote := MeltQuote{
				QuoteId:        invoice.Id,
				Mint:           invoice.Mint,
				Method:         cashu.BOLT11_METHOD,
				State:          state,
				Unit:           cashu.Sat.String(),
				PaymentRequest: invoice.PaymentRequest,
				Amount:         invoice.QuoteAmount,
				FeeReserve:     invoice.QuoteAmount - invoice.InvoiceAmount,
				Preimage:       invoice.Preimage,
				SettledAt:      invoice.SettledAt,
				QuoteExpiry:    invoice.QuoteExpiry,
			}
			if err := db.SaveMeltQuote(meltQuote); err != nil {
				return fmt.Errorf("error saving melt quote: %v", err)
			}

		default:
			continue
		}
	}

	// delete invoices bucket after migrating to quotes buckets
	if len(invoices) > 0 {
		db.bolt.Update(func(tx *bolt.Tx) error {
			tx.DeleteBucket([]byte(INVOICES_BUCKET))
			return nil
		})
	}

	return nil
}

func (db *BoltDB) SaveInvoice(invoice Invoice) error {
	jsonbytes, err := json.Marshal(invoice)
	if err != nil {
		return fmt.Errorf("invalid invoice: %v", err)
	}

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		invoicesb := tx.Bucket([]byte(INVOICES_BUCKET))
		key := []byte(invoice.PaymentHash)
		return invoicesb.Put(key, jsonbytes)
	}); err != nil {
		return fmt.Errorf("error saving invoice: %v", err)
	}
	return nil
}

func (db *BoltDB) GetInvoice(paymentHash string) *Invoice {
	var invoice *Invoice

	db.bolt.View(func(tx *bolt.Tx) error {
		invoicesb := tx.Bucket([]byte(INVOICES_BUCKET))
		invoiceBytes := invoicesb.Get([]byte(paymentHash))
		err := json.Unmarshal(invoiceBytes, &invoice)
		if err != nil {
			invoice = nil
		}

		return nil
	})
	return invoice
}

func (db *BoltDB) GetInvoiceByQuoteId(quoteId string) *Invoice {
	var quoteInvoice *Invoice

	if err := db.bolt.View(func(tx *bolt.Tx) error {
		invoicesb := tx.Bucket([]byte(INVOICES_BUCKET))

		c := invoicesb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var invoice Invoice
			if err := json.Unmarshal(v, &invoice); err != nil {
				return err
			}

			if invoice.Id == quoteId {
				quoteInvoice = &invoice
				break
			}
		}
		return nil
	}); err != nil {
		return nil
	}

	return quoteInvoice
}

func (db *BoltDB) GetInvoices() []Invoice {
	var invoices []Invoice

	db.bolt.View(func(tx *bolt.Tx) error {
		invoicesb := tx.Bucket([]byte(INVOICES_BUCKET))
		if invoicesb == nil {
			return nil
		}

		c := invoicesb.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var invoice Invoice
			if err := json.Unmarshal(v, &invoice); err != nil {
				invoices = []Invoice{}
				return nil
			}
			invoices = append(invoices, invoice)
		}
		return nil
	})
	return invoices
}
