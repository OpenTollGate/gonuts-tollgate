package storage

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
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
	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))

		// The same keyset id can exist under several mint-URL spellings
		// (trailing slash, casing, …), each bucket holding its own copy of
		// the serialized keyset — including the derivation Counter. A save
		// of a freshly fetched keyset carries Counter 0 and would silently
		// rewind a copy that already advanced, making the wallet re-derive
		// blinded messages the mint has already seen ("Duplicate outputs").
		// The counter is monotonic: never save a value below the highest
		// one already stored for this keyset id.
		if existing := maxKeysetCounterTx(keysetsb, keyset.Id); keyset.Counter < existing {
			keyset.Counter = existing
		}

		jsonKeyset, err := json.Marshal(keyset)
		if err != nil {
			return fmt.Errorf("invalid keyset format: %v", err)
		}

		mintBucket, err := keysetsb.CreateBucketIfNotExists([]byte(keyset.MintURL))
		if err != nil {
			return err
		}
		return mintBucket.Put([]byte(keyset.Id), jsonKeyset)
	}); err != nil {
		return fmt.Errorf("error saving keyset: %v", err)
	}
	return nil
}

// maxKeysetCounterTx returns the highest derivation counter stored for
// keysetId across every mint-URL bucket that holds a copy of it.
func maxKeysetCounterTx(keysetsb *bolt.Bucket, keysetId string) uint32 {
	var max uint32
	_ = keysetsb.ForEach(func(mintURL, _ []byte) error {
		mintBucket := keysetsb.Bucket(mintURL)
		if mintBucket == nil {
			return nil
		}
		keysetBytes := mintBucket.Get([]byte(keysetId))
		if keysetBytes == nil {
			return nil
		}
		var keyset crypto.WalletKeyset
		if err := json.Unmarshal(keysetBytes, &keyset); err != nil {
			return nil
		}
		if keyset.Counter > max {
			max = keyset.Counter
		}
		return nil
	})
	return max
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

		// Copies of one keyset id under different mint-URL spellings can
		// drift; increments derive from the highest copy and re-write every
		// copy so the id again has a single counter value everywhere.
		newCounter := maxKeysetCounterTx(keysetsb, keysetId) + num
		keysetFound := false

		err := keysetsb.ForEach(func(mintURL, v []byte) error {
			mintBucket := keysetsb.Bucket(mintURL)

			keysetBytes := mintBucket.Get([]byte(keysetId))
			if keysetBytes != nil {
				var keyset crypto.WalletKeyset
				if err := json.Unmarshal(keysetBytes, &keyset); err != nil {
					return fmt.Errorf("error reading keyset from db: %v", err)
				}
				keyset.Counter = newCounter

				// Marshal the pointer: WalletKeyset's custom JSON lives on
				// the pointer receiver, and marshaling the value copies it
				// into an interface where the custom encoding no longer
				// applies — producing bytes UnmarshalJSON cannot read back.
				jsonBytes, err := json.Marshal(&keyset)
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

func (db *BoltDB) GetKeysetCounter(keysetId string) uint32 {
	var counter uint32 = 0

	if err := db.bolt.Update(func(tx *bolt.Tx) error {
		keysetsb := tx.Bucket([]byte(KEYSETS_BUCKET))

		// The derivation base is the highest counter stored for this id:
		// copies under different mint-URL spellings may differ, and any
		// lower value would re-derive outputs the mint has already signed.
		counter = maxKeysetCounterTx(keysetsb, keysetId)

		if counter == 0 {
			// Distinguish "exists at 0" from "does not exist" — the
			// original semantics returned an error for the latter.
			if !keysetExistsTx(keysetsb, keysetId) {
				return errors.New("keyset does not exist")
			}
		}

		return nil
	}); err != nil {
		return 0
	}

	return counter
}

// keysetExistsTx reports whether any mint-URL bucket holds keysetId.
func keysetExistsTx(keysetsb *bolt.Bucket, keysetId string) bool {
	found := false
	_ = keysetsb.ForEach(func(mintURL, _ []byte) error {
		mintBucket := keysetsb.Bucket(mintURL)
		if mintBucket != nil && mintBucket.Get([]byte(keysetId)) != nil {
			found = true
		}
		return nil
	})
	return found
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
