package storage

import (
	"encoding/json"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type QuoteType int

const (
	Mint QuoteType = iota + 1
	Melt
)

func (quote QuoteType) String() string {
	switch quote {
	case Mint:
		return "Mint"
	case Melt:
		return "Melt"
	default:
		return "unknown"
	}
}

type WalletDB interface {
	SaveMnemonicSeed(string, []byte)
	GetSeed() []byte
	GetMnemonic() string

	SaveProofs(cashu.Proofs) error
	GetProofs() cashu.Proofs
	GetProofsByKeysetId(string) cashu.Proofs
	DeleteProof(string) error

	AddPendingProofs(cashu.Proofs) error
	AddPendingProofsByQuoteId(cashu.Proofs, string) error
	GetPendingProofs() []DBProof
	GetPendingProofsByQuoteId(string) []DBProof
	DeletePendingProofs([]string) error
	DeletePendingProofsByQuoteId(string) error

	SaveKeyset(*crypto.WalletKeyset) error

	// ReserveKeysetRangeWithIntent advances the keyset's derivation
	// counter by num AND stores the pending-swap intent in ONE bolt
	// transaction — the atomicity is the fund-safety invariant: an
	// intent can never exist for a range that was not reserved, and a
	// range can never be exposed without its intent (#497).
	ReserveKeysetRangeWithIntent(keysetId string, num uint32, intent *PendingSwapIntent) error
	GetPendingSwaps() []*PendingSwapIntent
	PutPendingSwap(intent *PendingSwapIntent) error
	DeletePendingSwap(opId string) error
	GetKeysets() crypto.KeysetsMap
	GetKeyset(string) *crypto.WalletKeyset
	IncrementKeysetCounter(string, uint32) error
	GetKeysetCounter(string) uint32
	UpdateKeysetMintURL(oldURL, newURL string) error

	SaveMintQuote(MintQuote) error
	GetMintQuotes() []MintQuote
	GetMintQuoteById(string) *MintQuote

	SaveMeltQuote(MeltQuote) error
	GetMeltQuotes() []MeltQuote
	GetMeltQuoteById(string) *MeltQuote

	Close() error
}

type DBProof struct {
	Y      string           `json:"y"`
	Amount uint64           `json:"amount"`
	Id     string           `json:"id"`
	Secret string           `json:"secret"`
	C      string           `json:"C"`
	DLEQ   *cashu.DLEQProof `json:"dleq,omitempty"`
	// set if pending proofs are tied to a melt quote
	MeltQuoteId string `json:"quote_id"`
}

// PendingSwapIntent is the durable pre-POST record of a swap the wallet
// is about to execute (or has executed without recording the outcome).
// It exists so a crash between the mint accepting the swap and the
// wallet saving the resulting proofs cannot destroy issued value: the
// mint re-signs an identical swap deterministically, so re-POSTing
// RequestBytes yields the same signatures, which the persisted Rs and
// Secrets can unblind (tollgate-module-basic-go #497).
type PendingSwapIntent struct {
	OpID         string
	MintURL      string
	KeysetID     string
	CounterStart uint32
	// CounterEnd is exclusive: [CounterStart, CounterEnd) is the
	// derivation range the request's outputs occupy.
	CounterEnd uint32
	// RequestBytes are the exact bytes to re-POST to {MintURL}/v1/swap.
	RequestBytes []byte
	// Outputs, Secrets and Rs reconstruct the proofs from the replayed
	// signatures.
	Outputs cashu.BlindedMessages
	Secrets []string
	// Rs are the serialized blinding factors (secp256k1 private keys).
	Rs [][]byte
	// OpType routes the resume path; empty means a swap (the first
	// operation this machinery covered) so pre-existing records stay
	// valid.
	OpType string
}

const (
	// PendingOpSwap is a /v1/swap replay.
	PendingOpSwap = "swap"
	// PendingOpMint is a /v1/mint/bolt11 replay.
	PendingOpMint = "mint"
)

type MintQuote struct {
	QuoteId        string
	Mint           string
	Method         string
	State          nut04.State
	Unit           string
	PaymentRequest string
	Amount         uint64
	CreatedAt      int64
	SettledAt      int64
	QuoteExpiry    uint64
	PrivateKey     *secp256k1.PrivateKey
}

type mintQuoteTemp struct {
	QuoteId        string
	Mint           string
	Method         string
	State          nut04.State
	Unit           string
	PaymentRequest string
	Amount         uint64
	CreatedAt      int64
	SettledAt      int64
	QuoteExpiry    uint64
	PrivateKey     []byte
}

// custom Marshaller to serialize and deserialize private key to and from []byte

func (mq *MintQuote) MarshalJSON() ([]byte, error) {
	tempQuote := mintQuoteTemp{
		QuoteId:        mq.QuoteId,
		Mint:           mq.Mint,
		Method:         mq.Method,
		State:          mq.State,
		Unit:           mq.Unit,
		PaymentRequest: mq.PaymentRequest,
		Amount:         mq.Amount,
		CreatedAt:      mq.CreatedAt,
		SettledAt:      mq.SettledAt,
		QuoteExpiry:    mq.QuoteExpiry,
	}

	if mq.PrivateKey != nil {
		tempQuote.PrivateKey = mq.PrivateKey.Serialize()
	}

	return json.Marshal(tempQuote)
}

func (mq *MintQuote) UnmarshalJSON(data []byte) error {
	tempQuote := &mintQuoteTemp{}

	if err := json.Unmarshal(data, tempQuote); err != nil {
		return err
	}

	mq.QuoteId = tempQuote.QuoteId
	mq.Mint = tempQuote.Mint
	mq.Method = tempQuote.Method
	mq.State = tempQuote.State
	mq.Unit = tempQuote.Unit
	mq.PaymentRequest = tempQuote.PaymentRequest
	mq.Amount = tempQuote.Amount
	mq.CreatedAt = tempQuote.CreatedAt
	mq.SettledAt = tempQuote.SettledAt
	mq.QuoteExpiry = tempQuote.QuoteExpiry
	if len(tempQuote.PrivateKey) > 0 {
		mq.PrivateKey = secp256k1.PrivKeyFromBytes(tempQuote.PrivateKey)
	}

	return nil
}

type MeltQuote struct {
	QuoteId        string
	Mint           string
	Method         string
	State          nut05.State
	Unit           string
	PaymentRequest string
	Amount         uint64
	FeeReserve     uint64
	Preimage       string
	CreatedAt      int64
	SettledAt      int64
	QuoteExpiry    uint64
}

type Invoice struct {
	TransactionType QuoteType
	// mint or melt quote id
	Id string
	// mint that issued quote
	Mint           string
	QuoteAmount    uint64
	InvoiceAmount  uint64
	PaymentRequest string
	PaymentHash    string
	Preimage       string
	CreatedAt      int64
	Paid           bool
	SettledAt      int64
	QuoteExpiry    uint64
}
