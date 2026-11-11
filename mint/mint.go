package mint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut01"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut02"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut06"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut07"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut10"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut11"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut14"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut17"
	"github.com/OpenTollGate/gonuts-tollgate/cashu/nuts/nut20"
	"github.com/OpenTollGate/gonuts-tollgate/crypto"
	"github.com/OpenTollGate/gonuts-tollgate/mint/lightning"
	"github.com/OpenTollGate/gonuts-tollgate/mint/pubsub"
	"github.com/OpenTollGate/gonuts-tollgate/mint/storage"
	"github.com/OpenTollGate/gonuts-tollgate/mint/storage/sqlite"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	decodepay "github.com/nbd-wtf/ln-decodepay"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	QuoteExpiryMins = 10
)

type Mint struct {
	db storage.MintDB

	// active keyset
	activeKeyset *crypto.MintKeyset

	// map of all keysets (both active and inactive)
	keysets map[string]crypto.MintKeyset

	// meltInFlight marks melt quotes whose MeltTokens call is currently
	// between claim and settle — the poll-path reconciler must not touch
	// them (a concurrent poll settling underneath an active melt produces
	// double-settle noise). After a crash nothing is in flight, so every
	// orphan reconciles on its first poll.
	meltInFlight sync.Map

	lightningClient lightning.Client
	mintInfo        nut06.MintInfo
	limits          MintLimits
	logger          *slog.Logger
	mppEnabled      bool

	publisher *pubsub.PubSub
	ctx       context.Context
	cancel    context.CancelFunc
}

func LoadMint(config Config) (*Mint, error) {
	path := config.MintPath
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}

	logger, err := setupLogger(path, config.LogLevel)
	if err != nil {
		return nil, err
	}

	db, err := sqlite.InitSQLite(path)
	if err != nil {
		return nil, fmt.Errorf("error setting up sqlite: %v", err)
	}

	seed, err := db.GetSeed()
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			seed, err = hdkeychain.GenerateSeed(32)
			if err != nil {
				return nil, err
			}
			if err := db.SaveSeed(seed); err != nil {
				return nil, fmt.Errorf("could not save generated seed to db: %v", err)
			}
		} else {
			return nil, err
		}
	}

	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	dbKeysets, err := db.GetKeysets()
	if err != nil {
		return nil, fmt.Errorf("error reading keysets from db: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	mint := &Mint{
		db:         db,
		keysets:    make(map[string]crypto.MintKeyset, len(dbKeysets)),
		limits:     config.Limits,
		logger:     logger,
		mppEnabled: config.EnableMPP,
		publisher:  pubsub.NewPubSub(),
		ctx:        ctx,
		cancel:     cancel,
	}

	// if no keysets stored, just create a new one
	if len(dbKeysets) == 0 {
		keyset, err := crypto.GenerateKeyset(master, 0, config.InputFeePpk, true)
		if err != nil {
			return nil, err
		}
		mint.activeKeyset = keyset
		mint.keysets[keyset.Id] = *keyset
		hexseed := hex.EncodeToString(seed)
		activeDbKeyset := storage.DBKeyset{
			Id:                keyset.Id,
			Unit:              keyset.Unit,
			Active:            true,
			Seed:              hexseed,
			DerivationPathIdx: keyset.DerivationPathIdx,
			InputFeePpk:       keyset.InputFeePpk,
		}
		if err := db.SaveKeyset(activeDbKeyset); err != nil {
			return nil, fmt.Errorf("error saving new active keyset: %v", err)
		}
	} else {
		// build keysets from db
		for _, dbkeyset := range dbKeysets {
			keyset, err := crypto.GenerateKeyset(
				master,
				dbkeyset.DerivationPathIdx,
				dbkeyset.InputFeePpk,
				dbkeyset.Active,
			)
			if err != nil {
				return nil, err
			}
			if keyset.Active {
				mint.activeKeyset = keyset
			}
			mint.keysets[keyset.Id] = *keyset
		}
		if config.RotateKeyset {
			_, err := mint.RotateKeyset(config.InputFeePpk)
			if err != nil {
				return nil, fmt.Errorf("could not rotate to new keyset: %v", err)
			}
		}
	}

	logger.Info(fmt.Sprintf("setting active keyset '%v' with fee %v",
		mint.activeKeyset.Id, mint.activeKeyset.InputFeePpk))

	if config.LightningClient == nil {
		return nil, errors.New("invalid lightning client")
	}
	if err := config.LightningClient.ConnectionStatus(); err != nil {
		return nil, fmt.Errorf("can't connect to lightning backend: %v", err)
	}
	mint.lightningClient = config.LightningClient
	mint.SetMintInfo(config.MintInfo)

	return mint, nil
}

func setupLogger(mintPath string, logLevel LogLevel) (*slog.Logger, error) {
	replacer := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.SourceKey {
			source := a.Value.Any().(*slog.Source)
			source.File = filepath.Base(source.File)
		}
		if a.Key == slog.TimeKey {
			a.Value = slog.StringValue(time.Now().Truncate(time.Second * 2).Format(time.DateTime))
		}
		return a
	}

	logFile, err := os.OpenFile(filepath.Join(mintPath, "mint.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("error opening log file: %v", err)
	}

	logWriter := io.MultiWriter(os.Stdout, logFile)
	level := slog.LevelInfo
	switch logLevel {
	case Debug:
		level = slog.LevelDebug
	case Disable:
		logWriter = io.Discard
	}

	return slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{
		AddSource:   true,
		Level:       level,
		ReplaceAttr: replacer,
	})), nil
}

// logInfof formats the strings with args and preserves the source position
// from where this method is called for the log msg. Otherwise all messages would be logged with
// source line of this log method and not the original caller
func (m *Mint) logInfof(format string, args ...any) {
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])
	r := slog.NewRecord(time.Now(), slog.LevelInfo, fmt.Sprintf(format, args...), pcs[0])
	_ = m.logger.Handler().Handle(context.Background(), r)
}

func (m *Mint) logErrorf(format string, args ...any) {
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])
	r := slog.NewRecord(time.Now(), slog.LevelError, fmt.Sprintf(format, args...), pcs[0])
	_ = m.logger.Handler().Handle(context.Background(), r)
}

func (m *Mint) logDebugf(format string, args ...any) {
	if !m.logger.Enabled(context.Background(), slog.LevelDebug) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(2, pcs[:])
	r := slog.NewRecord(time.Now(), slog.LevelDebug, fmt.Sprintf(format, args...), pcs[0])
	_ = m.logger.Handler().Handle(context.Background(), r)
}

func (m *Mint) Shutdown() error {
	m.cancel()
	return m.db.Close()
}

// RequestMintQuote will process a request to mint tokens
// and returns a mint quote or an error.
// The request to mint a token is explained in the spec here:
// https://github.com/cashubtc/nuts/blob/main/04.md
func (m *Mint) RequestMintQuote(mintQuoteRequest nut04.PostMintQuoteBolt11Request) (storage.MintQuote, error) {
	// NUT #04: Mints **MUST** include `amount_paid`, `amount_issued`, and `updated_at` in all mint quote responses.

	// only support sat unit
	if mintQuoteRequest.Unit != cashu.Sat.String() {
		errmsg := fmt.Sprintf("unit '%v' not supported", mintQuoteRequest.Unit)
		return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.UnitErrCode)
	}

	var publicKey *secp256k1.PublicKey
	if len(mintQuoteRequest.Pubkey) > 0 {
		hexPubkey, err := hex.DecodeString(mintQuoteRequest.Pubkey)
		if err != nil {
			errmsg := fmt.Sprintf("invalid public key '%v'", err)
			return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.StandardErrCode)
		}

		publicKey, err = secp256k1.ParsePubKey(hexPubkey)
		if err != nil {
			errmsg := fmt.Sprintf("invalid public key '%v'", err)
			return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.StandardErrCode)
		}
	}

	// check limits
	requestAmount := mintQuoteRequest.Amount
	// NUT-04: the amount MUST be a positive integer — a zero-amount quote
	// is malformed (cashu-audit #59 P2 hygiene; previously a 0-sat
	// invoice and an immediately-satisfiable quote were issued).
	if requestAmount == 0 {
		return storage.MintQuote{}, cashu.MintQuoteZeroAmountErr
	}
	if m.limits.MintingSettings.MaxAmount > 0 {
		if requestAmount > m.limits.MintingSettings.MaxAmount {
			return storage.MintQuote{}, cashu.MintAmountExceededErr
		}
	}
	if m.limits.MaxBalance > 0 {
		balance, err := m.TotalBalance()
		if err != nil {
			errmsg := fmt.Sprintf("could not get mint balance from db: %v", err)
			return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}
		if balance+requestAmount > m.limits.MaxBalance {
			return storage.MintQuote{}, cashu.MintingDisabled
		}
	}

	// get an invoice from the lightning backend
	m.logInfof("requesting invoice from lightning backend for %v sats", requestAmount)
	invoice, err := m.requestInvoice(requestAmount)
	if err != nil {
		errmsg := fmt.Sprintf("could not generate invoice: %v", err)
		return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.LightningBackendErrCode)
	}

	quoteId, err := cashu.GenerateRandomQuoteId()
	if err != nil {
		m.logErrorf("error generating random quote id: %v", err)
		return storage.MintQuote{}, cashu.StandardErr
	}
	mintQuote := storage.MintQuote{
		Id:             quoteId,
		Amount:         requestAmount,
		PaymentRequest: invoice.PaymentRequest,
		PaymentHash:    invoice.PaymentHash,
		State:          nut04.Unpaid,
		Expiry:         uint64(time.Now().Add(time.Second * time.Duration(invoice.Expiry)).Unix()),
		Pubkey:         publicKey,
	}

	err = m.db.SaveMintQuote(mintQuote)
	if err != nil {
		errmsg := fmt.Sprintf("error saving mint quote to db: %v", err)
		return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	// goroutine to check in the background when invoice gets paid and update db if so
	go m.checkInvoicePaid(m.ctx, quoteId)

	return mintQuote, nil
}

// GetMintQuoteState returns the state of a mint quote.
func (m *Mint) GetMintQuoteState(quoteId string) (storage.MintQuote, error) {
	mintQuote, err := m.db.GetMintQuote(quoteId)
	if err != nil {
		return storage.MintQuote{}, cashu.QuoteNotExistErr
	}

	// if previously unpaid, check if invoice has been paid
	if mintQuote.State == nut04.Unpaid {
		m.logDebugf("checking status of invoice with hash '%v'", mintQuote.PaymentHash)
		status, err := m.lightningClient.InvoiceStatus(mintQuote.PaymentHash)
		if err != nil {
			errmsg := fmt.Sprintf("error getting invoice status: %v", err)
			return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.LightningBackendErrCode)
		}

		if status.Settled {
			m.logInfof("mint quote '%v' with invoice payment hash '%v' was paid", mintQuote.Id, mintQuote.PaymentHash)
			// Unpaid->Paid ONLY (conditional): the read above is advisory;
			// between it and this write a concurrent minter may have
			// claimed the quote (Pending) — an unconditional write would
			// resurrect Paid and open a second claim (double issuance).
			claimed, err := m.db.UpdateMintQuoteStateCAS(mintQuote.Id, nut04.Unpaid, nut04.Paid)
			if err != nil {
				errmsg := fmt.Sprintf("error updating mint quote in db: %v", err)
				return storage.MintQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			if !claimed {
				// someone advanced the quote past UNPAID — return their truth
				fresh, err := m.db.GetMintQuote(mintQuote.Id)
				if err == nil {
					mintQuote = fresh
				}
			} else {
				mintQuote.State = nut04.Paid
				jsonQuote, _ := json.Marshal(mintQuote)
				m.publisher.Publish(BOLT11_MINT_QUOTE_TOPIC, jsonQuote)
			}
		}
	}

	return mintQuote, nil
}

// MintTokens verifies whether the mint quote with id has been paid and proceeds to
// sign the blindedMessages and return the BlindedSignatures if it was paid.
// mintQuoteClaimBarrier is a test seam (the postMeltBolt11 pattern):
// invoked between the quote read and the Paid->Pending CAS claim in
// MintTokens, so tests can deterministically stage both callers past the
// read before either claims — the double-issuance race window.
var mintQuoteClaimBarrier = func() {}

// Batch limits (NUT-29: implementations MAY impose maximum batch sizes).
const (
	BatchCheckLimit = 50
	BatchMaxOutputs = 1000
)

// MintTokensBatch atomically mints a consolidated output set against
// multiple PAID bolt11 quotes (NUT-29). All-or-nothing: every quote is
// claimed (Paid->Pending CAS) before any signing; any failure rolls every
// claim back (Pending->Paid, releasing only claims WE hold) so the batch
// is retryable. NUT-20 locked quotes are signed per-quote over
// quotes[i] + the FULL consolidated outputs (nuts/29.md).
func (m *Mint) MintTokensBatch(quoteIds []string, outputs cashu.BlindedMessages, signatures []string) (cashu.BlindedSignatures, error) {
	if len(quoteIds) == 0 {
		return nil, cashu.NoProofsProvided
	}
	if len(outputs) > BatchMaxOutputs {
		return nil, cashu.BuildCashuError(
			fmt.Sprintf("too many outputs: max %d", BatchMaxOutputs), cashu.StandardErrCode)
	}

	// validation rule 2: unique quote ids
	seen := make(map[string]bool, len(quoteIds))
	for _, id := range quoteIds {
		if seen[id] {
			return nil, cashu.DuplicateQuotesErr
		}
		seen[id] = true
	}

	// fetch every quote up front (all-or-nothing: unknown id rejects the
	// whole batch before anything is claimed)
	quotes := make([]storage.MintQuote, len(quoteIds))
	totalAmount := uint64(0)
	for i, id := range quoteIds {
		quote, err := m.GetMintQuoteState(id)
		if err != nil {
			return nil, err
		}
		if quote.State != nut04.Paid {
			return nil, cashu.MintQuoteRequestNotPaid
		}
		quotes[i] = quote
		totalAmount += quote.Amount
	}

	// outputs validation (rule 7, bolt11: sum(outputs) == sum(quotes))
	outputsAmount, err := outputs.AmountChecked()
	if err != nil {
		return nil, cashu.InvalidBlindedMessageAmount
	}
	if cashu.CheckDuplicateBlindedMessages(outputs) {
		return nil, cashu.DuplicateOutputs
	}
	if outputsAmount != totalAmount {
		return nil, cashu.OutputsOverQuoteAmountErr
	}

	// NUT-20: if any quote is locked, signatures[i] must verify over
	// quotes[i] + the full consolidated outputs (dual-accept framing).
	anyLocked := false
	for _, q := range quotes {
		if q.Pubkey != nil {
			anyLocked = true
			break
		}
	}
	if anyLocked && len(signatures) != len(quoteIds) {
		return nil, cashu.MintQuoteInvalidSigErr
	}

	// claim every quote (Paid -> Pending). On any loss/failure, roll back
	// the claims already taken.
	claimed := make([]string, 0, len(quotes))
	rollbackClaims := func() {
		for _, id := range claimed {
			if released, rbErr := m.db.UpdateMintQuoteStateCAS(id, nut04.Pending, nut04.Paid); rbErr != nil || !released {
				m.logErrorf("batch mint rollback did not release quote '%v' (released=%v, err=%v) — quote may rest PENDING", id, released, rbErr)
			}
		}
	}
	for i, q := range quotes {
		if q.Pubkey != nil {
			sigHex := signatures[i]
			if sigHex == "" {
				rollbackClaims()
				return nil, cashu.MintQuoteInvalidSigErr
			}
			sigBytes, err := hex.DecodeString(sigHex)
			if err != nil {
				rollbackClaims()
				return nil, cashu.MintQuoteInvalidSigErr
			}
			sig, err := schnorr.ParseSignature(sigBytes)
			if err != nil {
				rollbackClaims()
				return nil, cashu.MintQuoteInvalidSigErr
			}
			if !nut20.VerifyMintQuoteSignature(sig, q.Id, outputs, q.Pubkey) {
				rollbackClaims()
				return nil, cashu.MintQuoteInvalidSigErr
			}
		}
		claimedOk, err := m.db.UpdateMintQuoteStateCAS(q.Id, nut04.Paid, nut04.Pending)
		if err != nil {
			rollbackClaims()
			errmsg := fmt.Sprintf("error claiming mint quote '%v': %v", q.Id, err)
			return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}
		if !claimedOk {
			rollbackClaims()
			return nil, cashu.QuotePending
		}
		claimed = append(claimed, q.Id)
	}

	// sign the consolidated outputs once
	blindedSignatures, err := m.signBlindedMessages(outputs)
	if err != nil {
		rollbackClaims()
		return nil, err
	}

	// persist signatures, then mark every quote Issued (claim-holder only)
	B_s := make([]string, len(outputs))
	for i, bm := range outputs {
		B_s[i] = bm.B_
	}
	if err := m.db.SaveBlindSignatures(B_s, blindedSignatures); err != nil {
		rollbackClaims()
		errmsg := fmt.Sprintf("error saving blind signatures: %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}
	for _, q := range quotes {
		issued, err := m.db.UpdateMintQuoteStateCAS(q.Id, nut04.Pending, nut04.Issued)
		if err != nil || !issued {
			rollbackClaims()
			errmsg := fmt.Sprintf("quote '%v' left PENDING before batch issuance completed (issued=%v, err=%v)", q.Id, issued, err)
			return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}
		jsonQuote, _ := json.Marshal(q)
		m.publisher.Publish(BOLT11_MINT_QUOTE_TOPIC, jsonQuote)
	}

	return blindedSignatures, nil
}

// CheckMintQuotesBatch returns the states of the given bolt11 mint quotes
// in request order (NUT-29 batch check). All-or-nothing: an unknown id
// rejects the whole request.
func (m *Mint) CheckMintQuotesBatch(quoteIds []string) ([]storage.MintQuote, error) {
	if len(quoteIds) == 0 {
		return nil, cashu.NoProofsProvided
	}
	if len(quoteIds) > BatchCheckLimit {
		return nil, cashu.BuildCashuError(
			fmt.Sprintf("batch too large: max %d quote ids", BatchCheckLimit), cashu.StandardErrCode)
	}
	quotes := make([]storage.MintQuote, len(quoteIds))
	for i, id := range quoteIds {
		quote, err := m.GetMintQuoteState(id)
		if err != nil {
			return nil, err
		}
		quotes[i] = quote
	}
	return quotes, nil
}

// storedSignaturesFor reports whether the FULL output set is already
// signed in the db and returns those signatures — the retry/recovery
// signal for a Pending or Issued quote (a partial match is not a retry).
func (m *Mint) storedSignaturesFor(outputs cashu.BlindedMessages) (cashu.BlindedSignatures, bool) {
	if len(outputs) == 0 {
		return nil, false
	}
	B_s := make([]string, len(outputs))
	for i, bm := range outputs {
		B_s[i] = bm.B_
	}
	sigs, err := m.db.GetBlindSignatures(B_s)
	if err != nil || len(sigs) != len(outputs) {
		return nil, false
	}
	return sigs, true
}

func (m *Mint) MintTokens(mintTokensRequest nut04.PostMintBolt11Request) (cashu.BlindedSignatures, error) {
	// NUT #04: The total output amount **MUST NOT** exceed the quote's currently mintable amount, `amount_paid - amount_issued`.
	mintQuote, err := m.GetMintQuoteState(mintTokensRequest.Quote)
	if err != nil {
		return nil, err
	}

	var blindedSignatures cashu.BlindedSignatures

	// NUT-19/recovery: for Pending and Issued quotes, if the FULL output
	// set is already signed in the db, this is a retry of a mint that
	// completed (or crashed after SaveBlindSignatures but before the
	// Issued write) — replay the stored signatures and complete the state
	// machine instead of erroring (cashu-audit #59 crash-consistency: the
	// client must be able to learn its signatures after any crash point).
	if mintQuote.State == nut04.Pending || mintQuote.State == nut04.Issued {
		if stored, ok := m.storedSignaturesFor(mintTokensRequest.Outputs); ok {
			if mintQuote.State == nut04.Pending {
				// crash window: signatures saved, Issued write lost — finish it
				if issued, err := m.db.UpdateMintQuoteStateCAS(mintQuote.Id, nut04.Pending, nut04.Issued); err != nil || !issued {
					m.logErrorf("mint quote '%v' recovery could not complete Pending->Issued (issued=%v, err=%v)", mintQuote.Id, issued, err)
				}
			}
			m.logDebugf("replaying stored signatures for mint quote '%v' (state %v)", mintQuote.Id, mintQuote.State)
			return stored, nil
		}
	}

	switch mintQuote.State {
	case nut04.Unpaid:
		return nil, cashu.MintQuoteRequestNotPaid
	case nut04.Issued:
		// Issued with NO stored signatures for these outputs: the
		// pre-saga crash shape — value stranded, needs operator recovery.
		m.logErrorf("mint quote '%v' is ISSUED but its signatures are not recoverable for these outputs", mintQuote.Id)
		return nil, cashu.MintQuoteAlreadyIssued
	case nut04.Pending:
		return nil, cashu.QuotePending
	case nut04.Paid:
		err := func() error {
			// Atomically claim the quote Paid->Pending before any signing
			// work. The read-check above is advisory; THIS is the guard:
			// two concurrent MintTokens on one paid quote (with disjoint
			// outputs) both passed it, both unconditionally wrote Pending,
			// and both signed — double issuance for one payment (the
			// mint-side sibling of the melt-quote TOCTOU, cashu-audit #59).
			mintQuoteClaimBarrier()
			claimed, err := m.db.UpdateMintQuoteStateCAS(mintQuote.Id, nut04.Paid, nut04.Pending)
			if err != nil {
				errmsg := fmt.Sprintf("error claiming mint quote state: %v", err)
				return cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			if !claimed {
				return cashu.QuotePending
			}

			blindedMessages := mintTokensRequest.Outputs
			blindedMessagesAmount, err := blindedMessages.AmountChecked()
			if err != nil {
				return cashu.InvalidBlindedMessageAmount
			}

			if cashu.CheckDuplicateBlindedMessages(blindedMessages) {
				return cashu.DuplicateOutputs
			}

			// verify that amount from blinded messages is enough
			// for quote amount
			if blindedMessagesAmount > mintQuote.Amount {
				return cashu.OutputsOverQuoteAmountErr
			}

			B_s := make([]string, len(blindedMessages))
			for i, bm := range blindedMessages {
				B_s[i] = bm.B_
			}

			sigs, err := m.db.GetBlindSignatures(B_s)
			if err != nil {
				errmsg := fmt.Sprintf("error getting blind signatures from db: %v", err)
				return cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			if len(sigs) > 0 {
				return cashu.BlindedMessageAlreadySigned
			}

			// verify signature on mint quote
			if mintQuote.Pubkey != nil {
				if len(mintTokensRequest.Signature) == 0 {
					return cashu.MintQuoteInvalidSigErr
				}

				sigBytes, err := hex.DecodeString(mintTokensRequest.Signature)
				if err != nil {
					return cashu.MintQuoteInvalidSigErr
				}
				signature, err := schnorr.ParseSignature(sigBytes)
				if err != nil {
					return cashu.MintQuoteInvalidSigErr
				}

				if !nut20.VerifyMintQuoteSignature(
					signature,
					mintQuote.Id,
					mintTokensRequest.Outputs,
					mintQuote.Pubkey,
				) {
					return cashu.MintQuoteInvalidSigErr
				}
				m.logDebugf("verified signature on mint quote")
			}

			blindedSignatures, err = m.signBlindedMessages(blindedMessages)
			if err != nil {
				return err
			}

			// CRASH-CONSISTENCY ORDER (cashu-audit #59 saga): persist the
			// signatures BEFORE the Issued write. A crash between the two
			// leaves the quote Pending with recoverable signatures — the
			// retry replays them and completes Pending->Issued (see the
			// recovery head in MintTokens). The old order (Issued first)
			// stranded the quote Issued with nothing deliverable.
			if err := m.db.SaveBlindSignatures(B_s, blindedSignatures); err != nil {
				errmsg := fmt.Sprintf("error saving blind signatures: %v", err)
				return cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}

			// Pending->Issued conditionally: only the claim-holder reaches
			// here, so a loss means unexpected concurrent state surgery.
			mintQuote.State = nut04.Issued
			issued, err := m.db.UpdateMintQuoteStateCAS(mintQuote.Id, nut04.Pending, nut04.Issued)
			if err != nil {
				errmsg := fmt.Sprintf("error updating mint quote state: %v", err)
				return cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			if !issued {
				m.logErrorf("mint quote '%v' left PENDING before its claim-holder could mark it ISSUED — concurrent writer detected", mintQuote.Id)
				return cashu.BuildCashuError("mint quote state changed underneath issuance", cashu.DBErrCode)
			}

			jsonQuote, _ := json.Marshal(mintQuote)
			m.publisher.Publish(BOLT11_MINT_QUOTE_TOPIC, jsonQuote)
			return nil
		}()

		// release the claim on error so a corrected retry stays possible.
		// The rollback is itself conditional (Pending->Paid): we only ever
		// write back the state WE hold. A rollback failure means the row
		// moved underneath us — log loudly, it needs operator eyes (same
		// posture as the melt-path rollback).
		if err != nil {
			if err != cashu.QuotePending {
				released, rbErr := m.db.UpdateMintQuoteStateCAS(mintQuote.Id, nut04.Pending, nut04.Paid)
				if rbErr != nil || !released {
					m.logErrorf("mint quote '%v' rollback after failure did not release the claim (released=%v, err=%v) — quote may rest PENDING: %v",
						mintQuote.Id, released, rbErr, err)
				}
			}
			return nil, err
		}
	}

	return blindedSignatures, nil
}

// verifySigAllGroup dispatches spec SIG_ALL group verification by
// condition kind: P2PK (nut11) or HTLC (nut14). Both use the same
// aggregated first-input message; the witness type and receiver-path
// semantics differ (tollgate #809).
func (m *Mint) verifySigAllGroup(proofs cashu.Proofs, outputs cashu.BlindedMessages, quoteId string) error {
	first, err := nut10.DeserializeSecret(proofs[0].Secret)
	if err != nil {
		return err
	}
	switch first.Kind {
	case nut10.HTLC:
		return nut14.VerifySigAllHTLCProofs(proofs, outputs, quoteId)
	default:
		return nut11.VerifySigAllProofs(proofs, outputs, quoteId)
	}
}

// swapClaimMarker rides the pending_proofs.melt_quote_id column for swap
// claims (swaps have no quote to serialize on — the proof set itself is
// the claim key).
const swapClaimMarker = "swap"

// swapClaimBarrier is a test seam (the postMeltBolt11 pattern): invoked
// between Swap's read-checks and the proof claim, so tests can stage both
// callers past verification before either claims — the same-proofs
// double-spend race window.
var swapClaimBarrier = func() {}

// Swap will process a request to swap tokens.
// A swap requires a set of valid proofs and blinded messages.
// If valid, the mint will sign the blindedMessages and invalidate
// the proofs that were used as input.
// It returns the BlindedSignatures.
func (m *Mint) Swap(proofs cashu.Proofs, blindedMessages cashu.BlindedMessages) (cashu.BlindedSignatures, error) {
	// NUT #03: Mints verify and invalidate the inputs and issue new promises (`BlindSignatures`).
	var proofsAmount uint64
	Ys := make([]string, len(proofs))
	for i, proof := range proofs {
		proofsAmount += proof.Amount

		Y, err := crypto.HashToCurve([]byte(proof.Secret))
		if err != nil {
			return nil, cashu.InvalidProofErr
		}
		Yhex := hex.EncodeToString(Y.SerializeCompressed())
		Ys[i] = Yhex
	}

	blindedMessagesAmount, err := blindedMessages.AmountChecked()
	if err != nil {
		return nil, cashu.InvalidBlindedMessageAmount
	}

	if cashu.CheckDuplicateBlindedMessages(blindedMessages) {
		return nil, cashu.DuplicateOutputs
	}

	B_s := make([]string, len(blindedMessages))
	for i, bm := range blindedMessages {
		B_s[i] = bm.B_
	}

	fees := uint64(m.TransactionFees(proofs))
	proofsMinusFees, underflow := cashu.UnderflowSubUint64(proofsAmount, fees)
	if underflow {
		return nil, cashu.InvalidProofAmount
	}
	if proofsMinusFees < blindedMessagesAmount {
		return nil, cashu.InsufficientProofsAmount
	}

	if err := m.verifyProofs(proofs, Ys); err != nil {
		return nil, err
	}

	sigs, err := m.db.GetBlindSignatures(B_s)
	if err != nil {
		errmsg := fmt.Sprintf("error getting blind signatures from db: %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}
	if len(sigs) > 0 {
		return nil, cashu.BlindedMessageAlreadySigned
	}

	// if sig all, verify the first-input aggregate witness per NUT-11
	// (tollgate #809: the per-output witness lane was non-spec; spec
	// wallets put the signature over the aggregated swap message in the
	// FIRST input only)
	if nut11.ProofsSigAll(proofs) {
		m.logDebugf("locked proofs have SIG_ALL flag. Verifying first-input aggregate witness")
		if err := m.verifySigAllGroup(proofs, blindedMessages, ""); err != nil {
			return nil, err
		}
	}

	// Atomically claim the input proofs BEFORE signing (the swap-side
	// sibling of the quote CAS — cashu-audit #59): two concurrent swaps
	// with the SAME proofs both passed the read-checks above and both
	// signed — a double spend. The pending-insert (unique secret + the
	// in-tx used-check) is the race verdict; the loser gets a pending/
	// spent error and signs nothing.
	swapClaimBarrier()
	if err := m.db.AddPendingProofs(proofs, swapClaimMarker); err != nil {
		if errors.Is(err, cashu.ProofAlreadyUsedErr) {
			return nil, cashu.ProofAlreadyUsedErr
		}
		errmsg := fmt.Sprintf("error claiming swap proofs: %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	// if verification complete, sign blinded messages
	blindedSignatures, err := m.signBlindedMessages(blindedMessages)
	if err != nil {
		// release the claim so a corrected retry stays possible
		if rmErr := m.db.RemovePendingProofs(Ys); rmErr != nil {
			m.logErrorf("swap proof-claim rollback failed (proofs may rest PENDING): %v (sign error: %v)", rmErr, err)
		}
		return nil, err
	}

	// invalidate proofs atomically (pending -> used in one transaction —
	// the two-statement form left a re-claim window, see SettleProofs)
	if err := m.db.SettleProofs(Ys, proofs); err != nil {
		errmsg := fmt.Sprintf("error settling swap proofs (pending->used must be atomic): %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}
	if err := m.db.SaveBlindSignatures(B_s, blindedSignatures); err != nil {
		errmsg := fmt.Sprintf("error saving blind signatures: %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	m.publishProofsStateChanges(proofs, nut07.Spent)

	return blindedSignatures, nil
}

// RequestMeltQuote will process a request to melt tokens and return a MeltQuote.
// A melt is requested by a wallet to request the mint to pay an invoice.
func (m *Mint) RequestMeltQuote(meltQuoteRequest nut05.PostMeltQuoteBolt11Request) (storage.MeltQuote, error) {
	// NUT #05: `method` **MUST** match `[a-z0-9_-]+`.
	if meltQuoteRequest.Unit != cashu.Sat.String() {
		errmsg := fmt.Sprintf("unit '%v' not supported", meltQuoteRequest.Unit)
		return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.UnitErrCode)
	}

	// check invoice passed is valid
	request := meltQuoteRequest.Request
	bolt11, err := decodepay.Decodepay(request)
	if err != nil {
		errmsg := fmt.Sprintf("invalid invoice: %v", err)
		return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.MeltQuoteErrCode)
	}
	if bolt11.MSatoshi == 0 {
		return storage.MeltQuote{}, cashu.BuildCashuError("invoice has no amount", cashu.MeltQuoteErrCode)
	}
	invoiceSatAmount := uint64(bolt11.MSatoshi) / 1000
	quoteAmount := invoiceSatAmount

	// check if a mint quote exists with the same invoice.
	_, err = m.db.GetMintQuoteByPaymentHash(bolt11.PaymentHash)
	isInternal := false
	if err == nil {
		isInternal = true
	}

	isMpp := false
	var amountMsat uint64 = 0
	// check mpp option
	if len(meltQuoteRequest.Options) > 0 {
		mpp, ok := meltQuoteRequest.Options["mpp"]
		if ok {
			if m.mppEnabled {
				// if this is an internal invoice, reject MPP request
				if isInternal {
					return storage.MeltQuote{},
						cashu.BuildCashuError("mpp for internal invoice is not allowed", cashu.MeltQuoteErrCode)
				}

				// check mpp msat amount is less than invoice amount
				if mpp.AmountMsat >= uint64(bolt11.MSatoshi) {
					return storage.MeltQuote{},
						cashu.BuildCashuError("mpp amount is not less than amount in invoice",
							cashu.MeltQuoteErrCode)
				}
				isMpp = true
				amountMsat = mpp.AmountMsat
				quoteAmount = amountMsat / 1000
				m.logInfof("got melt quote request to pay partial amount '%v' of invoice with amount '%v'",
					quoteAmount, invoiceSatAmount)
			} else {
				return storage.MeltQuote{},
					cashu.BuildCashuError("MPP is not supported", cashu.MeltQuoteErrCode)
			}
		}
	}

	// check melt limit
	if m.limits.MeltingSettings.MaxAmount > 0 {
		if quoteAmount > m.limits.MeltingSettings.MaxAmount {
			return storage.MeltQuote{}, cashu.MeltAmountExceededErr
		}
	}

	// check if a melt quote for the invoice already exists
	quote, _ := m.db.GetMeltQuoteByPaymentRequest(request)
	if quote != nil {
		return storage.MeltQuote{}, cashu.MeltQuoteForRequestExists
	}

	quoteId, err := cashu.GenerateRandomQuoteId()
	if err != nil {
		m.logErrorf("error generating random quote id: %v", err)
		return storage.MeltQuote{}, cashu.StandardErr
	}
	// Fee reserve that is required by the mint
	fee := m.lightningClient.FeeReserve(quoteAmount)
	// if mint quote exists with same invoice, it can be
	// settled internally so set the fee to 0
	if isInternal {
		m.logDebugf(`in melt quote request found mint quote with same invoice. 
		Setting fee reserve to 0 because quotes can be settled internally.`)
		fee = 0
	}
	meltQuote := storage.MeltQuote{
		Id:             quoteId,
		InvoiceRequest: request,
		PaymentHash:    bolt11.PaymentHash,
		Amount:         quoteAmount,
		FeeReserve:     fee,
		State:          nut05.Unpaid,
		Expiry:         uint64(time.Now().Add(time.Minute * QuoteExpiryMins).Unix()),
		IsMpp:          isMpp,
		AmountMsat:     amountMsat,
	}

	m.logInfof("got melt quote request for invoice of amount '%v'. Setting fee reserve to %v",
		invoiceSatAmount, meltQuote.FeeReserve)

	if err := m.db.SaveMeltQuote(meltQuote); err != nil {
		errmsg := fmt.Sprintf("error saving melt quote to db: %v", err)
		return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	return meltQuote, nil
}

// GetMeltQuoteState returns the state of a melt quote.
// Used to check whether a melt quote has been paid.
func (m *Mint) GetMeltQuoteState(ctx context.Context, quoteId string) (storage.MeltQuote, error) {
	meltQuote, err := m.db.GetMeltQuote(quoteId)
	if err != nil {
		return storage.MeltQuote{}, cashu.QuoteNotExistErr
	}

	// if quote is pending, check with backend if status of payment has changed.
	// NEVER for a quote whose MeltTokens call is in flight — reconciling
	// underneath an active melt double-settles (the marker clears when the
	// call returns, so crash orphans reconcile on their first poll).
	if meltQuote.State == nut05.Pending {
		if _, inFlight := m.meltInFlight.Load(meltQuote.Id); inFlight {
			return meltQuote, nil
		}
		m.logDebugf("checking status of payment with hash '%v' for melt quote '%v'",
			meltQuote.PaymentHash, meltQuote.Id)

		paymentStatus, err := m.lightningClient.OutgoingPaymentStatus(ctx, meltQuote.PaymentHash)
		if err != nil {
			// A not-found outgoing payment is definitive: nothing was ever
			// paid (crash between the quote claim and the payment attempt —
			// the orphan that previously rested PENDING forever). Same
			// verdict as MeltTokens' own failure path: release the claim
			// and the pending proofs so the quote stays retryable.
			if errors.Is(err, lightning.OutgoingPaymentNotFound) || status.Code(err) == codes.NotFound {
				m.logInfof("no outgoing payment found for hash %v. Releasing orphaned claim on melt quote '%v' back to UNPAID",
					meltQuote.PaymentHash, meltQuote.Id)
				released, rbErr := m.db.UpdateMeltQuoteStateCAS(meltQuote.Id, nut05.Pending, nut05.Unpaid)
				if rbErr != nil {
					errmsg := fmt.Sprintf("error releasing orphaned melt quote: %v", rbErr)
					return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
				}
				if released {
					if _, err := m.removePendingProofsForQuote(meltQuote.Id); err != nil {
						errmsg := fmt.Sprintf("error removing pending proofs for quote: %v", err)
						return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
					}
					meltQuote.State = nut05.Unpaid
				}
				return meltQuote, nil
			}
			m.logErrorf(`error checking outgoing payment status: %v. Leaving proofs for quote '%v' as pending`,
				err, meltQuote.Id)
			return meltQuote, nil
		}

		switch paymentStatus.PaymentStatus {
		// settle proofs (remove pending, and add to used — ONE transaction:
		// the two-statement form left the same re-claim window the melt path
		// fixed) and mark quote as paid with preimage
		case lightning.Succeeded:
			m.logInfof("payment %v succeded. setting melt quote '%v' to paid and invalidating proofs",
				meltQuote.PaymentHash, meltQuote.Id)

			proofs, Ys, err := m.pendingProofsForQuote(meltQuote.Id)
			if err != nil {
				errmsg := fmt.Sprintf("error loading pending proofs for quote: %v", err)
				return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			// sign + persist the NUT-08 change BEFORE the settle/Paid
			// writes (persist-sigs-before-Paid). On signing failure the
			// quote stays PENDING with proofs pending — nothing is
			// rolled back (the payment stands) and the next poll
			// retries; the journaled blank outputs make the change
			// computable without the original request.
			if _, err := m.signMeltChange(meltQuote, proofs, proofs.Amount(), uint64(m.TransactionFees(proofs)), paymentStatus); err != nil {
				m.logErrorf("melt quote '%v': change signing failed during poll reconciliation: %v (quote stays PENDING)", meltQuote.Id, err)
				return storage.MeltQuote{}, cashu.BuildCashuError(fmt.Sprintf("error signing melt change: %v", err), cashu.DBErrCode)
			}
			err = m.db.SettleProofs(Ys, proofs)
			if err != nil {
				errmsg := fmt.Sprintf("error settling proofs for quote (pending->used must be atomic): %v", err)
				return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}

			meltQuote.State = nut05.Paid
			meltQuote.Preimage = paymentStatus.Preimage
			err = m.db.UpdateMeltQuote(meltQuote.Id, paymentStatus.Preimage, nut05.Paid)
			if err != nil {
				errmsg := fmt.Sprintf("error updating melt quote state: %v", err)
				return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			m.publishProofsStateChanges(proofs, nut07.Spent)

		case lightning.Failed:
			m.logInfof("payment %v failed with error: %v. Setting melt quote '%v' to unpaid and removing proofs from pending",
				meltQuote.PaymentHash, paymentStatus.PaymentFailureReason, meltQuote.Id)

			meltQuote.State = nut05.Unpaid
			err = m.db.UpdateMeltQuote(meltQuote.Id, "", meltQuote.State)
			if err != nil {
				errmsg := fmt.Sprintf("error updating melt quote state: %v", err)
				return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			_, err = m.removePendingProofsForQuote(meltQuote.Id)
			if err != nil {
				errmsg := fmt.Sprintf("error removing pending proofs for quote: %v", err)
				return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
		}
	}

	return meltQuote, nil
}

func (m *Mint) removePendingProofsForQuote(quoteId string) (cashu.Proofs, error) {
	dbproofs, err := m.db.GetPendingProofsByQuote(quoteId)
	if err != nil {
		return nil, err
	}

	proofs := make(cashu.Proofs, len(dbproofs))
	Ys := make([]string, len(dbproofs))
	for i, dbproof := range dbproofs {
		Ys[i] = dbproof.Y

		proof := cashu.Proof{
			Amount:  dbproof.Amount,
			Id:      dbproof.Id,
			Secret:  dbproof.Secret,
			C:       dbproof.C,
			Witness: dbproof.Witness,
		}
		proofs[i] = proof
	}

	err = m.db.RemovePendingProofs(Ys)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

// pendingProofsForQuote loads a quote's pending proofs and Ys WITHOUT
// removing them — for the atomic SettleProofs path (pending->used in one
// transaction; the remove+save two-statement form left a re-claim window).
func (m *Mint) pendingProofsForQuote(quoteId string) (cashu.Proofs, []string, error) {
	dbproofs, err := m.db.GetPendingProofsByQuote(quoteId)
	if err != nil {
		return nil, nil, err
	}
	proofs := make(cashu.Proofs, len(dbproofs))
	Ys := make([]string, len(dbproofs))
	for i, dbproof := range dbproofs {
		Ys[i] = dbproof.Y
		proofs[i] = cashu.Proof{
			Amount:  dbproof.Amount,
			Id:      dbproof.Id,
			Secret:  dbproof.Secret,
			C:       dbproof.C,
			Witness: dbproof.Witness,
		}
	}
	return proofs, Ys, nil
}

// MeltTokens verifies whether proofs provided are valid
// and proceeds to attempt payment. On a PAID melt it also signs the
// NUT-08 change for the request's blank outputs (the overpaid fee
// reserve and any over-funding), persisting the signatures before the
// quote's Paid write so every crash point leaves them recoverable.
func (m *Mint) MeltTokens(ctx context.Context, meltTokensRequest nut05.PostMeltBolt11Request) (storage.MeltQuote, cashu.BlindedSignatures, error) {
	// NUT #05: `inputs` are the proofs with a total amount sufficient to cover the requested amount plus any fees
	proofs := meltTokensRequest.Inputs

	var proofsAmount uint64
	Ys := make([]string, len(proofs))
	for i, proof := range proofs {
		proofsAmount += proof.Amount

		Y, err := crypto.HashToCurve([]byte(proof.Secret))
		if err != nil {
			return storage.MeltQuote{}, nil, cashu.InvalidProofErr
		}
		Yhex := hex.EncodeToString(Y.SerializeCompressed())
		Ys[i] = Yhex
	}

	meltQuote, err := m.db.GetMeltQuote(meltTokensRequest.Quote)
	if err != nil {
		return storage.MeltQuote{}, nil, cashu.QuoteNotExistErr
	}
	if meltQuote.State == nut05.Paid {
		// idempotent replay of a settled melt: identical blank outputs
		// (the journaled set) answer with the stored change signatures —
		// a wallet that lost the first response recovers byte-identical
		// change even after the NUT-19 response cache is gone (the
		// wallet-side #497 replay invariant, answered mint-side).
		if requestMatchesStoredOutputs(meltTokensRequest.Outputs, meltQuote.Id, m.db) {
			m.logInfof("replaying settled melt quote '%v': returning stored change", meltQuote.Id)
			return meltQuote, m.MeltQuoteChange(meltQuote.Id), nil
		}
		return storage.MeltQuote{}, nil, cashu.MeltQuoteAlreadyPaid
	}
	if meltQuote.State == nut05.Pending {
		return storage.MeltQuote{}, nil, cashu.QuotePending
	}

	err = m.verifyProofs(proofs, Ys)
	if err != nil {
		return storage.MeltQuote{}, nil, err
	}

	fees := m.TransactionFees(proofs)
	// checks if amount in proofs is enough
	if proofsAmount < meltQuote.Amount+meltQuote.FeeReserve+uint64(fees) {
		return storage.MeltQuote{}, nil, cashu.InsufficientProofsAmount
	}

	// NUT-08: blank outputs must be validated before the quote is
	// claimed — after the payment there is no refusing a bad request
	// shape anymore (fund-safety: local validation precedes the
	// irreversible payment).
	if err := m.validateMeltChangeOutputs(meltTokensRequest.Outputs); err != nil {
		return storage.MeltQuote{}, nil, err
	}

	// NUT-11 SIG_ALL melts are spec-legal: the witness lives in the first
	// input and signs the aggregate of inputs + NUT-08 blank outputs +
	// quote id. Verified here — before the quote CAS, so a bad witness can
	// never claim the quote (fund-safety: local validation precedes
	// irreversible state changes). tollgate #809 / cashu-audit #59 P1.
	if nut11.ProofsSigAll(proofs) {
		if err := m.verifySigAllGroup(proofs, meltTokensRequest.Outputs, meltQuote.Id); err != nil {
			return storage.MeltQuote{}, nil, err
		}
		m.logDebugf("verified SIG_ALL melt witness (aggregate + quote id)")
	}

	m.logInfof("verified proofs in melt tokens request. Claiming quote via CAS before attempting payment.")
	// Atomically claim the quote UNPAID->PENDING before any payment work.
	// The read-check above is advisory (friendly errors); THIS is the guard:
	// two concurrent melts on one quote (even with disjoint proof sets) both
	// passed it, both unconditionally wrote Pending, and both paid — the
	// double-settlement TOCTOU (cashu-audit #59 P0). Exactly one CAS wins.
	claimed, err := m.db.UpdateMeltQuoteStateCAS(meltQuote.Id, nut05.Unpaid, nut05.Pending)
	if err != nil {
		errmsg := fmt.Sprintf("error claiming melt quote state: %v", err)
		return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}
	if !claimed {
		return storage.MeltQuote{}, nil, cashu.QuotePending
	}
	// mark in-flight for the poll-path reconciler; released on every exit
	m.meltInFlight.Store(meltQuote.Id, struct{}{})
	defer m.meltInFlight.Delete(meltQuote.Id)
	meltQuote.State = nut05.Pending

	// set proofs as pending before trying to make payment (the per-Y guard:
	// this is what correctly rejects same-proofs races across quotes)
	err = m.db.AddPendingProofs(proofs, meltQuote.Id)
	if err != nil {
		errmsg := fmt.Sprintf("error setting proofs as pending in db: %v", err)
		// Release the claimed quote (Pending->Unpaid) so a retry with
		// different proofs stays possible. Without this, a same-proofs
		// race across two quotes strands the losing quote in PENDING
		// with no payment behind it (fund-safety: failure paths must
		// restore retryability; AddPendingProofs is a single tx, so
		// nothing was written when it fails).
		if _, rbErr := m.db.UpdateMeltQuoteStateCAS(meltQuote.Id, nut05.Pending, nut05.Unpaid); rbErr != nil {
			errmsg = fmt.Sprintf(
				"%v (rollback failed: %v — quote '%v' remains PENDING, needs pending-quote recovery)",
				errmsg, rbErr, meltQuote.Id,
			)
			m.logErrorf("melt quote '%v' stranded PENDING after AddPendingProofs failure: %v (rollback error: %v)",
				meltQuote.Id, err, rbErr)
		}
		return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	// journal the NUT-08 blank outputs BEFORE the payment attempt: once a
	// payment can exist, its change destinations must be durable — the
	// poll-path reconciler (and this retry path) signs the change from
	// this journal, not from the request it no longer has.
	if len(meltTokensRequest.Outputs) > 0 {
		if err := m.db.SaveMeltChangeOutputs(meltQuote.Id, meltTokensRequest.Outputs); err != nil {
			errmsg := fmt.Sprintf("error journaling melt change outputs: %v", err)
			// same rollback discipline as AddPendingProofs above:
			// release the claim and the pending proofs so the melt is
			// retryable (nothing was paid yet)
			if _, rbErr := m.db.UpdateMeltQuoteStateCAS(meltQuote.Id, nut05.Pending, nut05.Unpaid); rbErr != nil {
				errmsg = fmt.Sprintf(
					"%v (rollback failed: %v — quote '%v' remains PENDING, needs pending-quote recovery)",
					errmsg, rbErr, meltQuote.Id,
				)
			}
			if rmErr := m.db.RemovePendingProofs(Ys); rmErr != nil {
				errmsg = fmt.Sprintf("%v (also could not remove pending proofs: %v)", errmsg, rmErr)
			}
			return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}
	}

	// before asking backend to send payment, check if quotes can be settled
	// internally (i.e mint and melt quotes exist with the same invoice)
	mintQuote, err := m.db.GetMintQuoteByPaymentHash(meltQuote.PaymentHash)
	if err == nil {
		m.logDebugf("quotes '%v' and '%v' have same invoice so settling them internally", meltQuote.Id, mintQuote.Id)
		meltQuote, err = m.settleQuotesInternally(mintQuote, meltQuote)
		if err != nil {
			return storage.MeltQuote{}, nil, err
		}
		// internal settlement pays no Lightning fee: the whole fee
		// reserve (plus any over-funding) is overpaid and returns as
		// change — signed and persisted BEFORE the settle/Paid writes.
		var change cashu.BlindedSignatures
		change, err = m.signMeltChange(meltQuote, proofs, proofsAmount, uint64(fees), lightning.PaymentStatus{
			PaymentStatus: lightning.Succeeded, FeeSpentKnown: true,
		})
		if err != nil {
			// the payment stands (settled internally); the quote stays
			// PENDING with proofs pending so the poll-path reconciler
			// retries the change signing and completes the state machine
			m.logErrorf("melt quote '%v': change signing failed after internal settle: %v (leaving PENDING for reconciliation)", meltQuote.Id, err)
			return storage.MeltQuote{}, nil, err
		}
		if err := m.db.SettleProofs(Ys, proofs); err != nil {
			errmsg := fmt.Sprintf("error settling proofs (pending->used must be atomic): %v", err)
			return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}
		m.publishProofsStateChanges(proofs, nut07.Spent)
		return meltQuote, change, nil
	} else {
		var sendPaymentResponse lightning.PaymentStatus
		// if melt is MPP, pay partial amount. If not, send full payment
		if meltQuote.IsMpp {
			m.logInfof("attempting MPP payment of amount '%v' for invoice '%v'",
				meltQuote.Amount, meltQuote.InvoiceRequest)
			sendPaymentResponse, err = m.lightningClient.PayPartialAmount(
				ctx,
				meltQuote.InvoiceRequest,
				meltQuote.AmountMsat,
				m.lightningClient.FeeReserve(meltQuote.AmountMsat/1000),
			)
		} else {
			m.logInfof("attempting to pay invoice: %v", meltQuote.InvoiceRequest)
			sendPaymentResponse, err = m.lightningClient.SendPayment(ctx, meltQuote.InvoiceRequest, meltQuote.Amount)
		}
		if err != nil {
			// if SendPayment failed do not return yet, an extra check will be done
			sendPaymentResponse.PaymentStatus = lightning.Failed
			m.logDebugf("Payment failed with error: %v. Will do extra check", err)
		}

		switch sendPaymentResponse.PaymentStatus {
		case lightning.Succeeded:
			m.logInfof("succesfully paid invoice with hash '%v' for melt quote '%v'", meltQuote.PaymentHash, meltQuote.Id)
			// if payment succeeded:
			// - sign + persist the NUT-08 change BEFORE the settle/Paid
			//   writes (persist-sigs-before-Paid, the #59 discipline: a
			//   crash between signing and the Paid write replays from
			//   the blind-signature store)
			// - unset pending proofs and mark them as spent by adding them to the db
			// - mark melt quote as paid
			change, err := m.signMeltChange(meltQuote, proofs, proofsAmount, uint64(fees), sendPaymentResponse)
			if err != nil {
				// the payment already succeeded — do NOT roll anything
				// back: return the error with the quote still PENDING
				// (proofs pending) and let the poll-path reconciler
				// retry the change signing and complete the settle.
				m.logErrorf("melt quote '%v': change signing failed after successful payment: %v (leaving PENDING for reconciliation)", meltQuote.Id, err)
				return storage.MeltQuote{}, nil, err
			}
			meltQuote.State = nut05.Paid
			meltQuote.Preimage = sendPaymentResponse.Preimage
			err = m.settleProofs(Ys, proofs)
			if err != nil {
				return storage.MeltQuote{}, nil, err
			}
			err = m.db.UpdateMeltQuote(meltQuote.Id, sendPaymentResponse.Preimage, nut05.Paid)
			if err != nil {
				errmsg := fmt.Sprintf("error updating melt quote state: %v", err)
				return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
			}
			return meltQuote, change, nil

		case lightning.Pending:
			// if payment is pending, leave quote and proofs as pending and return
			m.logInfof("outgoing payment for quote '%v' is pending.", meltQuote.Id)
			return meltQuote, nil, nil

		case lightning.Failed:
			// if got failed from SendPayment
			// do additional check by calling to get outgoing payment status
			paymentStatus, err := m.lightningClient.OutgoingPaymentStatus(ctx, meltQuote.PaymentHash)
			if errors.Is(err, lightning.OutgoingPaymentNotFound) || status.Code(err) == codes.NotFound {
				m.logInfof("no outgoing payment found with hash: %v. Removing pending proofs and marking quote '%v' as unpaid",
					meltQuote.PaymentHash, meltQuote.Id)

				meltQuote.State = nut05.Unpaid
				err = m.db.UpdateMeltQuote(meltQuote.Id, "", meltQuote.State)
				if err != nil {
					errmsg := fmt.Sprintf("error updating melt quote state: %v", err)
					return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
				}
				err = m.db.RemovePendingProofs(Ys)
				if err != nil {
					errmsg := fmt.Sprintf("error removing proofs from pending: %v", err)
					return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
				}
				return meltQuote, nil, nil
			}
			if err != nil {
				m.logErrorf(`error checking outgoing payment status: %v. Leaving proofs for quote '%v' as pending`, err, meltQuote.Id)
				return meltQuote, nil, nil
			}

			switch paymentStatus.PaymentStatus {
			// only set quote to unpaid and remove pending proofs if OutgoingPaymentStatus
			// returned a nil err (meaning it was actually able to check the status)
			// and payment status was failed
			case lightning.Failed:
				m.logInfof("payment failed with error: %v. Removing pending proofs and marking quote '%v' as unpaid",
					paymentStatus.PaymentFailureReason, meltQuote.Id)

				meltQuote.State = nut05.Unpaid
				err = m.db.UpdateMeltQuote(meltQuote.Id, "", meltQuote.State)
				if err != nil {
					errmsg := fmt.Sprintf("error updating melt quote state: %v", err)
					return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
				}
				err = m.db.RemovePendingProofs(Ys)
				if err != nil {
					errmsg := fmt.Sprintf("error removing proofs from pending: %v", err)
					return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
				}
				return meltQuote, nil, nil
			case lightning.Succeeded:
				m.logInfof("succesfully paid invoice with hash '%v' for melt quote '%v'", meltQuote.PaymentHash, meltQuote.Id)
				change, err := m.signMeltChange(meltQuote, proofs, proofsAmount, uint64(fees), paymentStatus)
				if err != nil {
					m.logErrorf("melt quote '%v': change signing failed after reconciled payment: %v (leaving PENDING for reconciliation)", meltQuote.Id, err)
					return storage.MeltQuote{}, nil, err
				}
				err = m.settleProofs(Ys, proofs)
				if err != nil {
					return storage.MeltQuote{}, nil, err
				}
				meltQuote.State = nut05.Paid
				meltQuote.Preimage = paymentStatus.Preimage
				err = m.db.UpdateMeltQuote(meltQuote.Id, paymentStatus.Preimage, nut05.Paid)
				if err != nil {
					errmsg := fmt.Sprintf("error updating melt quote state: %v", err)
					return storage.MeltQuote{}, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
				}
				return meltQuote, change, nil
			}
		}
	}

	return meltQuote, nil, nil
}

// if a pair of mint and melt quotes have the same invoice,
// settle them internally and update in db
func (m *Mint) settleQuotesInternally(
	mintQuote storage.MintQuote,
	meltQuote storage.MeltQuote,
) (storage.MeltQuote, error) {
	// need to get the invoice from the backend first to get the preimage
	invoice, err := m.lightningClient.InvoiceStatus(mintQuote.PaymentHash)
	if err != nil {
		errmsg := fmt.Sprintf("error getting invoice status from lightning backend: %v", err)
		return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.LightningBackendErrCode)
	}

	meltQuote.State = nut05.Paid
	meltQuote.Preimage = invoice.Preimage
	err = m.db.UpdateMeltQuote(meltQuote.Id, meltQuote.Preimage, meltQuote.State)
	if err != nil {
		errmsg := fmt.Sprintf("error updating melt quote state: %v", err)
		return storage.MeltQuote{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	// mark mint quote request as paid — Unpaid->Paid ONLY (conditional):
	// a concurrent minter may have claimed it already; never resurrect
	// Paid over Pending/Issued (double-issuance guard, cashu-audit #59).
	mintQuote.State = nut04.Paid
	if _, err := m.db.UpdateMintQuoteStateCAS(mintQuote.Id, nut04.Unpaid, nut04.Paid); err != nil {
		m.logErrorf("could not mark mint quote '%v' PAID during internal settle: %v", mintQuote.Id, err)
	}
	jsonQuote, _ := json.Marshal(mintQuote)
	m.publisher.Publish(BOLT11_MINT_QUOTE_TOPIC, jsonQuote)

	return meltQuote, nil
}

// settleProofs will remove the proofs from the pending table
// and mark them as spent by adding them to the used proofs table
func (m *Mint) settleProofs(Ys []string, proofs cashu.Proofs) error {
	if err := m.db.SettleProofs(Ys, proofs); err != nil {
		errmsg := fmt.Sprintf("error settling proofs (pending->used must be atomic): %v", err)
		return cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}
	m.publishProofsStateChanges(proofs, nut07.Spent)

	return nil
}

func (m *Mint) ProofsStateCheck(Ys []string) ([]nut07.ProofState, error) {
	// status of proofs that are pending due to an in-flight lightning payment
	// could have changed so need to check with the lightning backend the status
	// of the payment
	pendingProofs, err := m.db.GetPendingProofs(Ys)
	if err != nil {
		errmsg := fmt.Sprintf("could not get pending proofs from db: %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	pendingQuotes := make(map[string]bool)
	for _, pendingProof := range pendingProofs {
		if !pendingQuotes[pendingProof.MeltQuoteId] {
			pendingQuotes[pendingProof.MeltQuoteId] = true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	m.logDebugf("checking if status of pending proofs has changed")
	for quoteId := range pendingQuotes {
		// GetMeltQuoteState will check the status of the quote
		// and update the db tables (pending proofs, used proofs) appropriately
		// if the status has changed
		_, err := m.GetMeltQuoteState(ctx, quoteId)
		if err != nil {
			return nil, err
		}
	}

	// get pending proofs from db since they could have changed
	// from checking the quote state
	pendingProofs, err = m.db.GetPendingProofs(Ys)
	if err != nil {
		errmsg := fmt.Sprintf("could not get pending proofs from db: %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	usedProofs, err := m.db.GetProofsUsed(Ys)
	if err != nil {
		errmsg := fmt.Sprintf("could not get used proofs from db: %v", err)
		return nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	proofStates := make([]nut07.ProofState, len(Ys))
	for i, y := range Ys {
		state := nut07.Unspent

		YSpentIdx := slices.IndexFunc(usedProofs, func(proof storage.DBProof) bool {
			return proof.Y == y
		})
		YPendingIdx := slices.IndexFunc(pendingProofs, func(proof storage.DBProof) bool {
			return proof.Y == y
		})

		var witness string
		if YSpentIdx >= 0 {
			state = nut07.Spent
			witness = usedProofs[YSpentIdx].Witness
		} else if YPendingIdx >= 0 {
			state = nut07.Pending
			witness = pendingProofs[YPendingIdx].Witness
		}

		proofStates[i] = nut07.ProofState{Y: y, State: state, Witness: witness}
	}

	return proofStates, nil
}

func (m *Mint) RestoreSignatures(blindedMessages cashu.BlindedMessages) (cashu.BlindedMessages, cashu.BlindedSignatures, error) {
	outputs := make(cashu.BlindedMessages, 0, len(blindedMessages))
	signatures := make(cashu.BlindedSignatures, 0, len(blindedMessages))

	for _, bm := range blindedMessages {
		sig, err := m.db.GetBlindSignature(bm.B_)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		} else if err != nil {
			errmsg := fmt.Sprintf("could not get signature from db: %v", err)
			return nil, nil, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}

		outputs = append(outputs, bm)
		signatures = append(signatures, sig)
	}

	return outputs, signatures, nil
}

func (m *Mint) verifyProofs(proofs cashu.Proofs, Ys []string) error {
	if len(proofs) == 0 {
		return cashu.NoProofsProvided
	}

	// check if proofs are either pending or already spent
	pendingProofs, err := m.db.GetPendingProofs(Ys)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			errmsg := fmt.Sprintf("could not get pending proofs from db: %v", err)
			return cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}
	}
	if len(pendingProofs) != 0 {
		return cashu.ProofPendingErr
	}

	usedProofs, err := m.db.GetProofsUsed(Ys)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			errmsg := fmt.Sprintf("could not get used proofs from db: %v", err)
			return cashu.BuildCashuError(errmsg, cashu.DBErrCode)
		}
	}
	if len(usedProofs) != 0 {
		return cashu.ProofAlreadyUsedErr
	}

	// check duplicte proofs
	if cashu.CheckDuplicateProofs(proofs) {
		return cashu.DuplicateProofs
	}

	for _, proof := range proofs {
		if len(proof.Secret) > cashu.MAX_SECRET_LENGTH {
			return cashu.SecretTooLongErr
		}

		// check that id in the proof matches id of any
		// of the mint's keyset
		var k *secp256k1.PrivateKey
		if keyset, ok := m.keysets[proof.Id]; !ok {
			return cashu.UnknownKeysetErr
		} else {
			if key, ok := keyset.Keys[proof.Amount]; ok {
				k = key.PrivateKey
			} else {
				return cashu.InvalidProofErr
			}
		}

		// if P2PK locked proof, verify valid witness
		nut10Secret, err := nut10.DeserializeSecret(proof.Secret)
		if err == nil {
			if nut11.IsSigAll(nut10Secret) {
				// SIG_ALL witnesses (P2PK and HTLC alike) live only in the
				// FIRST input and sign the aggregated transaction message —
				// verified as a group by the caller (verifySigAllGroup),
				// not per-input here.
				m.logDebugf("SIG_ALL input — deferring to group verification")
			} else if nut10Secret.Kind == nut10.P2PK {
				if err := nut11.VerifyP2PKLockedProof(proof, nut10Secret); err != nil {
					return err
				}
				m.logDebugf("verified P2PK locked proof")
			} else if nut10Secret.Kind == nut10.HTLC {
				if err := nut14.VerifyHTLCProof(proof, nut10Secret); err != nil {
					return err
				}
				m.logDebugf("verified HTLC proof")
			}
		}

		Cbytes, err := hex.DecodeString(proof.C)
		if err != nil {
			errmsg := fmt.Sprintf("invalid C: %v", err)
			return cashu.BuildCashuError(errmsg, cashu.StandardErrCode)
		}

		C, err := secp256k1.ParsePubKey(Cbytes)
		if err != nil {
			return cashu.BuildCashuError(err.Error(), cashu.StandardErrCode)
		}

		if !crypto.Verify(proof.Secret, k, C) {
			return cashu.InvalidProofErr
		}
	}
	return nil
}

// verifyBlindedMessages verified per-output witnesses on BlindedMessages —
// a NON-SPEC construction gonuts invented (witnesses are defined on Proofs
// only; SIG_ALL signs the aggregated transaction message in the FIRST
// input). DEPRECATED and no longer called since the tollgate #809
// alignment: kept one release for reference, removed next cut. Output
// witnesses carried by requests are ignored by the mint.
func verifyBlindedMessages(proofs cashu.Proofs, blindedMessages cashu.BlindedMessages) error {
	secret, err := nut10.DeserializeSecret(proofs[0].Secret)
	if err != nil {
		return cashu.BuildCashuError(err.Error(), cashu.StandardErrCode)
	}

	// pubkeys will hold list of public keys that can sign
	pubkeys, err := nut11.PublicKeys(secret)
	if err != nil {
		return err
	}

	signaturesRequired := 1
	p2pkTags, err := nut11.ParseP2PKTags(secret.Data.Tags)
	if err != nil {
		return err
	}
	if p2pkTags.NSigs > 0 {
		signaturesRequired = p2pkTags.NSigs
	}

	// Check that the conditions across all proofs are the same
	for _, proof := range proofs {
		secret, err := nut10.DeserializeSecret(proof.Secret)
		if err != nil {
			return cashu.BuildCashuError(err.Error(), cashu.StandardErrCode)
		}
		// all flags need to be SIG_ALL
		if !nut11.IsSigAll(secret) {
			return nut11.AllSigAllFlagsErr
		}

		currentSignaturesRequired := 1
		p2pkTags, err := nut11.ParseP2PKTags(secret.Data.Tags)
		if err != nil {
			return err
		}
		if p2pkTags.NSigs > 0 {
			currentSignaturesRequired = p2pkTags.NSigs
		}

		currentKeys, err := nut11.PublicKeys(secret)
		if err != nil {
			return err
		}

		// list of valid keys should be the same
		// across all proofs
		if !reflect.DeepEqual(pubkeys, currentKeys) {
			return nut11.SigAllKeysMustBeEqualErr
		}

		// all n_sigs must be same
		if signaturesRequired != currentSignaturesRequired {
			return nut11.NSigsMustBeEqualErr
		}
	}

	for _, bm := range blindedMessages {
		B_bytes, err := hex.DecodeString(bm.B_)
		if err != nil {
			return cashu.BuildCashuError(err.Error(), cashu.StandardErrCode)
		}
		hash := sha256.Sum256(B_bytes)

		var signatures []string
		switch secret.Kind {
		case nut10.P2PK:
			var witness nut11.P2PKWitness
			if err := json.Unmarshal([]byte(bm.Witness), &witness); err != nil {
				return nut11.InvalidWitness
			}
			signatures = witness.Signatures
		case nut10.HTLC:
			var witness nut14.HTLCWitness
			if err := json.Unmarshal([]byte(bm.Witness), &witness); err != nil {
				return nut11.InvalidWitness
			}

			// verify valid preimage
			preimageBytes, err := hex.DecodeString(witness.Preimage)
			if err != nil {
				return nut14.InvalidPreimageErr
			}
			hashBytes := sha256.Sum256(preimageBytes)
			hash := hex.EncodeToString(hashBytes[:])

			if len(secret.Data.Data) != 64 {
				return nut14.InvalidHashErr
			}
			if hash != secret.Data.Data {
				return nut14.InvalidPreimageErr
			}
			signatures = witness.Signatures
		default:
			return nut11.InvalidKindErr
		}

		if nut11.DuplicateSignatures(signatures) {
			return nut11.DuplicateSignaturesErr
		}
		if !nut11.HasValidSignatures(hash[:], signatures, signaturesRequired, pubkeys) {
			return nut11.NotEnoughSignaturesErr
		}
	}

	return nil
}

// signBlindedMessages will sign the blindedMessages and return the blindedSignatures
func (m *Mint) signBlindedMessages(blindedMessages cashu.BlindedMessages) (cashu.BlindedSignatures, error) {
	blindedSignatures := make(cashu.BlindedSignatures, len(blindedMessages))

	for i, msg := range blindedMessages {
		if _, ok := m.keysets[msg.Id]; !ok {
			return nil, cashu.UnknownKeysetErr
		}
		var k *secp256k1.PrivateKey
		if msg.Id != m.activeKeyset.Id {
			return nil, cashu.InactiveKeysetSignatureRequest
		} else {
			if key, ok := m.activeKeyset.Keys[msg.Amount]; ok {
				k = key.PrivateKey
			} else {
				return nil, cashu.InvalidBlindedMessageAmount
			}
		}

		B_bytes, err := hex.DecodeString(msg.B_)
		if err != nil {
			errmsg := fmt.Sprintf("invalid B_: %v", err)
			return nil, cashu.BuildCashuError(errmsg, cashu.StandardErrCode)
		}
		B_, err := btcec.ParsePubKey(B_bytes)
		if err != nil {
			return nil, cashu.BuildCashuError(err.Error(), cashu.StandardErrCode)
		}

		C_ := crypto.SignBlindedMessage(B_, k)
		C_hex := hex.EncodeToString(C_.SerializeCompressed())

		// DLEQ proof
		e, s := crypto.GenerateDLEQ(k, B_, C_)

		blindedSignature := cashu.BlindedSignature{
			Amount: msg.Amount,
			C_:     C_hex,
			Id:     m.activeKeyset.Id,
			DLEQ: &cashu.DLEQProof{
				E: hex.EncodeToString(e.Serialize()),
				S: hex.EncodeToString(s.Serialize()),
			},
		}
		blindedSignatures[i] = blindedSignature
	}

	return blindedSignatures, nil
}

// validateMeltChangeOutputs validates a melt request's NUT-08 blank
// outputs BEFORE the quote is claimed — everything signing needs later
// is checked here, so no post-payment state change can fail on request
// shape (fund-safety: local validation precedes irreversible operations).
//
// NUT-08: the outputs' amounts are IGNORED ("Alice MUST set the amount
// of each blank output to 0, and Bob MUST ignore it, imprinting the
// amount himself") — wallets legitimately send nonzero amounts here
// (the reference families accept them; the conformance corpus carries
// melts that do), and the mint imprints its own amounts at signing time
// regardless. The keyset MUST be one the mint can sign — the active
// keyset (signBlindedMessages refuses inactive ones); B_ values must be
// parseable curve points and unique.
func (m *Mint) validateMeltChangeOutputs(outputs cashu.BlindedMessages) error {
	if len(outputs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if output.Id != m.activeKeyset.Id {
			return cashu.InactiveKeysetSignatureRequest
		}
		B_bytes, err := hex.DecodeString(output.B_)
		if err != nil {
			return cashu.BuildCashuError(fmt.Sprintf("invalid B_: %v", err), cashu.StandardErrCode)
		}
		if _, err := btcec.ParsePubKey(B_bytes); err != nil {
			return cashu.BuildCashuError(err.Error(), cashu.StandardErrCode)
		}
		if _, dup := seen[output.B_]; dup {
			return cashu.DuplicateOutputs
		}
		seen[output.B_] = struct{}{}
	}
	return nil
}

// meltChangeTarget is the NUT-08 overpay the mint owes back as change:
//
//	change = inputs − input_fees − invoice_amount − fee_spent
//
// fee_spent is what the Lightning backend actually charged. Backends
// that cannot report it (FeeSpentKnown=false) are charged the FULL fee
// reserve: an unaccounted fee is never returned as change (operator
// fund-safety) — only the over-funding beyond amount+reserve+fees is
// returned for such backends. Saturating: a backend that overspent the
// reserve yields no change, never a negative one.
func meltChangeTarget(proofsAmount, inputFees uint64, quote storage.MeltQuote, payment lightning.PaymentStatus) uint64 {
	feeSpent := quote.FeeReserve
	if payment.FeeSpentKnown {
		feeSpent = payment.FeeSpent
	}
	spent := quote.Amount + feeSpent
	if proofsAmount <= inputFees+spent {
		return 0
	}
	return proofsAmount - inputFees - spent
}

// splitChangeAmounts decomposes the change target into denominations the
// active keyset can sign, largest first (binary decomposition for the
// canonical 2^n keysets). A remainder no denomination covers (targets
// exceeding the keyset's representable span) is returned as the
// shortfall — it stays with the mint and must be logged by the caller.
func (m *Mint) splitChangeAmounts(target uint64) (amounts []uint64, shortfall uint64) {
	amounts = make([]uint64, 0, 8)
	for target > 0 {
		best := uint64(0)
		for amount := range m.activeKeyset.Keys {
			if amount > best && amount <= target {
				best = amount
			}
		}
		if best == 0 {
			// no denomination fits the remainder (keyset floor > 1 or
			// remainder below the smallest key): cannot be returned
			return amounts, target
		}
		amounts = append(amounts, best)
		target -= best
	}
	return amounts, 0
}

// signMeltChange signs and durably records the NUT-08 change for a quote
// whose payment succeeded. Idempotent: if the signatures are already
// persisted (a retry or a poll-path reconciliation after a crash between
// signing and the Paid write), the stored set replays in output order —
// the #59 discipline: persist signatures BEFORE the quote's Paid write,
// so every crash point leaves the change recoverable.
//
// The blank outputs come from the journal (SaveMeltChangeOutputs at claim
// time), never from this call's arguments — recovery paths (the poll
// reconciler) no longer hold the original request.
func (m *Mint) signMeltChange(
	quote storage.MeltQuote,
	proofs cashu.Proofs,
	proofsAmount, inputFees uint64,
	payment lightning.PaymentStatus,
) (cashu.BlindedSignatures, error) {
	outputs, err := m.db.GetMeltChangeOutputs(quote.Id)
	if err != nil {
		return nil, cashu.BuildCashuError(fmt.Sprintf("could not load journaled melt outputs: %v", err), cashu.DBErrCode)
	}
	if len(outputs) == 0 {
		// no blank outputs sent: NUT-08 change is simply not claimed —
		// the overpay stays with the mint (spec: change only if outputs
		// were provided)
		return nil, nil
	}

	// replay head: signatures already persisted (SaveBlindSignatures is
	// one transaction, so the set is all-or-nothing)
	stored := make(cashu.BlindedSignatures, 0, len(outputs))
	for _, output := range outputs {
		sig, err := m.db.GetBlindSignature(output.B_)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				stored = nil
				break
			}
			return nil, cashu.BuildCashuError(fmt.Sprintf("could not load stored change signature: %v", err), cashu.DBErrCode)
		}
		stored = append(stored, sig)
	}
	if stored != nil {
		m.logDebugf("replaying %d stored change signatures for melt quote '%v'", len(stored), quote.Id)
		return stored, nil
	}

	target := meltChangeTarget(proofsAmount, inputFees, quote, payment)
	if target == 0 {
		return nil, nil
	}
	amounts, shortfall := m.splitChangeAmounts(target)
	if len(amounts) > len(outputs) {
		// more denominations than blank outputs: keep the LARGEST
		// amounts (descending already) — the smallest remainder stays
		// with the mint, mirroring the reference implementations
		amounts = amounts[:len(outputs)]
	}
	if shortfall > 0 {
		m.logInfof("melt quote '%v': %v sats of change exceed the keyset's representable denominations and stay with the mint", quote.Id, shortfall)
	}
	if len(amounts) == 0 {
		return nil, nil
	}

	// imprint the change amounts onto the FIRST outputs in request order
	// (NUT-08: signatures are returned in the blank outputs' order, value
	// signatures only — zero-value ones omitted)
	toSign := make(cashu.BlindedMessages, len(amounts))
	for i, amount := range amounts {
		toSign[i] = outputs[i]
		toSign[i].Amount = amount
	}

	signatures, err := m.signBlindedMessages(toSign)
	if err != nil {
		return nil, err
	}

	B_s := make([]string, len(toSign))
	for i, bm := range toSign {
		B_s[i] = bm.B_
	}
	if err := m.db.SaveBlindSignatures(B_s, signatures); err != nil {
		return nil, cashu.BuildCashuError(fmt.Sprintf("could not persist change signatures: %v", err), cashu.DBErrCode)
	}
	m.logInfof("melt quote '%v': returning %v sats NUT-08 change across %d outputs (fee_spent=%v known=%v)",
		quote.Id, signatures.Amount(), len(signatures), payment.FeeSpent, payment.FeeSpentKnown)
	return signatures, nil
}

// MeltQuoteChange returns the stored NUT-08 change signatures for a
// quote in blank-output order — for the melt-quote state endpoint, so a
// wallet that missed the melt response can still collect its change.
func (m *Mint) MeltQuoteChange(quoteId string) cashu.BlindedSignatures {
	outputs, err := m.db.GetMeltChangeOutputs(quoteId)
	if err != nil || len(outputs) == 0 {
		return nil
	}
	signatures := make(cashu.BlindedSignatures, 0, len(outputs))
	for _, output := range outputs {
		sig, err := m.db.GetBlindSignature(output.B_)
		if err != nil {
			return nil
		}
		signatures = append(signatures, sig)
	}
	return signatures
}

// requestMatchesStoredOutputs reports whether a re-POSTed melt request's
// blank outputs are exactly the journaled set for the quote (same order)
// — the identity check for replaying a PAID quote's change (the #497
// byte-identity invariant, mint side: an identical re-POST is answered
// idempotently even after the NUT-19 response cache is gone).
func requestMatchesStoredOutputs(requestOutputs cashu.BlindedMessages, quoteId string, db storage.MintDB) bool {
	if len(requestOutputs) == 0 {
		return false
	}
	stored, err := db.GetMeltChangeOutputs(quoteId)
	if err != nil || len(stored) != len(requestOutputs) {
		return false
	}
	for i := range stored {
		if stored[i].B_ != requestOutputs[i].B_ || stored[i].Id != requestOutputs[i].Id {
			return false
		}
	}
	return true
}

// requestInvoice requests an invoice from the Lightning backend for the given amount
func (m *Mint) requestInvoice(amount uint64) (*lightning.Invoice, error) {
	invoice, err := m.lightningClient.CreateInvoice(amount)
	if err != nil {
		return nil, err
	}
	return &invoice, nil
}

func (m *Mint) TransactionFees(inputs cashu.Proofs) uint {
	var fees uint = 0
	for _, proof := range inputs {
		// note: not checking that proof id is from valid keyset
		// because already doing that in call to verifyProofs
		fees += m.keysets[proof.Id].InputFeePpk
	}
	return (fees + 999) / 1000
}

func (m *Mint) ListKeysets() nut02.GetKeysetsResponse {
	keysets := make([]nut02.Keyset, len(m.keysets))
	i := 0
	for _, keyset := range m.keysets {
		keysetRes := nut02.Keyset{
			Id:          keyset.Id,
			Unit:        keyset.Unit,
			Active:      keyset.Active,
			InputFeePpk: keyset.InputFeePpk,
		}
		keysets[i] = keysetRes
		i++
	}
	return nut02.GetKeysetsResponse{Keysets: keysets}
}

func (m *Mint) GetActiveKeyset() nut01.Keyset {
	return nut01.Keyset{
		Id:   m.activeKeyset.Id,
		Unit: m.activeKeyset.Unit,
		Keys: m.activeKeyset.PublicKeys(),
	}
}

func (m *Mint) GetKeysetById(id string) (nut01.Keyset, error) {
	keyset, ok := m.keysets[id]
	if !ok {
		return nut01.Keyset{}, cashu.UnknownKeysetErr
	}
	return nut01.Keyset{
		Id:   keyset.Id,
		Unit: keyset.Unit,
		Keys: keyset.PublicKeys(),
	}, nil
}

func (m *Mint) RotateKeyset(fee uint) (*nut02.Keyset, error) {
	seed, err := m.db.GetSeed()
	if err != nil {
		return nil, err
	}

	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}

	currentActiveKeyset := m.activeKeyset

	newDerivationPathIdx := currentActiveKeyset.DerivationPathIdx + 1
	newKeyset, err := crypto.GenerateKeyset(
		master,
		newDerivationPathIdx,
		fee,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating new keyset: %v", err)
	}
	m.logInfof("setting keyset '%v' to inactive", currentActiveKeyset.Id)

	// deactivate previous one and change it in db
	currentActiveKeyset.Active = false
	m.keysets[currentActiveKeyset.Id] = *currentActiveKeyset
	if err := m.db.UpdateKeysetActive(currentActiveKeyset.Id, false); err != nil {
		return nil, fmt.Errorf("could not update active state of keyset in db: %v", err)
	}
	m.activeKeyset = newKeyset

	m.keysets[newKeyset.Id] = *newKeyset

	hexseed := hex.EncodeToString(seed)
	activeDbKeyset := storage.DBKeyset{
		Id:                newKeyset.Id,
		Unit:              newKeyset.Unit,
		Active:            true,
		Seed:              hexseed,
		DerivationPathIdx: newKeyset.DerivationPathIdx,
		InputFeePpk:       newKeyset.InputFeePpk,
	}
	if err := m.db.SaveKeyset(activeDbKeyset); err != nil {
		return nil, fmt.Errorf("error saving new active keyset: %v", err)
	}
	m.logInfof("setting new keyset %v to active", newKeyset.Id)

	return &nut02.Keyset{
		Id:          newKeyset.Id,
		Unit:        newKeyset.Unit,
		Active:      newKeyset.Active,
		InputFeePpk: newKeyset.InputFeePpk,
	}, nil
}

func (m *Mint) IssuedEcash() (map[string]uint64, error) {
	return m.db.GetIssuedEcash()
}

func (m *Mint) RedeemedEcash() (map[string]uint64, error) {
	return m.db.GetRedeemedEcash()
}

func (m *Mint) TotalBalance() (uint64, error) {
	ecashIssued, err := m.db.GetIssuedEcash()
	if err != nil {
		return 0, err
	}
	var totalIssued uint64
	for _, issuedForKeyset := range ecashIssued {
		totalIssued += issuedForKeyset
	}

	ecashRedeemed, err := m.db.GetRedeemedEcash()
	if err != nil {
		return 0, err
	}

	var totalRedeemed uint64
	for _, redeemedForKeyset := range ecashRedeemed {
		totalRedeemed += redeemedForKeyset
	}

	return totalIssued - totalRedeemed, nil
}

func (m *Mint) SetMintInfo(mintInfo MintInfo) {
	nuts := nut06.Nuts{
		Nut04: nut06.NutSetting{
			Methods: []nut06.MethodSetting{
				{
					Method:    cashu.BOLT11_METHOD,
					Unit:      cashu.Sat.String(),
					MinAmount: m.limits.MintingSettings.MinAmount,
					MaxAmount: m.limits.MintingSettings.MaxAmount,
				},
			},
			Disabled: false,
		},
		Nut05: nut06.NutSetting{
			Methods: []nut06.MethodSetting{
				{
					Method:    cashu.BOLT11_METHOD,
					Unit:      cashu.Sat.String(),
					MinAmount: m.limits.MeltingSettings.MinAmount,
					MaxAmount: m.limits.MeltingSettings.MaxAmount,
				},
			},
			Disabled: false,
		},
		Nut07: nut06.Supported{Supported: true},
		// NUT-08: the mint returns overpaid fee reserve as change
		// signatures for the melt request's blank outputs
		Nut08: nut06.Supported{Supported: true},
		Nut09: nut06.Supported{Supported: true},
		Nut10: nut06.Supported{Supported: true},
		Nut11: nut06.Supported{Supported: true},
		Nut12: nut06.Supported{Supported: true},
		Nut14: nut06.Supported{Supported: true},
		Nut17: nut17.InfoSetting{
			Supported: []nut17.SupportedMethod{
				{
					Method: cashu.BOLT11_METHOD,
					Unit:   cashu.Sat.String(),
					Commands: []string{
						nut17.Bolt11MintQuote.String(),
					},
				},
			},
		},
		Nut19: nut06.Nut19Setting{
			TTL: CACHE_ITEM_TTL,
			CachedEndpoints: []nut06.CachedEndpoint{
				{Method: "POST", Path: "/v1/mint/bolt11"},
				{Method: "POST", Path: "/v1/swap"},
				{Method: "POST", Path: "/v1/melt/bolt11"},
			},
		},
		Nut20: nut06.Supported{Supported: true},
		Nut29: nut06.Nut29Setting{
			Supported:           true,
			MaxBatchSize:        BatchCheckLimit,
			MaxBatchOutputsSize: BatchMaxOutputs,
		},
	}

	if m.mppEnabled {
		nuts.Nut15 = &nut06.NutSetting{
			Methods: []nut06.MethodSetting{
				{Method: cashu.BOLT11_METHOD, Unit: cashu.Sat.String()},
			},
		}
	}

	info := nut06.MintInfo{
		Name:            mintInfo.Name,
		Version:         "gonuts/0.4.0",
		Description:     mintInfo.Description,
		LongDescription: mintInfo.LongDescription,
		Contact:         mintInfo.Contact,
		Motd:            mintInfo.Motd,
		IconURL:         mintInfo.IconURL,
		URLs:            mintInfo.URLs,
		Time:            time.Now().Unix(),
		Nuts:            nuts,
	}
	m.mintInfo = info
}

func (m *Mint) RetrieveMintInfo() (nut06.MintInfo, error) {
	seed, err := m.db.GetSeed()
	if err != nil {
		return nut06.MintInfo{}, err
	}
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nut06.MintInfo{}, err
	}
	publicKey, err := master.ECPubKey()
	if err != nil {
		return nut06.MintInfo{}, err
	}

	mintingDisabled := false
	mintBalance, err := m.TotalBalance()
	if err != nil {
		errmsg := fmt.Sprintf("error getting mint balance: %v", err)
		return nut06.MintInfo{}, cashu.BuildCashuError(errmsg, cashu.DBErrCode)
	}

	if m.limits.MaxBalance > 0 {
		if mintBalance >= m.limits.MaxBalance {
			mintingDisabled = true
		}
	}
	nut04 := m.mintInfo.Nuts.Nut04
	nut04.Disabled = mintingDisabled
	m.mintInfo.Nuts.Nut04 = nut04
	m.mintInfo.Pubkey = hex.EncodeToString(publicKey.SerializeCompressed())

	return m.mintInfo, nil
}

func (m *Mint) publishProofsStateChanges(proofs cashu.Proofs, state nut07.State) {
	proofStates := make([]nut07.ProofState, len(proofs))

	for i, proof := range proofs {
		Y, _ := crypto.HashToCurve([]byte(proof.Secret))
		Yhex := hex.EncodeToString(Y.SerializeCompressed())
		proofStates[i] = nut07.ProofState{Y: Yhex, State: state, Witness: proof.Witness}
	}

	stateResponse := nut07.PostCheckStateResponse{
		States: proofStates,
	}

	proofStatesJson, _ := json.Marshal(&stateResponse)
	m.publisher.Publish(PROOF_STATE_TOPIC, proofStatesJson)
}
