package lightning

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/zpay32"
	decodepay "github.com/nbd-wtf/ln-decodepay"
)

const (
	InvoiceExpiry          = 3600
	FakePreimage           = "0000000000000000"
	FailPaymentDescription = "fail the payment"
)

type FakeBackendInvoice struct {
	PaymentRequest string
	PaymentHash    string
	Preimage       string
	Status         State
	Amount         uint64
	Expiry         uint64
	// AttemptedAt: when SendPayment/PayPartialAmount appended this outgoing
	// entry (settlement self-healing with PaymentDelay; zero = payee invoice).
	AttemptedAt int64
}

func (i *FakeBackendInvoice) ToInvoice() Invoice {
	return Invoice{
		PaymentRequest: i.PaymentRequest,
		PaymentHash:    i.PaymentHash,
		Preimage:       i.Preimage,
		Settled:        i.Status == Succeeded,
		Amount:         i.Amount,
		Expiry:         i.Expiry,
	}
}

type FakeBackend struct {
	Invoices     []FakeBackendInvoice
	PaymentDelay int64
	// FeeReserveSats: what FeeReserve reports for every amount — the
	// melt-quote fee_reserve knob (default 0 keeps existing fixtures
	// unchanged). Fake payments cost nothing, so every payment result
	// reports FeeSpentKnown with FeeSpent 0 — the whole reserve is
	// overpaid and must return as NUT-08 change.
	FeeReserveSats uint64
	// statePath: when set (LoadState), outgoing entries persist across
	// restarts — the kill/restart harness models a durable backend.
	statePath string
}

func (fb *FakeBackend) ConnectionStatus() error { return nil }

func (fb *FakeBackend) CreateInvoice(amount uint64) (Invoice, error) {
	req, preimage, paymentHash, err := CreateFakeInvoice(amount, false)
	if err != nil {
		return Invoice{}, err
	}

	fakeInvoice := FakeBackendInvoice{
		PaymentRequest: req,
		PaymentHash:    paymentHash,
		Preimage:       preimage,
		Status:         Succeeded,
		Amount:         amount,
		Expiry:         InvoiceExpiry,
	}
	fb.Invoices = append(fb.Invoices, fakeInvoice)

	return fakeInvoice.ToInvoice(), nil
}

func (fb *FakeBackend) InvoiceStatus(hash string) (Invoice, error) {
	invoiceIdx := slices.IndexFunc(fb.Invoices, func(i FakeBackendInvoice) bool {
		return i.PaymentHash == hash
	})
	if invoiceIdx == -1 {
		return Invoice{}, errors.New("invoice does not exist")
	}

	return fb.Invoices[invoiceIdx].ToInvoice(), nil
}

// LoadState restores outgoing-payment entries from a JSON file — models
// the backend as an independent durable process across mint restarts
// (the kill/restart harness's premise). Only attempted payments are
// persisted; payee invoices are reconstructed on demand.
func (fb *FakeBackend) LoadState(path string) error {
	fb.statePath = path
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &fb.Invoices)
}

// SaveState persists the invoice list (called on every append).
func (fb *FakeBackend) SaveState() error {
	if fb.statePath == "" {
		return nil
	}
	data, err := json.Marshal(fb.Invoices)
	if err != nil {
		return err
	}
	return os.WriteFile(fb.statePath, data, 0o644)
}

func (fb *FakeBackend) SendPayment(ctx context.Context, request string, maxFee uint64) (PaymentStatus, error) {
	invoice, err := decodepay.Decodepay(request)
	if err != nil {
		return PaymentStatus{}, fmt.Errorf("error decoding invoice: %v", err)
	}

	status := Succeeded
	if invoice.Description == FailPaymentDescription {
		status = Failed
	} else if fb.PaymentDelay > 0 {
		if time.Now().Unix() < int64(invoice.CreatedAt)+fb.PaymentDelay {
			status = Pending
		}
	}

	// the stored entry carries the attempt time so OutgoingPaymentStatus
	// can self-heal: with PaymentDelay set, a payment first seen PENDING is
	// reported SUCCEEDED once the delay elapses (mirrors a real backend
	// where the payment completes after the caller lost interest — the
	// kill/restart harness depends on this transition).
	outgoingPayment := FakeBackendInvoice{
		PaymentHash: invoice.PaymentHash,
		Preimage:    FakePreimage,
		Status:      status,
		Amount:      uint64(invoice.MSatoshi) * 1000,
		AttemptedAt: time.Now().Unix(),
	}
	fb.Invoices = append(fb.Invoices, outgoingPayment)
	fb.SaveState() // best-effort durability across restarts

	return PaymentStatus{
		Preimage:      FakePreimage,
		PaymentStatus: status,
		FeeSpent:      0,
		FeeSpentKnown: true,
	}, nil
}

func (fb *FakeBackend) PayPartialAmount(ctx context.Context, request string, amountMsat, maxFee uint64) (PaymentStatus, error) {
	invoice, err := decodepay.Decodepay(request)
	if err != nil {
		return PaymentStatus{}, fmt.Errorf("error decoding invoice: %v", err)
	}

	status := Succeeded
	if invoice.Description == FailPaymentDescription {
		status = Failed
	} else if fb.PaymentDelay > 0 {
		if time.Now().Unix() < int64(invoice.CreatedAt)+fb.PaymentDelay {
			status = Pending
		}
	}

	outgoingPayment := FakeBackendInvoice{
		PaymentHash: invoice.PaymentHash,
		Preimage:    FakePreimage,
		Status:      status,
		Amount:      uint64(invoice.MSatoshi) * 1000,
		AttemptedAt: time.Now().Unix(),
	}
	fb.Invoices = append(fb.Invoices, outgoingPayment)
	fb.SaveState() // best-effort durability across restarts

	return PaymentStatus{
		Preimage:      FakePreimage,
		PaymentStatus: status,
		FeeSpent:      0,
		FeeSpentKnown: true,
	}, nil
}

func (fb *FakeBackend) OutgoingPaymentStatus(ctx context.Context, hash string) (PaymentStatus, error) {
	invoiceIdx := slices.IndexFunc(fb.Invoices, func(i FakeBackendInvoice) bool {
		return i.PaymentHash == hash
	})
	if invoiceIdx == -1 {
		// the sentinel (mirrors the CLN/LND clients) — callers distinguish
		// "nothing was ever paid" from a transient status error
		return PaymentStatus{}, OutgoingPaymentNotFound
	}

	entry := fb.Invoices[invoiceIdx]
	status := entry.Status
	if status == Pending && fb.PaymentDelay > 0 && entry.AttemptedAt > 0 &&
		time.Now().Unix() >= entry.AttemptedAt+fb.PaymentDelay {
		// self-heal: the payment attempt settled after the delay
		status = Succeeded
	}
	return PaymentStatus{
		Preimage:      FakePreimage,
		PaymentStatus: status,
		FeeSpent:      0,
		FeeSpentKnown: true,
	}, nil
}

func (fb *FakeBackend) FeeReserve(amount uint64) uint64 {
	return fb.FeeReserveSats
}

func (fb *FakeBackend) SubscribeInvoice(ctx context.Context, paymentHash string) (InvoiceSubscriptionClient, error) {
	return &FakeInvoiceSub{
		paymentHash: paymentHash,
		fb:          fb,
	}, nil
}

type FakeInvoiceSub struct {
	paymentHash string
	fb          *FakeBackend
}

func (fakeSub *FakeInvoiceSub) Recv() (Invoice, error) {
	invoiceIdx := slices.IndexFunc(fakeSub.fb.Invoices, func(i FakeBackendInvoice) bool {
		return i.PaymentHash == fakeSub.paymentHash
	})
	if invoiceIdx == -1 {
		return Invoice{}, errors.New("invoice does not exist")
	}

	return fakeSub.fb.Invoices[invoiceIdx].ToInvoice(), nil
}

func (fb *FakeBackend) SetInvoiceStatus(hash string, status State) {
	invoiceIdx := slices.IndexFunc(fb.Invoices, func(i FakeBackendInvoice) bool {
		return i.PaymentHash == hash
	})
	if invoiceIdx == -1 {
		return
	}
	fb.Invoices[invoiceIdx].Status = status
}

func CreateFakeInvoice(amount uint64, failPayment bool) (string, string, string, error) {
	var random [32]byte
	_, err := rand.Read(random[:])
	if err != nil {
		return "", "", "", err
	}
	preimage := hex.EncodeToString(random[:])
	paymentHash := sha256.Sum256(random[:])
	hash := hex.EncodeToString(paymentHash[:])

	description := "test"
	if failPayment {
		description = FailPaymentDescription
	}

	invoice, err := zpay32.NewInvoice(
		&chaincfg.SigNetParams,
		paymentHash,
		time.Now(),
		zpay32.Amount(lnwire.MilliSatoshi(amount*1000)),
		zpay32.Description(description),
	)
	if err != nil {
		return "", "", "", err
	}

	invoiceStr, err := invoice.Encode(zpay32.MessageSigner{
		SignCompact: func(msg []byte) ([]byte, error) {
			key, err := secp256k1.GeneratePrivateKey()
			if err != nil {
				return []byte{}, err
			}
			return ecdsa.SignCompact(key, msg, true), nil
		},
	})
	if err != nil {
		return "", "", "", err
	}

	return invoiceStr, preimage, hash, nil
}
