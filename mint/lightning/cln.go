package lightning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type CLNConfig struct {
	RestURL string
	Rune    string
}

type CLNClient struct {
	config CLNConfig
	client *http.Client
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

func SetupCLNClient(config CLNConfig) (*CLNClient, error) {
	return &CLNClient{
		config: config,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (cln *CLNClient) Post(ctx context.Context, url string, body interface{}) (*http.Response, error) {
	var jsonData []byte
	if body != nil {
		var err error
		jsonData, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Rune", cln.config.Rune)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return cln.client.Do(req)
}

func (cln *CLNClient) ConnectionStatus() error {
	resp, err := cln.Post(context.Background(), cln.config.RestURL+"/v1/getinfo", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("could not get connection status from CLN: %s", bodyBytes)
	}

	return nil
}

func (cln *CLNClient) CreateInvoice(amount uint64) (Invoice, error) {
	r := rand.New(rand.NewPCG(uint64(time.Now().UnixMicro()), uint64(time.Now().UnixMilli())))

	body := map[string]interface{}{
		"amount_msat": amount * 1000,
		"label":       time.Now().Unix() + int64(r.Int()),
		"description": "Cashu Lightning Invoice",
		"expiry":      InvoiceExpiryTime,
	}

	resp, err := cln.Post(context.Background(), cln.config.RestURL+"/v1/invoice", body)
	if err != nil {
		return Invoice{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Invoice{}, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errRes ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
			return Invoice{}, err
		}
		return Invoice{}, errors.New(errRes.Message)
	}

	var response struct {
		Bolt11      string `json:"bolt11"`
		PaymentHash string `json:"payment_hash"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return Invoice{}, err
	}

	return Invoice{
		PaymentRequest: response.Bolt11,
		PaymentHash:    response.PaymentHash,
		Amount:         amount,
		Expiry:         InvoiceExpiryTime,
	}, nil
}

func (cln *CLNClient) InvoiceStatus(hash string) (Invoice, error) {
	body := map[string]string{"payment_hash": hash}

	resp, err := cln.Post(context.Background(), cln.config.RestURL+"/v1/listinvoices", body)
	if err != nil {
		return Invoice{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Invoice{}, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errRes ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
			return Invoice{}, err
		}
		return Invoice{}, errors.New(errRes.Message)
	}

	var response struct {
		Invoices []struct {
			Bolt11      string `json:"bolt11"`
			PaymentHash string `json:"payment_hash"`
			Preimage    string `json:"payment_preimage"`
			AmountMsat  uint64 `json:"amount_msat"`
			Status      string `json:"status"`
			ExpiresAt   int64  `json:"expires_at"`
		} `json:"invoices"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return Invoice{}, err
	}
	if len(response.Invoices) == 0 {
		return Invoice{}, fmt.Errorf("invoice not found")
	}

	invoice := response.Invoices[0]
	invoiceSettled := invoice.Status == "paid"

	return Invoice{
		PaymentRequest: invoice.Bolt11,
		PaymentHash:    invoice.PaymentHash,
		Preimage:       invoice.Preimage,
		Settled:        invoiceSettled,
		Amount:         invoice.AmountMsat / 1000,
		Expiry:         uint64(invoice.ExpiresAt),
	}, nil
}

func (cln *CLNClient) SendPayment(ctx context.Context, request string, maxFee uint64) (PaymentStatus, error) {
	body := map[string]interface{}{
		"bolt11": request,
		"maxfee": maxFee * 1000,
	}

	resp, err := cln.Post(ctx, cln.config.RestURL+"/v1/pay", body)
	if err != nil {
		return PaymentStatus{PaymentStatus: Pending}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return PaymentStatus{PaymentStatus: Pending}, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errRes ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
			return PaymentStatus{PaymentStatus: Pending}, err
		}
		return PaymentStatus{PaymentStatus: Failed}, errors.New(errRes.Message)
	}

	var response struct {
		Preimage       string      `json:"payment_preimage"`
		Status         string      `json:"status"`
		AmountMsat     json.Number `json:"amount_msat"`
		AmountSentMsat json.Number `json:"amount_sent_msat"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return PaymentStatus{PaymentStatus: Pending}, err
	}

	status := Pending
	switch response.Status {
	case "complete":
		status = Succeeded
	case "pending":
		status = Pending
	case "failed":
		status = Failed
	}

	paymentStatus := PaymentStatus{
		Preimage:      response.Preimage,
		PaymentStatus: status,
	}
	// NUT-08: report the fee the payment actually spent so the melt path
	// can return the unused reserve as change. Only claimed on `complete`
	// — earlier states carry no final fee.
	if status == Succeeded {
		paymentStatus.FeeSpent, paymentStatus.FeeSpentKnown = clnFeeSpent(response.AmountMsat, response.AmountSentMsat)
	}
	return paymentStatus, nil
}

// clnFeeSpent derives the fee actually charged from a pay response's
// amount_msat/amount_sent_msat pair (both are REQUIRED to be present for
// a complete payment; a missing half reports unknown — the melt path then
// keeps the reserve rather than guessing). CLN sends msat integers as
// JSON numbers; tolerate string spellings defensively.
func clnFeeSpent(amount, amountSent json.Number) (uint64, bool) {
	if amount.String() == "" || amountSent.String() == "" {
		return 0, false
	}
	amountMsat, err := parseMsat(amount)
	if err != nil {
		return 0, false
	}
	sentMsat, err := parseMsat(amountSent)
	if err != nil || sentMsat < amountMsat {
		return 0, false
	}
	feeMsat := sentMsat - amountMsat
	// round the msat fee up to whole sats (the quote currency): never
	// under-report what was spent
	return (feeMsat + 999) / 1000, true
}

func parseMsat(n json.Number) (uint64, error) {
	s := strings.TrimSuffix(n.String(), "msat")
	return strconv.ParseUint(s, 10, 64)
}

func (cln *CLNClient) PayPartialAmount(
	ctx context.Context,
	request string,
	amountMsat uint64,
	maxFee uint64,
) (PaymentStatus, error) {
	body := map[string]interface{}{
		"bolt11":       request,
		"partial_msat": amountMsat,
		"maxfee":       maxFee * 1000,
		"retry_for":    30,
	}

	resp, err := cln.Post(ctx, cln.config.RestURL+"/v1/pay", body)
	if err != nil {
		return PaymentStatus{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return PaymentStatus{PaymentStatus: Pending}, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errRes ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
			return PaymentStatus{PaymentStatus: Pending}, err
		}
		return PaymentStatus{PaymentStatus: Failed}, errors.New(errRes.Message)
	}

	var response struct {
		Preimage       string      `json:"payment_preimage"`
		Status         string      `json:"status"`
		AmountMsat     json.Number `json:"amount_msat"`
		AmountSentMsat json.Number `json:"amount_sent_msat"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return PaymentStatus{}, fmt.Errorf("failed to parse response: %w", err)
	}

	status := Pending
	switch response.Status {
	case "complete":
		status = Succeeded
	case "pending":
		status = Pending
	case "failed":
		status = Failed
	}

	paymentStatus := PaymentStatus{
		Preimage:      response.Preimage,
		PaymentStatus: status,
	}
	if status == Succeeded {
		paymentStatus.FeeSpent, paymentStatus.FeeSpentKnown = clnFeeSpent(response.AmountMsat, response.AmountSentMsat)
	}
	return paymentStatus, nil
}

func (cln *CLNClient) OutgoingPaymentStatus(ctx context.Context, paymentHash string) (PaymentStatus, error) {
	body := map[string]string{"payment_hash": paymentHash}
	resp, err := cln.Post(ctx, cln.config.RestURL+"/v1/listpays", body)
	if err != nil {
		return PaymentStatus{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return PaymentStatus{PaymentStatus: Pending}, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errRes ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
			return PaymentStatus{PaymentStatus: Pending}, err
		}
		return PaymentStatus{PaymentStatus: Failed}, errors.New(errRes.Message)
	}

	var listPaysResponse struct {
		Pays []struct {
			PaymentHash     string      `json:"payment_hash"`
			Status          string      `json:"status"`
			AmountMsat      json.Number `json:"amount_msat"`
			AmountSentMsat  json.Number `json:"amount_sent_msat"`
			PaymentPreimage string      `json:"preimage,omitempty"`
		} `json:"pays"`
	}
	if err := json.Unmarshal(bodyBytes, &listPaysResponse); err != nil {
		return PaymentStatus{PaymentStatus: Pending}, err
	}
	if len(listPaysResponse.Pays) == 0 {
		return PaymentStatus{PaymentStatus: Failed}, OutgoingPaymentNotFound
	}

	payment := listPaysResponse.Pays[0]
	switch payment.Status {
	case "complete":
		feeSpent, feeKnown := clnFeeSpent(payment.AmountMsat, payment.AmountSentMsat)
		return PaymentStatus{
			PaymentStatus: Succeeded,
			Preimage:      payment.PaymentPreimage,
			FeeSpent:      feeSpent,
			FeeSpentKnown: feeKnown,
		}, nil
	case "failed":
		return PaymentStatus{PaymentStatus: Failed}, nil
	default:
		return PaymentStatus{PaymentStatus: Pending}, nil
	}
}

func (cln *CLNClient) FeeReserve(amount uint64) uint64 {
	return uint64(math.Ceil(float64(amount) * FeePercent))
}

func (cln *CLNClient) SubscribeInvoice(ctx context.Context, paymentHash string) (InvoiceSubscriptionClient, error) {
	body := map[string]string{"payment_hash": paymentHash}

	resp, err := cln.Post(context.Background(), cln.config.RestURL+"/v1/listinvoices", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errRes ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
			return nil, err
		}
		return nil, errors.New(errRes.Message)
	}

	var response struct {
		Invoices []struct {
			Label string `json:"label"`
		} `json:"invoices"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return nil, err
	}
	if len(response.Invoices) == 0 {
		return nil, fmt.Errorf("invoice not found")
	}

	sub := &CLNInvoiceSub{
		client:       &CLNClient{config: cln.config, client: &http.Client{}},
		ctx:          ctx,
		paymentHash:  paymentHash,
		invoiceLabel: response.Invoices[0].Label,
	}
	return sub, nil
}

type CLNInvoiceSub struct {
	client       *CLNClient
	ctx          context.Context
	paymentHash  string
	invoiceLabel string
}

func (clnSub *CLNInvoiceSub) Recv() (Invoice, error) {
	body := map[string]string{"label": clnSub.invoiceLabel}

	// NOTE: this call blocks untils the invoice is either paid or expired
	resp, err := clnSub.client.Post(clnSub.ctx, clnSub.client.config.RestURL+"/v1/waitinvoice", body)
	if err != nil {
		return Invoice{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Invoice{}, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		var errRes ErrorResponse
		if err := json.Unmarshal(bodyBytes, &errRes); err != nil {
			return Invoice{}, err
		}
		return Invoice{}, errors.New(errRes.Message)
	}

	var response struct {
		Status      string `json:"status"`
		PaymentHash string `json:"payment_hash"`
		Preimage    string `json:"payment_preimage"`
		AmountMsat  uint64 `json:"amount_msat"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return Invoice{}, err
	}

	inv := Invoice{
		PaymentHash: response.PaymentHash,
		Settled:     false,
		Amount:      response.AmountMsat / 1000,
	}

	if response.Status == "paid" {
		inv.Settled = true
		inv.Preimage = response.Preimage
	}

	return inv, nil
}
