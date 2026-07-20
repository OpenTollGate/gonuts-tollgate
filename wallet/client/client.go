package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/Origami74/gonuts-tollgate/cashu"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut01"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut02"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut03"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut04"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut05"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut06"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut07"
	"github.com/Origami74/gonuts-tollgate/cashu/nuts/nut09"
)


const (
	maxRetries      = 4
	baseBackoff     = 500 * time.Millisecond
	maxBackoffDur   = 30 * time.Second
	jitterRange     = 250 * time.Millisecond
)

type RateLimitError struct {
	HTTPStatus   int
	RetryAfterMs int
	MintURL      string
	Body         string
}

func (e *RateLimitError) Error() string {
	if e.RetryAfterMs > 0 {
		return fmt.Sprintf("mint %s rate limited (HTTP %d), retry after %dms", e.MintURL, e.HTTPStatus, e.RetryAfterMs)
	}
	return fmt.Sprintf("mint %s rate limited (HTTP %d)", e.MintURL, e.HTTPStatus)
}

func parseRetryAfter(resp *http.Response) int {
	header := resp.Header.Get("Retry-After")
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds >= 0 {
		return seconds * 1000
	}
	return 0
}

func backoffDuration(attempt int, retryAfterMs int) time.Duration {
	if retryAfterMs > 0 {
		return time.Duration(retryAfterMs) * time.Millisecond
	}
	d := baseBackoff
	for i := 0; i < attempt; i++ {
		d *= 2
		if d > maxBackoffDur {
			d = maxBackoffDur
		}
	}
	return d + time.Duration(rand.Int63n(int64(jitterRange)))
}

func GetMintInfo(mintURL string) (*nut06.MintInfo, error) {
	resp, err := get(mintURL + "/v1/info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var mintInfo nut06.MintInfo
	if err := json.Unmarshal(body, &mintInfo); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &mintInfo, nil
}

func GetActiveKeysets(mintURL string) (*nut01.GetKeysResponse, error) {
	resp, err := get(mintURL + "/v1/keys")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var keysetRes nut01.GetKeysResponse
	if err := json.Unmarshal(body, &keysetRes); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &keysetRes, nil
}

func GetAllKeysets(mintURL string) (*nut02.GetKeysetsResponse, error) {
	resp, err := get(mintURL + "/v1/keysets")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var keysetsRes nut02.GetKeysetsResponse
	if err := json.Unmarshal(body, &keysetsRes); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &keysetsRes, nil
}

func GetKeysetById(mintURL, id string) (*nut01.GetKeysResponse, error) {
	resp, err := get(mintURL + "/v1/keys/" + id)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var keysetRes nut01.GetKeysResponse
	if err := json.Unmarshal(body, &keysetRes); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &keysetRes, nil
}

func PostMintQuoteBolt11(mintURL string, mintQuoteRequest nut04.PostMintQuoteBolt11Request) (
	*nut04.PostMintQuoteBolt11Response, error) {
	requestBody, err := json.Marshal(mintQuoteRequest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %v", err)
	}

	resp, err := httpPost(mintURL+"/v1/mint/quote/bolt11", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var reqMintResponse nut04.PostMintQuoteBolt11Response
	if err := json.Unmarshal(body, &reqMintResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &reqMintResponse, nil
}

func GetMintQuoteState(mintURL, quoteId string) (*nut04.PostMintQuoteBolt11Response, error) {
	resp, err := get(mintURL + "/v1/mint/quote/bolt11/" + quoteId)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var mintQuoteResponse nut04.PostMintQuoteBolt11Response
	if err := json.Unmarshal(body, &mintQuoteResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &mintQuoteResponse, nil
}

func PostMintBolt11(mintURL string, mintRequest nut04.PostMintBolt11Request) (
	*nut04.PostMintBolt11Response, error) {
	requestBody, err := json.Marshal(mintRequest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %v", err)
	}

	resp, err := httpPost(mintURL+"/v1/mint/bolt11", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var reqMintResponse nut04.PostMintBolt11Response
	if err := json.Unmarshal(body, &reqMintResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &reqMintResponse, nil
}

func PostSwap(mintURL string, swapRequest nut03.PostSwapRequest) (*nut03.PostSwapResponse, error) {
	requestBody, err := json.Marshal(swapRequest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %v", err)
	}

	resp, err := httpPost(mintURL+"/v1/swap", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var swapResponse nut03.PostSwapResponse
	if err := json.Unmarshal(body, &swapResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &swapResponse, nil
}

func PostMeltQuoteBolt11(mintURL string, meltQuoteRequest nut05.PostMeltQuoteBolt11Request) (
	*nut05.PostMeltQuoteBolt11Response, error) {

	requestBody, err := json.Marshal(meltQuoteRequest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %v", err)
	}

	resp, err := httpPost(mintURL+"/v1/melt/quote/bolt11", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var meltQuoteResponse nut05.PostMeltQuoteBolt11Response
	if err := json.Unmarshal(body, &meltQuoteResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &meltQuoteResponse, nil
}

func GetMeltQuoteState(mintURL, quoteId string) (*nut05.PostMeltQuoteBolt11Response, error) {
	resp, err := get(mintURL + "/v1/melt/quote/bolt11/" + quoteId)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var meltQuoteResponse nut05.PostMeltQuoteBolt11Response
	if err := json.Unmarshal(body, &meltQuoteResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &meltQuoteResponse, nil
}

func PostMeltBolt11(mintURL string, meltRequest nut05.PostMeltBolt11Request) (
	*nut05.PostMeltQuoteBolt11Response, error) {

	requestBody, err := json.Marshal(meltRequest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %v", err)
	}

	resp, err := httpPost(mintURL+"/v1/melt/bolt11", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var meltResponse nut05.PostMeltQuoteBolt11Response
	if err := json.Unmarshal(body, &meltResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &meltResponse, nil
}

func PostCheckProofState(mintURL string, stateRequest nut07.PostCheckStateRequest) (
	*nut07.PostCheckStateResponse, error) {

	requestBody, err := json.Marshal(stateRequest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %v", err)
	}

	resp, err := httpPost(mintURL+"/v1/checkstate", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var stateResponse nut07.PostCheckStateResponse
	if err := json.Unmarshal(body, &stateResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &stateResponse, nil
}

func PostRestore(mintURL string, restoreRequest nut09.PostRestoreRequest) (
	*nut09.PostRestoreResponse, error) {

	requestBody, err := json.Marshal(restoreRequest)
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %v", err)
	}

	resp, err := httpPost(mintURL+"/v1/restore", "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var restoreResponse nut09.PostRestoreResponse
	if err := json.Unmarshal(body, &restoreResponse); err != nil {
		return nil, fmt.Errorf("error reading response from mint: %v", err)
	}

	return &restoreResponse, nil
}

func get(url string) (*http.Response, error) {
	return getWithRetry(url, 0, 0)
}

func getWithRetry(url string, attempt int, retryAfterMs int) (*http.Response, error) {
	resp, err := http.Get(url)
	if err != nil {
		if attempt < maxRetries {
			time.Sleep(backoffDuration(attempt, 0))
			return getWithRetry(url, attempt+1, 0)
		}
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		if attempt < maxRetries {
			ms := parseRetryAfter(resp)
			resp.Body.Close()
			time.Sleep(backoffDuration(attempt, ms))
			return getWithRetry(url, attempt+1, ms)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, &RateLimitError{
			HTTPStatus:   resp.StatusCode,
			RetryAfterMs: retryAfterMs,
			MintURL:      url,
			Body:         string(body),
		}
	}

	return parse(resp)
}

func httpPost(url, contentType string, body io.Reader) (*http.Response, error) {
	return httpPostWithRetry(url, contentType, body, 0, 0)
}

func httpPostWithRetry(url, contentType string, body io.Reader, attempt int, retryAfterMs int) (*http.Response, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	resp, err := http.Post(url, contentType, bytes.NewReader(bodyBytes))
	if err != nil {
		if attempt < maxRetries {
			time.Sleep(backoffDuration(attempt, 0))
			return httpPostWithRetry(url, contentType, bytes.NewReader(bodyBytes), attempt+1, 0)
		}
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		if attempt < maxRetries {
			ms := parseRetryAfter(resp)
			resp.Body.Close()
			time.Sleep(backoffDuration(attempt, ms))
			return httpPostWithRetry(url, contentType, bytes.NewReader(bodyBytes), attempt+1, ms)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, &RateLimitError{
			HTTPStatus:   resp.StatusCode,
			RetryAfterMs: retryAfterMs,
			MintURL:      url,
			Body:         string(respBody),
		}
	}

	return parse(resp)
}

func parse(response *http.Response) (*http.Response, error) {
	if response.StatusCode == 400 {
		var errResponse cashu.Error
		err := json.NewDecoder(response.Body).Decode(&errResponse)
		if err != nil {
			return nil, fmt.Errorf("could not decode error response from mint: %v", err)
		}
		return nil, errResponse
	}

	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%s", body)
	}

	return response, nil
}
