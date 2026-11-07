package cashu

import "testing"

// The wire-visible error registry pinned to the nuts/error_codes.md
// table (cashu-audit #68 item A / FINDINGS-2026-11-04-error-identity).
//
// Every condition the spec table assigns MUST be emitted with its spec
// code, and spent/pending MUST be distinguishable. The previous hybrid
// scheme collided four codes with different spec classes (11002/11003/
// 11005/20009), conflated pending with spent under 11001, and squatted
// the NUT-21/22 3xxxx range with NUT-11/14 spending-condition failures.
//
// Classes the spec does not assign (payment method, unknown quote,
// melt-quote request validation, NUT-11/14 witness failures) are
// emitted from the private 41xxx block — reverting any mapping below
// must redden this test, which is what makes it a fence and not
// decoration.
func TestErrorCodesMatchSpecTable(t *testing.T) {
	specAligned := []struct {
		name string
		got  CashuErrCode
		want CashuErrCode // spec class from nuts/error_codes.md
	}{
		{"proof verification failed", InvalidProofErrCode, 10001},
		{"proofs already spent", ProofAlreadyUsedErrCode, 11001},
		{"proofs are pending", ProofPendingErrCode, 11002},
		{"outputs already signed", BlindedMessageAlreadySignedErrCode, 11003},
		{"transaction not balanced", InsufficientProofAmountErrCode, 11005},
		{"amount outside of limit range", AmountLimitExceeded, 11006},
		{"zero-amount quote (limit-range class)", MintQuoteZeroAmountErrCode, 11006},
		{"duplicate inputs", DuplicateInputErrCode, 11007},
		{"duplicate outputs", DuplicateOutputErrCode, 11008},
		{"unit not supported", UnitErrCode, 11013},
		{"duplicate quote ids in batch", DuplicateQuotesErrCode, 11016},
		{"keyset not known", UnknownKeysetErrCode, 12001},
		{"keyset inactive", InactiveKeysetErrCode, 12002},
		{"mint quote not paid", MintQuoteRequestNotPaidErrCode, 20001},
		{"mint quote already issued", MintQuoteAlreadyIssuedErrCode, 20002},
		{"minting disabled", MintingDisabledErrCode, 20003},
		{"lightning payment failed", LightningPaymentErrCode, 20004},
		{"melt quote pending", MeltQuotePendingErrCode, 20005},
		{"invoice already paid", MeltQuoteAlreadyPaidErrCode, 20006},
		{"mint quote signature invalid", MintQuoteInvalidSigErrCode, 20008},
	}
	for _, tc := range specAligned {
		if tc.got != tc.want {
			t.Errorf("%s: code = %d, want spec code %d", tc.name, tc.got, tc.want)
		}
	}
}

// Spent and pending must never share an identity again: a wallet that
// cannot tell them apart treats an in-flight settlement as a definitive
// consumption (the conflation the #68 matrix measured on the wire).
func TestSpentAndPendingAreDistinct(t *testing.T) {
	if ProofPendingErr.Code != ProofPendingErrCode {
		t.Errorf("ProofPendingErr code = %d, want %d", ProofPendingErr.Code, ProofPendingErrCode)
	}
	if ProofAlreadyUsedErr.Code == ProofPendingErr.Code {
		t.Errorf("spent (11001) and pending (%d) share a code", ProofPendingErr.Code)
	}
}

// Error VALUES carry the codes a response body will show — the constants
// alone are not enough (ProofPendingErr used to reuse ProofAlreadyUsedErr's
// code literal while its class diverged).
func TestErrorValuesCarrySpecCodes(t *testing.T) {
	values := []struct {
		name string
		err  Error
		want CashuErrCode
	}{
		{"InvalidProofErr", InvalidProofErr, 10001},
		{"NoProofsProvided", NoProofsProvided, 10001},
		{"ProofAlreadyUsedErr", ProofAlreadyUsedErr, 11001},
		{"ProofPendingErr", ProofPendingErr, 11002},
		{"BlindedMessageAlreadySigned", BlindedMessageAlreadySigned, 11003},
		{"InsufficientProofsAmount", InsufficientProofsAmount, 11005},
		{"MintAmountExceededErr", MintAmountExceededErr, 11006},
		{"MeltAmountExceededErr", MeltAmountExceededErr, 11006},
		{"MintQuoteZeroAmountErr", MintQuoteZeroAmountErr, 11006},
		{"DuplicateProofs", DuplicateProofs, 11007},
		{"DuplicateOutputs", DuplicateOutputs, 11008},
		{"UnitNotSupportedErr", UnitNotSupportedErr, 11013},
		{"DuplicateQuotesErr", DuplicateQuotesErr, 11016},
		{"UnknownKeysetErr", UnknownKeysetErr, 12001},
		{"InactiveKeysetSignatureRequest", InactiveKeysetSignatureRequest, 12002},
	}
	for _, tc := range values {
		if tc.err.Code != tc.want {
			t.Errorf("%s: code = %d, want %d", tc.name, tc.err.Code, tc.want)
		}
	}
}

// Spec-unassigned conditions live in the private 41xxx block, outside
// every spec-allocated range (10xxx proof, 11xxx transaction, 12xxx
// keyset, 20xxx quote, 3xxxx NUT-21/22 auth) — and 20009 in particular
// is the spec's NUT-20 "pubkey required for mint quote", which this
// mint never emits, so no generic failure may hide behind it.
func TestUnassignedClassesUsePrivateBlock(t *testing.T) {
	private := []struct {
		name string
		got  CashuErrCode
		want CashuErrCode
	}{
		{"payment method not supported", PaymentMethodErrCode, 41001},
		{"quote does not exist", QuoteNotExistErrCode, 41002},
		{"melt quote request rejected", MeltQuoteRequestErrCode, 41003},
		{"melt quote for request exists", MeltQuoteExistsErrCode, 41004},
	}
	for _, tc := range private {
		if tc.got != tc.want {
			t.Errorf("%s: code = %d, want private %d", tc.name, tc.got, tc.want)
		}
		if tc.got < 41000 || tc.got > 41999 {
			t.Errorf("%s: code %d outside the private 41xxx block", tc.name, tc.got)
		}
	}
	for _, e := range []Error{QuoteNotExistErr, MeltQuoteForRequestExists} {
		if e.Code == 20009 {
			t.Errorf("%q carries 20009 — spec books it for NUT-20 pubkey-required", e.Detail)
		}
	}
}
