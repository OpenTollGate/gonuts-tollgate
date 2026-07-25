package wallet

import "github.com/OpenTollGate/gonuts-tollgate/cashu"

// SendOptions provides configuration for send operations
type SendOptions struct {
	// IncludeFees determines whether to include fees in the calculation
	IncludeFees bool

	// AllowOverpayment allows sending more than requested amount when exact change isn't available offline
	AllowOverpayment bool

	// MaxOverpaymentPercent limits overpayment to a percentage (0-100, default 0 = no limit)
	MaxOverpaymentPercent uint

	// MaxOverpaymentAbsolute limits overpayment to an absolute amount (0 = no limit)
	MaxOverpaymentAbsolute uint64
}

// DefaultSendOptions returns the default send options (backwards compatible)
func DefaultSendOptions() SendOptions {
	return SendOptions{
		IncludeFees:            false,
		AllowOverpayment:       false,
		MaxOverpaymentPercent:  0,
		MaxOverpaymentAbsolute: 0,
	}
}

// SendResult contains the result of a send operation
type SendResult struct {
	// Proofs are the proofs that were sent
	Proofs cashu.Proofs

	// RequestedAmount is the amount that was requested
	RequestedAmount uint64

	// ActualAmount is the amount that was actually sent (may be higher due to overpayment)
	ActualAmount uint64

	// Overpayment is the difference between actual and requested amount
	Overpayment uint64

	// WasOffline indicates if the send was performed in offline mode
	WasOffline bool
}
