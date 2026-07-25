//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"log"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/wallet"
)

func main() {
	fmt.Println("=== Offline Send Example ===")

	// Initialize wallet
	config := wallet.Config{
		WalletPath:     "./example-wallet",
		CurrentMintURL: "https://testnut.cashu.space",
	}

	w, err := wallet.LoadWallet(config)
	if err != nil {
		log.Printf("Wallet initialization: %v", err)
		log.Println("This might be expected if offline - continuing with cached data")
	}
	if w != nil {
		defer w.Shutdown()
	}

	fmt.Printf("Current balance: %d sats\n", w.GetBalance())

	// Example 1: Traditional send (existing functionality - unchanged)
	fmt.Println("\n--- Example 1: Traditional Send ---")
	amount := uint64(15)
	proofs, err := w.Send(amount, w.CurrentMint(), true)
	if err != nil {
		fmt.Printf("Traditional send failed: %v\n", err)
	} else {
		fmt.Printf("Traditional send successful: %d sats\n", proofs.Amount())
	}

	// Example 2: Send with overpayment allowed (new functionality)
	fmt.Println("\n--- Example 2: Send with Overpayment ---")
	maxOverpay := uint64(5) // Allow up to 5 sats overpayment
	result, err := w.SendOffline(amount, w.CurrentMint(), maxOverpay)
	if err != nil {
		fmt.Printf("Offline send failed: %v\n", err)
	} else {
		fmt.Printf("Offline send successful!\n")
		fmt.Printf("  Requested: %d sats\n", result.RequestedAmount)
		fmt.Printf("  Actual: %d sats\n", result.ActualAmount)
		fmt.Printf("  Overpayment: %d sats\n", result.Overpayment)
		fmt.Printf("  Was offline: %t\n", result.WasOffline)

		// Create token from result
		token, err := cashu.NewTokenV4(result.Proofs, w.CurrentMint(), cashu.Sat, false)
		if err != nil {
			log.Printf("Error creating token: %v", err)
		} else {
			tokenStr, _ := token.Serialize()
			fmt.Printf("  Token: %s\n", tokenStr[:50]+"...")
		}
	}

	// Example 3: Send with percentage-based overpayment limit
	fmt.Println("\n--- Example 3: Send with Percentage Limit ---")
	options := wallet.SendOptions{
		IncludeFees:           true,
		AllowOverpayment:      true,
		MaxOverpaymentPercent: 10, // Allow up to 10% overpayment
	}
	result, err = w.SendWithOptions(amount, w.CurrentMint(), options)
	if err != nil {
		fmt.Printf("Percentage-limited send failed: %v\n", err)
	} else {
		overpaymentPercent := (result.Overpayment * 100) / result.RequestedAmount
		fmt.Printf("Percentage-limited send successful!\n")
		fmt.Printf("  Overpayment: %d sats (%.1f%%)\n", result.Overpayment, float64(overpaymentPercent))
	}

	// Example 4: Strict send (no overpayment allowed)
	fmt.Println("\n--- Example 4: Strict Send (No Overpayment) ---")
	strictOptions := wallet.SendOptions{
		IncludeFees:      true,
		AllowOverpayment: false,
	}
	result, err = w.SendWithOptions(amount, w.CurrentMint(), strictOptions)
	if err != nil {
		fmt.Printf("Strict send failed (expected when offline): %v\n", err)
	} else {
		fmt.Printf("Strict send successful: %d sats\n", result.ActualAmount)
	}

	fmt.Printf("\nFinal balance: %d sats\n", w.GetBalance())
}
