package nut15

import (
	"errors"
	"fmt"

	"github.com/OpenTollGate/gonuts-tollgate/cashu"
	"github.com/OpenTollGate/gonuts-tollgate/wallet/client"
)

// NUT #15: In this document, we describe how wallets can instruct multiple mints to each pay a partial amount of a bolt11 Lightning invoice.
var (
	ErrSplitTooShort = errors.New("length of split too short")
)

// IsMppSupported returns whether the mint supports NUT-15 for the specified unit
func IsMppSupported(mint string, unit cashu.Unit) (bool, error) {
	// NUT #15: The mint MUST indicate each `method` and `unit` that supports mpp.
	mintInfo, err := client.GetMintInfo(mint)
	if err != nil {
		return false, fmt.Errorf("error getting info from mint: %v", err)
	}

	// NUT #15: `amount` is the partial amount for the requested payment in millisats (msat).
	for _, method := range mintInfo.Nuts.Nut15.Methods {
		if method.Unit == unit.String() {
			return true, nil
		}
	}

	return false, nil
}
