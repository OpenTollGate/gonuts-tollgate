package mint

import "github.com/OpenTollGate/gonuts-tollgate/mint/lightning"

// Test seams for the external test package (the export_test.go pattern):
// the NUT-08 change math is pure and unit-tested directly.
var (
	MeltChangeTargetForTest = meltChangeTarget
)

func (m *Mint) SplitChangeAmountsForTest(target uint64) ([]uint64, uint64) {
	return m.splitChangeAmounts(target)
}

// keep the import tree honest if the seams change shape
var _ lightning.PaymentStatus
