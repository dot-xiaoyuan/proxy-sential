package controlplane

import (
	"os"
	"testing"
)

// Historical transport tests still verify actual HTTP receipts and retries.
// This bypass is set only by the test binary; shipped binaries always start
// with observation mode enabled and expose no configuration to turn it off.
func TestMain(m *testing.M) {
	legacyTransportTestBypass.Store(true)
	os.Exit(m.Run())
}
