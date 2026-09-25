package main

import (
	"os"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/secret"
)

// TestMain lowers the cost of password hashes: the login tests verify
// the logic, not PBKDF2, and 600 000 rounds per login under -race turn
// seconds into minutes.
//
// With LIMEN_RUN_MAIN set, the test binary is limen itself: the tests
// that must go through main() run it that way.
func TestMain(m *testing.M) {
	if os.Getenv("LIMEN_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	secret.SetIterationsForTesting(1000)
	os.Exit(m.Run())
}
