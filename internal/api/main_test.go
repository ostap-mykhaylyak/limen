package api

import (
	"os"
	"testing"

	"github.com/ostap-mykhaylyak/limen/internal/secret"
)

// TestMain lowers the cost of password hashes: the login tests verify
// the logic, not PBKDF2, and 600 000 rounds per login under -race turn
// seconds into minutes.
func TestMain(m *testing.M) {
	secret.SetIterationsForTesting(1000)
	os.Exit(m.Run())
}
