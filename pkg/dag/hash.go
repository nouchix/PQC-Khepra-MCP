package dag

import (
	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// HashBytes is a convenience wrapper around adinkra.Hash for use by
// packages that need content-addressed hashing without importing adinkra directly.
func HashBytes(data []byte) string {
	return adinkra.Hash(data)
}
