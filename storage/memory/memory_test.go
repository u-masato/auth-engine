package memory

import (
	"testing"

	authengine "github.com/u-masato/auth-engine"
	"github.com/u-masato/auth-engine/storage/storagetest"
)

func TestContract(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) authengine.Store { return New() })
}
