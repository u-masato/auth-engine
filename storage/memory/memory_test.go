package memory

import (
	"testing"

	authengine "github.com/muno/auth-engine"
	"github.com/muno/auth-engine/storage/storagetest"
)

func TestContract(t *testing.T) {
	storagetest.Run(t, func(t *testing.T) authengine.Store { return New() })
}
