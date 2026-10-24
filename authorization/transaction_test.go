package authorization

import (
	"testing"
	"time"
)

func TestStatusTransitions(t *testing.T) {
	all := []Status{StatusPending, StatusCompleted, StatusRejected, StatusConsumed}
	allowed := map[[2]Status]bool{
		{StatusPending, StatusCompleted}:  true,
		{StatusPending, StatusRejected}:   true,
		{StatusCompleted, StatusConsumed}: true,
		{StatusRejected, StatusConsumed}:  true,
	}
	for _, from := range all {
		for _, to := range all {
			if got := from.CanTransitionTo(to); got != allowed[[2]Status{from, to}] {
				t.Errorf("%s -> %s: got %v", from, to, got)
			}
		}
	}
	if Status("bogus").CanTransitionTo(StatusConsumed) {
		t.Error("unknown status must not transition")
	}
}

func TestExpiry(t *testing.T) {
	base := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	txn := &Transaction{ExpiresAt: base.Add(time.Minute)}
	if txn.Expired(base) || !txn.Expired(base.Add(time.Minute)) {
		t.Error("transaction expiry boundary")
	}
	code := &AuthorizationCode{ExpiresAt: base.Add(time.Minute)}
	if code.Expired(base) || !code.Expired(base.Add(time.Minute)) || code.Consumed() {
		t.Error("code expiry boundary")
	}
	code.ConsumedAt = base
	if !code.Consumed() {
		t.Error("consumed")
	}
}
