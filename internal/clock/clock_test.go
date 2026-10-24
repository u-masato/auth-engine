package clock

import (
	"testing"
	"time"
)

func TestFixed(t *testing.T) {
	base := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	c := NewFixed(base)
	if !c.Now().Equal(base) {
		t.Fatalf("Now = %v, want %v", c.Now(), base)
	}
	c.Advance(90 * time.Second)
	if got := c.Now(); !got.Equal(base.Add(90 * time.Second)) {
		t.Fatalf("after Advance: %v", got)
	}
	c.Set(base)
	if !c.Now().Equal(base) {
		t.Fatalf("after Set: %v", c.Now())
	}
}

func TestFunc(t *testing.T) {
	want := time.Unix(1_000_000, 0)
	var c Clock = Func(func() time.Time { return want })
	if !c.Now().Equal(want) {
		t.Fatal("Func must delegate")
	}
}

func TestRealIsClock(t *testing.T) {
	var c Clock = Real{}
	if time.Since(c.Now()) > time.Minute {
		t.Fatal("Real must return the current time")
	}
}
