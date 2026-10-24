// Package clock は、現在時刻の取得を差し替え可能にする。
//
// 期限（Transaction、Code、トークン）の判定はすべて Clock 経由で行い、
// テストでは Fixed を使って時刻を進める。
package clock

import (
	"sync"
	"time"
)

// Clock は現在時刻を返す。
type Clock interface {
	Now() time.Time
}

// Func は func() time.Time を Clock として使うためのアダプタ。
// 利用者が Engine の設定で独自の時刻源を渡すときに使う。
type Func func() time.Time

// Now は f() を返す。
func (f Func) Now() time.Time { return f() }

// Real は実時刻を返す Clock。
type Real struct{}

// Now は time.Now() を返す。
func (Real) Now() time.Time { return time.Now() }

// Fixed はテスト用の固定時刻。Advance で任意に進められる。
// 複数 goroutine から同時に使っても安全である。
type Fixed struct {
	mu  sync.Mutex
	now time.Time
}

// NewFixed は t を現在時刻とする Fixed を返す。
func NewFixed(t time.Time) *Fixed {
	return &Fixed{now: t}
}

// Now は固定された現在時刻を返す。
func (f *Fixed) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// Advance は現在時刻を d だけ進める。
func (f *Fixed) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// Set は現在時刻を t にする。
func (f *Fixed) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}
