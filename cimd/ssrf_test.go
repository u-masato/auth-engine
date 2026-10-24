package cimd

import (
	"errors"
	"net/netip"
	"testing"
)

// RFC 6890 の特殊用途アドレスは拒否し、グローバルなユニキャストだけを許す（CIMD §8.6）。
func TestCheckAddress(t *testing.T) {
	tests := []struct {
		addr         string
		ok           bool
		okIfLoopback bool
	}{
		{"93.184.216.34", true, true},
		{"2606:2800:220:1:248:1893:25c8:1946", true, true},
		{"127.0.0.1", false, true},
		{"127.5.6.7", false, true},
		{"::1", false, true},
		{"::ffff:127.0.0.1", false, true}, // IPv4-mapped loopback
		{"::ffff:10.0.0.1", false, false}, // IPv4-mapped private
		{"0.0.0.0", false, false},
		{"0.1.2.3", false, false},
		{"10.0.0.1", false, false},
		{"172.16.0.1", false, false},
		{"172.31.255.255", false, false},
		{"172.32.0.1", true, true},
		{"192.168.1.1", false, false},
		{"169.254.169.254", false, false}, // link-local（クラウドのメタデータサービス）
		{"100.64.0.1", false, false},      // Shared Address Space
		{"192.0.0.8", false, false},       // IETF Protocol Assignments
		{"192.0.2.1", false, false},       // TEST-NET-1
		{"192.88.99.1", false, false},
		{"198.18.0.1", false, false},
		{"198.51.100.1", false, false},
		{"203.0.113.1", false, false},
		{"224.0.0.1", false, false}, // multicast
		{"240.0.0.1", false, false},
		{"255.255.255.255", false, false},
		{"::", false, false},
		{"64:ff9b::7f00:1", false, false},
		{"100::1", false, false},
		{"2001::1", false, false},   // TEREDO
		{"2001:2::1", false, false}, // Benchmarking
		{"2001:db8::1", false, false},
		{"2001:470::1", true, true}, // 2001::/23 の外側（通常の割り当て）
		{"2002::1", false, false},
		{"fc00::1", false, false},
		{"fd12::1", false, false},
		{"fe80::1", false, false},
		{"fec0::1", false, false},
		{"ff02::1", false, false},
	}
	for _, tt := range tests {
		addr := netip.MustParseAddr(tt.addr)
		if err := checkAddress(addr, false); (err == nil) != tt.ok {
			t.Errorf("%s: ok=%v, err=%v", tt.addr, tt.ok, err)
		} else if err != nil && !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("%s: want ErrForbiddenAddress, got %v", tt.addr, err)
		}
		if err := checkAddress(addr, true); (err == nil) != tt.okIfLoopback {
			t.Errorf("%s (allow loopback): ok=%v, err=%v", tt.addr, tt.okIfLoopback, err)
		}
	}
}

func TestNewTransportDialControlRejects(t *testing.T) {
	tr := NewTransport(false)
	if tr.Proxy != nil {
		t.Error("transport must not use a proxy")
	}
	// Control は名前解決後のアドレスで呼ばれる。ここでは直接 IP を与えて拒否を確かめる。
	for _, addr := range []string{"127.0.0.1:443", "[::1]:443", "10.0.0.1:443", "169.254.169.254:80"} {
		_, err := tr.DialContext(t.Context(), "tcp", addr)
		if !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("%s: want ErrForbiddenAddress, got %v", addr, err)
		}
	}
}
