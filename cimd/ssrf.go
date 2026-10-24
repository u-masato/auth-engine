package cimd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrForbiddenAddress は、CIMD 文書の URL が RFC 6890 の特殊用途アドレス（loopback、private、
// link-local 等）に解決されたことを表す（CIMD §8.6 SSRF 対策）。
var ErrForbiddenAddress = errors.New("cimd: destination address is not allowed")

// specialPurposePrefixes は RFC 6890 の Special-Purpose IP Address Registries と、その後の追加
// （RFC 6598 Shared Address Space、RFC 7723 PCP Anycast 等）のうち、netip の判定メソッドで
// 拾えない範囲。loopback は AllowLoopback で許すので別に扱う。
var specialPurposePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "This host on this network"（RFC 1122 §3.2.1.3）
	netip.MustParsePrefix("100.64.0.0/10"),   // Shared Address Space（RFC 6598）
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF Protocol Assignments（RFC 6890）
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1（RFC 5737）
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 Relay Anycast（RFC 3068、廃止）
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking（RFC 2544）
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2（RFC 5737）
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3（RFC 5737）
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved（RFC 1112 §4）。255.255.255.255 を含む
	netip.MustParsePrefix("64:ff9b::/96"),    // IPv4-IPv6 Translation（RFC 6052）
	netip.MustParsePrefix("64:ff9b:1::/48"),  // Local-Use IPv4/IPv6 Translation（RFC 8215）
	netip.MustParsePrefix("100::/64"),        // Discard-Only（RFC 6666）
	netip.MustParsePrefix("2001::/23"),       // IETF Protocol Assignments（RFC 2928）。TEREDO、ORCHID、Benchmarking を含む
	netip.MustParsePrefix("2001:db8::/32"),   // Documentation（RFC 3849）
	netip.MustParsePrefix("2002::/16"),       // 6to4（RFC 3056）
	netip.MustParsePrefix("fc00::/7"),        // Unique-Local（RFC 4193）
	netip.MustParsePrefix("fe80::/10"),       // Link-Local（RFC 4291）
	netip.MustParsePrefix("fec0::/10"),       // Site-Local（RFC 3879、廃止）
	netip.MustParsePrefix("::ffff:0:0/96"),   // IPv4-mapped。Unmap 後に判定するが、念のため全体を拒否
	netip.MustParsePrefix("::/128"),          // Unspecified
}

// checkAddress は接続先 IP アドレスが CIMD 文書の取得先として許されるかを返す。
// allowLoopback が false なら loopback も拒否する。
func checkAddress(addr netip.Addr, allowLoopback bool) error {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("%w: loopback %s", ErrForbiddenAddress, addr)
	}
	switch {
	case addr.IsUnspecified(), addr.IsPrivate(), addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(), addr.IsMulticast():
		return fmt.Errorf("%w: %s", ErrForbiddenAddress, addr)
	}
	for _, p := range specialPurposePrefixes {
		if p.Contains(addr) {
			return fmt.Errorf("%w: %s", ErrForbiddenAddress, addr)
		}
	}
	return nil
}

// NewTransport は CIMD 文書の取得に使う http.Transport を返す。名前解決後の接続先アドレスを
// net.Dialer.Control で検査し、特殊用途アドレスへの接続を拒む（CIMD §8.6）。プロキシは使わない
// （プロキシ経由だと接続先の検査ができないため）。利用者が Config.HTTPClient を差し替えるときは、
// この Transport を基に TLS 設定などを足すとよい。
func NewTransport(allowLoopback bool) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrForbiddenAddress, address)
			}
			return checkAddress(ap.Addr(), allowLoopback)
		},
	}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	}
}

// errNoRedirect はリダイレクトを追従しないことを示す CheckRedirect のエラー。
var errNoRedirect = errors.New("cimd: redirects are not followed")

// noRedirect は http.Client.CheckRedirect に設定し、リダイレクトを追従させない（CIMD §5）。
func noRedirect(_ *http.Request, _ []*http.Request) error {
	return errNoRedirect
}
