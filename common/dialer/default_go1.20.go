//go:build go1.20

package dialer

import (
	"net"
<<<<<<< HEAD
=======

	"github.com/metacubex/tfo-go"
>>>>>>> v1.10.3
)

type tcpDialer = ExtendedTCPDialer

func newTCPDialer(dialer net.Dialer, tfoEnabled bool, tlsFragment *TLSFragment) (tcpDialer, error) {
	return tcpDialer{Dialer: dialer, DisableTFO: !tfoEnabled, TLSFragment: tlsFragment}, nil
}
