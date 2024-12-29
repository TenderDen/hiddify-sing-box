package tls

import (
	"context"
	"net"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badtls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
)

func NewDialerFromOptions(ctx context.Context, router adapter.Router, dialer N.Dialer, serverAddress interface{}, options option.OutboundTLSOptions) (N.Dialer, error) {
	addr := ""
	switch serverAddress.(type) {
	case option.IpAddr:
		addr = string(serverAddress)
	case string:
		addr = serverAddress
	}
	if !options.Enabled {
		return dialer, nil
	}
	config, err := NewClient(ctx, addr, options)
	if err != nil {
		return nil, err
	}
	return NewDialer(dialer, config), nil
}

func NewClient(ctx context.Context, serverAddress interface{}, options option.OutboundTLSOptions) (Config, error) {
	addr := ""
	switch serverAddress.(type) {
	case option.IpAddr:
		addr = string(serverAddress)
	case string:
		addr = serverAddress
	}
	if !options.Enabled {
		return nil, nil
	}
	if options.ECH != nil && options.ECH.Enabled {
		return NewECHClient(ctx, addr, options)
	} else if options.Reality != nil && options.Reality.Enabled {
		return NewRealityClient(ctx, addr, options)
	} else if options.UTLS != nil && options.UTLS.Enabled {
		return NewUTLSClient(ctx, addr, options)
	} else {
		return NewSTDClient(ctx, addr, options)
	}
}

func ClientHandshake(ctx context.Context, conn net.Conn, config Config) (Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	tlsConn, err := aTLS.ClientHandshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	readWaitConn, err := badtls.NewReadWaitConn(tlsConn)
	if err == nil {
		return readWaitConn, nil
	} else if err != os.ErrInvalid {
		return nil, err
	}
	return tlsConn, nil
}

type Dialer struct {
	dialer N.Dialer
	config Config
}

func NewDialer(dialer N.Dialer, config Config) N.Dialer {
	return &Dialer{dialer, config}
}

func (d *Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	conn, err := d.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return ClientHandshake(ctx, conn, d.config)
}

func (d *Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
