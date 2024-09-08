package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	dns "github.com/sagernet/sing-dns"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/core"

	// Mandatory features. Can't remove unless there are replacements.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Fix dependency cycle caused by core import in internet package
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"
	// Inbound and outbound proxies.
	// _ "github.com/xtls/xray-core/proxy/blackhole"
	// _ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/dokodemo"
	_ "github.com/xtls/xray-core/proxy/freedom"

	// _ "github.com/xtls/xray-core/proxy/http"
	// _ "github.com/xtls/xray-core/proxy/loopback"
	// _ "github.com/xtls/xray-core/proxy/shadowsocks"
	// _ "github.com/xtls/xray-core/proxy/socks"
	xnet "github.com/xtls/xray-core/common/net"
	_ "github.com/xtls/xray-core/proxy/trojan"

	// _ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	// _ "github.com/xtls/xray-core/proxy/vmess/inbound"
	_ "github.com/xtls/xray-core/proxy/vmess/outbound"
	// _ "github.com/xtls/xray-core/proxy/wireguard"

	// Transports
	_ "github.com/xtls/xray-core/transport/internet/domainsocket"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/http"
	_ "github.com/xtls/xray-core/transport/internet/httpupgrade"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/quic"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	// Transport headers
	_ "github.com/xtls/xray-core/transport/internet/headers/http"
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"
	_ "github.com/xtls/xray-core/transport/internet/headers/srtp"
	_ "github.com/xtls/xray-core/transport/internet/headers/tls"
	_ "github.com/xtls/xray-core/transport/internet/headers/utp"
	_ "github.com/xtls/xray-core/transport/internet/headers/wechat"

	// _ "github.com/xtls/xray-core/transport/internet/headers/wireguard"

	// JSON
	_ "github.com/xtls/xray-core/main/json"
)

var _ adapter.Outbound = (*Xray)(nil)

type Xray2 struct {
	myOutboundAdapter
	resolve      bool
	xrayInstance *core.Instance
	proxyStr     string
}

func NewXray2(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.XrayOutboundOptions) (*Xray2, error) {

	outbounds := []map[string]any{}
	if options.XrayOutboundJson != nil {
		xrayconf := *options.XrayOutboundJson
		if options.Fragment == nil || options.Fragment.Packets == "" {
			xrayconf["sockopt"] = map[string]any{}
		} else {
			xrayconf["sockopt"] = map[string]any{
				"dialerProxy":      "fragment",
				"tcpKeepAliveIdle": 100,
				"tcpNoDelay":       true,
			}
		}
		outbounds = append(outbounds, xrayconf)
	}

	if options.Fragment != nil && options.Fragment.Packets != "" {
		outbounds = append(outbounds, map[string]any{
			"tag":      "fragment",
			"protocol": "freedom",
			"settings": map[string]any{
				"domainStrategy": "AsIs",
				"fragment":       options.Fragment,
			},
			"streamSettings": map[string]any{
				"sockopt": map[string]any{
					"tcpKeepAliveIdle": 100,
					"tcpNoDelay":       true,
				},
			},
		})
	}

	xray := map[string]any{
		"log": map[string]any{
			"loglevel": options.LogLevel,
		},
		// "inbounds": []any{
		// 	map[string]any{
		// 		"listen":   "127.0.0.1",
		// 		"port":     port,
		// 		"protocol": "socks",
		// 		"settings": map[string]any{
		// 			"udp":  true,
		// 			"auth": "password",
		// 			"accounts": []any{
		// 				map[string]any{
		// 					"user": userpass,
		// 					"pass": userpass,
		// 				},
		// 			},
		// 		},
		// 	},
		// },
		"outbounds": outbounds,
	}
	protocol, ok := outbounds[0]["protocol"].(string)
	if !ok {
		return nil, fmt.Errorf("incorrect protocol")
	}
	jsonData, err := json.MarshalIndent(xray, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling to JSON: %v", err)
	}
	fmt.Printf(string(jsonData))

	// options.XrayOutboundJson
	reader := bytes.NewReader(jsonData)

	xrayConfig, err := core.LoadConfig("json", reader)
	if err != nil {
		return nil, err
	}
	server, err := core.New(xrayConfig)
	if err != nil {
		return nil, err
	}
	// socksNet := M.ParseSocksaddrHostPort("127.0.0.1", port)

	// outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &Xray2{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeSOCKS,
			network:      options.Network.Build(),
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		// client: socks.NewClient(outboundDialer, socksNet, socks.Version5, userpass, userpass),
		// client:       socks.NewClient(outboundDialer, socksNet, socks.Version5, "", ""),
		resolve:      false,
		xrayInstance: server,
		proxyStr:     "X" + protocol,
	}
	// uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	// if uotOptions.Enabled {
	// 	outbound.uotClient = &uot.Client{
	// 		Dialer:  outbound.client,
	// 		Version: uotOptions.Version,
	// 	}
	// }
	return outbound, nil
}

func (h *Xray2) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	var dest xnet.Destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		dest = xnet.TCPDestination(xnet.ParseAddress(destination.AddrString()), xnet.Port(destination.Port))
	case N.NetworkUDP:
		dest = xnet.UDPDestination(xnet.ParseAddress(destination.AddrString()), xnet.Port(destination.Port))
	}
	return core.Dial(ctx, h.xrayInstance, dest)

}

func (h *Xray2) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination

	// if h.resolve && destination.IsFqdn() {
	// 	destinationAddresses, err := h.router.LookupDefault(ctx, destination.Fqdn)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	packetConn, _, err := N.ListenSerial(ctx, c, destination, destinationAddresses)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	return packetConn, nil
	// }
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return core.DialUDP(ctx, h.xrayInstance)

}

func (h *Xray2) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if h.resolve {
		return NewDirectConnection(ctx, h.router, h, conn, metadata, dns.DomainStrategyUseIPv4)
	} else {
		return NewConnection(ctx, h, conn, metadata)
	}
}

func (h *Xray2) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	if h.resolve {
		return NewDirectPacketConnection(ctx, h.router, h, conn, metadata, dns.DomainStrategyUseIPv4)
	} else {
		return NewPacketConnection(ctx, h, conn, metadata)
	}
}
func (w *Xray2) Start() error {
	return w.xrayInstance.Start()
}
func (w *Xray2) Close() error {
	return w.xrayInstance.Close()
}

func (w *Xray2) Type() string {
	return w.proxyStr
}
