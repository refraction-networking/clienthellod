package listener

import (
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/refraction-networking/clienthellod/modcaddy/app"
	"go.uber.org/zap"
)

// clientHelloReadTimeout bounds how long the capture step may block waiting for
// a client's ClientHello. HandleTCPConn reads it synchronously inside Accept(),
// so without a deadline a client that connects but never sends a complete TLS
// record would block the Accept loop indefinitely and stall every new
// connection on this listener.
const clientHelloReadTimeout = 10 * time.Second

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper implements caddy.ListenerWrapper.
// It is used to extract the ClientHello from the incoming TLS
// connection before it reaches the "tls" in caddy.listeners
//
// For clienthellod to work, it must be placed before the "tls" in
// the Caddyfile's listener_wrappers directive. For example:
//
//	listener_wrappers {
//		clienthellod
//		tls
//	}
type ListenerWrapper struct {
	TCP bool `json:"tcp,omitempty"`
	UDP bool `json:"udp,omitempty"`

	logger       *zap.Logger
	reservoir    *app.Reservoir
	udpListener  *net.IPConn
	udp6Listener *net.IPConn
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo { // skipcq: GO-W1029
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.clienthellod",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

func (lw *ListenerWrapper) Cleanup() error { // skipcq: GO-W1029
	if lw.UDP {
		if lw.udpListener != nil {
			if err := lw.udpListener.Close(); err != nil {
				return err
			}
		}
		if lw.udp6Listener != nil {
			if err := lw.udp6Listener.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (lw *ListenerWrapper) Provision(ctx caddy.Context) error { // skipcq: GO-W1029
	// logger
	lw.logger = ctx.Logger(lw)
	lw.logger.Info("clienthellod listener logger loaded.")

	// reservoir
	if a, err := ctx.AppIfConfigured(app.CaddyAppID); err != nil {
		return err
	} else {
		lw.reservoir = a.(*app.Reservoir)
		lw.logger.Info("clienthellod listener reservoir loaded.")
	}

	var err error
	// UDP listener if enabled and not already provisioned
	if lw.UDP && lw.udpListener == nil {
		lw.udpListener, err = net.ListenIP("ip4:udp", &net.IPAddr{})
		if err != nil {
			return err
		}
		go lw.reservoir.QUICFingerprinter().HandleIPConn(lw.udpListener)

		lw.udp6Listener, err = net.ListenIP("ip6:udp", &net.IPAddr{})
		if err != nil {
			return err
		}
		go lw.reservoir.QUICFingerprinter().HandleIPConn(lw.udp6Listener)

		lw.logger.Info("clienthellod listener UDP listener loaded.")
	}

	lw.logger.Info("clienthellod listener provisioned.")
	return nil
}

func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener { // skipcq: GO-W1029
	lw.logger.Info("Wrapping listener " + l.Addr().String() + "on network " + l.Addr().Network() + "...")

	if l.Addr().Network() == "tcp" || l.Addr().Network() == "tcp4" || l.Addr().Network() == "tcp6" {
		if lw.TCP {
			return wrapTlsListener(l, lw.reservoir, lw.logger)
		} else {
			lw.logger.Debug("TCP not enabled. Skipping...")
		}
	} else {
		lw.logger.Debug("Not TCP. Skipping...")
	}

	return l
}

type tlsListener struct {
	net.Listener
	reservoir *app.Reservoir
	logger    *zap.Logger
}

func wrapTlsListener(in net.Listener, r *app.Reservoir, logger *zap.Logger) net.Listener {
	return &tlsListener{
		Listener:  in,
		reservoir: r,
		logger:    logger,
	}
}

func (l *tlsListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			// A non-temporary error returned here makes net/http's server stop
			// serving this listener permanently (the socket is closed and no
			// new connections are accepted). This path was previously silent,
			// which made an in-the-wild listener death impossible to diagnose.
			// Log it before propagating so the cause is always recorded.
			l.logger.Error("clienthellod listener: underlying Accept failed, listener will stop serving", zap.Error(err))
			return nil, err
		}

		// Bound the synchronous ClientHello read so a slow or silent client
		// cannot wedge the Accept loop. Reset on success so the deadline does
		// not carry into the TLS handshake on the rewound connection.
		_ = conn.SetReadDeadline(time.Now().Add(clientHelloReadTimeout))

		rewindConn, err := l.reservoir.TLSFingerprinter().HandleTCPConn(conn)
		if err != nil {
			// Per-connection failure (non-TLS client, malformed ClientHello,
			// or read timeout). Drop just this connection and keep serving;
			// never propagate as an Accept error.
			l.logger.Debug("clienthellod listener: failed to handle TCP connection, closing it", zap.Error(err))
			conn.Close()
			continue
		}

		_ = conn.SetReadDeadline(time.Time{})

		return rewindConn, nil
	}
}

func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { // skipcq: GO-W1029
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "tcp":
				if lw.TCP {
					return d.Err("clienthellod: tcp already specified")
				}
				lw.TCP = true
			case "udp":
				if lw.UDP {
					return d.Err("clienthellod: udp already specified")
				}
				lw.UDP = true
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.CleanerUpper    = (*ListenerWrapper)(nil)
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)
