package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/refraction-networking/clienthellod/modcaddy/app"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("clienthellod", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		m := &Handler{}
		if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
			return nil, err
		}
		return m, nil
	})
}

type Handler struct {
	// TLS enables handler to look up TLS ClientHello from reservoir.
	//
	// Mutually exclusive with QUIC. One and only one of TLS or QUIC must be true.
	TLS bool `json:"tls,omitempty"`

	// QUIC enables handler to look up QUIC ClientHello from reservoir.
	//
	// Mutually exclusive with TLS. One and only one of TLS or QUIC must be true.
	QUIC bool `json:"quic,omitempty"`

	logger    *zap.Logger
	reservoir *app.Reservoir
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo { // skipcq: GO-W1029
	return caddy.ModuleInfo{
		ID:  "http.handlers.clienthellod",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(ctx caddy.Context) error { // skipcq: GO-W1029
	h.logger = ctx.Logger(h)
	h.logger.Info("clienthellod handler logger loaded.")

	if a, err := ctx.AppIfConfigured(app.CaddyAppID); err != nil {
		return err
	} else {
		h.reservoir = a.(*app.Reservoir)
		h.logger.Info("clienthellod handler reservoir loaded.")
	}

	if h.TLS && h.QUIC {
		return errors.New("clienthellod handler: mutually exclusive TLS and QUIC are both enabled")
	} else if !(h.TLS || h.QUIC) {
		return errors.New("clienthellod handler: one and only one of TLS or QUIC must be enabled")
	}

	h.logger.Info("clienthellod handler provisioned.")

	return nil
}

// ServeHTTP
func (h *Handler) ServeHTTP(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error { // skipcq: GO-W1029
	h.logger.Debug("Serving HTTP to " + req.RemoteAddr + " on Protocol " + req.Proto)

	if h.TLS {
		if req.ProtoMajor <= 2 {
			return h.serveTLS(wr, req, next)
		}
		// H3: extract TLS ClientHello from QUIC reservoir (it's embedded in QUIC Initial packets)
		return h.serveTLSOverH3(wr, req, next)
	} else if h.QUIC {
		return h.serveQUIC(wr, req, next)
	}
	return next.ServeHTTP(wr, req)
}

// serveTLS handles HTTP/1.0, HTTP/1.1, H2 requests by looking up the
// ClientHello from the reservoir and writing it to the response.
func (h *Handler) serveTLS(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error { // skipcq: GO-W1029
	// get the client hello from the reservoir
	ch := h.reservoir.TLSFingerprinter().Peek(req.RemoteAddr)
	if ch == nil {
		h.logger.Debug(fmt.Sprintf("Unable to fetch TLS ClientHello sent by %s, maybe not TLS connection?", req.RemoteAddr))
		return next.ServeHTTP(wr, req)
	}
	// h.logger.Debug(fmt.Sprintf("Fetched TLS ClientHello for %s", req.RemoteAddr))

	ch.UserAgent = req.UserAgent()

	// dump JSON
	var b []byte
	var err error
	if req.URL.Query().Get("beautify") == "true" {
		b, err = json.MarshalIndent(ch, "", "  ")
	} else {
		b, err = json.Marshal(ch)
	}
	if err != nil {
		h.logger.Error("failed to marshal TLS ClientHello into JSON", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}

	// Properly set the Content-Type header
	wr.Header().Set("Content-Type", "application/json")

	// Close the HTTP connection after sending the response
	//
	// HTTP/1.X only. Forbidden in HTTP/2 (RFC 9113 Section 8.2.2)
	// and HTTP/3 (RFC 9114 Section 4.2)
	if req.ProtoMajor == 1 {
		wr.Header().Set("Connection", "close")
	}

	_, err = wr.Write(b)
	if err != nil {
		h.logger.Error("failed to write response", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}
	return nil
}

// serveTLSOverH3 handles HTTP/3 requests for the TLS handler by extracting the
// TLS ClientHello that clienthellod captured from the QUIC Initial packets.
func (h *Handler) serveTLSOverH3(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error { // skipcq: GO-W1029
	from := req.RemoteAddr
	// Use Peek (non-blocking) instead of PeekAwait. PeekAwait blocks for up to
	// quic_ttl on entries still being gathered, which stalls goroutines indefinitely.
	qfp := h.reservoir.QUICFingerprinter().Peek(from)
	if qfp == nil {
		// Fallback: look up the most recent QUIC session for this IP (handles connection reuse/migration)
		ip, _, splitErr := net.SplitHostPort(req.RemoteAddr)
		if splitErr == nil {
			if lastFrom, ok := h.reservoir.GetLastQUICVisitor(ip); ok {
				qfp = h.reservoir.QUICFingerprinter().Peek(lastFrom)
			}
		}
		if qfp == nil {
			h.logger.Debug(fmt.Sprintf("Unable to fetch QUIC data for TLS-over-H3 from %s", req.RemoteAddr))
			return next.ServeHTTP(wr, req)
		}
	}
	if qfp.ClientInitials == nil || qfp.ClientInitials.ClientHello == nil {
		return next.ServeHTTP(wr, req)
	}
	ch := &qfp.ClientInitials.ClientHello.ClientHello
	ch.UserAgent = req.UserAgent()

	var b []byte
	var err error
	if req.URL.Query().Get("beautify") == "true" {
		b, err = json.MarshalIndent(ch, "", "  ")
	} else {
		b, err = json.Marshal(ch)
	}
	if err != nil {
		h.logger.Error("failed to marshal TLS-over-H3 ClientHello into JSON", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}
	wr.Header().Set("Content-Type", "application/json")
	_, err = wr.Write(b)
	if err != nil {
		h.logger.Error("failed to write response", zap.Error(err))
	}
	return nil
}

// serveQUIC handles QUIC requests by looking up the ClientHello from the
// reservoir and writing it to the response.
func (h *Handler) serveQUIC(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error { // skipcq: GO-W1029
	var from string
	if req.ProtoMajor == 3 {
		from = req.RemoteAddr
		h.logger.Debug(fmt.Sprintf("Fetching QUIC Fingerprint directly sent by QUIC client at %s", from))
	} else {
		// Get IP part of the RemoteAddr
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			h.logger.Error(fmt.Sprintf("Can't split IP from %s: %v", req.RemoteAddr, err))
			return next.ServeHTTP(wr, req)
		}

		// Get the last QUIC visitor
		var ok bool
		from, ok = h.reservoir.GetLastQUICVisitor(ip)
		if !ok {
			h.logger.Debug(fmt.Sprintf("Can't find last QUIC visitor for %s", ip))
			return next.ServeHTTP(wr, req)
		}

		h.logger.Debug(fmt.Sprintf("Fetching most recent QUIC Fingerprint sent by %s for TLS client at %s", from, req.RemoteAddr))
	}

	// get the client hello from the reservoir (non-blocking Peek to avoid goroutine stalls)
	qfp := h.reservoir.QUICFingerprinter().Peek(from)
	if qfp == nil && req.ProtoMajor == 3 {
		// H3 direct lookup failed — try visitor fallback (handles port migration)
		ip, _, splitErr := net.SplitHostPort(req.RemoteAddr)
		if splitErr == nil {
			if lastFrom, ok := h.reservoir.GetLastQUICVisitor(ip); ok {
				qfp = h.reservoir.QUICFingerprinter().Peek(lastFrom)
			}
		}
	}
	if qfp == nil {
		h.logger.Debug(fmt.Sprintf("Unable to fetch QUIC fingerprint sent by %s", req.RemoteAddr))
		return next.ServeHTTP(wr, req)
	}

	// h.logger.Debug(fmt.Sprintf("Fetched QUIC fingerprint for %s", req.RemoteAddr))

	// If this is a QUIC request, we record the IP address as a QUIC visitor
	// so this QUIC fingerprint is associated with the IP address and can be
	// fetched for even HTTP-over-TLS (TCP-based) requests.
	if req.ProtoMajor == 3 {
		// Get IP part of the RemoteAddr
		ip, _, ipErr := net.SplitHostPort(req.RemoteAddr)
		if ipErr == nil {
			h.reservoir.NewQUICVisitor(ip, req.RemoteAddr)
		} else {
			h.logger.Error(fmt.Sprintf("Can't extract IP from %s: %v", req.RemoteAddr, ipErr))
		}
	}

	qfp.UserAgent = req.UserAgent()

	// dump JSON
	var b []byte
	var err error
	if req.URL.Query().Get("beautify") == "true" {
		b, err = json.MarshalIndent(qfp, "", "  ")
	} else {
		b, err = json.Marshal(qfp)
	}
	if err != nil {
		h.logger.Error("failed to marshal QUIC fingerprint into JSON", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}

	// Properly set the Content-Type header
	wr.Header().Set("Content-Type", "application/json")

	// Close the HTTP connection after sending the response
	//
	// HTTP/1.X only. Forbidden in HTTP/2 (RFC 9113 Section 8.2.2)
	// and HTTP/3 (RFC 9114 Section 4.2)
	if req.ProtoMajor == 1 {
		wr.Header().Set("Connection", "close")
	}

	_, err = wr.Write(b)
	if err != nil {
		h.logger.Error("failed to write response", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}
	return nil
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { // skipcq: GO-W1029
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "tls":
				if h.TLS {
					return d.Err("clienthellod: repeated tls in block")
				} else if h.QUIC {
					return d.Err("clienthellod: tls and quic are mutually exclusive in one block")
				}
				h.TLS = true
			case "quic":
				if h.QUIC {
					return d.Err("clienthellod: repeated quic in block")
				} else if h.TLS {
					return d.Err("clienthellod: tls and quic are mutually exclusive in one block")
				}
				h.QUIC = true
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
