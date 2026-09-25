package nginx

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"

	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// PanelHost is the name of the proxy host that publishes limen's own
// panel, and of the certificate limen issues for it when
// panel.certificate is "acme". Both are protected: they are the door to
// the tool that manages every other door.
const PanelHost = "limen-panel"

// DesiredPanelHost returns the proxy host the configuration asks for,
// or nil when panel.hostname is empty.
func DesiredPanelHost(cfg *config.Config) (*model.ProxyHost, error) {
	p := cfg.Panel
	if p.Hostname == "" {
		return nil, nil
	}
	h := model.NewProxyHost(PanelHost)
	h.Protected = true
	h.Description = "limen's own panel, from panel.hostname in config.yaml. Protected: it is how limen is reached."
	h.Domains = []string{p.Hostname}
	h.Websockets = true
	if p.IsUnixSocket() {
		h.Forward = model.Upstream{Scheme: "http", Socket: p.Listen}
	} else {
		host, port, err := net.SplitHostPort(p.Listen)
		if err != nil {
			return nil, err
		}
		n, _ := strconv.Atoi(port)
		h.Forward = model.Upstream{Scheme: "http", Host: host, Port: n}
	}
	switch p.Certificate {
	case "":
	case config.PanelCertificateACME:
		h.TLS = model.TLS{Certificate: PanelHost, ForceHTTPS: true, HTTP2: true}
	default:
		h.TLS = model.TLS{Certificate: p.Certificate, ForceHTTPS: true, HTTP2: true}
	}
	return h, nil
}

// DesiredPanelCertificate returns the certificate limen issues for its
// own panel, or nil when it issues none.
func DesiredPanelCertificate(cfg *config.Config) *model.Certificate {
	if cfg.Panel.Hostname == "" || cfg.Panel.Certificate != config.PanelCertificateACME {
		return nil
	}
	c := model.NewCertificate(PanelHost)
	c.Protected = true
	c.Description = "limen's own panel, from panel.certificate: acme in config.yaml."
	c.Domains = []string{cfg.Panel.Hostname}
	return c
}

// EnsurePanelHost makes the model agree with panel.hostname and
// panel.certificate: it creates or updates the protected host and, with
// "acme", its protected certificate; it removes them when the
// configuration no longer asks for them. It reports whether it changed
// anything.
func EnsurePanelHost(s *store.Store, cfg *config.Config) (bool, error) {
	wantHost, err := DesiredPanelHost(cfg)
	if err != nil {
		return false, err
	}
	wantCert := DesiredPanelCertificate(cfg)
	changed := false
	ch := store.Change{Author: "limen", Source: "config", Note: "panel settings in config.yaml"}

	err = s.Locked(func() error {
		// The certificate first: the host refers to it.
		if wantCert != nil {
			c, err := ensureOwn(s, model.KindCertificate, wantCert, samePanelCert, ch)
			changed = changed || c
			if err != nil {
				return err
			}
		}
		if wantHost != nil {
			c, err := ensureOwn(s, model.KindProxyHost, wantHost, samePanelHost, ch)
			changed = changed || c
			if err != nil {
				return err
			}
		} else if removed, err := removeOwn(s, model.KindProxyHost, ch); err != nil {
			return err
		} else {
			changed = changed || removed
		}
		// And removed last, once nothing refers to it.
		if wantCert == nil {
			removed, err := removeOwn(s, model.KindCertificate, ch)
			changed = changed || removed
			return err
		}
		return nil
	})
	return changed, err
}

// ensureOwn puts one of limen's own documents, unless it is already as
// wanted. A document of the same name that is not protected belongs to
// someone else, and is never overwritten.
func ensureOwn(s *store.Store, kind model.Kind, want model.Document, same func(a, b model.Document) bool, ch store.Change) (bool, error) {
	current, err := s.Get(kind, PanelHost)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if err == nil {
		if !current.Header().Protected {
			return false, fmt.Errorf("a %s named %q already exists and is not limen's: rename it", kind, PanelHost)
		}
		if same(current, want) {
			return false, nil
		}
	}
	_, err = s.Put(want, ch)
	return err == nil, err
}

func removeOwn(s *store.Store, kind model.Kind, ch store.Change) (bool, error) {
	current, err := s.Get(kind, PanelHost)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !current.Header().Protected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, s.DeleteProtected(kind, PanelHost, ch)
}

func samePanelHost(x, y model.Document) bool {
	a, b := x.(*model.ProxyHost), y.(*model.ProxyHost)
	return a.Protected == b.Protected && a.Enabled == b.Enabled &&
		slices.Equal(a.Domains, b.Domains) && a.Forward == b.Forward &&
		a.TLS == b.TLS && a.Websockets == b.Websockets && a.Description == b.Description
}

func samePanelCert(x, y model.Document) bool {
	a, b := x.(*model.Certificate), y.(*model.Certificate)
	return a.Protected == b.Protected && slices.Equal(a.Domains, b.Domains) &&
		a.Provider == b.Provider && a.Challenge == b.Challenge && a.Description == b.Description
}
