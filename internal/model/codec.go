package model

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// New returns an empty document of the given kind, carrying every
// default.
func New(kind Kind, name string) (Document, error) {
	switch kind {
	case KindProxyHost:
		return NewProxyHost(name), nil
	case KindRedirect:
		return NewRedirect(name), nil
	case KindStream:
		return NewStream(name), nil
	case KindAccessList:
		return NewAccessList(name), nil
	case KindUser:
		return NewUser(name), nil
	case KindCertificate:
		return NewCertificate(name), nil
	}
	return nil, fmt.Errorf("unknown kind %q", kind)
}

// Decode reads a document of the given kind on top of its defaults.
// It does not validate: the caller decides what an invalid document
// means (a warning when loading, a refusal when writing).
func Decode(kind Kind, name string, b []byte) (Document, error) {
	doc, err := New(kind, name)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	// A misspelled field in a hand-written file must be an error, not
	// a setting that silently does nothing: "acess_list: staff" would
	// otherwise publish the host unguarded.
	dec.KnownFields(true)
	if err := dec.Decode(doc); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty file is a document made only of defaults.
			return doc, nil
		}
		return nil, cleanYAMLError(err)
	}
	return doc, nil
}

var notFoundRe = regexp.MustCompile(`field (\S+) not found in type \S+`)

// cleanYAMLError turns the decoder's message, written for a Go
// programmer ("field x not found in type model.ProxyHost"), into one
// line an operator can act on ("line 5: unknown field x").
func cleanYAMLError(err error) error {
	var te *yaml.TypeError
	if !errors.As(err, &te) {
		return err
	}
	msgs := make([]string, 0, len(te.Errors))
	for _, m := range te.Errors {
		msgs = append(msgs, notFoundRe.ReplaceAllString(m, "unknown field $1"))
	}
	return errors.New(strings.Join(msgs, "; "))
}

var headers = map[Kind]string{
	KindProxyHost:   "limen proxy host",
	KindRedirect:    "limen redirect",
	KindStream:      "limen stream",
	KindAccessList:  "limen access list",
	KindUser:        "limen panel user",
	KindCertificate: "limen certificate",
}

// Encode renders a document as the YAML file limen writes. The header
// tells whoever opens the file that editing it by hand is fine.
func Encode(doc Document) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# %s. Written by limen; hand edits are welcome:\n", headers[doc.Header().Kind])
	buf.WriteString("# run `systemctl reload limen` afterwards to load them.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Clone returns a deep copy, so that a caller holding a document can
// never mutate what the store keeps.
func Clone(doc Document) Document {
	switch d := doc.(type) {
	case *ProxyHost:
		c := *d
		c.Domains = slices.Clone(d.Domains)
		c.Proxy.RequestHeaders = slices.Clone(d.Proxy.RequestHeaders)
		c.Proxy.ResponseHeaders = slices.Clone(d.Proxy.ResponseHeaders)
		c.Locations = slices.Clone(d.Locations)
		for i, l := range c.Locations {
			if l.Forward != nil {
				f := *l.Forward
				c.Locations[i].Forward = &f
			}
		}
		return &c
	case *Redirect:
		c := *d
		c.Domains = slices.Clone(d.Domains)
		return &c
	case *Stream:
		c := *d
		c.Protocols = slices.Clone(d.Protocols)
		return &c
	case *AccessList:
		c := *d
		c.Users = slices.Clone(d.Users)
		c.Rules = slices.Clone(d.Rules)
		return &c
	case *User:
		c := *d
		return &c
	case *Certificate:
		c := *d
		c.Domains = slices.Clone(d.Domains)
		return &c
	}
	panic(fmt.Sprintf("model.Clone: unhandled document type %T", doc))
}

// Domains returns the server names a document answers on, for the
// documents that have any.
func Domains(doc Document) []string {
	switch d := doc.(type) {
	case *ProxyHost:
		return d.Domains
	case *Redirect:
		return d.Domains
	}
	return nil
}

// Enabled reports whether a document is switched on. Access lists and
// users have no such switch of their own.
func Enabled(doc Document) bool {
	switch d := doc.(type) {
	case *ProxyHost:
		return d.Enabled
	case *Redirect:
		return d.Enabled
	case *Stream:
		return d.Enabled
	case *User:
		return !d.Disabled
	}
	return true
}
