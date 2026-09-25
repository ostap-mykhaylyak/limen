package nginx

import (
	"fmt"
	"strings"
)

// raw is a directive argument written by limen itself, which may carry
// nginx variables ("$host$request_uri") or quotes. Anything that comes
// from the model is a plain string and goes through the safety check.
type raw string

// quoted is an argument written between double quotes, whatever it
// holds: what an operator wrote in a snippet or a header value. Every
// backslash and double quote is escaped, so nginx reads back exactly
// the string — a ; or a } inside is data, never the end of a directive
// or a block. Variables ($request_id) keep working: nginx expands them
// inside quotes.
type quoted string

func (q quoted) String() string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(string(q)) + `"`
}

// conf builds one nginx configuration file.
//
// Model values are validated long before they get here; conf checks
// them once more, at the last moment, because a value that slips
// through with a ';' or a '}' would not just break one host — it would
// let a document write arbitrary directives into the configuration of
// the whole machine. A value that fails the check makes the file fail,
// and the document is left out.
type conf struct {
	b     strings.Builder
	depth int
	err   error
}

// unsafe lists what may never appear in a model value written into
// the configuration.
const unsafe = " \t\r\n;{}\"'\\$#"

func (c *conf) arg(a any) string {
	switch v := a.(type) {
	case raw:
		return string(v)
	case quoted:
		// Control characters are refused before, by the model; a
		// newline would still be harmless inside quotes, but nothing
		// that is not printable belongs in a configuration.
		if strings.ContainsFunc(string(v), func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			if c.err == nil {
				c.err = fmt.Errorf("refusing to write a control character into the nginx configuration")
			}
			return `"invalid"`
		}
		return v.String()
	case string:
		if v == "" || strings.ContainsAny(v, unsafe) {
			if c.err == nil {
				c.err = fmt.Errorf("refusing to write %q into the nginx configuration", v)
			}
			return "invalid"
		}
		return v
	case int:
		return fmt.Sprint(v)
	}
	panic(fmt.Sprintf("nginx.conf: unsupported argument type %T", a))
}

func (c *conf) indent() {
	c.b.WriteString(strings.Repeat("    ", c.depth))
}

// d writes one directive.
func (c *conf) d(name string, args ...any) {
	c.indent()
	c.b.WriteString(name)
	for _, a := range args {
		c.b.WriteByte(' ')
		c.b.WriteString(c.arg(a))
	}
	c.b.WriteString(";\n")
}

// block writes name args { body }.
func (c *conf) block(name string, args []any, body func()) {
	c.indent()
	c.b.WriteString(name)
	for _, a := range args {
		c.b.WriteByte(' ')
		c.b.WriteString(c.arg(a))
	}
	c.b.WriteString(" {\n")
	c.depth++
	body()
	c.depth--
	c.indent()
	c.b.WriteString("}\n")
}

// comment writes a comment line. Newlines are flattened: a comment must
// never be able to end early and turn its tail into directives.
func (c *conf) comment(format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	text = strings.NewReplacer("\n", " ", "\r", " ").Replace(text)
	c.indent()
	c.b.WriteString("# ")
	c.b.WriteString(text)
	c.b.WriteByte('\n')
}

func (c *conf) blank() { c.b.WriteByte('\n') }

// text appends verbatim configuration written by limen itself.
func (c *conf) text(s string) { c.b.WriteString(s) }

func (c *conf) bytes() ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	return []byte(c.b.String()), nil
}

// args turns strings into block arguments.
func args(a ...any) []any { return a }
