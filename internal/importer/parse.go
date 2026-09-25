// Package importer reads an existing nginx configuration and turns what
// it can represent faithfully into limen documents.
//
// Faithfully is the point. A server block that does something the model
// cannot say (serve files, run PHP, route /api elsewhere) is not
// approximated: it is left out, with the file, the line and the reason.
// And a server guarded in a way limen cannot reproduce is never
// imported unguarded.
package importer

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ostap-mykhaylyak/limen/internal/model"
)

// Directive is one nginx directive, with its block when it has one.
type Directive struct {
	Name  string
	Args  []string
	Block []*Directive
	File  string
	Line  int
	// HasBlock tells "events {}" (an empty block) from "events;".
	HasBlock bool
}

// At renders where the directive comes from.
func (d *Directive) At() string { return fmt.Sprintf("%s:%d", d.File, d.Line) }

// Arg returns the i-th argument, or "".
func (d *Directive) Arg(i int) string {
	if i < len(d.Args) {
		return d.Args[i]
	}
	return ""
}

// Parser reads a configuration and follows its includes.
type Parser struct {
	// Rebase maps an absolute path in the configuration to where the
	// file actually is: a backup of /etc/nginx lives elsewhere, but its
	// includes still say /etc/nginx.
	Rebase func(string) string

	root  string // the directory relative includes resolve against
	depth int
	Notes []string
}

// ParseFile parses a main configuration file.
func (p *Parser) ParseFile(path string) ([]*Directive, error) {
	p.root = filepath.Dir(path)
	return p.parse(path)
}

func (p *Parser) parse(path string) ([]*Directive, error) {
	if p.depth > 16 {
		return nil, fmt.Errorf("%s: includes nested too deep", path)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	toks := tokenize(string(src))
	pos := 0
	p.depth++
	defer func() { p.depth-- }()
	return p.block(toks, &pos, path, false)
}

func (p *Parser) block(toks []token, pos *int, file string, inner bool) ([]*Directive, error) {
	var out []*Directive
	for *pos < len(toks) {
		t := toks[*pos]
		switch t.kind {
		case tokClose:
			if !inner {
				return nil, fmt.Errorf("%s:%d: unexpected }", file, t.line)
			}
			*pos++
			return out, nil
		case tokSemi, tokOpen:
			return nil, fmt.Errorf("%s:%d: unexpected %q", file, t.line, t.text)
		}

		d := &Directive{Name: t.text, File: file, Line: t.line}
		*pos++
		for *pos < len(toks) && toks[*pos].kind == tokWord {
			d.Args = append(d.Args, toks[*pos].text)
			*pos++
		}
		if *pos >= len(toks) {
			return nil, fmt.Errorf("%s:%d: %s is not terminated", file, d.Line, d.Name)
		}
		switch toks[*pos].kind {
		case tokSemi:
			*pos++
		case tokOpen:
			*pos++
			d.HasBlock = true
			children, err := p.block(toks, pos, file, true)
			if err != nil {
				return nil, err
			}
			d.Block = children
		default:
			return nil, fmt.Errorf("%s:%d: unexpected }", file, toks[*pos].line)
		}

		if d.Name == "include" && !d.HasBlock {
			included, err := p.include(d)
			if err != nil {
				return nil, err
			}
			out = append(out, included...)
			continue
		}
		out = append(out, d)
	}
	if inner {
		return nil, fmt.Errorf("%s: a block is not closed", file)
	}
	return out, nil
}

// include inlines the files an include names. A pattern that matches
// nothing is fine, as it is for nginx; a single file that is missing is
// noted and skipped, since its content cannot be judged.
func (p *Parser) include(d *Directive) ([]*Directive, error) {
	pattern := d.Arg(0)
	if !filepath.IsAbs(pattern) && !strings.HasPrefix(pattern, "/") {
		pattern = filepath.Join(p.root, pattern)
	} else if p.Rebase != nil {
		pattern = p.Rebase(pattern)
	}
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("%s: include %q: %w", d.At(), d.Arg(0), err)
	}
	if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
		p.Notes = append(p.Notes, fmt.Sprintf("%s: include %s: file not found, its content is not imported", d.At(), d.Arg(0)))
		return nil, nil
	}
	sort.Strings(matches)
	var out []*Directive
	for _, m := range matches {
		if info, err := os.Stat(m); err != nil || info.IsDir() {
			continue
		}
		ds, err := p.parse(m)
		if err != nil {
			return nil, err
		}
		out = append(out, ds...)
	}
	return out, nil
}

// Find returns the direct children with the given name.
func Find(ds []*Directive, name string) []*Directive {
	var out []*Directive
	for _, d := range ds {
		if d.Name == name {
			out = append(out, d)
		}
	}
	return out
}

// First returns the first direct child with the given name, or nil.
func First(ds []*Directive, name string) *Directive {
	for _, d := range ds {
		if d.Name == name {
			return d
		}
	}
	return nil
}

// ---------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------

type tokenKind int

const (
	tokWord tokenKind = iota
	tokSemi
	tokOpen
	tokClose
)

type token struct {
	kind tokenKind
	text string
	line int
}

// tokenize splits a configuration into words, ';', '{' and '}'.
// Comments run to the end of the line; quotes group a word and allow
// backslash escapes.
func tokenize(src string) []token {
	var toks []token
	var cur strings.Builder
	quoted := false
	line, start := 1, 1

	flush := func() {
		if cur.Len() > 0 || quoted {
			toks = append(toks, token{tokWord, model.Unescape(cur.String()), start})
			cur.Reset()
			quoted = false
		}
	}
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if cur.Len() == 0 && !quoted {
			start = line
		}
		switch ch {
		case '\n':
			flush()
			line++
		case '#':
			flush()
			for i < len(src) && src[i] != '\n' {
				i++
			}
			line++
		case '"', '\'':
			quote := ch
			quoted = true
			// Escapes are kept here and resolved at flush, as nginx
			// resolves them: \" is a quote, but \. stays \. for PCRE.
			for i++; i < len(src) && src[i] != quote; i++ {
				if src[i] == '\\' && i+1 < len(src) {
					cur.WriteByte(src[i])
					i++
				}
				if src[i] == '\n' {
					line++
				}
				cur.WriteByte(src[i])
			}
		case ' ', '\t', '\r':
			flush()
		case ';':
			flush()
			toks = append(toks, token{tokSemi, ";", line})
		case '{':
			flush()
			toks = append(toks, token{tokOpen, "{", line})
		case '}':
			flush()
			toks = append(toks, token{tokClose, "}", line})
		default:
			cur.WriteByte(ch)
		}
	}
	flush()
	return toks
}
