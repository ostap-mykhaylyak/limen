package main

// The object commands: a noun (host, redirect, stream, access, user),
// then a verb (list, show, add, set, rm, enable, disable, ...).
//
// They work on the files, not through the daemon. The model is meant
// to be manageable when the panel is down — that is the whole point of
// keeping it in plain files — so the command line edits it directly,
// under the same lock and the same checks as the panel, and then asks
// the running daemon (if any) to reload.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"text/tabwriter"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/auth"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/logging"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/nginx"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
	"github.com/ostap-mykhaylyak/limen/internal/proc"
	"github.com/ostap-mykhaylyak/limen/internal/secret"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

// objectCommands are the model commands: bare nouns followed by a verb,
// like `systemctl` or `incus`.
var objectCommands = map[string]bool{
	"host":     true,
	"redirect": true,
	"stream":   true,
	"access":   true,
	"user":     true,
	"cert":     true,
	"history":  true,
	"rollback": true,
	"apply":    true,
	"logs":     true,
	"token":    true,
}

// cli carries what every object command needs. Tests build one on a
// temporary store.
type cli struct {
	store        *store.Store
	out          io.Writer
	errOut       io.Writer
	author       string
	nudge        func() string
	readPassword func(prompt string) (string, error)

	// apply pushes the model to nginx. nil in tests that are about the
	// model only.
	apply func(dryRun bool) (nginx.Result, error)

	// certs overrides the certificates directory, for tests.
	certs string

	// config reads config.yaml; tests give their own.
	config func() (*config.Config, error)

	// tokens are the API tokens; opened on first use, or by tests.
	tokens *auth.Tokens
}

// runObject is the entry point from main.
func runObject(noun string, args []string) error {
	s, err := store.Open(store.DefaultDirs())
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("%w (the model is readable by root only)", err)
		}
		return err
	}
	c := &cli{
		store:        s,
		out:          os.Stdout,
		errOut:       os.Stderr,
		author:       operator(),
		nudge:        nudgeDaemon,
		readPassword: readPasswordFromStdin,
		apply:        applier(s),
	}
	return c.run(noun, args)
}

var errNoNginx = errors.New("nginx not found")

// applier builds the same engine the daemon uses, on the configuration
// on disk. The command line applies by itself instead of asking the
// daemon to: the operator sees at once whether nginx took the change,
// and it works when the daemon is not running.
func applier(s *store.Store) func(bool) (nginx.Result, error) {
	return func(dryRun bool) (nginx.Result, error) {
		cfg, err := config.Load(paths.ConfigFile)
		if err != nil {
			return nginx.Result{}, fmt.Errorf("configuration: %w", err)
		}
		if _, err := os.Stat(cfg.Nginx.Bin); err != nil {
			return nginx.Result{}, fmt.Errorf("%w at %s", errNoNginx, cfg.Nginx.Bin)
		}
		if !dryRun {
			if _, err := nginx.EnsurePanelHost(s, cfg); err != nil {
				return nginx.Result{}, fmt.Errorf("panel host: %w", err)
			}
		}
		engine := &nginx.Engine{
			Store:    s,
			Config:   func() *config.Config { return cfg },
			CertsDir: paths.CertsDir,
			LockPath: paths.ApplyLock,
		}
		if logs, err := logging.Open(paths.LogDir, logging.Level(cfg.Log.Level)); err == nil {
			defer logs.Close()
			engine.Log = logs.Apply.With("via", "cli", "author", operator())
		}
		return engine.Apply(context.Background(), dryRun)
	}
}

var errUsage = errors.New("usage")

func (c *cli) run(noun string, args []string) error {
	switch noun {
	case "history":
		return c.history(args)
	case "rollback":
		return c.rollback(args)
	case "apply":
		return c.applyCmd(args)
	case "logs":
		return c.logsCmd(args)
	case "token":
		return c.tokenCmd(args)
	}

	kind, err := model.ParseKind(noun)
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		c.objectUsage(kind)
		if len(args) == 0 {
			return errUsage
		}
		return nil
	}

	verb, rest := args[0], args[1:]
	switch verb {
	case "list", "ls":
		return c.list(kind, rest)
	case "show":
		return c.show(kind, rest)
	case "add":
		return c.write(kind, rest, true)
	case "set":
		return c.write(kind, rest, false)
	case "rm", "delete":
		return c.remove(kind, rest)
	case "enable", "disable":
		if kind == model.KindAccessList || kind == model.KindCertificate {
			break
		}
		return c.toggle(kind, rest, verb == "enable")
	case "passwd":
		switch kind {
		case model.KindUser:
			return c.userPasswd(rest)
		case model.KindAccessList:
			return c.accessPasswd(rest)
		}
	case "deluser":
		if kind == model.KindAccessList {
			return c.accessDelUser(rest)
		}
	case "renew":
		if kind == model.KindCertificate {
			return c.certRenew(rest)
		}
	case "import":
		if kind == model.KindCertificate {
			return c.certImport(rest)
		}
	case "location":
		if kind == model.KindProxyHost {
			return c.location(rest)
		}
	case "logs":
		if kind == model.KindProxyHost {
			return c.hostLogs(rest)
		}
	}
	c.objectUsage(kind)
	return fmt.Errorf("%s: unknown command %q", noun, verb)
}

// ---------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------

func (c *cli) list(kind model.Kind, args []string) error {
	fs := c.flags(noun(kind) + " list")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := c.parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("list takes no arguments")
	}

	docs := c.store.List(kind)
	if *asJSON {
		return writeJSON(c.out, docs)
	}
	for _, w := range c.store.Warnings() {
		fmt.Fprintf(c.errOut, "warning: %s\n", w)
	}
	if len(docs) == 0 {
		fmt.Fprintf(c.out, "no %s yet\n", plural(kind))
		return nil
	}

	if kind == model.KindCertificate {
		return c.listCerts(docs)
	}
	tw := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	switch kind {
	case model.KindProxyHost:
		fmt.Fprintln(tw, "NAME\tDOMAINS\tFORWARD\tTLS\tACCESS\tSTATE")
		for _, d := range docs {
			h := d.(*model.ProxyHost)
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.Name, strings.Join(h.Domains, ","),
				h.Forward, tlsSummary(h.TLS), dash(h.AccessList), state(h.Enabled, h.Protected))
		}
	case model.KindRedirect:
		fmt.Fprintln(tw, "NAME\tDOMAINS\tTARGET\tCODE\tTLS\tSTATE")
		for _, d := range docs {
			r := d.(*model.Redirect)
			target := r.Target.String()
			if r.Target.PreservePath {
				target += "/…"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", r.Name, strings.Join(r.Domains, ","),
				target, r.Code, tlsSummary(r.TLS), state(r.Enabled, r.Protected))
		}
	case model.KindStream:
		fmt.Fprintln(tw, "NAME\tLISTEN\tPROTOCOLS\tFORWARD\tSTATE")
		for _, d := range docs {
			s := d.(*model.Stream)
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n", s.Name, s.Listen,
				strings.Join(s.Protocols, ","), s.Forward, state(s.Enabled, s.Protected))
		}
	case model.KindAccessList:
		fmt.Fprintln(tw, "NAME\tUSERS\tRULES\tSATISFY\tGUARDS")
		for _, d := range docs {
			a := d.(*model.AccessList)
			satisfy := "all"
			if a.SatisfyAny {
				satisfy = "any"
			}
			fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\n", a.Name, len(a.Users), len(a.Rules),
				satisfy, dash(strings.Join(c.store.AccessUsers(a.Name), ",")))
		}
	case model.KindUser:
		fmt.Fprintln(tw, "NAME\tROLE\tEMAIL\tSTATE")
		for _, d := range docs {
			u := d.(*model.User)
			st := "active"
			if u.Disabled {
				st = "disabled"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", u.Name, u.Role, dash(u.Email), st)
		}
	}
	return tw.Flush()
}

func (c *cli) show(kind model.Kind, args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	fs := c.flags(noun(kind) + " show")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := c.parse(fs, rest); err != nil {
		return err
	}

	doc, err := c.store.Get(kind, name)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, doc)
	}
	b, err := model.Encode(redact(doc))
	if err != nil {
		return err
	}
	// Skip the file header: it speaks to someone editing the file.
	body := string(b)
	for strings.HasPrefix(body, "#") {
		_, body, _ = strings.Cut(body, "\n")
	}
	fmt.Fprint(c.out, body)
	if kind == model.KindAccessList {
		if hosts := c.store.AccessUsers(name); len(hosts) > 0 {
			fmt.Fprintf(c.out, "# guards: %s\n", strings.Join(hosts, ", "))
		}
	}
	if cert, ok := doc.(*model.Certificate); ok {
		c.showCertState(cert)
	}
	return nil
}

// redact hides password hashes from what is printed. They are not the
// passwords, but there is no reason to put them on a terminal either.
func redact(doc model.Document) model.Document {
	switch d := doc.(type) {
	case *model.User:
		d.Password = "(hidden)"
	case *model.AccessList:
		for i := range d.Users {
			d.Users[i].Password = "(hidden)"
		}
	}
	return doc
}

// ---------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------

// applyFunc copies the flags the operator actually passed onto a
// document. Flags that were not passed leave the document alone: on
// `add` it keeps its defaults, on `set` its current values.
type applyFunc func(doc model.Document, set map[string]bool) error

// binder declares the flags of a kind. firstDomain, when not nil,
// returns the first --domain, so that a host or a redirect can be
// named after it.
type binder func(fs *flag.FlagSet, create bool) (apply applyFunc, firstDomain func() string)

var binders = map[model.Kind]binder{
	model.KindProxyHost:   hostFlags,
	model.KindRedirect:    redirectFlags,
	model.KindStream:      streamFlags,
	model.KindAccessList:  accessFlags,
	model.KindUser:        userFlags,
	model.KindCertificate: certFlags,
}

func (c *cli) write(kind model.Kind, args []string, create bool) error {
	verb := "set"
	if create {
		verb = "add"
	}
	name, rest, err := takeName(args)
	if err != nil && !create {
		return err
	}

	fs := c.flags(noun(kind) + " " + verb)
	description := fs.String("description", "", "free text describing the object")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	apply, firstDomain := binders[kind](fs, create)
	var passwordStdin *bool
	if kind == model.KindUser {
		passwordStdin = fs.Bool("password-stdin", false, "read the password from stdin (prompted without echo on a terminal)")
	}
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := visited(fs)

	if name == "" {
		// `limen host add --domain app.example.com ...` names the host
		// after its first domain.
		if firstDomain == nil || firstDomain() == "" {
			return fmt.Errorf("a name is required: limen %s %s NAME [flags]", noun(kind), verb)
		}
		name = strings.Replace(firstDomain(), "*.", "wildcard.", 1)
	}
	if err := model.ValidateName(name); err != nil {
		return err
	}

	// Passwords are read and hashed before taking the lock: nobody
	// should hold the whole model while someone types.
	var hash string
	if kind == model.KindUser {
		if create && !*passwordStdin {
			return fmt.Errorf("a new user needs a password: pass --password-stdin")
		}
		if *passwordStdin {
			if hash, err = c.panelPassword(); err != nil {
				return err
			}
		}
	}
	if kind == model.KindAccessList && create && set["user"] {
		if hash, err = c.basicPassword(); err != nil {
			return err
		}
	}

	var stored model.Document
	err = c.store.Locked(func() error {
		var doc model.Document
		current, err := c.store.Get(kind, name)
		switch {
		case create && err == nil:
			return fmt.Errorf("%s %q already exists: use `limen %s set %s`", kind, name, noun(kind), name)
		case create:
			doc, _ = model.New(kind, name)
		case err != nil:
			return err
		default:
			doc = current
		}

		if err := apply(doc, set); err != nil {
			return err
		}
		if set["description"] {
			doc.Header().Description = *description
		}
		if hash != "" {
			switch d := doc.(type) {
			case *model.User:
				d.Password = hash
			case *model.AccessList:
				d.Users[len(d.Users)-1].Password = hash
			}
		}
		stored, err = c.store.Put(doc, c.change(*note))
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s %q saved\n", kind, stored.Header().Name)
	return c.afterWrite(kind)
}

func (c *cli) remove(kind model.Kind, args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	fs := c.flags(noun(kind) + " rm")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	if err := c.store.Locked(func() error {
		return c.store.Delete(kind, name, c.change(*note))
	}); err != nil {
		return err
	}
	if kind == model.KindCertificate {
		// Moved aside, not destroyed: an uploaded certificate cannot be
		// issued again if the deletion is rolled back.
		if err := acme.Trash(c.certsDir(), name); err != nil {
			fmt.Fprintf(c.errOut, "warning: the certificate files stay in place: %v\n", err)
		}
	}
	fmt.Fprintf(c.out, "%s %q deleted (bring it back with `limen history %s %s`)\n", kind, name, noun(kind), name)
	if kind == model.KindUser {
		// Revoked, not orphaned: a rollback of the user must not bring
		// its keys back with it.
		tokens, err := c.openTokens()
		if err == nil {
			var n int
			if n, err = tokens.DeleteUser(name); n > 0 {
				fmt.Fprintf(c.out, "%d API token(s) of %s revoked\n", n, name)
			}
		}
		if err != nil {
			fmt.Fprintf(c.errOut, "warning: the API tokens of %s were not revoked: %v (run `limen token list`)\n", name, err)
		}
	}
	return c.afterWrite(kind)
}

func (c *cli) toggle(kind model.Kind, args []string, on bool) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	verb := "disable"
	if on {
		verb = "enable"
	}
	fs := c.flags(noun(kind) + " " + verb)
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	err = c.store.Locked(func() error {
		doc, err := c.store.Get(kind, name)
		if err != nil {
			return err
		}
		switch d := doc.(type) {
		case *model.ProxyHost:
			d.Enabled = on
		case *model.Redirect:
			d.Enabled = on
		case *model.Stream:
			d.Enabled = on
		case *model.User:
			d.Disabled = !on
		}
		_, err = c.store.Put(doc, c.change(*note))
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s %q %sd\n", kind, name, verb)
	return c.afterWrite(kind)
}

func (c *cli) userPasswd(args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	fs := c.flags("user passwd")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	if _, err := c.store.Get(model.KindUser, name); err != nil {
		return err
	}
	hash, err := c.panelPassword()
	if err != nil {
		return err
	}
	err = c.store.Locked(func() error {
		doc, err := c.store.Get(model.KindUser, name)
		if err != nil {
			return err
		}
		doc.(*model.User).Password = hash
		_, err = c.store.Put(doc, c.change(*note))
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "password of user %q changed\n", name)
	return c.afterWrite(model.KindUser)
}

// accessPasswd adds a basic-auth user to an access list, or changes the
// password of one already there.
func (c *cli) accessPasswd(args []string) error {
	list, rest, err := takeName(args)
	if err != nil {
		return err
	}
	username, rest, err := takeName(rest)
	if err != nil {
		return fmt.Errorf("usage: limen access passwd LIST USERNAME")
	}
	fs := c.flags("access passwd")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	if _, err := c.store.Get(model.KindAccessList, list); err != nil {
		return err
	}
	hash, err := c.basicPassword()
	if err != nil {
		return err
	}
	added := false
	err = c.store.Locked(func() error {
		doc, err := c.store.Get(model.KindAccessList, list)
		if err != nil {
			return err
		}
		a := doc.(*model.AccessList)
		added = true
		for i := range a.Users {
			if a.Users[i].Username == username {
				a.Users[i].Password = hash
				added = false
			}
		}
		if added {
			a.Users = append(a.Users, model.BasicUser{Username: username, Password: hash})
		}
		_, err = c.store.Put(a, c.change(*note))
		return err
	})
	if err != nil {
		return err
	}
	if added {
		fmt.Fprintf(c.out, "user %q added to access list %q\n", username, list)
	} else {
		fmt.Fprintf(c.out, "password of %q in access list %q changed\n", username, list)
	}
	return c.afterWrite(model.KindAccessList)
}

func (c *cli) accessDelUser(args []string) error {
	list, rest, err := takeName(args)
	if err != nil {
		return err
	}
	username, rest, err := takeName(rest)
	if err != nil {
		return fmt.Errorf("usage: limen access deluser LIST USERNAME")
	}
	fs := c.flags("access deluser")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	err = c.store.Locked(func() error {
		doc, err := c.store.Get(model.KindAccessList, list)
		if err != nil {
			return err
		}
		a := doc.(*model.AccessList)
		kept := a.Users[:0]
		for _, u := range a.Users {
			if u.Username != username {
				kept = append(kept, u)
			}
		}
		if len(kept) == len(a.Users) {
			return fmt.Errorf("access list %q has no user %q: %w", list, username, store.ErrNotFound)
		}
		a.Users = kept
		_, err = c.store.Put(a, c.change(*note))
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "user %q removed from access list %q\n", username, list)
	return c.afterWrite(model.KindAccessList)
}

// ---------------------------------------------------------------------
// History
// ---------------------------------------------------------------------

func (c *cli) history(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: limen history KIND NAME")
	}
	kind, err := model.ParseKind(args[0])
	if err != nil {
		return err
	}
	fs := c.flags("history")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := c.parse(fs, args[2:]); err != nil {
		return err
	}
	revs, err := c.store.History(kind, args[1])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(c.out, revs)
	}
	if len(revs) == 0 {
		fmt.Fprintf(c.out, "%s %q has no history\n", kind, args[1])
		return nil
	}
	fmt.Fprintln(c.out, "Each revision is the document as it was just before the change on its line.")
	tw := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "REVISION\tWHEN\tCHANGE\tBY\tVIA\tNOTE")
	for _, r := range revs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Time.Local().Format("2006-01-02 15:04:05"),
			r.Action, dash(r.Author), dash(r.Source), r.Note)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "\nRestore one with: limen rollback %s %s REVISION\n", noun(kind), args[1])
	return nil
}

func (c *cli) rollback(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: limen rollback KIND NAME REVISION")
	}
	kind, err := model.ParseKind(args[0])
	if err != nil {
		return err
	}
	name, id := args[1], args[2]
	fs := c.flags("rollback")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, args[3:]); err != nil {
		return err
	}
	err = c.store.Locked(func() error {
		ch := c.change(*note)
		ch.Source = "rollback"
		_, err := c.store.Rollback(kind, name, id, ch)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "%s %q rolled back to %s (the version it replaced is in the history)\n", kind, name, id)
	return c.afterWrite(kind)
}

// ---------------------------------------------------------------------
// Flags per kind
// ---------------------------------------------------------------------

func hostFlags(fs *flag.FlagSet, create bool) (applyFunc, func() string) {
	var domains stringList
	fs.Var(&domains, "domain", "server name, repeat for more (replaces the whole list)")
	forward := fs.String("forward", "", "backend, e.g. http://10.0.0.5:8080")
	verify := fs.Bool("verify-tls", false, "verify the backend certificate (https backends)")
	tls := tlsFlags(fs)
	acl := fs.String("access-list", "", "access list guarding the host (empty: none)")
	ws := fs.Bool("websockets", false, "allow websocket upgrades")
	block := fs.Bool("block-exploits", true, "block common exploit patterns")
	cache := fs.Bool("cache-assets", false, "cache static assets")
	maxBody := fs.String("max-body", "", "largest request body, e.g. 100m (empty: the global default)")
	proxy := proxyFlags(fs)
	disabled := addOnlyDisabled(fs, create)

	return func(doc model.Document, set map[string]bool) error {
		h := doc.(*model.ProxyHost)
		if err := proxy(h, set); err != nil {
			return err
		}
		if set["domain"] {
			h.Domains = lower(domains)
		}
		if set["forward"] {
			up, err := model.ParseUpstream(*forward)
			if err != nil {
				return err
			}
			up.VerifyTLS = h.Forward.VerifyTLS
			h.Forward = up
		}
		if set["verify-tls"] {
			h.Forward.VerifyTLS = *verify
		}
		tls(&h.TLS, set)
		if set["access-list"] {
			h.AccessList = *acl
		}
		if set["websockets"] {
			h.Websockets = *ws
		}
		if set["block-exploits"] {
			h.BlockExploits = *block
		}
		if set["cache-assets"] {
			h.CacheAssets = *cache
		}
		if set["max-body"] {
			h.ClientMaxBodySize = *maxBody
		}
		if set["disabled"] {
			h.Enabled = !*disabled
		}
		return nil
	}, domains.first
}

func redirectFlags(fs *flag.FlagSet, create bool) (applyFunc, func() string) {
	var domains stringList
	fs.Var(&domains, "domain", "server name, repeat for more (replaces the whole list)")
	to := fs.String("to", "", "destination, e.g. https://new.example.com (no scheme: keep the request's)")
	code := fs.Int("code", 301, "301, 302, 307 or 308")
	preserve := fs.Bool("preserve-path", true, "append the original path and query")
	tls := tlsFlags(fs)
	block := fs.Bool("block-exploits", true, "block common exploit patterns")
	disabled := addOnlyDisabled(fs, create)

	return func(doc model.Document, set map[string]bool) error {
		r := doc.(*model.Redirect)
		if set["domain"] {
			r.Domains = lower(domains)
		}
		if set["to"] {
			target, err := parseTarget(*to)
			if err != nil {
				return err
			}
			target.PreservePath = r.Target.PreservePath
			r.Target = target
		}
		if set["preserve-path"] {
			r.Target.PreservePath = *preserve
		}
		if set["code"] {
			r.Code = *code
		}
		tls(&r.TLS, set)
		if set["block-exploits"] {
			r.BlockExploits = *block
		}
		if set["disabled"] {
			r.Enabled = !*disabled
		}
		return nil
	}, domains.first
}

func streamFlags(fs *flag.FlagSet, create bool) (applyFunc, func() string) {
	listen := fs.Int("listen", 0, "port nginx listens on")
	forward := fs.String("forward", "", "backend host:port")
	protocol := fs.String("protocol", "tcp", "tcp, udp or tcp,udp")
	acl := fs.String("access-list", "", "access list of address rules restricting who may connect (empty: none)")
	disabled := addOnlyDisabled(fs, create)

	return func(doc model.Document, set map[string]bool) error {
		s := doc.(*model.Stream)
		if set["listen"] {
			s.Listen = *listen
		}
		if set["forward"] {
			ep, err := model.ParseEndpoint(*forward)
			if err != nil {
				return err
			}
			s.Forward = ep
		}
		if set["protocol"] {
			s.Protocols = splitList(*protocol)
		}
		if set["access-list"] {
			s.AccessList = *acl
		}
		if set["disabled"] {
			s.Enabled = !*disabled
		}
		return nil
	}, nil
}

func accessFlags(fs *flag.FlagSet, create bool) (applyFunc, func() string) {
	var rules stringList
	fs.Var(&rules, "rule", "allow:ADDRESS or deny:ADDRESS, in order; repeat (replaces all rules)")
	satisfyAny := fs.Bool("satisfy-any", false, "let in a request that passes the rules OR the password")
	passAuth := fs.Bool("pass-auth", false, "forward the Authorization header to the backend")
	var username *string
	if create {
		username = fs.String("user", "", "a first basic-auth user; the password is read from stdin")
	}

	return func(doc model.Document, set map[string]bool) error {
		a := doc.(*model.AccessList)
		if set["rule"] {
			a.Rules = nil
			for _, r := range rules {
				action, addr, ok := strings.Cut(r, ":")
				if !ok {
					return fmt.Errorf("--rule %q: want allow:ADDRESS or deny:ADDRESS", r)
				}
				a.Rules = append(a.Rules, model.Rule{Action: action, Address: addr})
			}
		}
		if set["satisfy-any"] {
			a.SatisfyAny = *satisfyAny
		}
		if set["pass-auth"] {
			a.PassAuth = *passAuth
		}
		if set["user"] {
			// The hash is filled in by the caller, once it has been read.
			a.Users = append(a.Users, model.BasicUser{Username: *username})
		}
		return nil
	}, nil
}

func userFlags(fs *flag.FlagSet, create bool) (applyFunc, func() string) {
	role := fs.String("role", model.RoleViewer, "admin, operator or viewer")
	email := fs.String("email", "", "e-mail address")
	fullName := fs.String("full-name", "", "full name")
	disabled := addOnlyDisabled(fs, create)

	return func(doc model.Document, set map[string]bool) error {
		u := doc.(*model.User)
		if set["role"] {
			u.Role = *role
		}
		if set["email"] {
			u.Email = *email
		}
		if set["full-name"] {
			u.FullName = *fullName
		}
		if set["disabled"] {
			u.Disabled = *disabled
		}
		return nil
	}, nil
}

// tlsFlags declares the HTTPS flags shared by hosts and redirects.
func tlsFlags(fs *flag.FlagSet) func(*model.TLS, map[string]bool) {
	cert := fs.String("certificate", "", "certificate to serve (empty: plain HTTP only)")
	force := fs.Bool("force-https", false, "redirect plain HTTP to HTTPS")
	http2 := fs.Bool("http2", true, "serve HTTP/2")
	hsts := fs.Bool("hsts", false, "send Strict-Transport-Security")
	hstsSub := fs.Bool("hsts-subdomains", false, "extend HSTS to every subdomain")
	return func(t *model.TLS, set map[string]bool) {
		if set["certificate"] {
			t.Certificate = *cert
		}
		if set["force-https"] {
			t.ForceHTTPS = *force
		}
		if set["http2"] {
			t.HTTP2 = *http2
		}
		if set["hsts"] {
			t.HSTS = *hsts
		}
		if set["hsts-subdomains"] {
			t.HSTSSubdomains = *hstsSub
		}
	}
}

// addOnlyDisabled declares --disabled on add. Afterwards, switching an
// object on and off is what `enable` and `disable` are for.
func addOnlyDisabled(fs *flag.FlagSet, create bool) *bool {
	if !create {
		v := false
		return &v
	}
	return fs.Bool("disabled", false, "create it switched off")
}

// parseTarget reads a redirect destination: "https://new.example.com",
// "new.example.com:8443" (scheme kept from the request).
func parseTarget(raw string) (model.Target, error) {
	t := model.Target{Scheme: "auto"}
	if scheme, rest, ok := strings.Cut(raw, "://"); ok {
		t.Scheme = scheme
		raw = rest
	}
	if strings.ContainsAny(raw, "/?#@") {
		return t, fmt.Errorf("--to %q: only a scheme, a host and a port are allowed", raw)
	}
	t.Domain = strings.ToLower(raw)
	return t, nil
}

// ---------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("limen "+name, flag.ContinueOnError)
	fs.SetOutput(c.errOut)
	return fs
}

// parse wraps FlagSet.Parse so that -h prints the flags and succeeds.
func (c *cli) parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return errHelpShown
		}
		return err
	}
	return nil
}

var errHelpShown = errors.New("help shown")

func (c *cli) change(note string) store.Change {
	return store.Change{Author: c.author, Source: "cli", Note: note}
}

// afterWrite pushes a saved change to nginx and tells the running
// daemon to pick it up. The change is saved whatever happens here: a
// failure says so, and leaves the model ahead of nginx until the next
// apply.
// afterWrite applies the model to nginx at once, so that the operator
// sees what nginx made of the change, then nudges the daemon. A panel
// user is nothing nginx sees: its change is not applied, so that the
// first admin, made on a fresh install, does not take nginx over before
// the operator starts limen.
func (c *cli) afterWrite(kind model.Kind) error {
	var applyErr error
	if c.apply != nil && kind != model.KindUser {
		res, err := c.apply(false)
		switch {
		case errors.Is(err, errNoNginx):
			fmt.Fprintf(c.out, "%v: the model is saved, nothing was applied\n", err)
		case err != nil:
			applyErr = fmt.Errorf("the change is saved, but nginx was not updated: %w", err)
		default:
			c.printApply(res)
		}
	}
	if c.nudge != nil {
		fmt.Fprintln(c.out, c.nudge())
	}
	return applyErr
}

func (c *cli) applyCmd(args []string) error {
	fs := c.flags("apply")
	dryRun := fs.Bool("dry-run", false, "render and test with nginx -t, change nothing")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := c.parse(fs, args); err != nil {
		return err
	}
	if c.apply == nil {
		return fmt.Errorf("no nginx engine available")
	}
	res, err := c.apply(*dryRun)
	if *asJSON {
		if jerr := writeJSON(c.out, res); jerr != nil {
			return jerr
		}
		return err
	}
	if err != nil {
		return err
	}
	c.printApply(res)
	if !*dryRun && c.nudge != nil && res.Changed {
		fmt.Fprintln(c.out, c.nudge())
	}
	return nil
}

func (c *cli) printApply(res nginx.Result) {
	switch {
	case res.DryRun && res.Changed:
		fmt.Fprintf(c.out, "nginx %s: the rendered configuration passes nginx -t (nothing installed)\n", res.NginxVersion)
	case res.DryRun:
		fmt.Fprintf(c.out, "nginx %s: nothing to change, generation %s is live\n", res.NginxVersion, res.Generation)
	case !res.Changed:
		fmt.Fprintf(c.out, "nginx: nothing to change, generation %s is live\n", res.Generation)
	case res.Reloaded:
		fmt.Fprintf(c.out, "nginx: generation %s installed and reloaded\n", res.Generation)
	case !res.NginxRunning:
		fmt.Fprintf(c.out, "nginx: generation %s installed; nginx is not running, it will use it when it starts\n", res.Generation)
	default:
		fmt.Fprintf(c.out, "nginx: generation %s installed\n", res.Generation)
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(c.out, "  left out: %s %q: %s\n", model.Kind(s.Kind), s.Name, s.Reason)
	}
	for _, w := range res.Warnings {
		fmt.Fprintf(c.out, "  warning: %s\n", w)
	}
}

func (c *cli) panelPassword() (string, error) {
	pw, err := c.readPassword("new password: ")
	if err != nil {
		return "", err
	}
	return secret.HashPanel(pw)
}

func (c *cli) basicPassword() (string, error) {
	pw, err := c.readPassword("password: ")
	if err != nil {
		return "", err
	}
	return secret.HashBasic(pw)
}

// takeName splits the leading positional name off the arguments.
func takeName(args []string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", args, fmt.Errorf("a name is required")
	}
	return args[0], args[1:], nil
}

func visited(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// nudgeDaemon asks the running daemon to reload the model.
func nudgeDaemon() string {
	switch err := proc.Reload(paths.Pidfile); {
	case err == nil:
		return "the running daemon has been asked to reload the model"
	case errors.Is(err, proc.ErrNotRunning):
		return "limen is not running: the change takes effect when it starts"
	default:
		return fmt.Sprintf("could not signal limen (%v): run `systemctl reload limen`", err)
	}
}

// operator names who is at the keyboard, for the history. Under sudo
// that is the person who ran sudo, not root.
func operator() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return "cli:" + u
	}
	if u, err := user.Current(); err == nil {
		return "cli:" + u.Username
	}
	return "cli"
}

// readPasswordFromStdin reads one line. On a terminal it prompts, turns
// echo off, and asks twice; from a pipe it reads the first line.
func readPasswordFromStdin(prompt string) (string, error) {
	info, err := os.Stdin.Stat()
	terminal := err == nil && info.Mode()&os.ModeCharDevice != 0
	reader := bufio.NewReader(os.Stdin)

	if !terminal {
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("no password on stdin")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	read := func(p string) (string, error) {
		fmt.Fprint(os.Stderr, p)
		// stty is the one portable way to stop the echo without a
		// dependency; if it is missing the password echoes, and we say so.
		if exec.Command("stty", "-F", "/dev/tty", "-echo").Run() != nil {
			fmt.Fprint(os.Stderr, "(echo could not be turned off) ")
		}
		defer func() {
			exec.Command("stty", "-F", "/dev/tty", "echo").Run()
			fmt.Fprintln(os.Stderr)
		}()
		line, err := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err
	}
	first, err := read(prompt)
	if err != nil {
		return "", err
	}
	again, err := read("again: ")
	if err != nil {
		return "", err
	}
	if first != again {
		return "", fmt.Errorf("the two passwords differ")
	}
	return first, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
func (s *stringList) first() string {
	if len(*s) == 0 {
		return ""
	}
	return strings.ToLower((*s)[0])
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, strings.ToLower(p))
		}
	}
	return out
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func tlsSummary(t model.TLS) string {
	if t.Certificate == "" {
		return "-"
	}
	s := t.Certificate
	if t.ForceHTTPS {
		s += " (forced)"
	}
	return s
}

func state(enabled, protected bool) string {
	s := "enabled"
	if !enabled {
		s = "disabled"
	}
	if protected {
		s += ", protected"
	}
	return s
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// noun is the command-line word for a kind.
func noun(k model.Kind) string {
	switch k {
	case model.KindProxyHost:
		return "host"
	case model.KindAccessList:
		return "access"
	case model.KindCertificate:
		return "cert"
	}
	return string(k)
}

func plural(k model.Kind) string {
	switch k {
	case model.KindProxyHost:
		return "proxy hosts"
	case model.KindAccessList:
		return "access lists"
	case model.KindCertificate:
		return "certificates"
	}
	return string(k) + "s"
}

func (c *cli) objectUsage(kind model.Kind) {
	n := noun(kind)
	w := c.errOut
	fmt.Fprintf(w, "usage: limen %s COMMAND [NAME] [flags]\n\n", n)
	fmt.Fprintf(w, "  list [--json]              every %s\n", strings.TrimSuffix(plural(kind), "s"))
	fmt.Fprintf(w, "  show NAME [--json]         one of them, as limen stores it\n")
	fmt.Fprintf(w, "  add NAME [flags]           create one (limen %s add -h for the flags)\n", n)
	fmt.Fprintf(w, "  set NAME [flags]           change only the flags you pass\n")
	fmt.Fprintf(w, "  rm NAME                    delete it (kept in the history)\n")
	switch kind {
	case model.KindAccessList:
		fmt.Fprintf(w, "  passwd NAME USERNAME       add a basic-auth user, or change its password\n")
		fmt.Fprintf(w, "  deluser NAME USERNAME      remove a basic-auth user\n")
	case model.KindUser:
		fmt.Fprintf(w, "  enable|disable NAME        let the user in, or keep them out\n")
		fmt.Fprintf(w, "  passwd NAME                change the password (read from stdin)\n")
	case model.KindProxyHost:
		fmt.Fprintf(w, "  enable|disable NAME        switch it on or off\n")
		fmt.Fprintf(w, "  location ...               custom locations (limen host location help)\n")
		fmt.Fprintf(w, "  logs NAME [--errors]       its requests or its errors (-n N, --follow, --grep, --status 5xx)\n")
	case model.KindCertificate:
		fmt.Fprintf(w, "  renew NAME                 ask the daemon to issue it again now\n")
		fmt.Fprintf(w, "  import NAME --chain F --key F   install a certificate issued elsewhere\n")
	default:
		fmt.Fprintf(w, "  enable|disable NAME        switch it on or off\n")
	}
	fmt.Fprintf(w, "\nEvery write takes --note \"why\", kept in `limen history %s NAME`.\n", n)
}
