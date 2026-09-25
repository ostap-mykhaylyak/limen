package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/auth"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
)

// `limen token add|list|rm`: the API tokens scripts use. The command
// line can make a token for any user — it runs as root, which could
// write the user's password anyway — while the panel makes tokens only
// for the user logged in.

func (c *cli) openTokens() (*auth.Tokens, error) {
	if c.tokens != nil {
		return c.tokens, nil
	}
	t, err := auth.OpenTokens(paths.TokensFile, paths.TokensLock)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("%w (the tokens are readable by root only)", err)
		}
		return nil, err
	}
	c.tokens = t
	return t, nil
}

func (c *cli) tokenUsage() {
	w := c.errOut
	fmt.Fprintln(w, "usage: limen token COMMAND [NAME] [flags]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  list [--json]                        every API token (never the secrets)")
	fmt.Fprintln(w, "  add NAME --user USER [flags]         make one; the token is printed once, on stdout")
	fmt.Fprintln(w, "      --role ROLE                      viewer, operator or admin (default: the user's)")
	fmt.Fprintln(w, "      --expires 90d                    30d, 12h, ... or never (default 90d)")
	fmt.Fprintln(w, "      --description TEXT               what it is for")
	fmt.Fprintln(w, "  rm NAME                              revoke it, at once")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Scripts send it as `Authorization: Bearer TOKEN`. A token acts as its user,")
	fmt.Fprintln(w, "never with more than the user's role, and stops working when the user is")
	fmt.Fprintln(w, "disabled or removed.")
}

func (c *cli) tokenCmd(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		c.tokenUsage()
		if len(args) == 0 {
			return errUsage
		}
		return nil
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "list", "ls":
		return c.tokenList(rest)
	case "add":
		return c.tokenAdd(rest)
	case "rm", "delete", "revoke":
		return c.tokenRemove(rest)
	}
	c.tokenUsage()
	return fmt.Errorf("unknown command %q for token", verb)
}

// parseLifetime reads 90d, 12h, 1h30m or never.
func parseLifetime(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "never" || s == "0" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > 3650 {
			return 0, fmt.Errorf("--expires %q: from 1d to 3650d, or never", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--expires %q: want 90d, 12h, ... or never", s)
	}
	return d, nil
}

func (c *cli) tokenAdd(args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	fs := c.flags("token add")
	userName := fs.String("user", "", "the panel user the token acts as (required)")
	role := fs.String("role", "", "viewer, operator or admin; never more than the user's")
	expires := fs.String("expires", "90d", "lifetime: 30d, 12h, ... or never")
	description := fs.String("description", "", "what the token is for")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *userName == "" {
		return fmt.Errorf("--user is required: the token acts as that panel user")
	}
	ttl, err := parseLifetime(*expires)
	if err != nil {
		return err
	}
	doc, err := c.store.Get(model.KindUser, *userName)
	if err != nil {
		return err
	}
	u := doc.(*model.User)
	if u.Disabled {
		return fmt.Errorf("user %q is disabled: its tokens would not work", u.Name)
	}
	if *role == "" {
		*role = u.Role
	}
	if _, ok := roleLevel[*role]; !ok {
		return fmt.Errorf("--role %q: want viewer, operator or admin", *role)
	}
	if roleLevel[*role] > roleLevel[u.Role] {
		return fmt.Errorf("--role %s: a token cannot have more than its user's role (%s)", *role, u.Role)
	}

	tokens, err := c.openTokens()
	if err != nil {
		return err
	}
	token, t, err := tokens.Create(auth.TokenSpec{
		Name: name, User: u.Name, UserCreated: u.Created, Role: *role,
		Description: *description, CreatedBy: c.author, TTL: ttl,
	})
	if err != nil {
		return err
	}
	// The token alone on stdout, so that a script can take it; the rest
	// on stderr.
	fmt.Fprintln(c.out, token)
	when := "never expires"
	if !t.Expires.IsZero() {
		when = "expires " + t.Expires.Format(time.DateOnly)
	}
	fmt.Fprintf(c.errOut, "token %q made for %s, role %s, %s.\n", t.Name, t.User, t.Role, when)
	fmt.Fprintln(c.errOut, "It is shown this once: keep it in your secret store.")
	return nil
}

var roleLevel = map[string]int{model.RoleViewer: 1, model.RoleOperator: 2, model.RoleAdmin: 3}

func (c *cli) tokenList(args []string) error {
	fs := c.flags("token list")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := c.parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("list takes no arguments")
	}
	tokens, err := c.openTokens()
	if err != nil {
		return err
	}
	list := tokens.List()
	if *asJSON {
		return writeJSON(c.out, list)
	}
	if len(list) == 0 {
		fmt.Fprintln(c.out, "no API tokens yet")
		return nil
	}
	now := time.Now()
	tw := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tUSER\tROLE\tSTATE\tEXPIRES\tLAST USED\tDESCRIPTION")
	for _, t := range list {
		expires := "never"
		if !t.Expires.IsZero() {
			expires = t.Expires.Format(time.DateOnly)
		}
		used := "never"
		if !t.LastUsed.IsZero() {
			used = t.LastUsed.Local().Format("2006-01-02 15:04") + " from " + t.LastClient
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.Name, t.User, t.Role, c.tokenState(t, now), expires, used, dash(t.Description))
	}
	return tw.Flush()
}

// tokenState says whether a token works: "active", "expired", or
// "orphaned" when its user is gone, disabled, or someone new.
func (c *cli) tokenState(t auth.Token, now time.Time) string {
	doc, err := c.store.Get(model.KindUser, t.User)
	if err != nil || doc.(*model.User).Disabled || !doc.Header().Created.Equal(t.UserCreated) {
		return "orphaned"
	}
	if t.Expired(now) {
		return "expired"
	}
	return "active"
}

func (c *cli) tokenRemove(args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(rest, " "))
	}
	tokens, err := c.openTokens()
	if err != nil {
		return err
	}
	t, err := tokens.Delete(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("token %q: no such token", name)
		}
		return err
	}
	fmt.Fprintf(c.out, "token %q of %s revoked: it stops working at its next request\n", t.Name, t.User)
	return nil
}
