package main

// limen cert: the certificates of the model, and the state of their
// files. Issuing is the daemon's job — it is the one that answers the
// CA's challenges — so `renew` asks it to, and `import` installs a
// certificate someone else issued.

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ostap-mykhaylyak/limen/internal/acme"
	"github.com/ostap-mykhaylyak/limen/internal/config"
	"github.com/ostap-mykhaylyak/limen/internal/model"
	"github.com/ostap-mykhaylyak/limen/internal/paths"
	"github.com/ostap-mykhaylyak/limen/internal/store"
)

func certFlags(fs *flag.FlagSet, create bool) (applyFunc, func() string) {
	var domains stringList
	fs.Var(&domains, "domain", "a name the certificate covers, repeat for more (replaces the list)")
	provider := fs.String("provider", model.ProviderACME, "acme (limen issues and renews it) or custom (uploaded)")
	challenge := fs.String("challenge", model.ChallengeHTTP, "http, or dns for a wildcard (needs acme.dns_hook)")
	keyType := fs.String("key-type", "", "ec256, ec384, rsa2048 or rsa4096 (empty: acme.key_type)")
	return func(doc model.Document, set map[string]bool) error {
		c := doc.(*model.Certificate)
		if set["domain"] {
			c.Domains = lower(domains)
		}
		if set["provider"] {
			c.Provider = *provider
			if c.Provider == model.ProviderCustom && !set["challenge"] {
				c.Challenge = ""
			}
		}
		if set["challenge"] {
			c.Challenge = *challenge
		}
		if set["key-type"] {
			c.KeyType = *keyType
		}
		// A wildcard can only be proven through DNS: say so by default.
		if create && !set["challenge"] && c.Provider == model.ProviderACME && c.Wildcard() {
			c.Challenge = model.ChallengeDNS
		}
		return nil
	}, domains.first
}

// certsDir is where the certificate files are; tests point it elsewhere.
func (c *cli) certsDir() string {
	if c.certs != "" {
		return c.certs
	}
	return paths.CertsDir
}

func (c *cli) renewBefore() time.Duration {
	if cfg, err := config.Load(paths.ConfigFile); err == nil {
		return cfg.ACME.RenewBefore.Std()
	}
	return config.Default().ACME.RenewBefore.Std()
}

func (c *cli) certSummary(cert *model.Certificate) acme.Summary {
	return acme.Summarize(cert, acme.ReadInfo(c.certsDir(), cert.Name), acme.ReadStatus(c.certsDir(), cert.Name), time.Now(), c.renewBefore())
}

func (c *cli) listCerts(docs []model.Document) error {
	tw := tabwriter.NewWriter(c.out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDOMAINS\tPROVIDER\tSTATE\tEXPIRES\tUSED BY")
	for _, d := range docs {
		cert := d.(*model.Certificate)
		sum := c.certSummary(cert)
		expires := "-"
		if sum.Info.Present && sum.Info.Error == "" {
			expires = fmt.Sprintf("%s (%dd)", sum.Info.NotAfter.Format(time.DateOnly), sum.DaysLeft)
		}
		provider := cert.Provider
		if cert.Provider == model.ProviderACME {
			provider += "/" + cert.Challenge
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", cert.Name, strings.Join(cert.Domains, ","), provider,
			sum.State, expires, dash(strings.Join(c.store.CertUsers(cert.Name), ",")))
	}
	return tw.Flush()
}

func (c *cli) showCertState(cert *model.Certificate) {
	sum := c.certSummary(cert)
	fmt.Fprintf(c.out, "# state: %s", sum.State)
	if sum.Detail != "" {
		fmt.Fprintf(c.out, " (%s)", sum.Detail)
	}
	fmt.Fprintln(c.out)
	if sum.Info.Present && sum.Info.Error == "" {
		fmt.Fprintf(c.out, "# valid %s to %s, %d day(s) left, issued by %s\n",
			sum.Info.NotBefore.Format(time.DateOnly), sum.Info.NotAfter.Format(time.DateOnly), sum.DaysLeft, sum.Info.Issuer)
		fmt.Fprintf(c.out, "# covers %s\n", strings.Join(sum.Info.Names, ", "))
	}
	if st := sum.Status; !st.LastAttempt.IsZero() {
		fmt.Fprintf(c.out, "# last attempt %s", st.LastAttempt.Local().Format(time.DateTime))
		if st.LastError != "" {
			fmt.Fprintf(c.out, ", failed (%d in a row): %s", st.Failures, st.LastError)
		}
		fmt.Fprintln(c.out)
		if !st.NextAttempt.IsZero() {
			fmt.Fprintf(c.out, "# next attempt %s\n", st.NextAttempt.Local().Format(time.DateTime))
		}
	}
	if users := c.store.CertUsers(cert.Name); len(users) > 0 {
		fmt.Fprintf(c.out, "# used by %s\n", strings.Join(users, ", "))
	}
}

func (c *cli) certRenew(args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	if err := c.parse(c.flags("cert renew"), rest); err != nil {
		return err
	}
	doc, err := c.store.Get(model.KindCertificate, name)
	if err != nil {
		return err
	}
	if doc.(*model.Certificate).Provider != model.ProviderACME {
		return fmt.Errorf("certificate %q is uploaded: limen does not issue it, `limen cert import` a new one", name)
	}
	if err := acme.RequestRenewal(c.certsDir(), name); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "renewal of %q requested\n", name)
	if c.nudge != nil {
		fmt.Fprintln(c.out, c.nudge())
	}
	fmt.Fprintf(c.out, "follow it with `limen cert show %s`\n", name)
	return nil
}

// certImport installs a certificate issued elsewhere: the chain and the
// key are checked against each other, and against the names the model
// wants, before anything is written.
func (c *cli) certImport(args []string) error {
	name, rest, err := takeName(args)
	if err != nil {
		return err
	}
	fs := c.flags("cert import")
	chainPath := fs.String("chain", "", "the certificate and its chain, PEM (fullchain.pem)")
	keyPath := fs.String("key", "", "its private key, PEM")
	note := fs.String("note", "", "why this change is made (kept in the history)")
	if err := c.parse(fs, rest); err != nil {
		return err
	}
	if *chainPath == "" || *keyPath == "" {
		return fmt.Errorf("usage: limen cert import NAME --chain fullchain.pem --key privkey.pem")
	}
	chain, err := os.ReadFile(*chainPath)
	if err != nil {
		return err
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	info, err := acme.ValidatePair(chain, key, time.Now())
	if err != nil {
		return err
	}

	err = c.store.Locked(func() error {
		doc, err := c.store.Get(model.KindCertificate, name)
		switch {
		case errors.Is(err, store.ErrNotFound):
			cert := model.NewCertificate(name)
			cert.Provider, cert.Challenge = model.ProviderCustom, ""
			cert.Domains = info.Names
			if _, err := c.store.Put(cert, c.change(*note)); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			cert := doc.(*model.Certificate)
			if cert.Provider != model.ProviderCustom {
				return fmt.Errorf("certificate %q is issued by limen: import under another name", name)
			}
			if missing := acme.Uncovered(info.Names, cert.Domains); len(missing) > 0 {
				return fmt.Errorf("the certificate does not cover %s", strings.Join(missing, ", "))
			}
		}
		return acme.WriteCert(c.certsDir(), name, chain, key)
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "certificate %q installed: %s, valid until %s\n", name, strings.Join(info.Names, ", "), info.NotAfter.Format(time.DateOnly))
	return c.afterWrite(model.KindCertificate)
}
