package coredyndns

import (
	"os"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

/*
coredyndns [zones...] {
	listen :443 tls insecure | listen :80
	cert file <filename>
	key file <filename>
	username <username>
	password <password>
}

*/

func init() { plugin.Register("coredyndns", setup) }

func setup(c *caddy.Controller) error {
	d, err := parse(c)
	if err != nil {
		return plugin.Error("coredyndns", err)
	}

	c.OnStartup(d.OnStartup)
	c.OnRestart(d.OnShutdown)
	c.OnFinalShutdown(d.OnShutdown)
	c.OnRestartFailed(d.OnStartup)

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		d.Next = next
		return d
	})

	return nil
}

func parse(c *caddy.Controller) (*coredyndns, error) {
	var err error
	d := &coredyndns{entries: make(map[string]dnsEntry), zones: []string{}}

	for c.Next() {
		for _, z := range c.RemainingArgs() {
			d.zones = append(d.zones, dns.Fqdn(z))
		}

		for c.NextBlock() {
			switch c.Val() {
			case "listen":
				if !c.NextArg() {
					return d, c.ArgErr()
				}
				d.listen = c.Val()
				if c.NextArg() {
					if c.Val() == "tls" {
						d.useTls = true
					} else {
						return d, c.Errf("unknown listen parameter '%s'", c.Val())
					}
					if c.NextArg() {
						if c.Val() == "insecure" {
							d.insecureTls = true
						} else {
							return d, c.Errf("unknown listen parameter '%s'", c.Val())
						}
					}
				}
			case "cert":
				d.tlsCert, err = parsePem(c)
				if err != nil {
					return d, c.Errf("%s", err.Error())
				}
			case "key":
				d.tlsKey, err = parsePem(c)
				if err != nil {
					return d, c.Errf("%s", err.Error())
				}
			case "username":
				if !c.NextArg() {
					return d, c.ArgErr()
				}
				d.username = c.Val()
			case "password":
				if !c.NextArg() {
					return d, c.ArgErr()
				}
				d.password = c.Val()
			default:
				return &coredyndns{}, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}
	return d, d.init()
}

func parsePem(c *caddy.Controller) ([]byte, error) {
	if !c.NextArg() {
		return nil, c.ArgErr()
	}
	switch c.Val() {
	case "file":
		fn := c.RemainingArgs()
		if len(fn) != 1 {
			return nil, c.ArgErr()
		}
		return os.ReadFile(fn[0])
	default:
		return nil, c.Errf("unhandled data type '%s'", c.Val())
	}
}
