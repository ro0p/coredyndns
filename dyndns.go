//go:build go1.18

package coredyndns

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// http(s)://<Server Name>/update?hostname=<Host Name>[&myip=<IP Address>]

type dnsEntry map[uint16]net.IP

type coredyndns struct {
	Next plugin.Handler

	entries map[string]dnsEntry
	m       sync.Mutex

	zones       []string
	listen      string
	useTls      bool
	insecureTls bool
	tlsCert     []byte
	tlsKey      []byte
	username    string
	password    string

	ln      net.Listener
	mux     *http.ServeMux
	nlSetup bool
}

func (d *coredyndns) init() error {
	if d.listen == "" {
		d.listen = ":9080"
	}
	if d.useTls && ((len(d.tlsCert) == 0) || (len(d.tlsKey) == 0)) {
		return errors.New("invalid TLS configuration")
	}
	if (len(d.username) == 0) != (len(d.password) == 0) {
		return errors.New("invalid auth configuration")
	}
	return nil
}

func (d *coredyndns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()

	answers := []dns.RR{}
	zone := plugin.Zones(d.zones).Matches(qname)

	if zone == "" {
		// PTR zones don't need to be specified in Origins.
		if state.QType() != dns.TypePTR {
			// if this doesn't match we need to fall through regardless of h.Fallthrough
			return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
		}
	}
	d.m.Lock()
	defer d.m.Unlock()
	if entry, ok := d.entries[qname]; ok {
		if addr, ok := entry[state.QType()]; ok {
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}
			r.A = addr
			answers = append(answers, r)
		}
	}

	if len(answers) == 0 {
		return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = answers

	err := w.WriteMsg(m)
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (d *coredyndns) Name() string { return "coredyndns" }

func (d *coredyndns) OnStartup() error {
	ln, err := reuseport.Listen("tcp", d.listen)
	if err != nil {
		return err
	}
	if d.useTls {
		crt, err := tls.X509KeyPair(d.tlsCert, d.tlsKey)
		if err != nil {
			return err
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{crt},
			MinVersion:   tls.VersionTLS12,
		}
		if d.insecureTls {
			tlsCfg.InsecureSkipVerify = true
		}
		d.ln = tls.NewListener(ln, tlsCfg)
	} else {
		d.ln = ln
	}
	d.mux = http.NewServeMux()
	d.nlSetup = true
	d.mux.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		if d.username != "" {
			u, p, ok := r.BasicAuth()
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if (d.username != u) || (d.password != p) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "missing hostname", http.StatusBadRequest)
			return
		}
		hostname := r.URL.Query().Get("hostname")
		if hostname == "" {
			http.Error(w, "missing hostname", http.StatusBadRequest)
			return
		}
		f := strings.Split(hostname, ".")
		host := f[0]
		zone := strings.Join(f[1:], ".")
		if len(d.zones) != 0 {
			if !slices.Contains(d.zones, zone) {
				http.Error(w, "invalid zone", http.StatusBadRequest)
				return
			}
		}
		myip := r.URL.Query().Get("myip")
		if myip != "" {
			ip = myip
		}

		fmt.Printf("host: '%s', zone: '%s', ip: '%s'\n", host, zone, ip)

		address := net.ParseIP(ip)
		if address == nil {
			http.Error(w, "invalid ip address", http.StatusBadRequest)
			return
		}
		fmt.Printf("ip: %s\n", address.String())
		d.addDnsEntry(hostname, address)
	})

	go func() { _ = http.Serve(d.ln, d.mux) }()

	return nil
}

func (d *coredyndns) OnShutdown() error {
	if !d.nlSetup {
		return nil
	}
	d.ln.Close()
	d.nlSetup = false
	return nil
}

func (d *coredyndns) addDnsEntry(hostname string, address net.IP) {
	d.m.Lock()
	defer d.m.Unlock()
	if _, ok := d.entries[hostname]; !ok {
		d.entries[hostname] = make(dnsEntry)
	}
	if address.To4() == nil {
		d.entries[hostname][dns.TypeAAAA] = address
	} else {
		d.entries[hostname][dns.TypeA] = address
	}
}
