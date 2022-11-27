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

type responseWriter struct {
	dns.ResponseWriter
	state request.Request
	addr  net.IP
}

func (r *responseWriter) WriteMsg(res *dns.Msg) error {
	fmt.Printf("resp: %+v\n", *res)
	switch r.state.QType() {
	case dns.TypeA:
		rr := res.Answer[0].(*dns.A)
		rr.A = r.addr
		rr.Hdr.Name = r.state.Name()
		res.Answer[0] = rr
		res.Question[0].Name = r.state.Name()
	case dns.TypeAAAA:
		rr := res.Answer[0].(*dns.AAAA)
		rr.AAAA = r.addr
		rr.Hdr.Name = r.state.Name()
		res.Answer[0] = rr
		res.Question[0].Name = r.state.Name()
	}
	fmt.Printf("send resp: %+v\n", *res)
	return r.ResponseWriter.WriteMsg(res)
}

func (r *responseWriter) Write(buf []byte) (int, error) {
	log.Warning("ResponseHeaderWriter called with Write: not able to capture response")
	n, err := r.ResponseWriter.Write(buf)
	return n, err
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
	log.Infof("listening on %s", d.listen)
	if len(d.zones) > 0 {
		log.Infof("allowed zones: %+v\n", d.zones)
	}
	return nil
}

func (d coredyndns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()
	qtype := state.QType()
	fmt.Printf("req: %+v\n", *r)
	zone := plugin.Zones(d.zones).Matches(qname)
	if zone != "" && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		if entry, ok := d.entries[qname]; ok {
			if addr, ok := entry[qtype]; ok {
				wr := responseWriter{ResponseWriter: w, state: state, addr: addr}
				r.Question[0].Name = zone
				return plugin.NextOrFailure(d.Name(), d.Next, ctx, &wr, r)
			}
		}
	}
	return plugin.NextOrFailure(d.Name(), d.Next, ctx, w, r)
}

func (d coredyndns) Name() string { return "coredyndns" }

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
	d.mux.HandleFunc("/update", d.dyndnsHandler)
	d.mux.HandleFunc("/nic/update", d.dyndnsHandler)

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

func (d *coredyndns) addDnsEntry(hostname string, address net.IP) bool {
	if _, ok := d.entries[hostname]; !ok {
		d.entries[hostname] = make(dnsEntry)
	}
	newAddress := true
	if address.To4() == nil {
		if a, ok := d.entries[hostname][dns.TypeAAAA]; ok && a.Equal(address) {
			newAddress = false
		}
		d.entries[hostname][dns.TypeAAAA] = address
	} else {
		if a, ok := d.entries[hostname][dns.TypeA]; ok && a.Equal(address) {
			newAddress = false
		}
		d.entries[hostname][dns.TypeA] = address
	}
	return newAddress
}

func (d *coredyndns) dyndnsHandler(w http.ResponseWriter, r *http.Request) {
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
	zone := strings.Join(f[1:], ".")
	if len(d.zones) > 0 {
		if !slices.Contains(d.zones, dns.Fqdn(zone)) {
			http.Error(w, "invalid zone", http.StatusBadRequest)
			return
		}
	}
	myip := r.URL.Query().Get("myip")
	if myip != "" {
		ip = myip
	}

	address := net.ParseIP(ip)
	if address == nil {
		http.Error(w, "invalid ip address", http.StatusBadRequest)
		return
	}
	updated := d.addDnsEntry(dns.Fqdn(hostname), address)
	var result string
	if updated {
		result = fmt.Sprintf("good %s", address.String())
		log.Infof("dyndns update: %s - %s", hostname, address.String())
	} else {
		result = fmt.Sprintf("nochg %s", address.String())
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(result))
}
