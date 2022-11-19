package coredyndns

import (
	"fmt"
	"net/http"
	"testing"
)

func TestDynDns(t *testing.T) {
	d := &coredyndns{
		listen:  ":9080",
		entries: make(map[string]dnsEntry),
	}
	if err := d.OnStartup(); err != nil {
		t.Fatalf("Unable to startup the dyndns server: %v", err)
	}
	defer func() {
		_ = d.OnShutdown()
	}()
	addr := fmt.Sprintf("http://%s%s?hostname=dev.example.com", d.ln.Addr().String(), "/update")
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("Unable to query %s: %v", addr, err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("Invalid status code: expecting '200', got '%d'", resp.StatusCode)
	}
}
