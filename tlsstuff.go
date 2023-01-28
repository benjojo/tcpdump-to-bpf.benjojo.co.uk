package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

var tlsRoot = flag.String("tls.names", "tcpdump-to-bpf.benjojo.co.uk", "What to lets encrypt for")
var tlsEmail = flag.String("tls.email", "", "What email to tell let's encrypt")

func setupSSLConfig(httpsSrv *http.Server, httpMux *http.ServeMux) (handler http.Handler) {
	getcertFunction, httpHandler := getNormalACMEConfig(httpMux)

	//Only enable cert failover logic where a cert is provided.
	httpsSrv.TLSConfig = &tls.Config{GetCertificate: getcertFunction, MinVersion: tls.VersionTLS12}
	return httpHandler
}

func getNormalACMEConfig(httpMux *http.ServeMux) (h func(*tls.ClientHelloInfo) (*tls.Certificate, error), handler http.Handler) {
	// Note: use a sensible value for data directory
	// this is where cached certificates are stored
	dataDir := "."
	hostPolicy := func(ctx context.Context, host string) error {
		for _, name := range strings.Split(*tlsRoot, ",") {
			if name == host {
				return nil
			}
		}

		return fmt.Errorf("acme/autocert: only %v host is allowed", tlsRoot)
	}

	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      autocert.DirCache(dataDir),
		Email:      *tlsEmail,
	}

	return m.GetCertificate, m.HTTPHandler(httpMux)
}

func redirect(w http.ResponseWriter, req *http.Request) {
	// remove/add not default ports from req.Host
	target := "https://" + req.Host + req.URL.Path
	if len(req.URL.RawQuery) > 0 {
		target += "?" + req.URL.RawQuery
	}

	http.Redirect(w, req, target,
		// see @andreiavrammsd comment: often 307 > 301
		http.StatusTemporaryRedirect)
}
