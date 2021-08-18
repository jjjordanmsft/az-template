package main

import (
	"net"
	"net/http"
	"time"

	"github.com/jjjordanmsft/az-template/keyvault"

	log "github.com/sirupsen/logrus"
)

type listener struct {
	ping     chan struct{}
	password string
}

// startListener creates an HTTP server that sends back pings on the specified channel
// when it is hit with the password specified in the config.
func startListener(cfg *config, ctx keyvault.TemplateContext, ping chan struct{}) error {
	if cfg.Listen == nil {
		return nil
	}

	l := &listener{ping: ping}
	if err := l.getPassword(cfg, ctx); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/ping", l)

	listener, err := net.Listen("unix", *cfg.Listen)
	if err != nil {
		return err
	}

	server := http.Server{Handler: mux}
	go server.Serve(listener)
	return nil
}

// getPassword fetches a password from a keyvault, and refreshes at the specified period.
func (l *listener) getPassword(cfg *config, ctx keyvault.TemplateContext) error {
	if cfg.Password == nil || cfg.Keyvault == nil {
		return nil
	}

	cl, err := ctx.GetClient(*cfg.Keyvault)
	if err != nil {
		return err
	}

	pwkey := *cfg.Password
	b, _, err := cl.GetSecret(pwkey)
	if err != nil {
		return err
	}

	l.password = *b.Value

	if cfg.Period != nil {
		go func() {
			t := time.Tick(time.Duration(*cfg.Period))
			for {
				<-t
				b, _, err := cl.GetSecret(pwkey)
				if err != nil {
					log.WithError(err).Warn("Failed to refresh password")
				} else {
					l.password = *b.Value
				}
			}
		}()
	}

	return nil
}

// ServeHTTP validates credentials and sends the ping.
func (l *listener) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if l.password != "" {
		_, pass, ok := r.BasicAuth()
		if !ok || pass != l.password {
			rw.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(rw, "Not authorized", 401)
			return
		}
	}

	go func() { l.ping <- struct{}{} }()
	rw.WriteHeader(200)
	rw.Write([]byte("OK"))
}
