// Package diagnostics exposes profiling only on an explicitly requested loopback listener.
package diagnostics

import (
	"errors"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"
)

func ValidateAddress(address string) error {
	if address == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	n, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || n < 0 || n > 65535 {
		return errors.New("pprof address must be a literal loopback IP and port")
	}
	return nil
}

// Start owns a separate mux: profile routes never enter the inference listener.
// An empty address starts nothing. Port zero is useful for isolated tests.
func Start(address string) (*http.Server, net.Listener, error) {
	if err := ValidateAddress(address); err != nil {
		return nil, nil, err
	}
	if address == "" {
		return nil, nil, nil
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return server, listener, nil
}
