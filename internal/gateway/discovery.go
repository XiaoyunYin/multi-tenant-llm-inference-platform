package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var kubernetesName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type DiscoveryConfig struct {
	Namespace string
	Service   string
	Interval  time.Duration
}

func (c DiscoveryConfig) Validate() error {
	if !kubernetesName.MatchString(c.Namespace) || len(c.Namespace) > 63 || !kubernetesName.MatchString(c.Service) || len(c.Service) > 63 || c.Interval <= 0 {
		return errors.New("discovery requires DNS-label namespace/service and a positive interval")
	}
	return nil
}

// EndpointSliceDiscovery lists one namespace with a service selector. No Pod,
// Secret, mutation or watch permission is required. Each failure clears routing.
type EndpointSliceDiscovery struct {
	config   DiscoveryConfig
	registry *Registry
	client   *http.Client
	apiURL   string
	token    func() (string, error)
	logger   *slog.Logger
	mu       sync.Mutex
	last     string
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewEndpointSliceDiscovery(config DiscoveryConfig, registry *Registry, client *http.Client, apiURL string, token func() (string, error), logger *slog.Logger) (*EndpointSliceDiscovery, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if registry == nil || client == nil || token == nil {
		return nil, errors.New("discovery dependencies are required")
	}
	u, err := url.Parse(apiURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("invalid API URL")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &EndpointSliceDiscovery{config: config, registry: registry, client: client, apiURL: strings.TrimRight(apiURL, "/"), token: token, logger: logger}, nil
}

func NewInClusterDiscovery(config DiscoveryConfig, registry *Registry, logger *slog.Logger) (*EndpointSliceDiscovery, error) {
	const directory = "/var/run/secrets/kubernetes.io/serviceaccount/"
	ca, err := os.ReadFile(directory + "ca.crt")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid Kubernetes CA")
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
	if host == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST is required")
	}
	if port == "" {
		port = "443"
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return NewEndpointSliceDiscovery(config, registry, client, "https://"+net.JoinHostPort(host, port), func() (string, error) {
		// Re-read projected tokens so rotation does not invalidate the client.
		value, err := os.ReadFile(directory + "token")
		return strings.TrimSpace(string(value)), err
	}, logger)
}

type endpointSliceList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		AddressType string `json:"addressType"`
		Metadata    struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Ports []struct {
			Name     string `json:"name"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"ports"`
		Endpoints []struct {
			Addresses  []string `json:"addresses"`
			Conditions struct {
				Ready       *bool `json:"ready"`
				Terminating *bool `json:"terminating"`
			} `json:"conditions"`
			TargetRef struct {
				Kind      string `json:"kind"`
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
				UID       string `json:"uid"`
			} `json:"targetRef"`
		} `json:"endpoints"`
	} `json:"items"`
}

func (d *EndpointSliceDiscovery) list(ctx context.Context) ([]*Backend, error) {
	query := url.Values{"labelSelector": {"kubernetes.io/service-name=" + d.config.Service}}
	path := d.apiURL + "/apis/discovery.k8s.io/v1/namespaces/" + d.config.Namespace + "/endpointslices?" + query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	token, err := d.token()
	if err != nil || token == "" {
		return nil, errors.New("cannot read service-account token")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := d.client.Do(request)
	if err != nil {
		return nil, errors.New("EndpointSlice API unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EndpointSlice API status %d", response.StatusCode)
	}
	const maxBytes = 4 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil || len(body) > maxBytes {
		return nil, errors.New("EndpointSlice response exceeds bound or cannot be read")
	}
	var slices endpointSliceList
	if err := json.Unmarshal(body, &slices); err != nil {
		return nil, errors.New("invalid EndpointSlice JSON")
	}
	if slices.Metadata.Continue != "" {
		return nil, errors.New("incomplete EndpointSlice list")
	}
	byID := make(map[string]*Backend)
	addresses := make(map[string]string)
	// The controller may transiently duplicate a Pod across slices. A draining
	// or unknown-readiness observation takes precedence over a ready duplicate.
	excluded := make(map[string]bool)
	for _, slice := range slices.Items {
		if slice.Metadata.Labels["kubernetes.io/service-name"] != d.config.Service {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || (endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
				excluded[endpoint.TargetRef.UID] = true
			}
		}
	}
	for _, slice := range slices.Items {
		if slice.Metadata.Labels["kubernetes.io/service-name"] != d.config.Service {
			continue
		}
		if slice.AddressType != "IPv4" && slice.AddressType != "IPv6" {
			continue
		}
		port := 0
		for _, p := range slice.Ports {
			if p.Name == "http" && (p.Protocol == "TCP" || p.Protocol == "") && p.Port > 0 && p.Port <= 65535 {
				if port != 0 && port != p.Port {
					return nil, errors.New("conflicting backend ports")
				}
				port = p.Port
			}
		}
		if port == 0 {
			continue
		}
		for _, endpoint := range slice.Endpoints {
			if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || (endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {
				continue
			}
			ref := endpoint.TargetRef
			if excluded[ref.UID] {
				continue
			}
			if ref.Kind != "Pod" || ref.Namespace != d.config.Namespace || ref.Name == "" || ref.UID == "" || len(endpoint.Addresses) != 1 {
				return nil, errors.New("ready endpoint lacks unique Pod identity/address")
			}
			ip := net.ParseIP(endpoint.Addresses[0])
			if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || (slice.AddressType == "IPv4") != (ip.To4() != nil) {
				return nil, errors.New("invalid backend pod IP")
			}
			backend, err := NewBackend(ref.Name, "http://"+net.JoinHostPort(ip.String(), strconv.Itoa(port)), ref.UID)
			if err != nil {
				return nil, err
			}
			if old := byID[backend.ID]; old != nil && (old.Generation != backend.Generation || old.URL.String() != backend.URL.String()) {
				return nil, errors.New("conflicting backend identity")
			}
			if id := addresses[backend.URL.String()]; id != "" && id != backend.ID {
				return nil, errors.New("shared backend address")
			}
			byID[backend.ID] = backend
			addresses[backend.URL.String()] = backend.ID
		}
	}
	backends := make([]*Backend, 0, len(byID))
	for _, backend := range byID {
		backends = append(backends, backend)
	}
	sort.Slice(backends, func(i, j int) bool { return backends[i].ID < backends[j].ID })
	return backends, nil
}

func (d *EndpointSliceDiscovery) Poll(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	requestCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	backends, err := d.list(requestCtx)
	if err != nil {
		backends = nil
	}
	d.registry.ReplaceBackends(backends)
	identities := make([]string, 0, len(backends))
	for _, backend := range backends {
		identities = append(identities, backend.ID+"@"+backend.Generation)
	}
	signature := strings.Join(identities, ",")
	if signature != d.last || err != nil {
		d.logger.Info("backend discovery changed", "backends", identities, "error", err)
		d.last = signature
	}
	return err
}

func (d *EndpointSliceDiscovery) Start(parent context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	d.cancel, d.done = cancel, make(chan struct{})
	go func() {
		defer close(d.done)
		ticker := time.NewTicker(d.config.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = d.Poll(ctx)
			}
		}
	}()
}

func (d *EndpointSliceDiscovery) Close() {
	d.mu.Lock()
	cancel, done := d.cancel, d.done
	d.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
