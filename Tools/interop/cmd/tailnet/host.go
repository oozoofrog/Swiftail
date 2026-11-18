package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type dnsRecord struct {
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Value          string    `json:"value"`
	NodeKeySummary string    `json:"nodeKeySummary"`
	Time           time.Time `json:"time"`
}
type dnsFault struct {
	Count, Status, DelayMs int
	Body                   string
	WrongTXT               bool
}
type hostTools struct {
	configured  bool
	enabled     *bool
	domains     *[]string
	nodeDomains map[key.NodePublic][]string
	manualMaps  map[key.NodePublic]bool
	log         []dnsRecord
	fault       dnsFault
	acme        *acmeServer
	done        chan struct{}
	stopped     chan struct{}
}

func (n *network) initHostTools() {
	n.host = hostTools{nodeDomains: map[key.NodePublic][]string{}, manualMaps: map[key.NodePublic]bool{}, log: []dnsRecord{}, done: make(chan struct{}), stopped: make(chan struct{})}
	n.control.MaybeRejectRequest = n.inspectDNS
	n.control.OnSetDNS = n.publishDNS
	n.control.ModifyFirstMapResponse = func(m *tailcfg.MapResponse, r *tailcfg.MapRequest) {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.configureMap(m, r.NodeKey)
	}
	// AddRawMapResponse suppresses upstream automatic maps. Continue forwarding changes to the original full map.
	go func() {
		defer close(n.host.stopped)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		last := map[key.NodePublic][]byte{}
		lastSent := map[key.NodePublic]time.Time{}
		for {
			select {
			case <-n.host.done:
				return
			case <-ticker.C:
			}
			n.mu.Lock()
			configured := n.host.configured
			n.mu.Unlock()
			if !configured {
				continue
			}
			for _, node := range n.control.AllNodes() {
				m, err := n.control.MapResponse(&tailcfg.MapRequest{NodeKey: node.Key})
				if err != nil || m == nil {
					continue
				}
				n.mu.Lock()
				n.configureMap(m, node.Key)
				slices.SortFunc(m.UserProfiles, func(a, b tailcfg.UserProfile) int { return cmp.Compare(a.ID, b.ID) })
				if !n.host.manualMaps[node.Key] {
					b, err := json.Marshal(m)
					// Resend periodically so reconnected streams with automatic maps suppressed also receive an initial map.
					if err == nil && (!bytes.Equal(last[node.Key], b) || time.Since(lastSent[node.Key]) >= time.Second) && n.control.AddRawMapResponse(node.Key, m) {
						last[node.Key] = b
						lastSent[node.Key] = time.Now()
					}
				}
				n.mu.Unlock()
			}
		}
	}()
}
func (n *network) closeHostTools() {
	close(n.host.done)
	<-n.host.stopped
	n.mu.Lock()
	a := n.host.acme
	n.mu.Unlock()
	if a != nil {
		a.close()
	}
}

// configureMap runs under n.mu. It does not intervene in runs that use only the existing setMagicDNS.
func (n *network) configureMap(m *tailcfg.MapResponse, k key.NodePublic) {
	if !n.host.configured {
		return
	}
	d := m.DNSConfig
	if d == nil {
		d = &tailcfg.DNSConfig{Proxied: true}
	} else {
		d = d.Clone()
	}
	if n.host.enabled != nil {
		d.Proxied = *n.host.enabled
	}
	if domains, ok := n.host.nodeDomains[k]; ok {
		d.CertDomains = slices.Clone(domains)
	} else if n.host.domains != nil {
		d.CertDomains = slices.Clone(*n.host.domains)
	} else if m.Node != nil {
		d.CertDomains = []string{m.Node.Hostinfo.Hostname() + "." + n.control.MagicDNSDomain}
	}
	if d.CertDomains == nil {
		d.CertDomains = []string{}
	}
	m.DNSConfig = d
}
func certDomainValid(s string) bool {
	if len(s) == 0 || len("_acme-challenge."+s) > 253 || s != strings.ToLower(s) {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !validName.MatchString(label) {
			return false
		}
	}
	return true
}

func (n *network) inspectDNS(r *http.Request) (int, string, string) {
	if r.URL.Path != "/machine/set-dns" {
		return 0, "", ""
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	r.Body.Close()
	if err != nil || len(b) > 1<<20 {
		return 400, "", "invalid set-dns body"
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	var req tailcfg.SetDNSRequest
	if json.Unmarshal(b, &req) != nil {
		return 0, "", ""
	}
	n.mu.Lock()
	n.host.log = append(n.host.log, dnsRecord{req.Name, req.Type, req.Value, req.NodeKey.ShortString(), time.Now().UTC()})
	fault := dnsFault{}
	if n.host.fault.Count > 0 {
		fault = n.host.fault
		n.host.fault.Count--
	}
	configured := n.host.configured
	n.mu.Unlock()
	if fault.DelayMs > 0 {
		timer := time.NewTimer(time.Duration(fault.DelayMs) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return 408, "", "test delay ended"
		case <-n.host.done:
			return 503, "", "shutting down"
		case <-timer.C:
		}
	}
	if fault.Status != 0 {
		return fault.Status, "", "test set-dns rejection"
	}
	if fault.Body != "" {
		switch fault.Body {
		case "large":
			return 200, "", `{"padding":"` + strings.Repeat("x", 8192) + `"}`
		case "null":
			return 200, "", "null"
		case "array":
			return 200, "", "[]"
		case "scalar":
			return 200, "", `"test"`
		case "empty":
			return 200, "", ""
		}
	}
	if req.Type != "TXT" || req.Name == "" || req.Value == "" {
		return 0, "", ""
	}
	node := n.control.Node(req.NodeKey)
	if node == nil {
		return 0, "", ""
	}
	if !configured && req.Name != "_acme-challenge."+node.Hostinfo.Hostname()+"."+n.control.MagicDNSDomain {
		return 403, "", "not a cert domain"
	}
	if configured {
		m, _ := n.control.MapResponse(&tailcfg.MapRequest{NodeKey: req.NodeKey})
		n.mu.Lock()
		n.configureMap(m, req.NodeKey)
		n.mu.Unlock()
		domain, ok := strings.CutPrefix(req.Name, "_acme-challenge.")
		if !ok || !slices.Contains(m.DNSConfig.CertDomains, domain) {
			return 403, "", "not a cert domain"
		}
	}
	// Upstream allows only automatic FQDNs. Check the original name under this tool's policy and leave the machine ownership check to upstream.
	original := req
	if fault.WrongTXT {
		original.Value = "swiftail-invalid-txt"
	}
	envelope, _ := json.Marshal(original)
	req.Name = "_acme-challenge." + node.Hostinfo.Hostname() + "." + n.control.MagicDNSDomain
	req.Value = string(envelope)
	encoded, _ := json.Marshal(req)
	r.Body = io.NopCloser(bytes.NewReader(encoded))
	return 0, "", ""
}
func (n *network) publishDNS(req *tailcfg.SetDNSRequest) error {
	var original tailcfg.SetDNSRequest
	// Restore the body overlaid by inspectDNS only after it passes the upstream key and machine checks.
	if err := json.Unmarshal([]byte(req.Value), &original); err != nil {
		return errors.New("invalid internal set-dns body")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if a := n.host.acme; a != nil {
		name := strings.ToLower(strings.TrimSuffix(original.Name, ".")) + "."
		a.challenge.DeleteDNSTXTRecord(name)
		a.challenge.AddDNSTXTRecord(name, original.Value)
	}
	return nil
}

func (n *network) executeHost(c command) (map[string]any, error) {
	switch c.Cmd {
	case "setCertDomains":
		if c.Domains == nil {
			return nil, errors.New("a domains array is required")
		}
		domains := slices.Clone(*c.Domains)
		for _, d := range domains {
			if !certDomainValid(d) {
				return nil, errors.New("domains contains an invalid DNS name")
			}
		}
		var k key.NodePublic
		if c.NodeKey != "" {
			if err := k.UnmarshalText([]byte(c.NodeKey)); err != nil || n.control.Node(k) == nil {
				return nil, errors.New("a registered nodeKey is required")
			}
		}
		n.mu.Lock()
		n.host.configured = true
		if c.NodeKey == "" {
			n.host.domains = &domains
			clear(n.host.nodeDomains)
		} else {
			n.host.nodeDomains[k] = domains
		}
		n.mu.Unlock()
		return map[string]any{"event": "certDomains", "nodeKey": c.NodeKey, "domains": append([]string{}, domains...)}, nil
	case "setDNSConfig":
		if c.Enabled == nil {
			return nil, errors.New("enabled requires a bool")
		}
		enabled := *c.Enabled
		n.mu.Lock()
		n.host.configured = true
		n.host.enabled = &enabled
		n.mu.Unlock()
		return map[string]any{"event": "dnsConfig", "enabled": enabled}, nil
	case "setDNSLog":
		n.mu.Lock()
		records := append([]dnsRecord{}, n.host.log...)
		n.mu.Unlock()
		return map[string]any{"event": "setDNSLog", "requests": records}, nil
	case "setDNSFault":
		if c.Count == nil || *c.Count < 0 || *c.Count > 10000 || c.DelayMs < 0 || c.DelayMs > 3600000 || (c.Status != 0 && (c.Status < 200 || c.Status > 599)) {
			return nil, errors.New("count, status, or delayMs is out of range")
		}
		if c.Body != "" && !slices.Contains([]string{"large", "null", "array", "scalar", "empty"}, c.Body) {
			return nil, errors.New("invalid body kind")
		}
		modes := 0
		if c.Status != 0 {
			modes++
		}
		if c.DelayMs != 0 {
			modes++
		}
		if c.Body != "" {
			modes++
		}
		if c.WrongTXT {
			modes++
		}
		if (*c.Count > 0 && modes != 1) || (*c.Count == 0 && modes != 0) {
			return nil, errors.New("specify only one type of fault. A count of 0 resets it")
		}
		n.mu.Lock()
		n.host.fault = dnsFault{*c.Count, c.Status, c.DelayMs, c.Body, c.WrongTXT}
		n.mu.Unlock()
		return map[string]any{"event": "setDNSFault", "count": *c.Count}, nil
	case "acmeStart":
		return n.startACME(c)
	}
	p := n.peers[c.Name]
	if p == nil {
		return nil, errors.New("peer not found")
	}
	if c.Cmd == "goState" {
		return map[string]any{"event": "goState", "name": c.Name, "directory": p.dir, "stopped": p.stopped}, nil
	}
	if p.stopped {
		return nil, errors.New("peer is stopped")
	}
	if c.Cmd == "peerHTTP" {
		return n.peerHTTP(c, p)
	}
	if _, err := netip.ParseAddr(c.To); err != nil {
		if _, err = netip.ParseAddrPort(c.To); err != nil {
			return nil, errors.New("to must be an IP or IP:port")
		}
	}
	lc, err := p.server.LocalClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	who, err := lc.WhoIs(ctx, c.To)
	if err != nil {
		return nil, errors.New("WhoIs lookup failed")
	}
	return map[string]any{"event": "peerWhoIs", "name": c.Name, "stableID": who.Node.StableID, "nodeName": strings.TrimSuffix(who.Node.Name, "."), "computedName": who.Node.ComputedName, "loginName": who.UserProfile.LoginName}, nil
}
func (n *network) stopPeer(c command) (map[string]any, error) {
	if c.Port != 0 {
		return nil, errors.New("stop and port cannot be used together")
	}
	p := n.peers[c.Name]
	if p == nil || p.stopped {
		return nil, errors.New("no running peer")
	}
	p.transfers.close()
	if p.capture != nil {
		p.capture.close()
		p.capture = nil
	}
	if err := p.server.Close(); err != nil {
		return nil, err
	}
	p.stopped = true
	return map[string]any{"event": "peerClose", "name": c.Name, "stopped": true}, nil
}

func (n *network) peerHTTP(c command, p *peer) (map[string]any, error) {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("an http or https URL is required")
	}
	timeout, err := transferTimeout(c)
	if err != nil {
		return nil, err
	}
	if (c.Send == nil) != (c.Seed == nil) || (c.Send != nil && *c.Send > maxTransferBytes) {
		return nil, errors.New("the body requires both send (0…4GiB) and seed")
	}
	// Use the URL name as is for TLS and restrict Dial to registered tailnet addresses.
	var target netip.Addr
	for _, node := range n.control.AllNodes() {
		for _, prefix := range node.Addresses {
			if u.Hostname() == prefix.Addr().String() || strings.EqualFold(strings.TrimSuffix(u.Hostname(), "."), strings.TrimSuffix(node.Name, ".")) {
				target = prefix.Addr()
				break
			}
		}
		if target.IsValid() {
			break
		}
	}
	if c.To != "" {
		target, err = netip.ParseAddr(c.To)
		if err != nil || target.Zone() != "" {
			return nil, errors.New("invalid to address")
		}
		found := false
		for _, node := range n.control.AllNodes() {
			for _, prefix := range node.Addresses {
				if prefix.Addr() == target {
					found = true
				}
			}
		}
		if !found {
			return nil, errors.New("only registered tailnet addresses are allowed")
		}
	}
	if !target.IsValid() {
		return nil, errors.New("no registered node matches the URL host. You can specify to")
	}
	roots := x509.NewCertPool()
	root := c.RootPEM
	if root == "" {
		n.mu.Lock()
		if n.host.acme != nil {
			root = n.host.acme.rootPEM
		}
		n.mu.Unlock()
	}
	if u.Scheme == "https" && !roots.AppendCertsFromPEM([]byte(root)) {
		return nil, errors.New("a test rootPEM is required")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxResponseHeaderBytes: 1 << 20, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		return p.server.Dial(ctx, "tcp", net.JoinHostPort(target.String(), port))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		select {
		case <-n.host.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	var body io.Reader
	if c.Send != nil && *c.Send > 0 {
		body = io.LimitReader(newStream(*c.Seed), int64(*c.Send))
	}
	req, err := http.NewRequestWithContext(ctx, c.Method, c.URL, body)
	if err != nil {
		return nil, errors.New("invalid HTTP request")
	}
	if c.Send != nil {
		req.ContentLength = int64(*c.Send)
	}
	for name, values := range c.Headers {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	if c.Range != "" {
		req.Header.Set("Range", c.Range)
	}
	start := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.New("tailnet HTTP request failed")
	}
	defer res.Body.Close()
	digest := sha256.New()
	count, err := io.CopyBuffer(digest, res.Body, make([]byte, 32<<10))
	if err != nil {
		return nil, errors.New("failed to read the HTTP response body")
	}
	return map[string]any{"event": "peerHTTP", "name": c.Name, "status": res.StatusCode, "headers": res.Header, "bodyLength": count, "bodySHA256": hex.EncodeToString(digest.Sum(nil)), "elapsedMs": time.Since(start).Milliseconds()}, nil
}
