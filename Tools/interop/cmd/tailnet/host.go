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
	// AddRawMapResponse 뒤에는 upstream 자동 맵이 억제된다. 원래 전체 맵의 변경도 계속 전달한다.
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
					// 자동 맵이 억제된 스트림의 재접속도 첫 맵을 받도록 주기적으로 다시 보낸다.
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

// configureMap은 n.mu 아래에서 호출한다. 기존 setMagicDNS만 쓴 실행에는 개입하지 않는다.
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
		return 400, "", "잘못된 set-dns 본문"
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
			return 408, "", "시험 지연 종료"
		case <-n.host.done:
			return 503, "", "종료 중"
		case <-timer.C:
		}
	}
	if fault.Status != 0 {
		return fault.Status, "", "시험 set-dns 거절"
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
		return 403, "", "cert 도메인이 아닙니다"
	}
	if configured {
		m, _ := n.control.MapResponse(&tailcfg.MapRequest{NodeKey: req.NodeKey})
		n.mu.Lock()
		n.configureMap(m, req.NodeKey)
		n.mu.Unlock()
		domain, ok := strings.CutPrefix(req.Name, "_acme-challenge.")
		if !ok || !slices.Contains(m.DNSConfig.CertDomains, domain) {
			return 403, "", "cert 도메인이 아닙니다"
		}
	}
	// upstream은 자동 FQDN만 허용한다. 원래 이름은 도구 정책으로 검사하고, machine 소유 검사는 upstream에 맡긴다.
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
	// inspectDNS가 덧씌운 본문은 upstream 키·machine 검사를 통과한 뒤에만 복원한다.
	if err := json.Unmarshal([]byte(req.Value), &original); err != nil {
		return errors.New("set-dns 내부 본문 오류")
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
			return nil, errors.New("domains 배열이 필요합니다")
		}
		domains := slices.Clone(*c.Domains)
		for _, d := range domains {
			if !certDomainValid(d) {
				return nil, errors.New("domains에 잘못된 DNS 이름이 있습니다")
			}
		}
		var k key.NodePublic
		if c.NodeKey != "" {
			if err := k.UnmarshalText([]byte(c.NodeKey)); err != nil || n.control.Node(k) == nil {
				return nil, errors.New("등록된 nodeKey가 필요합니다")
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
			return nil, errors.New("enabled에 bool이 필요합니다")
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
			return nil, errors.New("count·status·delayMs 범위가 잘못되었습니다")
		}
		if c.Body != "" && !slices.Contains([]string{"large", "null", "array", "scalar", "empty"}, c.Body) {
			return nil, errors.New("body 종류가 잘못되었습니다")
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
			return nil, errors.New("결함은 한 종류만 지정합니다. count 0은 초기화입니다")
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
		return nil, errors.New("피어가 없습니다")
	}
	if c.Cmd == "goState" {
		return map[string]any{"event": "goState", "name": c.Name, "directory": p.dir, "stopped": p.stopped}, nil
	}
	if p.stopped {
		return nil, errors.New("멈춘 피어입니다")
	}
	if c.Cmd == "peerHTTP" {
		return n.peerHTTP(c, p)
	}
	if _, err := netip.ParseAddr(c.To); err != nil {
		if _, err = netip.ParseAddrPort(c.To); err != nil {
			return nil, errors.New("to는 IP 또는 IP:port여야 합니다")
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
		return nil, errors.New("WhoIs 조회 실패")
	}
	return map[string]any{"event": "peerWhoIs", "name": c.Name, "stableID": who.Node.StableID, "nodeName": strings.TrimSuffix(who.Node.Name, "."), "computedName": who.Node.ComputedName, "loginName": who.UserProfile.LoginName}, nil
}
func (n *network) stopPeer(c command) (map[string]any, error) {
	if c.Port != 0 {
		return nil, errors.New("stop과 port는 함께 쓸 수 없습니다")
	}
	p := n.peers[c.Name]
	if p == nil || p.stopped {
		return nil, errors.New("실행 중인 피어가 없습니다")
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
		return nil, errors.New("http 또는 https URL이 필요합니다")
	}
	timeout, err := transferTimeout(c)
	if err != nil {
		return nil, err
	}
	if (c.Send == nil) != (c.Seed == nil) || (c.Send != nil && *c.Send > maxTransferBytes) {
		return nil, errors.New("본문은 send(0…4GiB)·seed를 함께 지정합니다")
	}
	// URL의 이름은 TLS에 그대로 쓰고, Dial은 등록된 tailnet 주소로만 제한한다.
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
			return nil, errors.New("to 주소가 잘못되었습니다")
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
			return nil, errors.New("등록된 tailnet 주소만 허용합니다")
		}
	}
	if !target.IsValid() {
		return nil, errors.New("URL 호스트에 대응하는 등록 노드가 없습니다. to를 지정할 수 있습니다")
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
		return nil, errors.New("시험용 rootPEM이 필요합니다")
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
		return nil, errors.New("HTTP 요청이 잘못되었습니다")
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
		return nil, errors.New("tailnet HTTP 요청 실패")
	}
	defer res.Body.Close()
	digest := sha256.New()
	count, err := io.CopyBuffer(digest, res.Body, make([]byte, 32<<10))
	if err != nil {
		return nil, errors.New("HTTP 응답 본문 읽기 실패")
	}
	return map[string]any{"event": "peerHTTP", "name": c.Name, "status": res.StatusCode, "headers": res.Header, "bodyLength": count, "bodySHA256": hex.EncodeToString(digest.Sum(nil)), "elapsedMs": time.Since(start).Milliseconds()}, nil
}
