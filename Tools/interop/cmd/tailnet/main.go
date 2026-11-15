package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"swiftail/interop/internal/testcontrol"
	"tailscale.com/derp/derpserver"
	"tailscale.com/envknob"
	"tailscale.com/logtail"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
)

type command struct {
	ID                 json.RawMessage     `json:"id"`
	Cmd                string              `json:"cmd"`
	Name               string              `json:"name"`
	To                 string              `json:"to"`
	Type               string              `json:"type"`
	Port               int                 `json:"port"`
	Proto              string              `json:"proto"`
	Payload            string              `json:"payload"`
	NodeKey            string              `json:"nodeKey"`
	Response           json.RawMessage     `json:"response"`
	RequireAuth        *bool               `json:"requireAuth"`
	AuthKey            *string             `json:"authKey"`
	AuthURL            string              `json:"authURL"`
	Enabled            *bool               `json:"enabled"`
	Send               *uint64             `json:"send"`
	Seed               *uint64             `json:"seed"`
	TimeoutSec         *int                `json:"timeoutSec"`
	Domains            *[]string           `json:"domains"`
	Count              *int                `json:"count"`
	Status             int                 `json:"status"`
	DelayMs            int                 `json:"delayMs"`
	Body               string              `json:"body"`
	WrongTXT           bool                `json:"wrongTXT"`
	NonceReject        *int                `json:"nonceReject"`
	AuthzReuse         *int                `json:"authzReuse"`
	ValidationDelaySec int                 `json:"validationDelaySec"`
	URL                string              `json:"url"`
	Method             string              `json:"method"`
	Headers            map[string][]string `json:"headers"`
	Range              string              `json:"range"`
	RootPEM            string              `json:"rootPEM"`
	Stop               bool                `json:"stop"`
	// Tailnet Lock 명령(lock.go).
	LockKey     string   `json:"lockKey"`
	Signers     []string `json:"signers"`
	AddKeys     []string `json:"addKeys"`
	RemoveKeys  []string `json:"removeKeys"`
	WrongSecret bool     `json:"wrongSecret"`
	OmitTKAInfo bool     `json:"omitTKAInfo"`
}
type peer struct {
	server    *tsnet.Server
	dir       string
	capture   *peerCapture
	transfers *peerTransfers
	stopped   bool
}
type network struct {
	control            *testcontrol.Server
	http               *httptest.Server
	derpHTTP           *httptest.Server
	derp               *derpserver.Server
	stun               *net.UDPConn
	peers              map[string]*peer
	mu                 sync.Mutex
	started            bool
	authKey            string
	controlConnections int
	derpConnections    int
	stunRequests       int
	transfers          []*transfer
	host               hostTools
	lock               lockTools
}

func newNetwork() (*network, error) {
	logtail.Disable()
	os.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	os.Setenv("TS_DISABLE_PORTMAPPER", "true")
	for _, name := range []string{"TS_AUTHKEY", "TS_CLIENT_ID", "TS_CLIENT_SECRET", "TS_ID_TOKEN", "TS_AUDIENCE"} {
		os.Unsetenv(name)
	}
	n := &network{peers: map[string]*peer{}}
	var err error
	n.stun, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	go func() {
		var b [65536]byte
		for {
			count, addr, e := n.stun.ReadFromUDPAddrPort(b[:])
			if e != nil {
				return
			}
			id, e := stun.ParseBindingRequest(b[:count])
			if e == nil {
				n.mu.Lock()
				n.stunRequests++
				n.mu.Unlock()
				_, _ = n.stun.WriteToUDPAddrPort(stun.Response(id, addr), addr)
			}
		}
	}()
	n.derp = derpserver.New(key.NewNode(), log.Printf)
	mux := http.NewServeMux()
	mux.Handle("/derp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		n.derpConnections++
		n.mu.Unlock()
		derpserver.Handler(n.derp).ServeHTTP(w, r)
	}))
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	n.derpHTTP = httptest.NewUnstartedServer(mux)
	n.derpHTTP.StartTLS()
	port := n.derpHTTP.Listener.Addr().(*net.TCPAddr).Port
	// testcontrol의 기본 등록 로그가 공개 nodeKey를 기록하므로 끈다.
	n.control = &testcontrol.Server{Logf: func(string, ...any) {}, MagicDNSDomain: "tail0001.test", AllOnline: true, DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "test", RegionName: "test", Nodes: []*tailcfg.DERPNode{{Name: "1a", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: n.stun.LocalAddr().(*net.UDPAddr).Port, InsecureForTests: true}}}}}}
	n.initHostTools()
	n.http = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		n.started = true
		if r.URL.Path == "/ts2021" {
			n.controlConnections++
		}
		n.mu.Unlock()
		n.control.ServeHTTP(w, r)
	}))
	n.control.ExplicitBaseURL = "http://" + n.http.Listener.Addr().String()
	n.http.Start()
	return n, nil
}
func (n *network) close() {
	n.closeHostTools()
	for _, p := range n.peers {
		p.transfers.close()
		if p.capture != nil {
			p.capture.close()
		}
		if !p.stopped {
			p.server.Close()
		}
		os.RemoveAll(p.dir)
	}
	n.http.Close()
	n.derp.Close()
	n.derpHTTP.Close()
	n.stun.Close()
}
func (n *network) ready() map[string]any {
	return map[string]any{"event": "ready", "controlURL": n.control.ExplicitBaseURL, "magicDNSSuffix": n.control.MagicDNSDomain, "derp": map[string]any{"regionID": 1, "host": "127.0.0.1", "port": n.derpHTTP.Listener.Addr().(*net.TCPAddr).Port, "stunPort": n.stun.LocalAddr().(*net.UDPAddr).Port}}
}
func addresses(ns *tailcfg.Node) []string {
	a := make([]string, 0, len(ns.Addresses))
	for _, p := range ns.Addresses {
		a = append(a, p.Addr().String())
	}
	return a
}

var validName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (n *network) execute(c command) (map[string]any, error) {
	result := map[string]any{}
	switch c.Cmd {
	case "setCertDomains", "setDNSConfig", "setDNSLog", "setDNSFault", "acmeStart", "peerWhoIs", "peerHTTP", "goState":
		return n.executeHost(c)
	case "setLockCapability", "setLockBootstrapFault", "lockRequestResign", "lockRegistrations", "lockRequests",
		"lockStatus", "lockInit", "lockSign", "lockWrapAuthKey", "lockModify", "lockDisable":
		return n.executeLock(c)
	case "addPeer":
		if !validName.MatchString(c.Name) {
			return nil, errors.New("name이 잘못되었습니다")
		}
		if n.peers[c.Name] != nil {
			return nil, errors.New("이미 존재하는 피어입니다")
		}
		dir, e := os.MkdirTemp("", "swiftail-peer-")
		if e != nil {
			return nil, e
		}
		authKey := n.authKey
		if c.AuthKey != nil { // lockWrapAuthKey로 감싼 인증 키로 등록할 때
			authKey = *c.AuthKey
		}
		s := &tsnet.Server{Dir: dir, Hostname: c.Name, ControlURL: n.control.ExplicitBaseURL, AuthKey: authKey, UserLogf: func(string, ...any) {}}
		ok := false
		defer func() {
			if !ok {
				s.Close()
				os.RemoveAll(dir)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		st, e := s.Up(ctx)
		if e != nil {
			return nil, fmt.Errorf("피어 시작 실패: %w", e)
		}
		tcp, e := s.Listen("tcp", ":7")
		if e != nil {
			return nil, e
		}
		go func() {
			for {
				conn, e := tcp.Accept()
				if e != nil {
					return
				}
				go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
			}
		}()
		for _, ip := range st.TailscaleIPs {
			udp, e := s.ListenPacket("udp", netip.AddrPortFrom(ip, 7).String())
			if e != nil {
				return nil, e
			}
			go func() {
				var b [65536]byte
				for {
					count, a, e := udp.ReadFrom(b[:])
					if e != nil {
						return
					}
					_, _ = udp.WriteTo(b[:count], a)
				}
			}()
		}
		n.peers[c.Name] = &peer{server: s, dir: dir, transfers: newPeerTransfers()}
		ok = true
		result = map[string]any{"event": "peer", "name": c.Name, "nodeKey": st.Self.PublicKey.String(), "addresses": st.TailscaleIPs, "fqdn": st.Self.DNSName}
	case "removePeer":
		p := n.peers[c.Name]
		if p == nil {
			return nil, errors.New("피어가 없습니다")
		}
		delete(n.peers, c.Name)
		p.transfers.close()
		if p.capture != nil {
			p.capture.close()
		}
		var e error
		if !p.stopped {
			e = p.server.Close()
		}
		os.RemoveAll(p.dir)
		if e != nil {
			return nil, e
		}
		result = map[string]any{"event": "removed", "name": c.Name}
	case "nodes":
		nodes := []any{}
		for _, v := range n.control.AllNodes() {
			online := false
			if v.Online != nil {
				online = *v.Online
			}
			nodes = append(nodes, map[string]any{"nodeKey": v.Key.String(), "name": v.Name, "addresses": addresses(v), "online": online, "endpoints": append([]netip.AddrPort{}, v.Endpoints...)})
		}
		result = map[string]any{"event": "nodes", "nodes": nodes}
	case "networkStatus":
		n.mu.Lock()
		result = map[string]any{"event": "networkStatus", "controlConnections": n.controlConnections, "derpConnections": n.derpConnections, "stunRequests": n.stunRequests}
		n.mu.Unlock()
	case "setMagicDNS":
		if c.Enabled == nil {
			return nil, errors.New("enabled에 bool이 필요합니다")
		}
		n.mu.Lock()
		if n.started {
			n.mu.Unlock()
			return nil, errors.New("DNS 설정은 첫 제어 요청 전에만 바꿀 수 있습니다")
		}
		n.control.DNSConfig = &tailcfg.DNSConfig{Proxied: *c.Enabled}
		if n.host.configured {
			enabled := *c.Enabled
			n.host.enabled = &enabled
		}
		n.mu.Unlock()
		result = map[string]any{"event": "magicDNS", "enabled": *c.Enabled}
	case "startCapture", "captureStatus":
		p := n.peers[c.Name]
		if p == nil {
			return nil, errors.New("피어가 없습니다")
		}
		if c.Cmd == "startCapture" {
			if p.capture != nil {
				return nil, errors.New("이미 관측 중입니다")
			}
			var err error
			p.capture, err = startPeerCapture(p.server)
			if err != nil {
				return nil, err
			}
			result = map[string]any{"event": "captureStarted"}
		} else {
			if p.capture == nil {
				return nil, errors.New("관측을 시작하지 않았습니다")
			}
			if c.Port < 1 || c.Port > 65535 {
				return nil, errors.New("port는 1…65535여야 합니다")
			}
			var err error
			result, err = p.capture.status(uint16(c.Port))
			if err != nil {
				return nil, err
			}
		}
	case "peerStatus", "peerPing":
		p := n.peers[c.Name]
		if p == nil {
			return nil, errors.New("피어가 없습니다")
		}
		lc, e := p.server.LocalClient()
		if e != nil {
			return nil, e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c.Cmd == "peerStatus" {
			st, e := lc.Status(ctx)
			if e != nil {
				return nil, e
			}
			peers := []any{}
			for _, v := range st.Peer {
				peers = append(peers, map[string]any{"nodeKey": v.PublicKey.String(), "addresses": v.TailscaleIPs, "online": v.Online, "curAddr": v.CurAddr, "relay": v.Relay, "active": v.Active, "lastWrite": v.LastWrite})
			}
			selfAddrs := []string{}
			if st.Self != nil {
				selfAddrs = append(selfAddrs, st.Self.Addrs...)
			}
			result = map[string]any{"event": "peerStatus", "name": c.Name, "peers": peers, "selfAddrs": selfAddrs}
		} else {
			addr, e := netip.ParseAddr(c.To)
			if e != nil {
				return nil, errors.New("to 주소가 잘못되었습니다")
			}
			typ := tailcfg.PingType(c.Type)
			if typ != tailcfg.PingDisco && typ != tailcfg.PingTSMP && typ != tailcfg.PingICMP {
				return nil, errors.New("ping type이 잘못되었습니다")
			}
			ping, e := lc.Ping(ctx, addr, typ)
			if e != nil {
				return nil, e
			}
			result = map[string]any{"event": "peerPing", "name": c.Name, "result": ping}
		}
	case "peerServe", "peerDial", "peerClose", "transfers":
		if c.Cmd == "peerClose" && c.Stop {
			return n.stopPeer(c)
		}
		if p := n.peers[c.Name]; c.Cmd != "transfers" && p != nil && p.stopped {
			return nil, errors.New("멈춘 피어입니다")
		}
		return n.executeTransfer(c)
	case "peerSend":
		p := n.peers[c.Name]
		if p == nil {
			return nil, errors.New("피어가 없습니다")
		}
		addr, e := netip.ParseAddr(c.To)
		if e != nil || addr.Zone() != "" {
			return nil, errors.New("to 주소가 잘못되었습니다")
		}
		if c.Port < 1 || c.Port > 65535 {
			return nil, errors.New("port는 1…65535여야 합니다")
		}
		if c.Proto != "udp" && c.Proto != "tcp" {
			return nil, errors.New("proto는 udp 또는 tcp여야 합니다")
		}
		payload, e := hex.DecodeString(c.Payload)
		if e != nil || len(payload) > 65507 {
			return nil, errors.New("payload는 65507바이트 이하의 hex여야 합니다")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, sendErr := p.server.Dial(ctx, c.Proto, netip.AddrPortFrom(addr, uint16(c.Port)).String())
		sent := false
		if sendErr == nil {
			defer conn.Close()
			sendErr = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if sendErr == nil {
				var count int
				count, sendErr = conn.Write(payload)
				sent = sendErr == nil && count == len(payload)
				if sendErr == nil && !sent {
					sendErr = io.ErrShortWrite
				}
			}
		}
		message := ""
		if sendErr != nil {
			message = sendErr.Error()
		}
		// TCP 제한 시간은 SYN 송신의 증거가 아니다. 수신자가 패킷을 직접 확인한다.
		result = map[string]any{"event": "peerSend", "name": c.Name, "attempted": true, "sent": sent, "error": message}
	case "injectMapResponse":
		var k key.NodePublic
		if e := k.UnmarshalText([]byte(c.NodeKey)); e != nil {
			return nil, errors.New("nodeKey가 잘못되었습니다")
		}
		var m tailcfg.MapResponse
		if len(c.Response) == 0 || string(c.Response) == "null" {
			return nil, errors.New("response가 필요합니다")
		}
		if e := json.Unmarshal(c.Response, &m); e != nil {
			return nil, errors.New("response가 잘못되었습니다")
		}
		n.mu.Lock()
		injected := n.control.AddRawMapResponse(k, &m)
		if injected {
			n.host.manualMaps[k] = true
		}
		n.mu.Unlock()
		if !injected {
			return nil, errors.New("연결된 맵 스트림이 없습니다")
		}
		result = map[string]any{"event": "injected"}
	case "setAuth":
		if c.AuthURL != "" {
			if !n.control.CompleteAuth(c.AuthURL) {
				return nil, errors.New("인증 URL이 없습니다")
			}
		} else {
			n.mu.Lock()
			if n.started {
				n.mu.Unlock()
				return nil, errors.New("인증 설정은 첫 제어 요청 전에만 바꿀 수 있습니다")
			}
			if c.RequireAuth != nil {
				n.control.RequireAuth = *c.RequireAuth
			}
			if c.AuthKey != nil {
				n.control.RequireAuthKey = *c.AuthKey
				n.authKey = *c.AuthKey
			}
			n.mu.Unlock()
		}
		result = map[string]any{"event": "auth"}
	case "setNeverDirectUDP":
		if c.Enabled == nil {
			return nil, errors.New("enabled에 bool이 필요합니다")
		}
		// 시험 계약의 런타임 전환이며, envknob의 동시 읽기 안전성 한계는 README에 적는다.
		envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", strconv.FormatBool(*c.Enabled))
		result = map[string]any{"event": "neverDirectUDP", "enabled": *c.Enabled}
	case "quit":
		result = map[string]any{"event": "quit"}
	default:
		return nil, errors.New("알 수 없는 명령입니다")
	}
	return result, nil
}
func run(in io.Reader, out io.Writer) (runErr error) {
	os.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	os.Setenv("TS_DISABLE_PORTMAPPER", "true")
	n, e := newNetwork()
	if e != nil {
		return e
	}
	enc := json.NewEncoder(out)
	var outputMu sync.Mutex
	var httpWG sync.WaitGroup
	var writeErr error
	encode := func(value any) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		err := enc.Encode(value)
		if err != nil && writeErr == nil {
			writeErr = err
		}
		return err
	}
	closed := false
	shutdown := func() {
		if !closed {
			n.close()
			closed = true
		}
		httpWG.Wait()
	}
	defer func() {
		shutdown()
		if runErr == nil {
			runErr = writeErr
		}
	}()
	if e = encode(n.ready()); e != nil {
		return e
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	for scanner.Scan() {
		var c command
		e = json.Unmarshal(scanner.Bytes(), &c)
		var result map[string]any
		if e != nil {
			result = map[string]any{"event": "error", "message": "JSON이 잘못되었습니다"}
		} else if len(c.ID) == 0 || string(c.ID) == "null" {
			result = map[string]any{"event": "error", "message": "id가 필요합니다"}
		} else if c.Cmd == "peerHTTP" && n.peers[c.Name] != nil && !n.peers[c.Name].stopped {
			p := n.peers[c.Name]
			httpWG.Add(1)
			go func() {
				defer httpWG.Done()
				response, err := n.peerHTTP(c, p)
				if err != nil {
					response = map[string]any{"event": "error", "message": err.Error()}
				}
				response["id"] = c.ID
				encode(response)
			}()
			continue
		} else {
			result, e = n.execute(c)
			if e != nil {
				result = map[string]any{"event": "error", "message": e.Error()}
			}
		}
		if len(c.ID) > 0 {
			result["id"] = c.ID
		}
		if c.Cmd == "quit" && result["event"] == "quit" {
			shutdown()
		}
		if e = encode(result); e != nil {
			return e
		}
		if c.Cmd == "quit" && result["event"] == "quit" {
			return nil
		}
	}
	return scanner.Err()
}
func main() {
	if e := run(os.Stdin, os.Stdout); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
