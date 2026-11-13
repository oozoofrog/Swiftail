package main

import (
	"bufio"
	"context"
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
	"sync"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/logtail"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

type command struct {
	ID          json.RawMessage `json:"id"`
	Cmd         string          `json:"cmd"`
	Name        string          `json:"name"`
	To          string          `json:"to"`
	Type        string          `json:"type"`
	NodeKey     string          `json:"nodeKey"`
	Response    json.RawMessage `json:"response"`
	RequireAuth *bool           `json:"requireAuth"`
	AuthKey     *string         `json:"authKey"`
	AuthURL     string          `json:"authURL"`
}
type peer struct {
	server *tsnet.Server
	dir    string
}
type network struct {
	control  *testcontrol.Server
	http     *httptest.Server
	derpHTTP *httptest.Server
	derp     *derpserver.Server
	stun     *net.UDPConn
	peers    map[string]*peer
	mu       sync.Mutex
	started  bool
	authKey  string
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
				_, _ = n.stun.WriteToUDPAddrPort(stun.Response(id, addr), addr)
			}
		}
	}()
	n.derp = derpserver.New(key.NewNode(), log.Printf)
	mux := http.NewServeMux()
	mux.Handle("/derp", derpserver.Handler(n.derp))
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	n.derpHTTP = httptest.NewUnstartedServer(mux)
	n.derpHTTP.StartTLS()
	port := n.derpHTTP.Listener.Addr().(*net.TCPAddr).Port
	n.control = &testcontrol.Server{MagicDNSDomain: "tail0001.test", AllOnline: true, DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "test", RegionName: "test", Nodes: []*tailcfg.DERPNode{{Name: "1a", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: n.stun.LocalAddr().(*net.UDPAddr).Port, InsecureForTests: true}}}}}}
	n.http = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		n.started = true
		n.mu.Unlock()
		n.control.ServeHTTP(w, r)
	}))
	n.control.ExplicitBaseURL = "http://" + n.http.Listener.Addr().String()
	n.http.Start()
	return n, nil
}
func (n *network) close() {
	for _, p := range n.peers {
		p.server.Close()
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
		s := &tsnet.Server{Dir: dir, Hostname: c.Name, ControlURL: n.control.ExplicitBaseURL, AuthKey: n.authKey, UserLogf: func(string, ...any) {}}
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
		n.peers[c.Name] = &peer{s, dir}
		ok = true
		result = map[string]any{"event": "peer", "name": c.Name, "nodeKey": st.Self.PublicKey.String(), "addresses": st.TailscaleIPs, "fqdn": st.Self.DNSName}
	case "removePeer":
		p := n.peers[c.Name]
		if p == nil {
			return nil, errors.New("피어가 없습니다")
		}
		delete(n.peers, c.Name)
		e := p.server.Close()
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
			nodes = append(nodes, map[string]any{"nodeKey": v.Key.String(), "name": v.Name, "addresses": addresses(v), "online": online})
		}
		result = map[string]any{"event": "nodes", "nodes": nodes}
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
				peers = append(peers, map[string]any{"nodeKey": v.PublicKey.String(), "addresses": v.TailscaleIPs, "online": v.Online, "curAddr": v.CurAddr, "relay": v.Relay})
			}
			result = map[string]any{"event": "peerStatus", "name": c.Name, "peers": peers}
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
		if !n.control.AddRawMapResponse(k, &m) {
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
	case "quit":
		result = map[string]any{"event": "quit"}
	default:
		return nil, errors.New("알 수 없는 명령입니다")
	}
	return result, nil
}
func run(in io.Reader, out io.Writer) error {
	os.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	os.Setenv("TS_DISABLE_PORTMAPPER", "true")
	n, e := newNetwork()
	if e != nil {
		return e
	}
	defer n.close()
	enc := json.NewEncoder(out)
	if e = enc.Encode(n.ready()); e != nil {
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
		} else {
			result, e = n.execute(c)
			if e != nil {
				result = map[string]any{"event": "error", "message": e.Error()}
			}
		}
		if len(c.ID) > 0 {
			result["id"] = c.ID
		}
		if e = enc.Encode(result); e != nil {
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
