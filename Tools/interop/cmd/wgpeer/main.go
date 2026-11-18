package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

type config struct {
	PrivateKey    string   `json:"privateKey"`
	PeerPublicKey string   `json:"peerPublicKey"`
	PeerEndpoint  string   `json:"peerEndpoint"`
	AllowedIPs    []string `json:"allowedIPs"`
	ListenPort    int      `json:"listenPort"`
}
type command struct {
	Cmd    string `json:"cmd"`
	Packet string `json:"packet"`
}
type event struct {
	Event             string  `json:"event"`
	Message           string  `json:"message,omitempty"`
	ListenPort        *uint16 `json:"listenPort,omitempty"`
	PublicKey         string  `json:"publicKey,omitempty"`
	Packet            string  `json:"packet,omitempty"`
	LastHandshakeSec  *int64  `json:"lastHandshakeSec,omitempty"`
	LastHandshakeNsec *int64  `json:"lastHandshakeNsec,omitempty"`
	TxBytes           *int64  `json:"txBytes,omitempty"`
	RxBytes           *int64  `json:"rxBytes,omitempty"`
}
type output struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (o *output) write(e event) { o.mu.Lock(); defer o.mu.Unlock(); _ = o.enc.Encode(e) }

// The default bind listens on all addresses, so combine a loopback socket with the standard endpoint parser.
type loopbackBind struct {
	conn.Bind
	socket *net.UDPConn
	mu     sync.RWMutex
}

func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.socket = s
	receive := func(slab []byte, packets []conn.ReceivedPacket) (int, error) {
		n, addr, err := s.ReadFromUDPAddrPort(slab)
		if err != nil {
			return 0, err
		}
		ep, err := b.ParseEndpoint(addr.String())
		if err != nil {
			return 0, err
		}
		packets[0] = conn.ReceivedPacket{Size: n, Endpoint: ep}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(s.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}
func (b *loopbackBind) SetMark(uint32) error { return nil }
func (b *loopbackBind) BatchSize() int       { return 1 }
func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.socket == nil {
		return net.ErrClosed
	}
	addr, err := netip.ParseAddrPort(ep.DstToString())
	if err != nil {
		return err
	}
	for _, buf := range bufs {
		if _, err := b.socket.WriteToUDPAddrPort(buf[offset:], addr); err != nil {
			return err
		}
	}
	return nil
}

type peer struct {
	dev    *device.Device
	tun    *tuntest.ChannelTUN
	port   uint16
	public string
}

func newPeer(c config) (*peer, error) {
	key, err := hex.DecodeString(c.PrivateKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("privateKey must be 32 bytes in hexadecimal")
	}
	if subtle.ConstantTimeCompare(key, make([]byte, 32)) == 1 {
		return nil, errors.New("invalid privateKey")
	}
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, errors.New("invalid privateKey")
	}
	peerKey, err := hex.DecodeString(c.PeerPublicKey)
	if err != nil || len(peerKey) != 32 {
		return nil, errors.New("peerPublicKey must be 32 bytes in hexadecimal")
	}
	if _, err = private.ECDH(mustPublic(peerKey)); err != nil {
		return nil, errors.New("invalid peerPublicKey")
	}
	endpoint, err := netip.ParseAddrPort(c.PeerEndpoint)
	if err != nil || endpoint.Addr() != netip.MustParseAddr("127.0.0.1") || endpoint.Port() == 0 {
		return nil, errors.New("peerEndpoint must be a port on 127.0.0.1")
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return nil, errors.New("invalid listenPort")
	}
	if len(c.AllowedIPs) == 0 {
		return nil, errors.New("allowedIPs is empty")
	}
	var allowed strings.Builder
	for _, ip := range c.AllowedIPs {
		prefix, e := netip.ParsePrefix(ip)
		if e != nil {
			return nil, errors.New("invalid allowedIPs")
		}
		fmt.Fprintf(&allowed, "allowed_ip=%s\n", prefix.String())
	}
	t := tuntest.NewChannelTUN()
	logger := log.New(os.Stderr, "wgpeer: ", log.LstdFlags)
	d := device.NewDevice(t.TUN(), &loopbackBind{Bind: conn.NewDefaultBind()}, &device.Logger{Verbosef: logger.Printf, Errorf: logger.Printf})
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nendpoint=%s\n%s", hex.EncodeToString(key), c.ListenPort, hex.EncodeToString(peerKey), endpoint, allowed.String())
	if err = d.IpcSet(cfg); err != nil {
		d.Close()
		return nil, errors.New("device configuration failed")
	}
	if err = d.Up(); err != nil {
		d.Close()
		return nil, fmt.Errorf("could not open device: %w", err)
	}
	state, err := d.IpcGet()
	if err != nil {
		d.Close()
		return nil, errors.New("could not read device status")
	}
	values := parseState(state)
	port, err := strconv.ParseUint(values["listen_port"], 10, 16)
	if err != nil || port == 0 {
		d.Close()
		return nil, errors.New("could not read listen port")
	}
	return &peer{dev: d, tun: t, port: uint16(port), public: hex.EncodeToString(private.PublicKey().Bytes())}, nil
}
func mustPublic(b []byte) *ecdh.PublicKey { p, _ := ecdh.X25519().NewPublicKey(b); return p }
func parseState(s string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}
func (p *peer) stats() (event, error) {
	s, err := p.dev.IpcGet()
	if err != nil {
		return event{}, err
	}
	m := parseState(s)
	vals := make([]int64, 4)
	for i, k := range []string{"last_handshake_time_sec", "last_handshake_time_nsec", "tx_bytes", "rx_bytes"} {
		vals[i], err = strconv.ParseInt(m[k], 10, 64)
		if err != nil {
			return event{}, err
		}
	}
	return event{Event: "stats", LastHandshakeSec: &vals[0], LastHandshakeNsec: &vals[1], TxBytes: &vals[2], RxBytes: &vals[3]}, nil
}
func decode(line []byte, dst any) error {
	d := json.NewDecoder(strings.NewReader(string(line)))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing data after JSON")
	}
	return nil
}
func validPacket(b []byte) bool {
	if len(b) < 20 {
		return false
	}
	switch b[0] >> 4 {
	case 4:
		return int(b[0]&15)*4 >= 20 && int(b[0]&15)*4 <= len(b) && int(binary.BigEndian.Uint16(b[2:4])) == len(b)
	case 6:
		return len(b) >= 40 && int(binary.BigEndian.Uint16(b[4:6]))+40 == len(b)
	}
	return false
}
func run(in io.Reader, out io.Writer) int {
	o := &output{enc: json.NewEncoder(out)}
	fail := func(msg string) { o.write(event{Event: "error", Message: msg}) }
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	if !scanner.Scan() {
		fail("configuration is missing")
		return 1
	}
	var c config
	if decode(scanner.Bytes(), &c) != nil {
		fail("invalid configuration JSON")
		return 1
	}
	p, err := newPeer(c)
	if err != nil {
		fail(err.Error())
		return 1
	}
	defer p.dev.Close()
	o.write(event{Event: "ready", ListenPort: &p.port, PublicKey: p.public})
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case b, ok := <-p.tun.Inbound:
				if !ok {
					return
				}
				o.write(event{Event: "recv", Packet: hex.EncodeToString(b)})
			case <-done:
				return
			}
		}
	}()
	for scanner.Scan() {
		var cmd command
		if decode(scanner.Bytes(), &cmd) != nil {
			fail("invalid command JSON")
			continue
		}
		switch cmd.Cmd {
		case "send":
			b, e := hex.DecodeString(cmd.Packet)
			if e != nil || !validPacket(b) || len(b) > device.MaxContentSize {
				fail("invalid packet")
				continue
			}
			p.tun.Outbound <- b
		case "stats":
			e, err := p.stats()
			if err != nil {
				fail("could not read status")
			} else {
				o.write(e)
			}
		case "quit":
			return 0
		default:
			fail("unknown command")
		}
	}
	if scanner.Err() != nil {
		fail("could not read input")
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Stdin, os.Stdout)) }
