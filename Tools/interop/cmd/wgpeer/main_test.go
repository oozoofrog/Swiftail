package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun/tuntest"
)

func TestExchange(t *testing.T) {
	var keys [2]*ecdh.PrivateKey
	var sockets [2]*net.UDPConn
	var ports [2]int
	for i := range keys {
		var err error
		keys[i], err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sockets[i], err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = sockets[i].LocalAddr().(*net.UDPAddr).Port
	}
	for _, s := range sockets {
		s.Close()
	}
	var peers [2]*peer
	for i := range peers {
		j := 1 - i
		c := config{PrivateKey: hex.EncodeToString(keys[i].Bytes()), PeerPublicKey: hex.EncodeToString(keys[j].PublicKey().Bytes()), PeerEndpoint: fmt.Sprintf("127.0.0.1:%d", ports[j]), AllowedIPs: []string{fmt.Sprintf("10.99.0.%d/32", j+1)}, ListenPort: ports[i]}
		var err error
		peers[i], err = newPeer(c)
		if err != nil {
			t.Fatal(err)
		}
		defer peers[i].dev.Close()
	}
	for i := range peers {
		j := 1 - i
		src := netip.MustParseAddr(fmt.Sprintf("10.99.0.%d", i+1))
		dst := netip.MustParseAddr(fmt.Sprintf("10.99.0.%d", j+1))
		packet := tuntest.Ping(dst, src)
		select {
		case peers[i].tun.Outbound <- packet:
		case <-time.After(5 * time.Second):
			t.Fatal("send timed out")
		}
		select {
		case got := <-peers[j].tun.Inbound:
			if !bytes.Equal(got, packet) {
				t.Fatal("received packet mismatch")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("receive timed out")
		}
	}
	for _, p := range peers {
		e, err := p.stats()
		if err != nil || *e.LastHandshakeSec == 0 {
			t.Fatalf("invalid handshake status: %v", err)
		}
	}
}
