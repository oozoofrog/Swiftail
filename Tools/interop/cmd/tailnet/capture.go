// Origin of the pcap format: tailscale.com v1.104.6 feature/capture/capture.go, net/packet/capture.go.
// Copyright (c) Tailscale Inc & contributors; SPDX-License-Identifier: BSD-3-Clause.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	_ "tailscale.com/feature/capture"
	"tailscale.com/tsnet"
)

// Retain and print only the counts needed for the gate. Do not store or print raw packets or addresses.
type peerCapture struct {
	stream         io.ReadCloser
	cancel         context.CancelFunc
	done           chan struct{}
	mu             sync.Mutex
	servicePackets int
	ports          map[uint16]int
	failure        error
}

func startPeerCapture(server *tsnet.Server) (*peerCapture, error) {
	lc, err := server.LocalClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(5*time.Second, cancel)
	defer timer.Stop()
	stream, err := lc.StreamDebugCapture(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	p := &peerCapture{stream: stream, cancel: cancel, done: make(chan struct{}), ports: map[uint16]int{}}
	ready := make(chan error, 1)
	go func() {
		defer close(p.done)
		var header [24]byte
		_, err := io.ReadFull(stream, header[:])
		if err == nil && (binary.LittleEndian.Uint32(header[:4]) != 0xa1b2c3d4 || binary.LittleEndian.Uint32(header[20:]) != 147) {
			err = errors.New("unsupported capture header")
		}
		ready <- err
		if err != nil {
			return
		}
		for {
			var record [16]byte
			if _, err = io.ReadFull(stream, record[:]); err != nil {
				break
			}
			size := binary.LittleEndian.Uint32(record[8:12])
			if size > 65535 {
				err = errors.New("capture packet exceeds size limit")
				break
			}
			data := make([]byte, int(size))
			if _, err = io.ReadFull(stream, data); err != nil {
				break
			}
			service, port, parseErr := inspectCapturedPacket(data)
			if parseErr != nil {
				err = parseErr
				break
			}
			p.mu.Lock()
			if service {
				p.servicePackets++
			}
			if port != 0 {
				p.ports[port]++
			}
			p.mu.Unlock()
		}
		p.mu.Lock()
		p.failure = err
		p.mu.Unlock()
	}()
	select {
	case err := <-ready:
		if err == nil {
			return p, nil
		}
		p.close()
		return nil, errors.New("invalid initial capture header")
	case <-ctx.Done():
		p.close()
		return nil, errors.New("capture start timed out")
	}
}

func (p *peerCapture) close() { p.cancel(); p.stream.Close(); <-p.done }
func (p *peerCapture) status(port uint16) (map[string]any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failure != nil {
		return nil, errors.New("capture stream ended")
	}
	return map[string]any{"event": "captureStatus", "servicePackets": p.servicePackets, "observedPackets": p.ports[port]}, nil
}

// Count only FromPeer packets. Check the NAT metadata and IP boundaries before reading only the destination and UDP source port.
func inspectCapturedPacket(data []byte) (bool, uint16, error) {
	invalid := errors.New("invalid capture packet boundaries")
	if len(data) < 4 {
		return false, 0, invalid
	}
	if binary.LittleEndian.Uint16(data[:2]) != 1 {
		return false, 0, nil
	}
	offset := 2
	for range 2 {
		if offset >= len(data) {
			return false, 0, invalid
		}
		size := int(data[offset])
		if size != 0 && size != 4 && size != 16 {
			return false, 0, invalid
		}
		offset += 1 + size
	}
	if offset >= len(data) {
		return false, 0, invalid
	}
	ip := data[offset:]
	var destination netip.Addr
	var proto byte
	var transport int
	switch ip[0] >> 4 {
	case 4:
		if len(ip) < 20 {
			return false, 0, invalid
		}
		destination, _ = netip.AddrFromSlice(ip[16:20])
		proto, transport = ip[9], int(ip[0]&15)*4
		if transport < 20 || transport > len(ip) {
			return false, 0, invalid
		}
	case 6:
		if len(ip) < 40 {
			return false, 0, invalid
		}
		destination, _ = netip.AddrFromSlice(ip[24:40])
		proto, transport = ip[6], 40
	default:
		return false, 0, invalid
	}
	service := destination == netip.MustParseAddr("100.100.100.100") || destination == netip.MustParseAddr("fd7a:115c:a1e0::53")
	if proto == 17 {
		if transport+8 > len(ip) {
			return false, 0, invalid
		}
		return service, binary.BigEndian.Uint16(ip[transport:]), nil
	}
	return service, 0, nil
}
