package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const maxTransferBytes uint64 = 1 << 32

// stream is an LCG64 stream from a public test seed. Reads starting in the middle of a word produce the same byte sequence.
type stream struct {
	state  uint64
	word   [8]byte
	offset int
}

func newStream(seed uint64) *stream { return &stream{state: seed, offset: 8} }
func (s *stream) Read(p []byte) (int, error) {
	for i := range p {
		if s.offset == 8 {
			s.state = s.state*6364136223846793005 + 1442695040888963407
			binary.LittleEndian.PutUint64(s.word[:], s.state)
			s.offset = 0
		}
		p[i] = s.word[s.offset]
		s.offset++
	}
	return len(p), nil
}

type transferStatus struct {
	ID             uint64 `json:"transferID"`
	Name           string `json:"name"`
	Remote         string `json:"remote"`
	Sent           uint64 `json:"sent"`
	SentSHA256     string `json:"sentSHA256"`
	Received       uint64 `json:"received"`
	ReceivedSHA256 string `json:"receivedSHA256"`
	ElapsedMs      int64  `json:"elapsedMs"`
	Error          string `json:"error"`
	State          string `json:"state"`
}

type transfer struct {
	mu     sync.Mutex
	status transferStatus
	start  time.Time
}

func (n *network) newTransfer(name, remote, state string) *transfer {
	n.mu.Lock()
	defer n.mu.Unlock()
	empty := sha256.Sum256(nil)
	t := &transfer{start: time.Now(), status: transferStatus{ID: uint64(len(n.transfers) + 1), Name: name, Remote: remote, State: state, SentSHA256: hex.EncodeToString(empty[:]), ReceivedSHA256: hex.EncodeToString(empty[:])}}
	n.transfers = append(n.transfers, t)
	return t
}
func (t *transfer) snapshot() transferStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.status
	if s.State == "dialing" || s.State == "running" {
		s.ElapsedMs = time.Since(t.start).Milliseconds()
	}
	return s
}
func (t *transfer) finish(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.State = "complete"
	if err != nil {
		t.status.State = "error"
		t.status.Error = err.Error()
	}
	t.status.ElapsedMs = time.Since(t.start).Milliseconds()
}

// peerTransfers cleans up only the connections and goroutines it started when the peer is removed.
type peerTransfers struct {
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	listeners map[int]net.Listener
	conns     map[net.Conn]bool
	wg        sync.WaitGroup
}

func newPeerTransfers() *peerTransfers {
	ctx, cancel := context.WithCancel(context.Background())
	return &peerTransfers{ctx: ctx, cancel: cancel, listeners: map[int]net.Listener{}, conns: map[net.Conn]bool{}}
}
func (p *peerTransfers) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.cancel()
	for _, listener := range p.listeners {
		listener.Close()
	}
	for conn := range p.conns {
		conn.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}
func (p *peerTransfers) track(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx.Err() != nil {
		conn.Close()
		return false
	}
	p.conns[conn] = true
	return true
}
func (p *peerTransfers) release(conn net.Conn) {
	conn.Close()
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

func transferTimeout(c command) (time.Duration, error) {
	seconds := 15
	if c.TimeoutSec != nil {
		seconds = *c.TimeoutSec
	}
	if seconds < 1 || seconds > 3600 {
		return 0, errors.New("timeoutSec must be 1…3600")
	}
	return time.Duration(seconds) * time.Second, nil
}

func (n *network) executeTransfer(c command) (map[string]any, error) {
	if c.Cmd == "transfers" {
		n.mu.Lock()
		jobs := append([]*transfer(nil), n.transfers...)
		n.mu.Unlock()
		statuses := []transferStatus{}
		for _, t := range jobs {
			status := t.snapshot()
			if c.Name == "" || status.Name == c.Name {
				statuses = append(statuses, status)
			}
		}
		return map[string]any{"event": "transfers", "transfers": statuses}, nil
	}
	p := n.peers[c.Name]
	if p == nil {
		return nil, errors.New("peer not found")
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, errors.New("port must be 1…65535")
	}
	timeout, err := transferTimeout(c)
	if err != nil {
		return nil, err
	}
	switch c.Cmd {
	case "peerServe":
		p.transfers.mu.Lock()
		defer p.transfers.mu.Unlock()
		if p.transfers.listeners[c.Port] != nil {
			return nil, errors.New("already listening on this port")
		}
		listener, err := p.server.Listen("tcp", ":"+strconv.Itoa(c.Port))
		if err != nil {
			return nil, err
		}
		p.transfers.listeners[c.Port] = listener
		p.transfers.wg.Add(1)
		go func() {
			defer p.transfers.wg.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				if !p.transfers.track(conn) {
					return
				}
				t := n.newTransfer(c.Name, "", "running")
				p.transfers.wg.Add(1)
				go func() {
					defer p.transfers.wg.Done()
					defer p.transfers.release(conn)
					err := conn.SetDeadline(time.Now().Add(timeout))
					var preface [16]byte
					if err == nil {
						_, err = io.ReadFull(conn, preface[:])
					}
					if err == nil {
						count := binary.BigEndian.Uint64(preface[:8])
						seed := binary.BigEndian.Uint64(preface[8:])
						if count > maxTransferBytes {
							err = errors.New("length in transfer header exceeds 4GiB")
						} else {
							err = t.exchange(conn, count, seed)
						}
					}
					t.finish(err)
				}()
			}
		}()
		return map[string]any{"event": "peerServe", "name": c.Name, "port": c.Port}, nil
	case "peerClose":
		p.transfers.mu.Lock()
		listener := p.transfers.listeners[c.Port]
		delete(p.transfers.listeners, c.Port)
		p.transfers.mu.Unlock()
		if listener == nil {
			return nil, errors.New("no listening port")
		}
		if err := listener.Close(); err != nil {
			return nil, err
		}
		return map[string]any{"event": "peerClose", "name": c.Name, "port": c.Port}, nil
	case "peerDial":
		addr, err := netip.ParseAddr(c.To)
		if err != nil || addr.Zone() != "" {
			return nil, errors.New("to requires an IP address without a zone")
		}
		if c.Send == nil || *c.Send > maxTransferBytes {
			return nil, errors.New("send must be 0…4294967296")
		}
		if c.Seed == nil {
			return nil, errors.New("seed requires a UInt64")
		}
		remote := net.JoinHostPort(addr.String(), strconv.Itoa(c.Port))
		count, seed := *c.Send, *c.Seed
		t := n.newTransfer(c.Name, remote, "dialing")
		p.transfers.wg.Add(1)
		go func() {
			defer p.transfers.wg.Done()
			ctx, cancel := context.WithTimeout(p.transfers.ctx, timeout)
			defer cancel()
			conn, err := p.server.Dial(ctx, "tcp", remote)
			if err == nil {
				if !p.transfers.track(conn) {
					t.finish(context.Canceled)
					return
				}
				defer p.transfers.release(conn)
				deadline, _ := ctx.Deadline()
				err = conn.SetDeadline(deadline)
				var preface [16]byte
				binary.BigEndian.PutUint64(preface[:8], count)
				binary.BigEndian.PutUint64(preface[8:], seed)
				if err == nil {
					err = writeAll(conn, preface[:])
				}
				if err == nil {
					err = t.exchange(conn, count, seed)
				}
			}
			t.finish(err)
		}()
		return map[string]any{"event": "peerDial", "name": c.Name, "transferID": t.snapshot().ID}, nil
	}
	return nil, errors.New("unknown transfer command")
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (t *transfer) exchange(conn net.Conn, count, seed uint64) error {
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.New("connection does not support CloseWrite")
	}
	t.mu.Lock()
	t.status.State = "running"
	if remote := conn.RemoteAddr(); remote != nil {
		t.status.Remote = remote.String()
	}
	t.mu.Unlock()
	written := make(chan error, 1)
	go func() {
		h := sha256.New()
		source := newStream(seed)
		var buffer [32 << 10]byte
		var sent uint64
		var err error
		for sent < count {
			size := min(uint64(len(buffer)), count-sent)
			source.Read(buffer[:size])
			var n int
			n, err = conn.Write(buffer[:size])
			h.Write(buffer[:n])
			sent += uint64(n)
			t.mu.Lock()
			t.status.Sent, t.status.SentSHA256 = sent, hex.EncodeToString(h.Sum(nil))
			t.mu.Unlock()
			if err != nil {
				break
			}
			if n != int(size) {
				err = io.ErrShortWrite
				break
			}
		}
		if err == nil {
			err = half.CloseWrite()
		}
		if err != nil {
			conn.Close()
		}
		written <- err
	}()
	h := sha256.New()
	var buffer [32 << 10]byte
	var received uint64
	var readErr error
	for {
		n, err := conn.Read(buffer[:])
		h.Write(buffer[:n])
		received += uint64(n)
		t.mu.Lock()
		t.status.Received, t.status.ReceivedSHA256 = received, hex.EncodeToString(h.Sum(nil))
		t.mu.Unlock()
		if err != nil {
			if err != io.EOF {
				readErr = err
				conn.Close()
			}
			break
		}
	}
	writeErr := <-written
	if writeErr != nil {
		return fmt.Errorf("write failed: %w", writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("read failed: %w", readErr)
	}
	return nil
}
