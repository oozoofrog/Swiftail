package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const maxBody = 8 << 20

func number(r *http.Request, name string, limit int) (int, error) {
	value, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || value < 0 || value > limit {
		return 0, fmt.Errorf("%s is out of range", name)
	}
	return value, nil
}

func headerValue(size int) string {
	var b strings.Builder
	for i := 0; i < size; i++ {
		b.WriteByte(byte('a' + i%26))
	}
	return b.String()
}

func handle(w http.ResponseWriter, r *http.Request) {
	// The default server generates Date automatically, so omit it from deterministic tests.
	w.Header()["Date"] = nil
	bad := func(err error) { http.Error(w, err.Error(), http.StatusBadRequest) }
	method := http.MethodGet
	if r.URL.Path == "/echo" {
		method = http.MethodPost
	}
	if r.Method != method {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/small":
		_, _ = io.WriteString(w, "ok")
	case "/echo":
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_, _ = w.Write(body)
	case "/bytes":
		size, err := number(r, "size", maxBody)
		if err != nil {
			bad(err)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		b := make([]byte, 16384)
		for start := 0; start < size; {
			n := min(len(b), size-start)
			for i := range n {
				b[i] = byte((start + i) % 251)
			}
			if _, err := w.Write(b[:n]); err != nil {
				return
			}
			start += n
		}
	case "/stream":
		count, err := number(r, "count", 1_000_000)
		if err != nil {
			bad(err)
			return
		}
		interval, err := number(r, "intervalMs", 60_000)
		if err != nil {
			bad(err)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		for i := 0; count == 0 || i < count; i++ {
			timer := time.NewTimer(time.Duration(interval) * time.Millisecond)
			select {
			case <-r.Context().Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if _, err := fmt.Fprintf(w, "%d\n", i); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
		}
	case "/headers":
		count, err := number(r, "count", 1024)
		if err != nil {
			bad(err)
			return
		}
		size, err := number(r, "size", 64<<10)
		if err != nil {
			bad(err)
			return
		}
		if count*(size+64) > 1<<20 {
			bad(errors.New("combined headers are too large"))
			return
		}
		for i := range count {
			w.Header().Set(fmt.Sprintf("x-test-%d", i), headerValue(size))
		}
		w.WriteHeader(http.StatusOK)
	case "/status":
		code, err := number(r, "code", 599)
		if err != nil || code < 200 {
			bad(errors.New("code must be 200...599"))
			return
		}
		w.WriteHeader(code)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type server struct {
	listener net.Listener
	base     *http.Server
	h2       http2.Server
	mu       sync.Mutex
	conns    map[net.Conn]bool
	draining bool
	done     chan struct{}
}

func start() (*server, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &server{listener: listener, base: &http.Server{}, conns: make(map[net.Conn]bool), done: make(chan struct{})}
	// Use the same ServeConn path as testcontrol with the default HTTP/2 configuration.
	if err := http2.ConfigureServer(s.base, &s.h2); err != nil {
		listener.Close()
		return nil, err
	}
	go func() {
		defer close(s.done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			if s.draining {
				s.mu.Unlock()
				conn.Close()
				continue
			}
			s.conns[conn] = true
			s.mu.Unlock()
			go func() {
				defer func() { conn.Close(); s.mu.Lock(); delete(s.conns, conn); s.mu.Unlock() }()
				s.h2.ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(handle)})
			}()
		}
	}()
	return s, nil
}

func (s *server) goaway() {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
	s.listener.Close()
	// Shutdown waits for open streams to finish, so keep processing commands.
	go func() { _ = s.base.Shutdown(context.Background()) }()
}
func (s *server) close() {
	s.mu.Lock()
	s.draining = true
	s.listener.Close()
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()
	<-s.done
}
func run(in io.Reader, out io.Writer) error {
	s, err := start()
	if err != nil {
		return err
	}
	defer s.close()
	enc := json.NewEncoder(out)
	if err := enc.Encode(map[string]any{"event": "ready", "port": s.listener.Addr().(*net.TCPAddr).Port}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		var command struct {
			Cmd string `json:"cmd"`
		}
		err := json.Unmarshal(scanner.Bytes(), &command)
		if err == nil {
			switch command.Cmd {
			case "quit":
				return nil
			case "goaway":
				s.goaway()
				continue
			}
		}
		if err := enc.Encode(map[string]string{"event": "error", "message": "invalid command"}); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func main() {
	fixtures := flag.String("hpack-fixtures", "", "HPACK fixture output file")
	flag.Parse()
	var err error
	if flag.NArg() != 0 {
		err = errors.New("positional arguments are not accepted")
	} else if *fixtures != "" {
		err = writeHPACK(*fixtures)
	} else {
		err = run(os.Stdin, os.Stdout)
	}
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
