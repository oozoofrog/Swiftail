package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func client(t *testing.T, s *server) *http2.ClientConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", s.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := new(http2.Transport).NewClientConn(conn)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	return cc
}
func request(t *testing.T, cc *http2.ClientConn, method, path string, body io.Reader) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, method, "https://tail0001.test"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}
	return resp
}
func body(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return b
}
func TestPaths(t *testing.T) {
	s, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	cc := client(t, s)
	if got := request(t, cc, "GET", "/small", nil); got.StatusCode != 200 || string(body(t, got)) != "ok" {
		t.Fatal("small response mismatch")
	}
	b := make([]byte, 3<<20)
	for i := range b {
		b[i] = byte(i % 251)
	}
	if got := request(t, cc, "POST", "/echo", bytes.NewReader(b)); got.StatusCode != 200 || !bytes.Equal(body(t, got), b) {
		t.Fatal("large POST round-trip mismatch")
	}
	got := request(t, cc, "GET", fmt.Sprintf("/bytes?size=%d", len(b)), nil)
	if got.StatusCode != 200 || !bytes.Equal(body(t, got), b) {
		t.Fatal("bytes response mismatch")
	}
	for _, p := range []struct{ count, size int }{{96, 400}, {4, 20}, {4, 20}} {
		got := request(t, cc, "GET", fmt.Sprintf("/headers?count=%d&size=%d", p.count, p.size), nil)
		if got.StatusCode != 200 {
			t.Fatal(got.Status)
		}
		for i := range p.count {
			if got.Header.Get(fmt.Sprintf("x-test-%d", i)) != headerValue(p.size) {
				t.Fatal("header mismatch")
			}
		}
		if len(body(t, got)) != 0 {
			t.Fatal("headers body is not empty")
		}
	}
	for _, code := range []int{200, 204, 304, 418, 503} {
		got := request(t, cc, "GET", fmt.Sprintf("/status?code=%d", code), nil)
		if got.StatusCode != code || len(body(t, got)) != 0 {
			t.Fatal("status mismatch")
		}
	}
	got = request(t, cc, "GET", "/stream?count=3&intervalMs=1", nil)
	if string(body(t, got)) != "0\n1\n2\n" {
		t.Fatal("stream mismatch")
	}
	for _, path := range []string{"/bytes?size=-1", "/bytes?size=8388609", "/headers?count=1024&size=65536", "/stream?count=0&intervalMs=-1", "/status?code=101"} {
		got := request(t, cc, "GET", path, nil)
		if got.StatusCode != 400 {
			t.Fatalf("input validation failed: %s", path)
		}
		body(t, got)
	}
}
func TestMultiplexCancelAndGoaway(t *testing.T) {
	s, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	cc := client(t, s)
	stream := request(t, cc, "GET", "/stream?count=0&intervalMs=1", nil)
	reader := bufio.NewReader(stream.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "0\n" {
		t.Fatalf("first line: %q %v", line, err)
	}
	small := request(t, cc, "GET", "/small", nil)
	if string(body(t, small)) != "ok" {
		t.Fatal("multiplexing failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := cc.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	s.goaway()
	deadline := time.Now().Add(2 * time.Second)
	for cc.CanTakeNewRequest() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if cc.CanTakeNewRequest() {
		t.Fatal("GOAWAY did not block a new stream")
	}
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("GOAWAY closed an existing stream: %v", err)
	}
	stream.Body.Close()
}
func TestJSONCommands(t *testing.T) {
	in, writer := io.Pipe()
	out, reader := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- run(in, reader); reader.Close() }()
	defer in.Close()
	defer writer.Close()
	defer out.Close()
	scanner := bufio.NewScanner(out)
	if !scanner.Scan() {
		t.Fatal("ready is missing")
	}
	var ready struct {
		Event string
		Port  int
	}
	if err := json.Unmarshal(scanner.Bytes(), &ready); err != nil || ready.Event != "ready" || ready.Port == 0 {
		t.Fatal("ready mismatch")
	}
	if _, err := io.WriteString(writer, "invalid\n"); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() || !strings.Contains(scanner.Text(), `"event":"error"`) {
		t.Fatal("error JSON is missing")
	}
	if _, err := io.WriteString(writer, "{\"cmd\":\"goaway\"}\n{\"cmd\":\"quit\"}\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown failed")
	}
	var eof bytes.Buffer
	if err := run(strings.NewReader(""), &eof); err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(strings.TrimSpace(eof.String()), "\n")) != 1 {
		t.Fatal("EOF output mismatch")
	}
}
func TestHPACKFixtures(t *testing.T) {
	for _, connection := range hpackFixtures() {
		decoder := hpack.NewDecoder(4096, nil)
		for i, block := range connection.Blocks {
			raw, err := hex.DecodeString(block.Hex)
			if err != nil {
				t.Fatal(err)
			}
			fields, err := decoder.DecodeFull(raw)
			if err != nil {
				t.Fatalf("%s/%d: %v", connection.Name, i, err)
			}
			got := make([]header, 0, len(fields))
			for _, f := range fields {
				got = append(got, header{f.Name, f.Value, f.Sensitive})
			}
			if !reflect.DeepEqual(got, block.Headers) {
				t.Fatalf("%s/%d decode mismatch", connection.Name, i)
			}
		}
	}
	if len(hpackFixtures()[0].Blocks[1].Hex) >= len(hpackFixtures()[0].Blocks[0].Hex) {
		t.Fatal("no dynamic index was used")
	}
}

// Inspect frames to verify that the Go server actually sends CONTINUATION and per-connection dynamic indexes.
type recordedConn struct {
	net.Conn
	mu       sync.Mutex
	incoming bytes.Buffer
}

func (c *recordedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.incoming.Write(p[:n])
	c.mu.Unlock()
	return n, err
}
func TestHeaderFrames(t *testing.T) {
	s, err := start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	conn, err := net.DialTimeout("tcp4", s.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	recorded := &recordedConn{Conn: conn}
	cc, err := new(http2.Transport).NewClientConn(recorded)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	defer cc.Close()
	for _, path := range []string{"/headers?count=4&size=20", "/headers?count=4&size=20", "/headers?count=96&size=400"} {
		body(t, request(t, cc, "GET", path, nil))
	}
	recorded.mu.Lock()
	raw := bytes.Clone(recorded.incoming.Bytes())
	recorded.mu.Unlock()
	frames := http2.NewFramer(nil, bytes.NewReader(raw))
	var sizes []int
	continuation := false
	for {
		frame, err := frames.ReadFrame()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			sizes = append(sizes, len(f.HeaderBlockFragment()))
		case *http2.ContinuationFrame:
			continuation = true
			sizes[len(sizes)-1] += len(f.HeaderBlockFragment())
		}
	}
	if len(sizes) != 3 || sizes[1] >= sizes[0] {
		t.Fatalf("the dynamic table did not shrink the second response: %v", sizes)
	}
	if !continuation {
		t.Fatal("the large header did not use CONTINUATION")
	}
}
