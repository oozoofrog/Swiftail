// controlfaults is a test control server that deliberately misbehaves according to its mode.
//
// It uses tailscale.com's controlhttpserver for the real control server transport (`/key`, the `/ts2021` upgrade and Noise, and HTTP/2 within it)
// and changes only the `/machine/register` and `/machine/map` responses according to the mode.
// Uses only synthetic values and prints neither request bodies nor keys. See the controlfaults section of Tools/interop/README.md for usage.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/types/key"
)

var modes = map[string]bool{
	"basic":             true, // approve registration immediately, return 200 for status updates, and send one self Node on the map stream before holding it open
	"initialUploadHang": true, // leave status updates (Stream=false) unanswered
	"interactiveRace":   true, // hold the first registration request until /release
	"followupReconnect": true, // close the stream on the first Followup request and approve the second Followup
	"followupHold":      true, // hold the Followup request until /release
	"sameAuthURL":       true, // immediately return the same AuthURL for every registration until /release
	"expiryTimer":       true, // set the self Node's KeyExpiry to the response time + 1 second
	"alwaysExpired":     true, // always set the self Node's KeyExpiry to a time in the past
	"authEcho":          true, // reject registration with an auth key using an Error that echoes the key
	"manyMaps":          true, // send 200 responses on the first map stream and close it. Hold the next stream open without sending anything
}

// server counts requests. /probe returns the counts.
type server struct {
	mode    string
	base    string
	private key.MachinePrivate

	mu          sync.Mutex
	connections int
	registers   int
	followups   int
	withAuth    int
	maps        int
	streams     int
	nodeKeys    map[string]bool
	released    chan struct{}
	releaseOnce sync.Once
}

type probe struct {
	Connections int `json:"connections"`
	Registers   int `json:"registers"`
	Followups   int `json:"followups"`
	WithAuth    int `json:"withAuth"` // Number of registration requests containing Auth.AuthKey
	Maps        int `json:"maps"`
	NodeKeys    int `json:"nodeKeys"` // Number of distinct NodeKey values in registration requests. Does not expose the keys themselves
}

func main() {
	if len(os.Args) != 2 || !modes[os.Args[1]] {
		fmt.Fprintln(os.Stderr, "Usage: controlfaults <mode>")
		os.Exit(2)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	s := &server{
		mode:     os.Args[1],
		base:     "http://" + listener.Addr().String(),
		private:  key.NewMachine(),
		nodeKeys: map[string]bool{},
		released: make(chan struct{}),
	}
	fmt.Println(s.base)
	go func() {
		// Exit when standard input closes (EOF), so the server does not linger if the test process dies.
		_, _ = bufio.NewReader(os.Stdin).ReadString(0)
		os.Exit(0)
	}()
	log.Fatal(http.Serve(listener, http.HandlerFunc(s.outer)))
}

func (s *server) outer(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/key":
		_ = json.NewEncoder(w).Encode(map[string]any{"publicKey": s.private.Public()})
	case "/release":
		s.releaseOnce.Do(func() { close(s.released) })
	case "/probe":
		s.mu.Lock()
		p := probe{s.connections, s.registers, s.followups, s.withAuth, s.maps, len(s.nodeKeys)}
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(p)
	case "/ts2021":
		s.mu.Lock()
		s.connections++
		s.mu.Unlock()
		conn, err := controlhttpserver.AcceptHTTP(r.Context(), w, r, s.private, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(s.inner)})
	default:
		http.NotFound(w, r)
	}
}

func (s *server) inner(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	switch r.URL.Path {
	case "/machine/register":
		s.register(w, r)
	case "/machine/map":
		s.mapRequest(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	var request struct {
		NodeKey  string
		Followup string
		Auth     *struct{ AuthKey string }
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.registers++
	ordinal := s.registers
	s.nodeKeys[request.NodeKey] = true
	if request.Followup != "" {
		s.followups++
	}
	followup := s.followups
	if request.Auth != nil && request.Auth.AuthKey != "" {
		s.withAuth++
	}
	s.mu.Unlock()

	switch s.mode {
	case "interactiveRace":
		if ordinal == 1 {
			select {
			case <-s.released:
			case <-r.Context().Done():
				return
			}
		}
	case "authEcho":
		if request.Auth != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"Error": "invalid authkey: " + request.Auth.AuthKey})
			return
		}
	case "followupHold":
		if request.Followup == "" {
			_ = json.NewEncoder(w).Encode(map[string]any{"AuthURL": fmt.Sprintf("%s/login/%d", s.base, ordinal)})
			return
		}
		select {
		case <-s.released:
		case <-r.Context().Done():
			return
		}
	case "sameAuthURL":
		select {
		case <-s.released:
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"AuthURL": s.base + "/login/1"})
			return
		}
	case "followupReconnect":
		switch {
		case request.Followup == "":
			_ = json.NewEncoder(w).Encode(map[string]any{"AuthURL": s.base + "/login/1"})
			return
		case followup == 1:
			// Simulate a disconnect while waiting for sign-in. Close the stream with RST_STREAM.
			panic(http.ErrAbortHandler)
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"MachineAuthorized": true})
}

func (s *server) mapRequest(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Stream  bool
		NodeKey string
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.maps++
	if request.Stream {
		s.streams++
	}
	stream := s.streams
	s.mu.Unlock()

	if !request.Stream {
		if s.mode == "initialUploadHang" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if s.mode == "manyMaps" && stream > 1 {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return
	}
	node := map[string]any{"ID": 1, "Key": request.NodeKey, "MachineAuthorized": true}
	switch s.mode {
	case "expiryTimer":
		node["KeyExpiry"] = time.Now().Add(time.Second).UTC()
	case "alwaysExpired":
		node["KeyExpiry"] = time.Now().Add(-time.Hour).UTC()
	}
	writeFrame(w, map[string]any{"Node": node})
	if s.mode == "manyMaps" {
		// Domain changes in each response, so the client emits 200 netmap events. The last is "d199".
		for i := 1; i < 200; i++ {
			writeFrame(w, map[string]any{"Domain": fmt.Sprintf("d%d", i)})
		}
		return
	}
	<-r.Context().Done()
}

// writeFrame writes and flushes one map response with a 4-byte little-endian length prefix.
func writeFrame(w http.ResponseWriter, response map[string]any) {
	payload, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}
	frame := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	_, _ = w.Write(append(frame, payload...))
	w.(http.Flusher).Flush()
}
