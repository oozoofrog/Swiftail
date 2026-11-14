// controlfaults는 모드마다 일부러 어긋나게 구는 시험용 제어 서버다.
//
// 진짜 제어 서버의 전송(`/key`, `/ts2021` 업그레이드·Noise, 그 안의 HTTP/2)은 tailscale.com의
// controlhttpserver로 그대로 하고, `/machine/register`와 `/machine/map`의 응답만 모드에 따라 바꾼다.
// 합성 값만 쓰며 요청 본문과 키를 출력하지 않는다. 사용법은 Tools/interop/README.md의 controlfaults 절.
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
	"basic":             true, // 등록은 곧바로 승인, 상태 갱신은 200, 맵 스트림은 self Node 하나를 보내고 붙잡는다
	"initialUploadHang": true, // 상태 갱신(Stream=false)에 답하지 않는다
	"interactiveRace":   true, // 첫 등록 요청을 /release까지 붙잡는다
	"followupReconnect": true, // 첫 Followup 요청에서 스트림을 끊고, 두 번째 Followup은 승인한다
	"expiryTimer":       true, // self Node의 KeyExpiry를 응답 시각 + 1초로 준다
	"alwaysExpired":     true, // self Node의 KeyExpiry를 늘 지난 시각으로 준다
	"authEcho":          true, // 인증 키가 있는 등록을 그 키를 되풀이한 Error로 거절한다
	"manyMaps":          true, // 첫 맵 스트림에 응답 200개를 보내고 끝낸다. 다음 스트림은 아무것도 보내지 않고 붙잡는다
}

// server는 요청을 센다. /probe가 센 값을 돌려준다.
type server struct {
	mode    string
	base    string
	private key.MachinePrivate

	mu          sync.Mutex
	connections int
	registers   int
	followups   int
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
	Maps        int `json:"maps"`
	NodeKeys    int `json:"nodeKeys"` // 등록 요청에 나온 서로 다른 NodeKey 수. 키 자체는 내놓지 않는다
}

func main() {
	if len(os.Args) != 2 || !modes[os.Args[1]] {
		fmt.Fprintln(os.Stderr, "사용법: controlfaults <모드>")
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
		// 표준 입력이 닫히면(EOF) 끝낸다. 시험 프로세스가 죽어도 남지 않는다.
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
		p := probe{s.connections, s.registers, s.followups, s.maps, len(s.nodeKeys)}
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
	case "followupReconnect":
		switch {
		case request.Followup == "":
			_ = json.NewEncoder(w).Encode(map[string]any{"AuthURL": s.base + "/login/1"})
			return
		case followup == 1:
			// 로그인을 기다리는 도중에 끊긴 상황. 스트림을 RST_STREAM으로 끊는다.
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
		// 응답마다 Domain이 달라 클라이언트는 netmap 사건을 200개 낸다. 마지막은 "d199".
		for i := 1; i < 200; i++ {
			writeFrame(w, map[string]any{"Domain": fmt.Sprintf("d%d", i)})
		}
		return
	}
	<-r.Context().Done()
}

// writeFrame은 맵 응답 하나를 4바이트 리틀엔디언 길이 접두와 함께 쓰고 내보낸다.
func writeFrame(w http.ResponseWriter, response map[string]any) {
	payload, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}
	frame := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	_, _ = w.Write(append(frame, payload...))
	w.(http.Flusher).Flush()
}
