// authkeyrecorder는 인증 키 발급의 상호 운용 관문(계약 docs/contracts/SwiftailPairing.md 7절 7)을 위한 도구다.
//
//	authkeyrecorder serve [-reject-basic]
//	    127.0.0.1의 임의 포트에서 듣는 기록 서버. 표준 출력의 첫 줄에 서버 URL을 쓴다. 토큰·키 요청을 적고
//	    고정된 가짜 토큰과 키를 돌려준다. -reject-basic이면 Authorization이 있는 토큰 요청을 401로 거절하고
//	    폼의 client_id·client_secret만 받는다. GET /recorded는 적은 요청을 JSON 배열로 내놓고 비운다. 표준
//	    입력이 닫히면 끝난다.
//	authkeyrecorder issue -base <URL> -tags tag:a,tag:b -expiry <초>
//	    cmd/get-authkey와 같은 흐름(golang.org/x/oauth2/clientcredentials + tailscale.com/client/tailscale의
//	    CreateKeyWithExpiry)으로 키 하나를 만들고 표준 출력에 쓴다. 클라이언트 ID와 비밀은 get-authkey처럼
//	    TS_API_CLIENT_ID·TS_API_CLIENT_SECRET에서 읽는다.
//
// 가짜 값만 다루는 시험 도구다. 실제 관리 API를 부르지 않도록 -base는 루프백 http만 받는다.
// 사용법은 Tools/interop/README.md의 authkeyrecorder 절.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
)

// recorded는 받은 요청 하나다. 본문은 비교하기 쉽게 정규형도 함께 싣는다.
type recorded struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Authorization string `json:"authorization"`
	ContentType   string `json:"contentType"`
	Body          string `json:"body"`
	// JSON 본문이면 키를 정렬해 다시 쓴 것, 아니면 "".
	JSON string `json:"json"`
	// JSON이 아닌 폼 본문이면 url.Values.Encode()로 다시 쓴 것(키 정렬), 아니면 "".
	Form string `json:"form"`
}

const (
	fakeToken = `{"access_token":"tskey-api-EXAMPLE-token","token_type":"Bearer","expires_in":3600}`
	fakeKey   = `{"id":"kEXAMPLE","key":"tskey-auth-EXAMPLE","created":"2026-01-01T00:00:00Z","expires":"2026-01-01T00:10:00Z",` +
		`"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":["tag:example"]}}}}`
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ExitOnError)
		rejectBasic := flags.Bool("reject-basic", false, "Basic 머리의 토큰 요청을 거절한다")
		flags.Parse(os.Args[2:])
		if flags.NArg() != 0 {
			usage()
		}
		serve(*rejectBasic)
	case "issue":
		issue(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "사용법: authkeyrecorder serve [-reject-basic] | authkeyrecorder issue -base <URL> -tags <태그,…> -expiry <초>")
	os.Exit(2)
}

func serve(rejectBasic bool) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	var mu sync.Mutex
	var requests []recorded

	mux := http.NewServeMux()
	mux.HandleFunc("GET /recorded", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		out := requests
		requests = nil
		mu.Unlock()
		if out == nil {
			out = []recorded{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	})
	record := func(response string, token bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
			if err != nil {
				http.Error(w, "본문을 읽지 못했다", http.StatusBadRequest)
				return
			}
			entry := recorded{
				Method:        r.Method,
				Path:          r.URL.Path,
				Authorization: r.Header.Get("Authorization"),
				ContentType:   r.Header.Get("Content-Type"),
				Body:          string(body),
			}
			var value any
			if json.Unmarshal(body, &value) == nil {
				canonical, _ := json.Marshal(value) // map은 키를 정렬해 쓴다
				entry.JSON = string(canonical)
			} else if form, err := url.ParseQuery(string(body)); err == nil {
				entry.Form = form.Encode()
			}
			mu.Lock()
			requests = append(requests, entry)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if token && rejectBasic {
				form, _ := url.ParseQuery(string(body))
				if entry.Authorization != "" || form.Get("client_id") == "" || form.Get("client_secret") == "" {
					w.WriteHeader(http.StatusUnauthorized)
					io.WriteString(w, `{"error":"invalid_client"}`)
					return
				}
			}
			io.WriteString(w, response)
		}
	}
	mux.HandleFunc("/api/v2/oauth/token", record(fakeToken, true))
	mux.HandleFunc("/api/v2/tailnet/-/keys", record(fakeKey, false))

	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	fmt.Printf("http://%s\n", listener.Addr())
	// 표준 입력이 닫히면 끝난다.
	io.Copy(io.Discard, bufio.NewReader(os.Stdin))
	server.Close()
}

func issue(args []string) {
	flags := flag.NewFlagSet("issue", flag.ExitOnError)
	base := flags.String("base", "", "기록 서버 URL(루프백 http)")
	tags := flags.String("tags", "", "쉼표로 나눈 태그")
	expiry := flags.Int64("expiry", 0, "키 수명(초)")
	flags.Parse(args)

	parsed, err := url.Parse(*base)
	if err != nil || parsed.Scheme != "http" || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1") {
		log.Fatal("-base는 루프백 http URL이어야 한다")
	}
	if *tags == "" || *expiry <= 0 {
		usage()
	}
	clientID := os.Getenv("TS_API_CLIENT_ID")
	clientSecret := os.Getenv("TS_API_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("TS_API_CLIENT_ID와 TS_API_CLIENT_SECRET이 있어야 한다")
	}

	// cmd/get-authkey와 같은 짜임. 그것이 쓰는 internal/client/tailscale은 모듈 밖에서 쓸 수 없어 공개 패키지를 쓴다.
	tailscale.I_Acknowledge_This_API_Is_Unstable = true
	credentials := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     *base + "/api/v2/oauth/token",
	}
	ctx := context.Background()
	client := tailscale.NewClient("-", nil)
	client.UserAgent = "tailscale-get-authkey"
	client.HTTPClient = credentials.Client(ctx)
	client.BaseURL = *base

	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				// 계약 4절 K3의 고정 값.
				Reusable:      false,
				Ephemeral:     false,
				Preauthorized: true,
				Tags:          strings.Split(*tags, ","),
			},
		},
	}
	key, _, err := client.CreateKeyWithExpiry(ctx, caps, time.Duration(*expiry)*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
}
