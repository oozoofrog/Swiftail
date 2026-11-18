// authkeyrecorder supports the auth key issuance interop gate (contract docs/contracts/SwiftailPairing.md §7, item 7).
//
//	authkeyrecorder serve [-reject-basic]
//	    Recording server listening on a random port on 127.0.0.1. Writes the server URL on the first line of standard output. Records token and key requests
//	    and returns a fixed fake token and key. With -reject-basic, it rejects token requests with Authorization with a 401
//	    and accepts only client_id and client_secret in the form. GET /recorded returns the recorded requests as a JSON array and clears them. Exits
//	    when standard input closes.
//	authkeyrecorder issue -base <URL> -tags tag:a,tag:b -expiry <seconds>
//	    Creates one key with the same flow as cmd/get-authkey (golang.org/x/oauth2/clientcredentials + tailscale.com/client/tailscale
//	    CreateKeyWithExpiry) and writes it to standard output. As in get-authkey, it reads the client ID and secret
//	    from TS_API_CLIENT_ID and TS_API_CLIENT_SECRET.
//
// This test tool handles only fake values. To avoid calling the real admin API, -base accepts only loopback http.
// See the authkeyrecorder section of Tools/interop/README.md for usage.
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

// recorded is one received request. It also includes a canonical form of the body to simplify comparisons.
type recorded struct {
	Method        string `json:"method"`
	Path          string `json:"path"`
	Authorization string `json:"authorization"`
	ContentType   string `json:"contentType"`
	Body          string `json:"body"`
	// The JSON body re-encoded with sorted keys, or "" otherwise.
	JSON string `json:"json"`
	// The non-JSON form body re-encoded with url.Values.Encode() (keys sorted), or "" otherwise.
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
		rejectBasic := flags.Bool("reject-basic", false, "reject token requests with a Basic header")
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
	fmt.Fprintln(os.Stderr, "Usage: authkeyrecorder serve [-reject-basic] | authkeyrecorder issue -base <URL> -tags <tag,…> -expiry <seconds>")
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
				http.Error(w, "could not read body", http.StatusBadRequest)
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
				canonical, _ := json.Marshal(value) // map keys are written in sorted order
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
	// Exit when standard input closes.
	io.Copy(io.Discard, bufio.NewReader(os.Stdin))
	server.Close()
}

func issue(args []string) {
	flags := flag.NewFlagSet("issue", flag.ExitOnError)
	base := flags.String("base", "", "recording server URL (loopback http)")
	tags := flags.String("tags", "", "comma-separated tags")
	expiry := flags.Int64("expiry", 0, "key lifetime (seconds)")
	flags.Parse(args)

	parsed, err := url.Parse(*base)
	if err != nil || parsed.Scheme != "http" || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1") {
		log.Fatal("-base must be a loopback http URL")
	}
	if *tags == "" || *expiry <= 0 {
		usage()
	}
	clientID := os.Getenv("TS_API_CLIENT_ID")
	clientSecret := os.Getenv("TS_API_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("TS_API_CLIENT_ID and TS_API_CLIENT_SECRET are required")
	}

	// Same setup as cmd/get-authkey. Its internal/client/tailscale package cannot be used outside the module, so use the public package.
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
				// Fixed value from contract §4 K3.
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
