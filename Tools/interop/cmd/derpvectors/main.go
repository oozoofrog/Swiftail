// derpvectors는 SwiftailDERP 단위 시험의 고정 벡터를 Go의 NaCl box로 뽑아 JSON 한 줄로 출력한다.
//
// 키는 SHA-256("swiftail-fixtures/derp/<번호>")를 X25519 개인 키 입력으로 쓴다(시험용 공개 값, 운영 키가 아니다).
// 봉하는 방식은 tailscale.com `derp/derp_client.go`의 sendClientKey와 `types/key/node.go`의 SealTo와 같다
// (`box.Seal(nonce, 평문, &nonce, 상대 공개 키, 내 개인 키)`). 시험은 nonce를 고정해야 하므로 SealTo의 난수
// 대신 고정 nonce를 넣는다. 출처 tailscale.com v1.104.6, BSD-3-Clause.
//
// 실행: Tools/interop에서 `go run ./cmd/derpvectors` (환경 변수는 README.md의 것).
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func seed(n int) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("swiftail-fixtures/derp/%d", n)))
}

func public(private [32]byte) [32]byte {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &private)
	return pub
}

// nonce는 고정 값 0x00 0x01 … 0x17이다.
func fixedNonce() [24]byte {
	var n [24]byte
	for i := range n {
		n[i] = byte(i)
	}
	return n
}

// sealTo는 SealTo와 같은 출력(nonce ‖ box)을 고정 nonce로 만든다.
func sealTo(private, peer [32]byte, nonce [24]byte, cleartext []byte) []byte {
	return box.Seal(nonce[:], cleartext, &nonce, &peer, &private)
}

func main() {
	client, server := seed(1), seed(2)
	clientPub, serverPub := public(client), public(server)
	nonce := fixedNonce()

	clientInfo := []byte(`{"version":2,"CanAckPings":true}`)
	serverInfo := []byte(`{"version":2}`)

	// ClientInfo 프레임 본문: 클라이언트 공개 키 ‖ nonce ‖ box.
	clientBody := append(clientPub[:], sealTo(client, serverPub, nonce, clientInfo)...)
	// ServerInfo 프레임 본문: nonce ‖ box (서버 개인 키, 클라이언트 공개 키).
	serverBody := sealTo(server, clientPub, nonce, serverInfo)

	out := map[string]string{
		"clientSeed":     hex.EncodeToString(client[:]),
		"serverSeed":     hex.EncodeToString(server[:]),
		"clientPublic":   hex.EncodeToString(clientPub[:]),
		"serverPublic":   hex.EncodeToString(serverPub[:]),
		"nonce":          hex.EncodeToString(nonce[:]),
		"clientInfoJSON": string(clientInfo),
		"clientInfoBody": hex.EncodeToString(clientBody),
		"serverInfoJSON": string(serverInfo),
		"serverInfoBody": hex.EncodeToString(serverBody),
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
