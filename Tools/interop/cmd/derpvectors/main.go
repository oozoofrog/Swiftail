// derpvectors generates fixed vectors for SwiftailDERP unit tests with Go's NaCl box and prints one JSON line.
//
// For keys, use SHA-256("swiftail-fixtures/derp/<number>") as X25519 private key input (public test values, never production keys).
// Sealing follows sendClientKey in tailscale.com `derp/derp_client.go` and SealTo in `types/key/node.go`
// (`box.Seal(nonce, plaintext, &nonce, peer public key, own private key)`). Tests require a fixed nonce, so supply one
// in place of SealTo's randomness. Origin: tailscale.com v1.104.6, BSD-3-Clause.
//
// Run `go run ./cmd/derpvectors` in Tools/interop (use the environment variables in README.md).
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

// The nonce is fixed at 0x00 0x01 … 0x17.
func fixedNonce() [24]byte {
	var n [24]byte
	for i := range n {
		n[i] = byte(i)
	}
	return n
}

// sealTo produces the same output as SealTo (nonce ‖ box) with a fixed nonce.
func sealTo(private, peer [32]byte, nonce [24]byte, cleartext []byte) []byte {
	return box.Seal(nonce[:], cleartext, &nonce, &peer, &private)
}

func main() {
	client, server := seed(1), seed(2)
	clientPub, serverPub := public(client), public(server)
	nonce := fixedNonce()

	clientInfo := []byte(`{"version":2,"CanAckPings":true}`)
	serverInfo := []byte(`{"version":2}`)

	// ClientInfo frame body: client public key ‖ nonce ‖ box.
	clientBody := append(clientPub[:], sealTo(client, serverPub, nonce, clientInfo)...)
	// ServerInfo frame body: nonce ‖ box (server private key, client public key).
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
