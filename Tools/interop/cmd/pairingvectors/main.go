// pairingvectors generates fixed vectors for the Swiftail pairing procedure (docs/contracts/SwiftailPairing.md §5) with the Go standard library
// (crypto/hmac, crypto/sha256) and writes JSON to standard output. It follows the contract text alone and neither reads
// nor calls the Swift implementation. The inputs are fixed patterns for testing only.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const reference = "docs/contracts/SwiftailPairing.md 5절, Go crypto/hmac·crypto/sha256"

type decision struct {
	StableID string `json:"stableID,omitempty"`
	Name     string `json:"name,omitempty"`
	Bytes    string `json:"bytes"`
}

type vector struct {
	Label            string   `json:"label"`
	Secret           string   `json:"secret"`
	OfferHost        string   `json:"offerHost"`
	OfferPort        uint16   `json:"offerPort"`
	DeviceName       string   `json:"deviceName"`
	JoinerNonce      string   `json:"joinerNonce"`
	HostNonce        string   `json:"hostNonce"`
	JoinerAddress    string   `json:"joinerAddress"`
	JoinerPort       uint16   `json:"joinerPort"`
	HostAddress      string   `json:"hostAddress"`
	HostPort         uint16   `json:"hostPort"`
	JoinerCommitment string   `json:"joinerCommitment"`
	HostCommitment   string   `json:"hostCommitment"`
	Hello            string   `json:"hello"`
	Challenge        string   `json:"challenge"`
	ChallengeNoOffer string   `json:"challengeNoOffer"`
	ProofTranscript  string   `json:"proofTranscript"`
	Transcript       string   `json:"transcript"`
	Proof            string   `json:"proof"`
	Accepted         string   `json:"accepted"`
	ConfirmationCode string   `json:"confirmationCode"`
	Approved         decision `json:"approved"`
	Denied           decision `json:"denied"`
	TimedOut         decision `json:"timedOut"`
}

type input struct {
	label                   string
	secret                  []byte
	offerHost               string
	offerPort               uint16
	deviceName              string
	joinerNonce, hostNonce  []byte
	joiner, host            netip.AddrPort
	hostStableID, hostLabel string
}

// pattern is a byte sequence whose ith byte is (i·mul + add) mod 256.
func pattern(n, mul, add int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*mul + add)
	}
	return b
}

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }

func tag(secret []byte, label string, parts ...[]byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(label))
	for _, p := range parts {
		mac.Write(p)
	}
	return mac.Sum(nil)
}

// commitment commits to the nonce as SHA256(label ‖ nonce). The joiner carries commitJ in hello, and the host carries commitH
// in challenge. The two labels differ.
func commitment(label string, nonce []byte) []byte {
	sum := sha256.Sum256(append([]byte(label), nonce...))
	return sum[:]
}

func joinerCommitment(in input) []byte {
	return commitment("swiftail-pairing-3 commit joiner", in.joinerNonce)
}

func hostCommitment(in input) []byte {
	return commitment("swiftail-pairing-3 commit host", in.hostNonce)
}

// proofTranscript is P: commitJ ‖ commitH ‖ nonceJ ‖ SHA256(host) ‖ port ‖ SHA256(device name) ‖ J address (16) ‖ J port
// ‖ H address (16) ‖ H port (198 bytes). Encode IPv4 addresses as 16-byte IPv4-mapped IPv6 addresses (netip.Addr.As16).
func proofTranscript(in input) []byte {
	hostHash := sha256.Sum256([]byte(in.offerHost))
	nameHash := sha256.Sum256([]byte(in.deviceName))
	j, h := in.joiner.Addr().As16(), in.host.Addr().As16()
	return bytes.Join([][]byte{
		joinerCommitment(in), hostCommitment(in), in.joinerNonce, hostHash[:], be16(in.offerPort), nameHash[:],
		j[:], be16(in.joiner.Port()), h[:], be16(in.host.Port()),
	}, nil)
}

// transcript is T: P ‖ nonceH (230 bytes).
func transcript(in input) []byte {
	return append(proofTranscript(in), in.hostNonce...)
}

func confirmationCode(secret, t []byte) string {
	sas := tag(secret, "swiftail-pairing-3 sas", t)
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sas[:4])%1000000)
}

func decide(secret, t, body []byte) string {
	return hex.EncodeToString(append(body, tag(secret, "swiftail-pairing-3 decision", t, body)...))
}

func evaluate(in input) vector {
	commitJ, commitH := joinerCommitment(in), hostCommitment(in)
	hello := bytes.Join([][]byte{[]byte("SWPR"), {0x03}, commitJ, {byte(len(in.deviceName))}, []byte(in.deviceName)}, nil)
	p, t := proofTranscript(in), transcript(in)
	// proof contains the revealed nonceJ and the HMAC of P, and accepted contains the revealed nonceH and the HMAC of T.
	proof := append(append([]byte{}, in.joinerNonce...), tag(in.secret, "swiftail-pairing-3 joiner", p)...)
	accepted := append(append([]byte{}, in.hostNonce...), tag(in.secret, "swiftail-pairing-3 host", t)...)
	approved := bytes.Join([][]byte{{1, byte(len(in.hostStableID))}, []byte(in.hostStableID), {byte(len(in.hostLabel))}, []byte(in.hostLabel)}, nil)
	return vector{
		Label:            in.label,
		Secret:           hex.EncodeToString(in.secret),
		OfferHost:        in.offerHost,
		OfferPort:        in.offerPort,
		DeviceName:       in.deviceName,
		JoinerNonce:      hex.EncodeToString(in.joinerNonce),
		HostNonce:        hex.EncodeToString(in.hostNonce),
		JoinerAddress:    in.joiner.Addr().String(),
		JoinerPort:       in.joiner.Port(),
		HostAddress:      in.host.Addr().String(),
		HostPort:         in.host.Port(),
		JoinerCommitment: hex.EncodeToString(commitJ),
		HostCommitment:   hex.EncodeToString(commitH),
		Hello:            hex.EncodeToString(hello),
		Challenge:        hex.EncodeToString(append([]byte{0}, commitH...)),
		ChallengeNoOffer: hex.EncodeToString(append([]byte{1}, commitH...)),
		ProofTranscript:  hex.EncodeToString(p),
		Transcript:       hex.EncodeToString(t),
		Proof:            hex.EncodeToString(proof),
		Accepted:         hex.EncodeToString(accepted),
		ConfirmationCode: confirmationCode(in.secret, t),
		Approved:         decision{in.hostStableID, in.hostLabel, decide(in.secret, t, approved)},
		Denied:           decision{Bytes: decide(in.secret, t, []byte{2})},
		TimedOut:         decision{Bytes: decide(in.secret, t, []byte{3})},
	}
}

func inputs() []input {
	ipv4 := input{
		label: "IPv4", secret: pattern(32, 7, 1), offerHost: "rd-mac-1a2b3c4d.tail0001.ts.net", offerPort: 4747,
		deviceName: "rd-phone-5e6f7a8b", joinerNonce: pattern(32, 3, 2), hostNonce: pattern(32, 5, 9),
		joiner: netip.MustParseAddrPort("100.64.0.2:49152"), host: netip.MustParseAddrPort("100.64.0.1:4747"),
		hostStableID: "nEXAMPLE1CNTRL", hostLabel: "rd-mac-1a2b3c4d",
	}
	ipv6 := input{
		label: "IPv6, 한글 기기 이름, 빈 표시 이름", secret: pattern(32, 11, 5), offerHost: "rd-mac-1a2b3c4d.tail0001.ts.net",
		offerPort: 65535, deviceName: "거실 iPad", joinerNonce: pattern(32, 13, 7), hostNonce: pattern(32, 17, 3),
		joiner: netip.MustParseAddrPort("[fd7a:115c:a1e0::2]:1"), host: netip.MustParseAddrPort("[fd7a:115c:a1e0::1]:65535"),
		hostStableID: "nEXAMPLE2CNTRL", hostLabel: "",
	}
	longest := input{
		label: "가장 긴 이름들", secret: pattern(32, 19, 4), offerHost: strings.Repeat("a", 63) + ".tail0001.ts.net",
		offerPort: 1, deviceName: strings.Repeat("기", 21) + "a", joinerNonce: pattern(32, 23, 6), hostNonce: pattern(32, 29, 8),
		joiner: netip.MustParseAddrPort("100.127.255.254:65535"), host: netip.MustParseAddrPort("100.64.0.1:1"),
		hostStableID: strings.Repeat("n", 255), hostLabel: strings.Repeat("표", 21) + "b",
	}
	// For a SAS starting with 0, vary the first byte of the joiner's nonce and take the first match.
	leadingZero := ipv4
	leadingZero.label = "확인 숫자가 0으로 시작"
	for first := 0; ; first++ {
		if first > 255 {
			panic("could not find a SAS starting with 0")
		}
		leadingZero.joinerNonce = append([]byte{byte(first)}, pattern(31, 3, 2)...)
		if strings.HasPrefix(confirmationCode(leadingZero.secret, transcript(leadingZero)), "0") {
			break
		}
	}
	return []input{ipv4, ipv6, longest, leadingZero}
}

func generate() ([]byte, error) {
	var vectors []vector
	for _, in := range inputs() {
		vectors = append(vectors, evaluate(in))
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "  ")
	err := enc.Encode(struct {
		Reference string   `json:"reference"`
		Vectors   []vector `json:"vectors"`
	}{reference, vectors})
	return out.Bytes(), err
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: pairingvectors > pairing-vectors.json")
		os.Exit(2)
	}
	out, err := generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
