// Reference API: gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72,
// pkg/tcpip/header/{tcp,ipv4,ipv6}.go. Call the public API without copying its implementation. SACK option order follows
// makeSynOptions and makeOptions in pkg/tcpip/transport/tcp/connect.go.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

const reference = "gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72"

type decoded struct {
	IPVersion       int     `json:"ipVersion"`
	Source          string  `json:"source"`
	Destination     string  `json:"destination"`
	IPHeaderLength  int     `json:"ipHeaderLength"`
	SourcePort      uint16  `json:"sourcePort"`
	DestinationPort uint16  `json:"destinationPort"`
	SequenceNumber  uint32  `json:"sequenceNumber"`
	AckNumber       uint32  `json:"ackNumber"`
	Flags           uint8   `json:"flags"`
	Window          uint16  `json:"window"`
	TCPHeaderLength int     `json:"tcpHeaderLength"`
	OptionsHex      string  `json:"optionsHex"`
	MSS             *uint16 `json:"mss"`
	WindowScale     *int    `json:"windowScale"`
	SACKPermitted   *bool   `json:"sackPermitted"`
	// Populate SACKBlocks only for non-SYN segments. Each block is [left edge, right edge], with an empty list when there are no blocks.
	SACKBlocks [][2]uint32 `json:"sackBlocks"`
	DataLength int         `json:"dataLength"`
}
type result struct {
	Error           string   `json:"error"`
	IPChecksumValid *bool    `json:"ipChecksumValid"`
	ChecksumValid   *bool    `json:"checksumValid"`
	Decoded         *decoded `json:"decoded"`
}
type fixture struct {
	Name            string `json:"name"`
	Packet          string `json:"packet"`
	Go              result `json:"go"`
	Swiftail        result `json:"swiftail"`
	SwiftailDiffers string `json:"swiftailDiffers,omitempty"`
}
type document struct {
	Reference string    `json:"reference"`
	CaseCount int       `json:"caseCount"`
	Cases     []fixture `json:"cases"`
}

func packet(ipv6, ipOptions bool, flags header.TCPFlags, options, payload []byte) []byte {
	ipLength := header.IPv4MinimumSize
	src := tcpip.AddrFrom4([4]byte{100, 64, 0, 1})
	dst := tcpip.AddrFrom4([4]byte{100, 64, 0, 2})
	if ipv6 {
		ipLength = header.IPv6MinimumSize
		src = tcpip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
		dst = tcpip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	} else if ipOptions {
		ipLength += 4
	}
	for len(options)%4 != 0 {
		options = append(options, header.TCPOptionNOP)
	}
	b := make([]byte, ipLength+header.TCPMinimumSize+len(options)+len(payload))
	if ipv6 {
		header.IPv6(b).Encode(&header.IPv6Fields{PayloadLength: uint16(len(b) - ipLength), TransportProtocol: header.TCPProtocolNumber, HopLimit: 64, SrcAddr: src, DstAddr: dst})
	} else {
		fields := header.IPv4Fields{TotalLength: uint16(len(b)), Flags: header.IPv4FlagDontFragment, TTL: 64, Protocol: uint8(header.TCPProtocolNumber), SrcAddr: src, DstAddr: dst}
		if ipOptions {
			fields.Options = header.IPv4OptionsSerializer{&header.IPv4SerializableNOPOption{}, &header.IPv4SerializableListEndOption{}}
		}
		ip := header.IPv4(b)
		ip.Encode(&fields)
		ip.SetChecksum(^ip.CalculateChecksum())
	}
	tcp := header.TCP(b[ipLength:])
	tcp.Encode(&header.TCPFields{SrcPort: 42001, DstPort: 9100, SeqNum: 0xfffffff0, AckNum: 0x10203040, DataOffset: uint8(20 + len(options)), Flags: flags, WindowSize: 65535})
	copy(tcp[20:], options)
	copy(tcp[20+len(options):], payload)
	sum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(len(tcp)))
	tcp.SetChecksum(^checksum.Checksum(tcp, sum))
	return b
}

// observe checks lengths before calling gVisor's unchecked header accessors.
// error is the API's bool normalized to the contract's error name.
func observe(b []byte) result {
	r := result{Error: "malformed"}
	if len(b) == 0 {
		return r
	}
	var src, dst tcpip.Address
	var ipLength, total int
	var protocol uint8
	version := int(b[0] >> 4)
	switch version {
	case 4:
		ip := header.IPv4(b)
		if !ip.IsValid(len(b)) {
			return r
		}
		ipLength, total, protocol = int(ip.HeaderLength()), int(ip.TotalLength()), ip.Protocol()
		valid := ip.IsChecksumValid()
		r.IPChecksumValid = &valid
		if !valid {
			return r
		}
		src, dst = ip.SourceAddress(), ip.DestinationAddress()
	case 6:
		ip := header.IPv6(b)
		if !ip.IsValid(len(b)) {
			return r
		}
		ipLength, total, protocol = 40, 40+int(ip.PayloadLength()), ip.NextHeader()
		src, dst = ip.SourceAddress(), ip.DestinationAddress()
	default:
		return r
	}
	if protocol != uint8(header.TCPProtocolNumber) {
		r.Error = "notTCP"
		return r
	}
	if total-ipLength < header.TCPMinimumSize {
		return r
	}
	tcp := header.TCP(b[ipLength:total])
	offset := int(tcp.DataOffset())
	if offset < 20 || offset > len(tcp) {
		return r
	}
	payload := tcp[offset:]
	_, valid, ok := header.TCPValid(tcp, func() uint16 { return checksum.Checksum(payload, 0) }, uint16(len(payload)), src, dst, false)
	if !ok {
		return r
	}
	r.ChecksumValid = &valid
	d := &decoded{IPVersion: version, Source: src.String(), Destination: dst.String(), IPHeaderLength: ipLength, SourcePort: tcp.SourcePort(), DestinationPort: tcp.DestinationPort(), SequenceNumber: tcp.SequenceNumber(), AckNumber: tcp.AckNumber(), Flags: uint8(tcp.Flags()), Window: tcp.WindowSize(), TCPHeaderLength: offset, OptionsHex: hex.EncodeToString(tcp.Options()), DataLength: len(payload)}
	if tcp.Flags().Contains(header.TCPFlagSyn) {
		opts := header.ParseSynOptions(tcp.Options(), tcp.Flags().Contains(header.TCPFlagAck))
		d.MSS, d.WindowScale, d.SACKPermitted = &opts.MSS, &opts.WS, &opts.SACKPermitted
	} else {
		d.SACKBlocks = [][2]uint32{}
		for _, block := range header.ParseTCPOptions(tcp.Options()).SACKBlocks {
			d.SACKBlocks = append(d.SACKBlocks, [2]uint32{uint32(block.Start), uint32(block.End)})
		}
	}
	r.Decoded = d
	r.Error = ""
	if !valid {
		r.Error = "badChecksum"
	}
	return r
}

func evaluate() ([]byte, error) {
	doc := document{Reference: reference, Cases: []fixture{}}
	add := func(name string, b []byte, differs string, errorName string, mss int, shift int) {
		goResult := observe(b)
		swift := goResult
		if goResult.Decoded != nil {
			d := *goResult.Decoded
			swift.Decoded = &d
		}
		if differs != "" {
			swift.Error = errorName
			if mss >= 0 {
				value := uint16(mss)
				swift.Decoded.MSS = &value
			}
			if shift >= 0 {
				value := shift
				swift.Decoded.WindowScale = &value
			}
		}
		doc.Cases = append(doc.Cases, fixture{Name: name, Packet: hex.EncodeToString(b), Go: goResult, Swiftail: swift, SwiftailDiffers: differs})
	}
	plain := func(name string, b []byte) { add(name, b, "", "", -1, -1) }
	mssws := func(mss uint32, shift int) []byte {
		b := make([]byte, 8)
		header.EncodeMSSOption(mss, b)
		b[4] = header.TCPOptionNOP
		header.EncodeWSOption(shift, b[5:])
		return b
	}
	// Order in makeSynOptions (connect.go): MSS, two NOPs and SACK-Permitted, then NOP and WS.
	sackSyn := func(mss uint32, shift int) []byte {
		b := make([]byte, 12)
		offset := header.EncodeMSSOption(mss, b)
		offset += header.EncodeNOP(b[offset:])
		offset += header.EncodeNOP(b[offset:])
		offset += header.EncodeSACKPermittedOption(b[offset:])
		offset += header.EncodeNOP(b[offset:])
		header.EncodeWSOption(shift, b[offset:])
		return b
	}
	// Order in makeOptions (connect.go): two NOPs and SACK blocks.
	sackBlocks := func(edges ...uint32) []byte {
		var blocks []header.SACKBlock
		for i := 0; i+1 < len(edges); i += 2 {
			blocks = append(blocks, header.SACKBlock{Start: seqnum.Value(edges[i]), End: seqnum.Value(edges[i+1])})
		}
		b := make([]byte, 2+2+8*len(blocks))
		offset := header.EncodeNOP(b)
		offset += header.EncodeNOP(b[offset:])
		header.EncodeSACKBlocks(blocks, b[offset:])
		return b
	}
	syn := header.TCPFlagSyn
	ack := header.TCPFlagAck
	for _, v6 := range []bool{false, true} {
		family := "ipv4"
		if v6 {
			family = "ipv6"
		}
		plain(family+"-syn-mss-ws", packet(v6, false, syn, mssws(1220, 3), nil))
		plain(family+"-synack", packet(v6, false, syn|ack, mssws(1240, 0), nil))
		plain(family+"-odd-payload", packet(v6, false, ack|header.TCPFlagPsh, nil, []byte{0, 1, 2, 0xff, 0xfe}))
		plain(family+"-checksum-carries", packet(v6, false, ack, nil, []byte{255, 255, 255, 255, 255, 255, 255, 255, 255}))
		plain(family+"-fin-ack", packet(v6, false, ack|header.TCPFlagFin, nil, nil))
		plain(family+"-rst", packet(v6, false, header.TCPFlagRst, nil, nil))
		plain(family+"-non-syn-options", packet(v6, false, ack, mssws(1200, 15), nil))
		defaults := packet(v6, false, syn, nil, nil)
		if v6 {
			add(family+"-no-options", defaults, "W2 and T5: gVisor ParseSynOptions defaults to MSS 536 for both address families. The contract sets the IPv6 default to 1220.", "", 1220, -1)
		} else {
			plain(family+"-no-options", defaults)
		}
		zero := packet(v6, false, syn, mssws(0, 3), nil)
		fallback := 536
		if v6 {
			fallback = 1220
		}
		add(family+"-mss-zero", zero, "W2: gVisor stops parsing options at MSS 0 and skips WS. The contract substitutes the default MSS and reads the following WS.", "", fallback, 3)
		plain(family+"-shift-15", packet(v6, false, syn, mssws(1220, 15), nil))
		bad := packet(v6, false, ack, nil, []byte{1, 2, 3})
		bad[len(bad)-1] ^= 1
		plain(family+"-bad-checksum", bad)
	}
	plain("ipv4-options", packet(false, true, syn, mssws(1240, 3), nil))
	plain("nop-unaligned", packet(false, false, syn, []byte{1, 2, 4, 4, 216, 1, 3, 3, 2}, nil))
	plain("eol-ignores-tail", packet(false, false, syn, []byte{2, 4, 4, 216, 0, 3, 0, 255}, nil))
	plain("unknown-option", packet(false, false, syn, []byte{254, 4, 0xaa, 0xbb, 2, 4, 4, 216}, nil))
	plain("sack-timestamp-options", packet(false, false, syn, []byte{4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 2, 4, 4, 216, 3, 3, 3}, nil))
	plain("shift-14", packet(false, false, syn, mssws(1240, 14), nil))
	plain("max-tcp-header", packet(false, false, syn, append(mssws(1240, 3), make([]byte, 32)...), nil))
	add("small-mss", packet(false, false, syn, mssws(1, 3), nil), "W2 and X9: gVisor clamps a nonzero MSS to at least 48. The contract's codec preserves the advertised value of 1 and the connection state machine rejects values below 64.", "", 1, -1)
	for _, opts := range []struct {
		name  string
		bytes []byte
	}{
		{"unknown-length-zero", []byte{254, 0, 1, 1}},
		{"unknown-length-one", []byte{254, 1, 1, 1}},
		{"unknown-length-outside", []byte{254, 5, 1, 1}},
		{"missing-option-length", []byte{1, 1, 1, 254}},
		{"mss-outside", []byte{1, 1, 2, 4}},
	} {
		add(opts.name, packet(false, false, syn, opts.bytes, nil), "W2: gVisor TCPValid does not check the option length and ParseSynOptions stops parsing. The contract rejects the packet as malformed.", "malformed", -1, -1)
	}
	// For MSS and Window Scale options with a nonstandard length of at least 2 that fit within the header, the contract also skips by length without reading the value (W's "Decisions made
	// during implementation"). This matches gVisor's result, so it is not marked as a difference.
	plain("mss-length-three", packet(false, false, syn, []byte{2, 3, 1, 1}, nil))
	plain("ws-length-two", packet(false, false, syn, []byte{3, 2, 1, 1}, nil))
	// SACK-Permitted and SACK (RFC 2018 §§2 and 3). The gVisor encoder also produces the same bytes as Swiftail.
	plain("ipv4-syn-sack-permitted", packet(false, false, syn, sackSyn(1240, 3), nil))
	plain("ipv6-syn-sack-permitted", packet(true, false, syn|ack, sackSyn(1220, 3), nil))
	plain("ipv4-ack-sack-one-block", packet(false, false, ack, sackBlocks(5500, 6000), nil))
	plain("ipv6-ack-sack-four-blocks", packet(true, false, ack, sackBlocks(8000, 8500, 0xfffffff0, 0x10, 6000, 6500, 7000, 7500), nil))
	plain("ipv4-ack-sack-payload", packet(false, false, ack|header.TCPFlagPsh, sackBlocks(6000, 7500, 8000, 8500), []byte{1, 2, 3, 4, 5}))
	plain("sack-duplicate", packet(false, false, ack, append(sackBlocks(1, 2), sackBlocks(3, 4, 5, 6)...), nil))
	plain("sack-on-syn", packet(false, false, syn, append([]byte{2, 4, 4, 216}, sackBlocks(1, 2)...), nil))
	plain("sack-permitted-on-ack", packet(false, false, ack, []byte{1, 1, 4, 2}, nil))
	// Options with nonstandard lengths of at least 2 that fit within the header: gVisor stops parsing, and the contract skips them by length. With no subsequent option,
	// the results are the same.
	plain("sack-permitted-length-three", packet(false, false, syn, []byte{2, 4, 4, 216, 4, 3, 0}, nil))
	plain("sack-length-two", packet(false, false, ack, []byte{1, 1, 5, 2}, nil))
	plain("sack-length-not-multiple", packet(false, false, ack, []byte{5, 9, 0, 0, 0, 1, 0, 0, 0}, nil))
	for _, opts := range []struct {
		name  string
		bytes []byte
	}{
		{"sack-outside", []byte{1, 1, 5, 10, 0, 0, 0, 1}},
		{"sack-five-blocks", append([]byte{5, 42}, make([]byte, 38)...)},
	} {
		add(opts.name, packet(false, false, ack, opts.bytes, nil), "W2: gVisor ParseTCPOptions stops parsing when SACK extends past the header. The contract rejects the packet as malformed.", "malformed", -1, -1)
	}
	// After truncation, adjust only the IP length so processing reaches the TCP header length check.
	for _, size := range []int{0, 1, 19} {
		b := packet(false, false, syn, nil, nil)[:20+size]
		ip := header.IPv4(b)
		ip.SetTotalLength(uint16(len(b)))
		ip.SetChecksum(0)
		ip.SetChecksum(^ip.CalculateChecksum())
		plain(fmt.Sprintf("tcp-truncated-%d", size), b)
	}
	for _, size := range []int{0, 1, 19, 39} {
		b := packet(true, false, syn, nil, nil)
		plain(fmt.Sprintf("ip-truncated-%d", size), b[:size])
	}
	for _, offset := range []int{4, 6, 15} {
		b := packet(false, false, syn, nil, nil)
		header.TCP(b[20:]).SetDataOffset(uint8(offset * 4))
		plain(fmt.Sprintf("data-offset-%d", offset), b)
	}
	// The data offset is 4 bits, so it cannot represent 16 and wraps to 0.
	b := packet(false, false, syn, nil, nil)
	header.TCP(b[20:]).SetDataOffset(64)
	plain("data-offset-16-wraps-zero", b)
	b = packet(false, false, syn, nil, nil)
	b[9] = 17
	ip := header.IPv4(b)
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	plain("not-tcp", b)
	doc.CaseCount = len(doc.Cases)
	data, err := json.MarshalIndent(doc, "", "  ")
	return append(data, '\n'), err
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: tcpfixtures <Netstack Fixtures directory>")
		os.Exit(1)
	}
	data, err := evaluate()
	if err == nil {
		err = os.MkdirAll(os.Args[1], 0755)
	}
	if err == nil {
		err = os.WriteFile(filepath.Join(os.Args[1], "tcp-segments.json"), data, 0644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
