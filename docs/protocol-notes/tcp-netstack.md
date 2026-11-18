# TCP and In-Process Netstack Notes

- References: `tailscale.com v1.104.6`, `gvisor.dev/gvisor v0.0.0-20260915211658-a6f909f08a72` (version pinned by `tailscale.com/go.mod:156`), RFCs 9293, 6298, 5681, 6582, 5961, 6528, 6928, 7323, 2018, 1071, 8200, and 791 (official RFC Editor text checked on 2026-11-15)
- Author: Claude Fable 5.2, 2026-11-15
- Verification: GPT-6.1 Sol, 2026-11-15. Independently of the authoring session, checked the 12 RFCs above, the pinned Tailscale and gVisor sources, and the first adopter's `286c214`, and made corrections. No behavior was verified by execution. §11 lists what remains unverified.

## 1. Scope

These notes cover only the facts needed to implement Swift TCP for M6 (`docs/contracts/SwiftailNetstack.md`).

In scope are the TCP header and option formats, the state machine and segment processing order, retransmission timers, windows and flow control, congestion control, whether each option is required for interoperability, how Tailscale configures and uses gVisor, the MTU and MSS of the tailnet path, the behavior of tsnet `Listen` and `Dial`, and what the first adopter uses.

Out of scope are UDP and ICMP sockets, IP fragment reassembly, ECN, TCP Fast Open, MPTCP, subnet router TCP forwarding (`forwardTCP`), Funnel and Serve, and gVisor internals (dispatchers, segment queues, and locks).

## 2. References

- Go source references give paths relative to the module root and line numbers. `netstack.go` means `tailscale.com/wgengine/netstack/netstack.go`, `tsnet.go` means `tailscale.com/tsnet/tsnet.go`, and `gvisor/…` means `gvisor.dev/gvisor@v0.0.0-20260915211658-a6f909f08a72/pkg/tcpip/…`.
- Bare references to `connect.go`, `snd.go`, `rcv.go`, `endpoint.go`, and `protocol.go` also use `pkg/tcpip/transport/tcp/` in the gVisor version above. `link_endpoint.go` and `netstack_tcpbuf_*.go` use Tailscale's `wgengine/netstack/`. First adopter paths use the separately identified commit.
- RFC references give the RFC and section number (e.g., RFC 9293 3.10.7.4) and the requirement number where available (MUST-14).
- The notes distinguish RFC requirements from behavior in the pinned implementation. Values calculated from formulas include the origins of their inputs. The scope choices in §9 and tests in §10 are proposals, with no execution results. §11 lists material that was not read.
- Official texts: [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293), [6298](https://www.rfc-editor.org/rfc/rfc6298), [5681](https://www.rfc-editor.org/rfc/rfc5681), [6582](https://www.rfc-editor.org/rfc/rfc6582), [5961](https://www.rfc-editor.org/rfc/rfc5961), [6528](https://www.rfc-editor.org/rfc/rfc6528), [6928](https://www.rfc-editor.org/rfc/rfc6928), [7323](https://www.rfc-editor.org/rfc/rfc7323), [2018](https://www.rfc-editor.org/rfc/rfc2018), [1071](https://www.rfc-editor.org/rfc/rfc1071), [8200](https://www.rfc-editor.org/rfc/rfc8200), [791](https://www.rfc-editor.org/rfc/rfc791). This review used the published RFC texts and excluded determinations from separate errata.

## 3. Wire Format

### 3.1 TCP Header (RFC 9293 3.1)

| Offset | Length | Field | Encoding |
| --- | --- | --- | --- |
| 0 | 2 | source port | Big-endian |
| 2 | 2 | destination port | Big-endian |
| 4 | 4 | sequence number(SEG.SEQ) | Big-endian, wraps modulo 2^32 |
| 8 | 4 | acknowledgment number(SEG.ACK) | Meaningful only if the ACK bit is set |
| 12 | 1 | High 4 bits are data offset (number of 32-bit words, 5…15), low 4 bits reserved | |
| 13 | 1 | Control bits: CWR 0x80, ECE 0x40, URG 0x20, ACK 0x10, PSH 0x08, RST 0x04, SYN 0x02, FIN 0x01 | |
| 14 | 2 | window(SEG.WND) | Big-endian. Multiply by `2^shift` when reading non-SYN segments (§4.6) |
| 16 | 2 | checksum | Internet checksum of pseudo-header + TCP header + data |
| 18 | 2 | urgent pointer | Only when URG is set |
| 20 | 0…40 | options | Extends to the point indicated by data offset. Fill remaining space with zeros (MUST-69) |

- SEG.LEN is the number of data bytes plus 1 each for SYN and FIN (RFC 9293 3.4).
- The IPv4 checksum pseudo-header contains the source address, destination address, 0, protocol 6, and TCP length (16 bits). The IPv6 pseudo-header contains the source address, destination address, length (32 bits), three zeros, and next header 6 (RFC 9293 3.1, RFC 8200 8.1). TCP length is the TCP header with options plus the data, excluding the IP header and extension headers. If an IPv6 Routing header is present, use the final destination address (RFC 8200 8.1). `Sources/SwiftailEngine/Tunnel/ServiceIPReply+Checksum.swift:31-37` adds this pseudo-header using `Sources/SwiftailBase/InternetChecksum.swift:43-66`.
- The checksum is the one's complement of the one's-complement sum of 16-bit words. Set the checksum field to 0 for computation and pad an odd final byte on the right with an unsent zero. For verification, the sum including the received checksum must be `0xFFFF` (RFC 9293 3.1 MUST-2 and MUST-3, RFC 1071 §§1 and 2). The repository implements the sum in `Sources/SwiftailBase/InternetChecksum.swift:17-36` and `:68-75`.
- Tailscale checks IPv4 header and unfragmented TCP and UDP checksums before injecting into netstack (`tailscale.com/wgengine/netstack/gro/gro.go:22-31`, `tailscale.com/wgengine/netstack/link_endpoint.go:238-251`, `:319-323`). gVisor rejects SYNs with incorrect checksums (`gvisor/transport/tcp/forwarder.go:74`). **Checksums emitted by Swiftail must be correct.**

### 3.2 Options

| Kind | Length | Name | Format | Reference |
| --- | --- | --- | --- | --- |
| 0 | 1 | End of Option List | Stop reading here | RFC 9293 3.2 |
| 1 | 1 | No-Operation | For alignment. Must read even off a word boundary (MUST-64) | RFC 9293 3.2 |
| 2 | 4 | Maximum Segment Size | 16-bit MSS. SYN only | RFC 9293 3.2, 3.7.1 |
| 3 | 3 | Window Scale | 1-byte shift.cnt. SYN only | RFC 7323 2.2 |
| 4 | 2 | SACK-Permitted | SYN only. MUST NOT send in non-SYN segments | RFC 2018 2 |
| 5 | 2+8×block count | SACK | Two 32-bit edges per block (in network byte order). Left edge is the block's first sequence number. Right edge is the sequence number after its last byte. Up to 4 blocks in the 40-byte option space, or up to 3 with a timestamp (10 + 2 padding) | RFC 2018 3 |
| 8 | 10 | Timestamps | Two 32-bit values, TSval and TSecr | RFC 7323 3.2 |

- Skip unknown options using the length field (MUST-6). All options except EOL and NOP have a length field (MUST-68). Handle options with length 0 or extending past the header (MUST-7. The source text suggests resetting the connection and logging the error cause as one procedure. The RFC does not make the reset itself a MUST).
- Options can appear on any segment (MUST-5).
- Sending SACK blocks (RFC 2018 4, checked against the RFC Editor text on 2026-11-15). Send SACK only if the peer's SYN included SACK-Permitted (MAY), and never otherwise (MUST NOT). If sending it, send it in every permitted case (SHOULD). Include it in every ACK that does not acknowledge the highest sequence number in the queue, meaning ACKs while the receiver holds noncontiguous data (SHOULD). ACK every valid segment with new data and include SACK in each such "duplicate" ACK (SHOULD). The first block must be the contiguous block containing the segment that triggered the ACK (MUST), unless that segment advanced the Acknowledgment Number. Include as many distinct blocks as possible (SHOULD). Fill the remaining slots by repeating the most recently reported blocks (by first block of each preceding SACK) that are not subsets of already included blocks (SHOULD). Order is unrestricted after the first block. §7 Case 1~3 illustrates these rules (Case 3: after holding 6000–6500, 7000–7500, and 8000–8500, receiving 6500 gives blocks 6000–7500 and 8000–8500. Receiving 5500 gives ACK 7500 and 8000–8500). A receiver may later discard data reported by SACK (reneging), although this is discouraged and incurs the additional rules in §8. Swiftail retains such data (contract behavior F5 below).

## 4. Procedures and State Machine

### 4.1 States and Variables (RFC 9293 3.3.1, 3.3.2)

States are LISTEN, SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT, and CLOSED.

Sender variables are SND.UNA (oldest unacknowledged), SND.NXT (next number to send), SND.WND (window from the peer), SND.WL1 and SND.WL2 (SEQ and ACK of the last segment to update the window), and ISS. Receiver variables are RCV.NXT, RCV.WND, and IRS.

All sequence number comparisons use arithmetic modulo 2^32 (RFC 9293 3.4).

### 4.2 Processing Incoming Segments (RFC 9293 3.10.7)

**Without a connection (CLOSED, 3.10.7.1)**. Drop segments with RST set. Otherwise reply with RST. If ACK is clear, send `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`. If set, send `<SEQ=SEG.ACK><CTL=RST>`. gVisor does the same (`gvisor/transport/tcp/protocol.go:185-200`, `replyWithReset` `:223`).

**LISTEN (3.10.7.2)**, in order. ① Ignore RST. ② If ACK is set, send `<SEQ=SEG.ACK><CTL=RST>`. ③ For SYN, set RCV.NXT = SEG.SEQ+1 and IRS = SEG.SEQ, choose ISS, send `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`, set SND.NXT = ISS+1 and SND.UNA = ISS, and enter SYN-RECEIVED. Hold data and other controls accompanying SYN for later processing and skip repeating the SYN and ACK checks. ④ Drop anything else.

**SYN-SENT (3.10.7.3)**, in order.

1. If ACK is set and either `SEG.ACK =< ISS` or `SEG.ACK > SND.NXT` holds, send `<SEQ=SEG.ACK><CTL=RST>` (skip sending if RST is set) and drop the segment.
2. If RST is set and ACK was acceptable, report "connection reset" and enter CLOSED. If there was no ACK, drop it.
3. If SYN is set, set RCV.NXT = SEG.SEQ+1 and IRS = SEG.SEQ. If ACK is present, set SND.UNA = SEG.ACK. If `SND.UNA > ISS`, enter ESTABLISHED and send `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`. If this path has accompanying data or controls, resume processing at step 6 (URG) of 3.10.7.4. If `SND.UNA > ISS` is false (simultaneous open), enter SYN-RECEIVED and send `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>`. Set SND.WND, WL1, and WL2 and hold data and other controls until ESTABLISHED.
4. Drop if neither SYN nor RST is present.

Like Linux, gVisor returns "connection refused" in step 2 (`gvisor/transport/tcp/connect.go:289-301`).

**Other states (3.10.7.4)**, in order. Exclude SYN-SENT, LISTEN, and CLOSED from this list. When applying RFC 5961, preserve the RST's original SEG.SEQ during data trimming and do not skip the challenge ACK by putting an in-window RST differing from RCV.NXT in the reordering queue. A SYN in a synchronized state warrants a challenge ACK regardless of its sequence number (RFC 5961 3.2 and 4.2, RFC 9293 3.10.7.4).

1. **Sequence check.** Acceptance conditions (Table 6).

   | SEG.LEN | RCV.WND | Condition |
   | --- | --- | --- |
   | 0 | 0 | SEG.SEQ = RCV.NXT |
   | 0 | >0 | RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND |
   | >0 | 0 | Reject |
   | >0 | >0 | First or last byte is inside the window |

   For an unacceptable segment, send `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` unless RST is set and drop it. Handle valid ACK, URG, and RST specially even when the window is 0. Trim any portion outside the window and defer segments starting after RCV.NXT for later processing (SHLD-31). Combine ACKs where possible, and send an ACK after processing all contiguous queued segments (MUST-58, MUST-59). Send separate ACKs when an exception calls for them.
2. **RST** (implementation following RFC 5961 3.2). Silently drop it outside the window. Close the connection if SEG.SEQ = RCV.NXT. If it is in-window but differs from RCV.NXT, send a challenge ACK `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` and drop it. On closing in SYN-RECEIVED, silently return to LISTEN after a passive open, or report "connection refused" after an active open. In ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, and CLOSE-WAIT, report "connection reset" and enter CLOSED. In CLOSING, LAST-ACK, and TIME-WAIT, enter CLOSED.
3. (Security checks are unused.)
4. **SYN**. In SYN-RECEIVED after a passive open, return to LISTEN. In synchronized states, send a challenge ACK regardless of the sequence number and drop the segment (RFC 5961 4.2. gVisor `connect.go:1337-1359`).
5. **ACK**. Drop if ACK is clear. Under RFC 5961 5.2, drop segments outside `SND.UNA - MAX.SND.WND =< SEG.ACK =< SND.NXT` and send an ACK (MAY-12).
   - SYN-RECEIVED: If `SND.UNA < SEG.ACK =< SND.NXT`, enter ESTABLISHED and populate SND.WND, WL1, and WL2 from this segment. Otherwise send `<SEQ=SEG.ACK><CTL=RST>`.
   - ESTABLISHED: If `SND.UNA < SEG.ACK =< SND.NXT`, set SND.UNA = SEG.ACK and remove acknowledged entries from the retransmission queue. `SEG.ACK =< SND.UNA` is a duplicate. If `SEG.ACK > SND.NXT`, send an ACK and drop the segment. A window update first requires `SND.UNA =< SEG.ACK =< SND.NXT`. Within that range, set SND.WND = SEG.WND, WL1 = SEG.SEQ, and WL2 = SEG.ACK only if `SND.WL1 < SEG.SEQ` or (`SND.WL1 = SEG.SEQ` and `SND.WL2 =< SEG.ACK`).
   - FIN-WAIT-1: In addition to the above, enter FIN-WAIT-2 if our FIN is acknowledged. FIN-WAIT-2 and CLOSE-WAIT also use ESTABLISHED ACK processing. CLOSING: Enter TIME-WAIT if our FIN is acknowledged. LAST-ACK: Enter CLOSED if our FIN is acknowledged. TIME-WAIT: ACK a retransmitted peer FIN and restart 2MSL.
6. URG (unused, §9).
7. **Data**. Accept only in ESTABLISHED, FIN-WAIT-1, and FIN-WAIT-2. Advance RCV.NXT and send `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>` (see §4.6 for delayed ACK). Do not decrease RCV.NXT+RCV.WND. Ignore data in other states.
8. **FIN**. When earlier data has arrived in order and FIN is at RCV.NXT, advance RCV.NXT past FIN and ACK it. Discard a FIN trimmed outside the window and defer a FIN preceded by a gap (steps 1 and 7). SYN-RECEIVED and ESTABLISHED → CLOSE-WAIT. FIN-WAIT-1 → TIME-WAIT if our FIN is acknowledged, or CLOSING otherwise. FIN-WAIT-2 → TIME-WAIT. TIME-WAIT → restart 2MSL. CLOSE-WAIT, CLOSING, and LAST-ACK retain their states.

gVisor's order differs from the RFC list: RST → SYN → receive processing of segments with ACK → sender-side ACK processing (`gvisor/transport/tcp/connect.go:1328-1395`). Do not use this code as an alternative specification for the RFC’s ACK check and data processing order. gVisor's strict RST check is in `connect.go:1227-1239`, but SYN-RECEIVED uses a separate `synRcvdState` that accepts in-window RSTs (`connect.go:394-402`). TIME-WAIT also has a separate path. It ignores RST and extends the time after ACKing a FIN with `SEG.SEQ+1 = RCV.NXT` (`rcv.go:552-567`, `:600-604`). If the general sequence check drops a duplicate FIN at `RCV.NXT-1` first, the extension is lost, so specify the TIME-WAIT exception (ACK and FIN steps of RFC 9293 3.10.7.4). For out-of-window segments, always ACK if there is data and rate-limit ACKs otherwise (`rcv.go:465-468`, `snd.go:1885-1891`).

### 4.3 Connection Establishment and ISN

1. The 3-way handshake follows the LISTEN, SYN-SENT, and SYN-RECEIVED rules in §4.2 exactly (RFC 9293 3.5).
2. ISN must be clock-driven (MUST-8), and `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)` is recommended (SHLD-1, RFC 9293 3.4.1 and RFC 6528 3). M is a clock component that advances by at least 1 approximately every 4 microseconds. F cannot be computed externally (MUST-9). gVisor draws a 16-byte secret per stack (`seqnumSecret` in `gvisor/transport/tcp/protocol.go:588-597`) and adds a clock in 64ns units to SHA-256(secret ‖ addresses ‖ ports) (`connect.go:226-252`).
3. SYN retransmission. The recommended initial RTO is 1 second (RFC 6298 2.1. gVisor `InitialRTO`, `connect.go:41`). Double on each expiration (RFC 6298 5.5). gVisor defines `DefaultSynRetries = 6` (`protocol.go:68`, `:617`), but the actual handshake ends when the `backoffTimer` reaches its limit. The timer uses `InitialRTO = 1 second` and `MaxRTO = 120 seconds` independently of the count (`connect.go:181`, `:621-643`, `:721-736`). On the normal no-response path, it sends SYN or SYN-ACK at t=0, retransmits six times at t=1, 3, 7, 15, 31, and 63 seconds, and fails at t=127 seconds because the next interval of 128 seconds exceeds the 120-second cap (calculated from source, without runtime measurement). The separate `maxSynRetries` field is unused in the decision on this path (`endpoint.go:931-934`, `connect.go:730-736`). This 127-second default path falls short of SYN R2 ≥ 3 minutes (MUST-23) in RFC 9293 3.8.3. Keep current gVisor behavior distinct from the RFC requirement. If the SYN retransmission timer expired and RTO is below 3 seconds, reset RTO to 3 seconds when data transmission starts (RFC 6298 5.7).
4. gVisor reports a valid RST acknowledging the opener's SYN as a refusal. RFC 9293's SYN-SENT description says "connection reset" (§4.2 SYN-SENT step 2 and `connect.go:289-301`).

### 4.4 Closing (RFC 9293 3.6)

- FIN consumes one sequence number. Both sides close after the sent FIN is acknowledged and the peer FIN is received and ACKed.
- The two directions close independently. Sending can continue in the open direction when only one side is closed (3.6.1).
- If an implementation uses half-duplex CLOSE that also disallows reads, and unread data remains or new data arrives after CLOSE, it should signal data loss with an RST (SHLD-3). This rule excludes a send-only half-close (3.6.1).
- The first side to close stays in TIME-WAIT for 2×MSL (MUST-13). gVisor defaults TIME-WAIT to 60 seconds (`protocol.go:64`). FIN-WAIT-2 linger also defaults to 60 seconds (`protocol.go:56`), but applies to connections the app has closed with `Close` and does not limit the lifetime of all send-only half-closed connections to 60 seconds (`endpoint.go:1131-1174`). RFC 9293 sets MSL at 2 minutes (3.4.3 and §4), giving an RFC 2MSL of 4 minutes. gVisor's 60 seconds is an implementation value.
- Distinguish a peer FIN close from an RST abort for the application (MUST-12).

### 4.5 Retransmission Timer (RFC 6298, RFC 9293 3.8.1 MUST-18)

1. Before measuring RTT, RTO SHOULD be 1 second, and a value above 1 second is also allowed (2.1).
2. First measurement R: `SRTT = R`, `RTTVAR = R/2`, `RTO = SRTT + max(G, 4*RTTVAR)` (2.2).
3. Subsequent measurement R': `RTTVAR = 3/4*RTTVAR + 1/4*|SRTT - R'|`, `SRTT = 7/8*SRTT + 1/8*R'` (in that order), `RTO = SRTT + max(G, 4*RTTVAR)` (2.3).
4. Round up to 1 second if lower (SHOULD, 2.4). A cap, if used, is at least 60 seconds (2.5). **gVisor uses a 200ms minimum and 120-second maximum** (`gvisor/transport/tcp/snd.go:32`, `:35`).
5. Skip RTT measurement on retransmitted segments (Karn, §3). The timestamp option permits measurement (RFC 7323 4).
6. Timer management (§5). When sending data with the timer off, start it with RTO (5.1). Stop it when all data is acknowledged (5.2). When receiving an ACK for new data, restart with the current RTO (5.3). On expiration, retransmit the oldest unacknowledged segment (5.4), double RTO (5.5), and restart (5.6).
7. R2 is a threshold on retransmissions or elapsed time for the same segment. Close the connection when it is reached. R2 SHOULD be at least 100 seconds (RFC 9293 3.8.3 MUST-20, SHLD-11). gVisor defaults to a maximum of 15 retransmissions (`snd.go:50`, `protocol.go:620`). It checks at the next RTO whether `xmitCount`, which includes the initial transmission, exceeded 15, so there is still a wait after the last retransmission (`snd.go:674-680`, `:1814-1822`).

### 4.6 Windows and Flow Control

1. The receiver SHOULD avoid moving the right window edge (RCV.NXT+RCV.WND) left (SHLD-14). Do not shrink the promised receive sequence range based solely on free bytes in the physical buffer (3.8.6 and 3.8.6.2.2). The sender must tolerate window shrinkage (MUST-34). Hold new data and handle retransmission of previously sent unacknowledged data separately (SHLD-15 and SHLD-16).
2. **Zero-window probe**. Probe periodically if the peer's window is 0 (MUST-36). Send the first probe when the window has been zero for one RTO, and increase the interval exponentially (SHLD-29, SHLD-30). Keep the connection open while the peer ACKs probes (MUST-37).
3. **SWS avoidance**. For the sender (MUST-38), let `U = SND.UNA + SND.WND - SND.NXT` and D be data to send. Send if ① `min(D,U) >= Eff.snd.MSS`, ② all queued PUSHed data can be sent (`D <= U`), ③ `min(D,U) >= Max(SND.WND)/2`, or ④ the override timer (0.1~1 seconds) expires (3.8.6.2.1). If Nagle is enabled, ② and ③ also require `SND.NXT = SND.UNA`. The override timer must break deadlocks with small nonzero windows as well as zero windows. The receiver (MUST-39) holds the right window edge until `RCV.BUFF - RCV.USER - RCV.WND >= min(RCV.BUFF/2, Eff.snd.MSS)` (3.8.6.2.2).
4. **Delayed ACK** (3.8.6.3, RFC 5681 4.2). Implement it (SHOULD, SHLD-18), limit the delay to less than 0.5 seconds (MUST-40), and ACK at least every two full segments (SHOULD, SHLD-19). ACK out-of-order data and data filling all or part of a gap immediately (SHOULD, RFC 5681 4.2). MSS in the 2×MSS criterion is the receiver's advertised RMSS (RFC 9293 3.8.6.3). Send at most one ACK per segment (window updates are an exception, RFC 5681 4.2).
5. **Window scaling** (RFC 7323 2.3). Include Window Scale in SYN-ACK only if SYN included it. Enable scaling only when both SYNs include it, otherwise both shifts are 0. Leave the SYN window unscaled. For other segments, receive with `SND.WND = SEG.WND << Snd.Wind.Shift` and send with `SEG.WND = RCV.WND >> Rcv.Wind.Shift`. Shift is at most 14. gVisor chooses shift using the maximum receive buffer with autotuning on and the current receive buffer with it off (`endpoint.go:3220-3237`). `FindWndScale` uses 0 for a window below 65,536. Otherwise it selects the smallest s for which `65535 << s` is at least the window, capped at 14 (`connect.go:199-212`).
   Even if window scaling quantization shrinks the most recently advertised window edge, the receiver must still accept segments within the window from a previous ACK. Track the actual maximum receive window edge separately (SHOULD). The sender's original transmissions must fit the window in the latest ACK (RFC 7323 2.4).
6. Nagle is a SHOULD (SHLD-7) and must be possible to disable (MUST-17, RFC 9293 3.7.4).
7. Keep-alive is optional (MAY-5). If implemented, the application must be able to enable or disable it per connection (MUST-24). Keep-alive must default to off (MUST-25) and have a default idle interval of at least 2 hours (MUST-28). A probe typically has `SEG.SEQ = SND.NXT-1`, and a data-free ACK is recommended (3.8.4 SHLD-12). Send only if there is no unacknowledged send data and no data or ACK has arrived during the idle interval (MUST-26). The interval must be configurable (MUST-27). A single unanswered probe does not mean the connection is dead (MUST-29).

### 4.7 Congestion Control (RFC 5681, RFC 6582)

Slow start, congestion avoidance, and exponential RTO backoff are required (RFC 9293 3.8.2 MUST-19).

1. Variables are cwnd and ssthresh. Total unacknowledged data is limited to `min(cwnd, SND.WND)`. Subtract FlightSize to get the allowance for new data (RFC 5681 2 and 3.1).
2. Initial window cap: RFC 5681 3.1 uses 2~4 segments depending on SMSS. RFC 6928 (experimental) uses `min(10*MSS, max(2*MSS, 14600))`. gVisor's `InitialCwnd` is 10 segments (`snd.go:41`). RFC 6928 §2 also includes changes that keep ACKs of SYN and SYN-ACK from increasing IW and avoid unconditional reduction of IW to 1 after SYN loss, and a recommendation to reduce RW to the RFC 3390 level after loss in an initial or restart window.
3. Slow start (`cwnd < ssthresh`): `cwnd += min(N, SMSS)` per ACK of new data (N is newly acknowledged bytes, equation 2). Congestion avoidance: `cwnd += SMSS*SMSS/cwnd` per ACK of new data (permitted equation 3). If integer division gives 0, round up to 1 byte (SHOULD). In congestion avoidance, increase by at most SMSS per RTT. Either algorithm is allowed when `cwnd == ssthresh` (3.1).
4. When an RTO first detects loss of a segment that has never been retransmitted by RTO, set `ssthresh <= max(FlightSize/2, 2*SMSS)` (equation 4). Leave ssthresh unchanged for repeated RTOs of that segment. After RTO, cwnd is at most 1 SMSS (loss window) (RFC 5681 3.1). Equation 4 also caps ssthresh on entry to fast retransmit (3.2 step 2).
5. Fast retransmit and fast recovery (RFC 5681 3.2). On the third duplicate ACK, set ssthresh using equation 4 (step 2), retransmit the SND.UNA segment and set `cwnd = ssthresh + 3*SMSS` (step 3). For each further duplicate ACK, `cwnd += SMSS` (step 4) and send new data if the window allows (step 5). On an ACK of new data, set `cwnd = ssthresh` (step 6).
6. NewReno (RFC 6582 3.2). Initialize `recover` to ISS. On the third duplicate ACK, enter fast retransmit only if `SEG.ACK - 1 > recover` and set `recover = highest sequence number sent so far`. If an ACK during recovery acknowledges everything through recover (full ACK), set `cwnd = min(ssthresh, max(FlightSize, SMSS) + SMSS)` or ssthresh and exit. Otherwise (partial ACK), retransmit the first unacknowledged segment, reduce cwnd by newly acknowledged bytes, add SMSS if at least 1 SMSS was acknowledged, and continue recovery. Restart the retransmission timer on the first partial ACK. On RTO expiration, record the highest sequence number in recover and exit recovery.
7. Duplicate ACK definition (RFC 5681 2). Outstanding data exists, the ACK contains no data, SYN and FIN are clear, the acknowledgment number matches the highest so far, and the advertised window equals the preceding ACK's.
8. If **time without sending data** exceeds RTO, reduce cwnd to at most `min(IW, cwnd)` (SHOULD, RFC 5681 4.1).

### 4.8 Which Options and Features Are Required for Interoperability?

| Feature | Specification requirement | Effect of omission | gVisor (Tailscale configuration) |
| --- | --- | --- | --- |
| Sending and receiving MSS options | Both capabilities are mandatory (MUST-14). Advertise on each SYN if the value differs from the default (SHOULD, SHLD-5). If absent, IPv4 536, IPv6 1220 (MUST-15) | Omitting the option alone does not prevent connection establishment. The peer's default send limit per the specification is 536 for IPv4 and 1220 for IPv6 | Advertises it (`connect.go:584-590`). In the absence of a received option, this version's parser defaults to 536 regardless of IP family (`gvisor/header/tcp.go:439-450`, `connect.go:748-755`) |
| Checksum | Required | The peer drops the segment (§3.1) | Verifies it |
| Window scaling | Optional (RFC 7323). Disabled if either side omits it | Window limited to 65,535 bytes | Sends it (`connect.go:585`) |
| SACK | Optional (RFC 2018 2 and 4). Sending SACK blocks in either direction requires receiving SACK-Permitted in the peer's SYN (§4 MUST NOT) | Slower recovery from multiple losses in one window | Enabled (`protocol.go:610`). Used only when the peer permits it. SYN option order is MSS, two NOPs and SACK-Permitted, then NOP and WS (`makeSynOptions` in `connect.go`). Blocks follow two NOPs and appear only on ACK-bearing segments while holding out-of-order segments in ESTABLISHED, including segments carrying data (`makeOptions` and `sendRaw` in the same file). The list puts the block for the new segment first and merges overlapping blocks (`UpdateSACKBlocks` in `sack.go`) |
| Timestamps | Optional (RFC 7323 3.2). Enable if present in both SYNs. If enabled, include in every non-RST segment | No RTT measurement during retransmission. No PAWS | Includes them in SYN (`connect.go:586`) |
| RFC 5961 | RST and SYN mitigations are SHOULD, ACK range check is MAY (3.2, 4.2, and 5.2) | With old RFC 793 behavior, in-window RST or SYN can break a connection | Follows the RST and SYN rules in synchronized states (`connect.go:1227-1239`, `:1333-1360`). See §4.2 for SYN-RECEIVED and TIME-WAIT differences |
| Delayed ACK | SHOULD (RFC 9293 3.8.6.3) | ACK count may rise depending on receive batching and piggybacking | Does not delay by time. ACKs if needed at the end of a receive batch (`connect.go:1272-1306`). ACKs out-of-order segments immediately (`rcv.go:482-515`). This conclusion uses more than `SetQuickAck(true)` |
| Nagle | SHOULD | Small writes go out as small segments | Only if the stack option (`TCPDelayEnabled`) is on (`endpoint.go:921-924`). The Tailscale creation path leaves it off (`netstack.go:388-435`, `protocol.go:598-625`) |
| Keep-alive | MAY | Idle connections to dead peers remain | Tailscale enables it on every inbound connection (§5) |
| Urgent | MUST-30 | Urgent data is read as ordinary data | Does not read urgent data |
| ECN | SHOULD (RFC 9293 3.8.2 SHLD-8) | Uses loss-based congestion detection (RFC 5681 §3) | Marks it unsupported and clears ECN bits (`endpoint.go:1943-1954`) |

### 4.9 RFC 5961 Rate Limiting

Challenge ACKs SHOULD be rate-limited. The example is 10 per 5 seconds (RFC 5961 7). A timestamp and counter can implement it without a timer.

## 5. Tailscale Netstack (gVisor) Configuration

| Item | Value | Reference |
| --- | --- | --- |
| Congestion control | CUBIC | `netstack.go:406-407` |
| Loss recovery | RACK off by default. Enabled only with `TS_NETSTACK_ENABLE_RACK=true`. With RACK off, use SACK recovery if SACK was negotiated and Reno recovery otherwise | Actual configuration in `netstack.go:412-418` (the executed branch takes precedence because the default in the comment at `:141-153` disagrees), `gvisor/transport/tcp/snd.go:356-361` |
| SACK | Enabled (gVisor default). Offer on active SYN and advertise on passive SYN-ACK only if the peer permitted it | `gvisor/transport/tcp/protocol.go:610`, `connect.go:584-603`, `endpoint.go:3271-3281` |
| Window scaling | Offer on active SYN, include in passive SYN-ACK only if present in the peer SYN. Default autotuning gives shift 8 on !iOS and 7 on iOS (computed from the maximum receive buffer) | `connect.go:199-212`, `:584-603`, `endpoint.go:3200-3207`, `:3220-3237`, buffer limits below |
| Timestamps | Offer on active SYN, include in passive SYN-ACK only if present in the peer SYN | `connect.go:584-603`, `endpoint.go:3249-3255` |
| Receive buffer (min/default/max) | 4KiB / 1MiB / 8MiB. iOS maximum 4MiB | `tailscale.com/wgengine/netstack/netstack_tcpbuf_default.go:12-20`, `netstack_tcpbuf_ios.go:17-23`, `netstack.go:309-345`, `gvisor/transport/tcp/protocol.go:41-52` |
| Send buffer (min/default/max) | 4KiB / 1MiB / 6MiB. iOS maximum 4MiB | Same references |
| Receive buffer autotuning | Enabled | `gvisor/transport/tcp/protocol.go:613`, `endpoint.go:916-918` |
| Out-of-order segments | Queue only if reordering queue memory usage plus new payload length is below 75% of the receive buffer | `gvisor/transport/tcp/rcv.go:488-510` |
| NIC MTU | 1280 (configurable via `TS_DEBUG_MTU`) | `netstack.go:434`, `tailscale.com/net/tstun/mtu.go:79`, `:133-148` |
| Advertised MSS | Path MTU − 20. Path MTU is NIC MTU − IP header (IPv4 20, IPv6 40) → IPv4 1240, IPv6 1220 | `gvisor/transport/tcp/endpoint.go:638-648`, `gvisor/network/ipv4/ipv4.go:419-425`, `gvisor/network/ipv6/ipv6.go:736-742` |
| Initial cwnd | 10 segments | `snd.go:41` |
| RTO | Initial 1 second, minimum 200ms, maximum 120 seconds | `connect.go:41`, `snd.go:32`, `:35` |
| Retransmission limit | 15 attempts | `snd.go:50` |
| SYN and SYN-ACK retransmission | With no response, retransmit at 1, 3, 7, 15, 31, and 63 seconds and fail at 127 seconds (calculated). The actual exit condition is the 120-second interval cap | `connect.go:181`, `:621-643`, `:721-736`. The constant 6 in `protocol.go:68` alone does not establish this behavior |
| Duplicate ACK threshold | 3 | `snd.go:45` |
| Keep-alive | Enabled on every inbound connection. Idle 2 hours, 75-second interval, 9 probes (the idle time and interval can be reduced with environment variables `TS_NETSTACK_KEEPALIVE_IDLE` and `_INTERVAL`) | `netstack.go:125-139`, `:1677-1702`, `protocol.go:72-80` |
| TIME-WAIT, linger | 60 seconds, 60 seconds | `protocol.go:56`, `:64` |
| Limit on connections being established | 1,024 on mobile, 8,192 on Linux, 2,048 elsewhere (macOS). 2/3 of that per remote Tailscale IP | `netstack.go:85-105`, `:111-120`, `:669` |
| SYN above the limit | Drop without responding | `gvisor/transport/tcp/forwarder.go:88-92` |
| GRO and GSO | Enabled on Linux when `buildfeatures.HasGRO` | `netstack.go:427-433` |

### 5.1 Implementation Differences for Small MSS and Zero-Window Probes

- gVisor raises a peer's nonzero advertised MSS to at least **48** (`gvisor/header/tcp.go:463-470`). This is `TCPMinimumSendMSS = TCPOptionsMaximumSize(40) + MinIPFragmentPayloadSize(8)` (`gvisor/header/tcp.go:208`, `:228-230`, `gvisor/header/ipv4.go:138-140`). This differs from the minimum **88** for the application-specified MSS via `MaxSegOption` (`endpoint.go:1957-1964`, `gvisor/header/tcp.go:224-226`). An advertised MSS of 0 stops option parsing and keeps the default up to that point (`gvisor/header/tcp.go:442-465`).
- This minimum adjustment is behavior of the pinned implementation and is outside what RFC 9293 3.7.1 MUST-16 permits. Sending data larger than the peer's MSS exceeds its receive limit. Swiftail's arbitrary 64-byte floor poses the same risk. If the MSS is too small to support, specify a policy to honor it or reject the connection attempt (effective send MSS formula in the same section).
- gVisor's zero-window probe is an ACK with one zero byte at `SND.UNA-1`. It elicits a response using an already acknowledged sequence number (`snd.go:1009-1034`). RFC 9293 3.8.6.1 separately describes sending at least one byte if new data is available or retransmitting. The interval starts at the current RTO and doubles up to 120 seconds. It fails at the next expiration after 15 unacknowledged probes and reduces the unanswered count on an ACK reply (`snd.go:597-608`, `:664-670`, `:1018-1034`, `:1631-1634`).

### 5.2 Peer Removal and Open Connections

- Netmap updates call `UpdateNetstackIPs` (`tailscale.com/ipn/ipnlocal/local.go:7476-7481`). This function updates local and service addresses. There is no mapping from peer node keys to open TCP connections for closing them on peer removal, and this function leaves connections open when the owner of the address changes (`netstack.go:729-835`). TCP identifies the peer using the IP and port 4-tuple (`gvisor/stack/registration.go:34-51`, `connect.go:644-654`).
- **Static source review** shows that removing a peer from the netmap alone does not immediately close its gVisor TCP connections. If there is no response, the connection ends when retransmission or keep-alive probes are exhausted, or when the application cancels or closes it. Inbound connections default to keep-alive after 2 hours (`netstack.go:125-139`, `:1677-1702`, `gvisor/transport/tcp/connect.go:1401-1465`). Full stack shutdown separately aborts every registered endpoint (`netstack.go:471-477`, `gvisor/stack/stack.go:2064-2067`). No packet test covered another key inheriting the same IP, so whether actual transmission continues is unverified. Swiftail's `peerRemoved` is a separate protection policy that goes beyond Go's behavior.

## 6. tsnet `Listen` and `Dial`

### 6.1 `Listen(network, addr)` (`tsnet.go:1321-1323`, `:2115-2158`)

1. `network` accepts the empty string, `tcp`, `tcp4`, or `tcp6` (and `udp`, `udp4`, or `udp6`) (`tsnet.go:2115-2119`). The host in `addr` must be empty or an IP literal. `0.0.0.0` and `::` are equivalent to an empty host (`tsnet.go:2069-2096`).
2. A listener with an empty host accepts **only traffic to the local node's tailnet IPv4 or IPv6 addresses**. `tcp` accepts both families (`tsnet.go:1238-1266`).
3. A listener already registered for the same (network, address, port) causes an error (`tsnet.go:2209-2213`).
4. Port 0 in default fake TUN mode picks from 10002…19999 (`tsnet.go:2111-2112`, `:2189-2196`). TCP listeners in real TUN mode are delegated to gVisor (`tsnet.go:2131-2146`).
5. `Listen` starts the node without waiting for `Running` (`tsnet.go:2124-2126`).

### 6.2 Inbound Connection Path

1. Under the tsnet default (fake TUN), netstack processes all packets to local addresses (`tsnet.go:921-927`).
2. Packets go through WireGuard decryption → filtering before entering netstack (`injectInbound` in `netstack.go:1472-1512` is a post-filter hook in the `tstun` wrapper). Hook registration is at `netstack.go:465`, and hook ordering after the filter call is at `tailscale.com/net/tstun/wrap.go:1193-1248`. Swiftail's filter compares only new connections (SYN, no ACK) against ACL rules (`Sources/SwiftailEngine/PacketFilter.swift:14`, `:84-88`).
3. The forwarder receives a SYN (no ACK, valid checksum) that was not delivered to an existing connection. If a request with the same 4-tuple is in progress or the limit is reached, it drops the SYN without making a request. Otherwise it makes a request (`gvisor/transport/tcp/forwarder.go:66-104`) for `acceptTCP` to handle (`netstack.go:1602`).
4. `acceptTCP` calls `GetTCPHandlerForFlow` (tsnet's listener lookup). With no listener, send **RST** (`netstack.go:1748-1754`, `tsnet.go:1289-1303`). If a listener exists, start the handshake asynchronously on the endpoint, enable keep-alive, and hand the connection to the listener. The connection's `RemoteAddr` and `LocalAddr` may be nil before establishment. Reads and writes wait for handshake completion (`netstack.go:1666-1720`, `:1748-1759`).
5. In default fake TUN mode, close the connection if the listener's `Accept` does not take it within 1 second after delivery starts (`tsnet.go:2406-2418`). The channel is unbuffered (`tsnet.go:2349`). Real TUN mode delegates `Accept` directly to the gVisor listener, so the 1-second rule does not apply (`tsnet.go:2359-2365`).
6. With no connection, gVisor replies with RST to a valid non-RST segment. Received RST and checksum errors get no reply (`gvisor/transport/tcp/protocol.go:185-199`, §4.2).
7. Service IP TCP accepts only 53 (DNS) and a few other ports, with RST elsewhere (`netstack.go:1724-1735`, `:1770-1787`). Swiftail replies with RST for all in M5 (tunnel contract D4).

### 6.3 `Dial(ctx, network, address)` (`tsnet.go:382-390`)

1. Wait for `Running` (`Start` and `awaitRunning` in `tsnet.go:383-389`).
2. Address resolution (`tailscale.com/net/tsdial/tsdial.go:401-417`, `:423-436`). Use IP literals as is. Otherwise lowercase the name, remove its trailing dot, and look it up in the netmap. Accept peer FQDNs, short names, and `ExtraRecords` (`tailscale.com/net/tsdial/dnsmap.go:14-18`, `tailscale.com/ipn/ipnlocal/resolve.go:54-75`). For `tcp`, prefer the node's IPv4 and fall back to IPv6 (`tailscale.com/ipn/ipnlocal/resolve.go:115-143`).
3. Look up names absent from the netmap using `net.Resolver`. This is usually system DNS, but uses the exit-node DoH resolver if configured and the relevant build feature exists (`tailscale.com/net/tsdial/tsdial.go:438-470`).
4. If the address belongs to a peer (`PeerForIP`), dial with netstack. The source is the local tailnet address of the same family as the destination (`tsnet.go:935-950`). Otherwise, use the peer dialer if it is a Tailscale route, or the system/std dialer if not. A failed `PeerForIP` lookup therefore can still lead to peer dialing (`tailscale.com/net/tsdial/tsdial.go:608-638`).
5. The returned connection (`gonet.TCPConn`) has `CloseWrite` and `CloseRead` (`gvisor/adapters/gonet/gonet.go:446`, `:457`).

## 7. MTU and MSS

- The default Tailscale TUN MTU is 1280 (`tailscale.com/net/tstun/mtu.go:79`). The first adopter's tunnel also uses 1280…1420 (tunnel contract behavior U1).
- At MTU 1280, MSS is 1240 for IPv4 (1280 − 20 − 20) and 1220 for IPv6 (1280 − 40 − 20). A gVisor peer using the default NIC MTU advertises these calculated values (§5 sources).
- **Outgoing data length** is at most `min(SendMSS+20, MMS_S) − TCPhdrsize − IPoptionsize` from RFC 9293 3.7.1 MUST-16. For MTU 1280 and the base IP header, this is `min(SendMSS, 1280 − fixed IP header − 20) − TCP option length − IP option/extension header length`. Subtract option lengths from the peer MSS limit as well. Only subtract fixed headers when advertising MSS (MUST-67 in the same section).
- The engine rejects fragmented packets (`Sources/SwiftailEngine/IPPacket.swift:167`, `:183`). Matching MSS to the local NIC MTU alone cannot account for smaller intermediate MTUs. IPv4 can be fragmented or dropped depending on intermediate path MTU and DF (RFC 791 2.3 and 3.1). IPv6 can omit PMTUD when sending 1280 or below, but general IPv6 nodes still have reassembly requirements (RFC 8200 5). The tailnet MTU 1280 assumption and subtraction of IP option lengths are required.

## 8. Scope Used by the First Adopter

Read at commit `286c214` in the first adopter's repository. Paths and line numbers in this section refer to that commit. The working files may have changed since then.

1. **Mac host**. Opens a listener when `Running` and not yet listening (`core/internal/node/node.go:604-608`). After `Up`, the TLS path wraps `srv.Listen("tcp", ":<port>")` with `tls.NewListener` (`GetCertificate`) (`core/internal/node/tls.go:22-41`). The non-TLS path uses `srv.Listen` directly (`core/internal/node/node.go:780-791`). Default port is 443 (`core/internal/node/config.go:104-105`). `http.Server` calls `Serve` with `ReadHeaderTimeout` of 10 seconds and `IdleTimeout` of 60 seconds (`core/internal/node/node.go:812-818`).
2. `identify` for tailnet requests calls WhoIs using `r.RemoteAddr` (5-second limit). If the context has an authenticated peer from a direct connection, it skips the lookup (`core/internal/host/host.go:230-244`). Tailnet connections need a remote address.
3. **Transfer sizes**. Server-to-client transfers include IPA Range transfers (`docs/protocol.md:53`, `docs/protocol-addenda.md:140-156`) and file transfers (up to 4GiB each, with Range and HEAD support, `docs/protocol-addenda.md:334-355`). Log bodies are up to 4MB total (`docs/protocol-addenda.md:484`). Request body limits can differ.
4. **Inference about the peer TCP stack from the path**. The ordinary iPhone VPN path (`docs/tunnel.md:9-14`) uses system URLSession and the installer, background file transfers, and Safari behind the official Tailscale app (`docs/protocol.md:236`, `docs/protocol-addenda.md:219`, `:355`), so the peer is presumed to use kernel TCP. The `srv.Dial` peer in proxy mode takes the tsnet/gVisor path (step 5 below and §6.3). No SYN captures identified the stack or options.
5. **Proxy mode**. The node supplies `srv.Dial` as the proxy dial function (`core/internal/node/node.go:952`). The proxy dials allowed CONNECT destinations with `"tcp"` and a 15-second limit and checks that the remote address is in the tailnet (`core/internal/proxy/proxy.go:17`, `:116-137`). It copies in both directions, half-closes with `CloseWrite` on normal EOF if supported, and closes both ends on error (`core/internal/proxy/proxy.go:156-176`). `docs/tunnel.md:14` describes its diagnostic scope.
6. **Distinguish product paths from test tools**. The `core/internal/node/` product path above uses `Listen`, `Dial`, `Up`, `LocalClient`, `Start`, and `Close` (`core/internal/node/node.go:349`, `:421`, `:790`, `:952`, `:1004`, `core/internal/node/tls.go:23-37`). The earlier claim that all of `core/` uses only these was incorrect. Test tools also use `HTTPClient` (`core/cmd/rdtestenv/main.go:140`, `core/e2e/helpers_test.go:82`) and `ListenPacket` (`core/e2e/tunnel/tunnel_test.go:192`).

## 9. Minimum Requirements for Swiftail

The contract's [Scope supported in M6](../contracts/SwiftailNetstack.md#scope-supported-in-m6) determines what Swiftail implements. The following choices are based on these notes.

- Specification requirements. Checksum (RFC 9293 3.1 MUST-2 and MUST-3), sending and receiving MSS options (3.7.1 MUST-14), segment processing by state (3.10.7), RFC 6298 retransmission timer (3.8.1 MUST-18), zero-window probes (3.8.6.1 MUST-36), and slow start, congestion avoidance, and RTO backoff (3.8.2 MUST-19). Omitting a required feature does not always cause handshake failure. In particular, omitting the MSS advertisement can leave the connection using the default MSS (§4.8).
- Optional for basic TCP interoperability. Window scaling, SACK, and timestamps (RFC 9293 3.2.1). Without scaling, the window field limit is 65,535 (RFC 7323 §2). Ignore unnegotiated TS and never send SACK blocks unless the peer sent SACK-Permitted (RFC 7323 3.2, RFC 2018 4 MUST NOT). Sending SACK is MAY even after receiving SACK-Permitted (RFC 2018 4 first paragraph). There is therefore no rule that a peer must reject a connection solely for omitting these options.
- Delayed ACK, Nagle, and ECN are SHOULD (RFC 9293 3.8.6.3, 3.7.4, and 3.8.2 respectively), and keep-alive is MAY (3.8.4). Urgent and simultaneous open are specification MUSTs (3.8.5 MUST-30, 3.5 MUST-10) and **must never be classified as optional**. The scope exclusions in the contract are separate from RFC compliance. Their exclusion is an implementation choice for the first adopter paths above and the contract's exclusions table, with no guarantee of interoperability with all TCP applications.

## 10. Interop Test Checks

The following are planned tests. This document review ran no packet tests.

1. A gVisor peer accepts Swiftail's SYN and SYN-ACK and reaches ESTABLISHED (checksum, MSS, and window scale options).
2. A SYN to a port without a listener gets RST, and Go `Dial` returns refusal before its timeout.
3. Hashes match for a bidirectional 100MB transfer. Check window scale by checking both SYN options and interpreting the window with the negotiated shift. The wire's 16-bit window field itself cannot exceed 65,535 (RFC 7323 2.2 and 2.3).
4. Transfers finish at 1% and 5% loss.
5. Half-close. After one side sends FIN, data in the other direction continues to completion.
6. If Swiftail aborts via RST, reads on the Go side end with a reset error. If Go aborts, Swiftail recognizes the reset.
7. Checks 1~6 with macOS and iOS kernel stacks as peers.

## 11. Unverified Items

All 12 official RFCs were downloaded and their cited sections read, and all necessary Tailscale and gVisor sources were available. No items remained due to failed downloads or missing sources. Static paths for delayed ACK, SYN retransmission, minimum MSS, active options, and peer removal were previously unverified and are resolved in §§4.2, 4.3, and 5. The remaining limitations of reading and execution follow.

1. The full gVisor CUBIC window update algorithm (`gvisor/transport/tcp/cubic.go`). Only the Tailscale configuration selecting CUBIC was verified (§5). Swiftail's NewReno is based on RFCs 5681 and 6582.
2. Default MSS, window scale shift, SACK, timestamps, and delayed ACK timing in macOS and iOS XNU. The review did not read the XNU source or capture SYNs on a real device. Verify at the §10 gate.
3. Actual connection lifetime after peer removal, key change for the same IP, or local address change. §5.2 reports static source findings without packet tests. Validity of gVisor routes after local address removal was beyond the trace, so equivalence to peer removal is unconfirmed.
4. Whether the first adopter's `http.Server` uses HTTP/2. Confirmed that `core/internal/node/tls.go:41` has no `NextProtos` and that `core/internal/node/node.go:818` calls `Serve`. TLS and net/http automatic configuration paths and ALPN in the pinned Go toolchain were unverified.
5. The text of RFCs 6675 and 8985 and the full PAWS procedure in RFC 7323 §5 were outside this review. RFC 2018 §4 confirmed the conditions for generating SACK in §§4.8 and 9, but the full SACK implementation and recovery algorithm were unverified.
6. The requirement for administrator privileges to create utun. The review did not read the XNU source. Only the prerequisite in test 9 of `docs/contracts/SwiftailTunnel.md` was checked.
7. gVisor's 127-second SYN result and ACK send path were calculated and traced from source. Runtime timing, scheduler delay, and actual packet intervals were unmeasured.

## 12. Sender-Side SACK Recovery (RFC 6675)

- References: RFC 6675 (2012, replaces RFC 3517), RFC 2018 sender rules (§§5, 5.1, and 8) and its erratum 1610, and RFC 2883 (D-SACK). Downloaded and read the official RFC Editor texts (`https://www.rfc-editor.org/rfc/rfc6675.txt`, `rfc2018.txt`, `rfc2883.txt`) and errata search results (`https://www.rfc-editor.org/errata/rfc6675`, `rfc2018`) on 2026-11-15. RFC 6675 has no registered errata. RFC 2018 has one verified erratum, 1610 (§12.5).
- gVisor comparison: Version pinned in §2, `sack_recovery.go`, `sack_scoreboard.go`, and `snd.go` under `gvisor/transport/tcp/`, and option parsing in `gvisor/header/tcp.go`.
- Author: Claude Opus 5.5, 2026-11-15. **Awaiting verification**. Outside the verification scope of §§1~11.
- Scope: Only the **sender side**, which uses received SACK blocks to determine what to retransmit and how much to send in recovery. SACK-Permitted negotiation and SACK block generation (receiver side, RFC 2018 §§2 and 4) are out of scope. Congestion control algorithms (such as CUBIC), RACK and TLP (RFC 8985), PRR, and F-RTO were unread.

### 12.1 Wire Format Details for the Sender

- The SACK option (kind 5) has two 32-bit values per block, the left edge (first sequence number in the block) and the right edge (one past the last number). Its length is `8*n+2`. The 40-byte option space holds up to 4 blocks, or up to 3 with a timestamp (RFC 2018 3). A block is "contiguous bytes received and queued". Bytes just below (`left edge − 1`) and above (`right edge`) the block have not been received (RFC 2018 3).
- The first block must describe the contiguous range containing the segment that triggered this ACK, unless the segment advanced the ACK number. When filling remaining slots, the receiver should select the most recently reported blocks that are not subsets of blocks already included. The blocks after the first may appear in any wire order (RFC 2018 §4). The sender must therefore avoid assuming that blocks are sorted.
- SACK is advisory. The receiver may later discard data reported by SACK (reneging, RFC 2018 3 and 8). Even after discarding data, the first block must report the newest segment, and other blocks must not report data no longer held (RFC 2018 8).
- The ACK number retains its meaning in the presence of SACK (RFC 2018 3).

### 12.2 Terminology (RFC 6675 2)

| Name | Meaning | Swiftail equivalent |
| --- | --- | --- |
| HighACK | Sequence number of the highest cumulatively acknowledged byte | `SND.UNA − 1` |
| HighData | Highest sequence number sent so far | `SND.NXT − 1` |
| HighRxt | Highest sequence number retransmitted in this recovery | New variable |
| RescueRxt | Highest sequence number retransmitted optimistically to keep the ACK clock from stopping | New variable (only if used) |
| Pipe | Estimated number of bytes in the network | New computation |
| DupAcks | Number of duplicate ACKs since the last cumulative ACK | Differs from the current `duplicateACKCount` (below) |
| DupThresh | Number of duplicate ACKs that triggers retransmission. 3 per RFC 5681 | `duplicateACKThreshold` |
| RecoveryPoint | HighData at the start of recovery (§5 (4.1)) | Current `recover` (then-current `SND.NXT`) minus 1 |

- **The duplicate ACK definition changes.** A duplicate ACK in RFC 6675 is a segment with a SACK block covering bytes between HighACK and HighData that have been neither acknowledged nor SACKed. Count it even if it carries data, changes the window, or advances the cumulative ACK number. The RFC explicitly distinguishes this from the RFC 5681 §2 definition (RFC 6675 2).
- A range `[A,B]` "covers" S if `A <= S <= B` (RFC 6675 2). The RFC numbers bytes (octets), and HighACK, HighData, and HighRxt are inclusive ends (the number itself). Converting to Swiftail's half-open `[start, end)` ranges can introduce off-by-one errors.

### 12.3 Scoreboard and Four Functions (RFC 6675 3 and 4)

The scoreboard data structure is outside the RFC's scope. It must support marking arbitrary sequence ranges as SACKed and may be range-based. The algorithm assumes a sender that does not retain segment boundaries after sending (RFC 6675 3).

1. **Update()**. Mark the bytes cumulatively acknowledged or SACKed by the ACK, and record the number of SACKed bytes. SACKed data **must remain** in the retransmission buffer until cumulatively acknowledged (MUST NOT, RFC 6675 4 cites RFC 2018).
2. **IsLost(SeqNum)**. True if **DupThresh discontiguous SACK ranges** arrived above SeqNum, or if the number of **SACKed bytes** with sequence numbers above SeqNum **exceeds `(DupThresh − 1) * SMSS`** (RFC 6675 4). The byte threshold is lower than RFC 3517's `DupThresh * SMSS`, and the RFC says the requirement that three segments beyond that sequence number were SACKed still holds (RFC 6675 9). The source text gives no further instruction on counting discontiguous SACK ranges by segment or range.
3. **SetPipe()**. For each unsacked byte S1 from HighACK through HighData, add ① 1 if `IsLost(S1)` is false and ② 1 if `S1 <= HighRxt`. Bytes retransmitted without being considered lost count twice (RFC 6675 4). This result is mandatory (MUST).
4. **NextSeg()**. Select the next range to send in this order (RFC 6675 4).
   1. If there is a **lowest unsacked sequence number S2** meeting all three conditions, choose one segment of up to SMSS bytes starting at S2 (MUST). (1.a) `S2 > HighRxt`, (1.b) S2 is below the highest byte covered by any received SACK, and (1.c) `IsLost(S2)`.
   2. Otherwise, if unsent data exists and the peer's window permits, choose up to SMSS bytes of new data starting at `HighData + 1` (MUST).
   3. If neither applies, and an unsacked sequence number S3 meets (1.a) and (1.b) alone, choose up to SMSS bytes starting at S3 (SHOULD, upgraded from MAY in RFC 3517, RFC 6675 9).
   4. If none applies and unacknowledged, unsacked data exists, perform **rescue retransmission** once per recovery. If HighACK exceeds RescueRxt or RescueRxt is unset, choose one segment of at most SMSS **including** the highest unacknowledged, unsacked number (SHOULD), and set RescueRxt to RecoveryPoint. HighRxt must stay unchanged (MUST NOT).
   5. If none applies, report failure (MUST).
   - The RFC says rules 3 and 4 are last resorts when evidence is weaker. Two copies of the same data can then be in the network, which may cause pipe to be underestimated (RFC 6675 4).

### 12.4 Algorithm (RFC 6675 5)

- On every ACK with SACK, call Update() (MUST). For a cumulative ACK, reset DupAcks to 0 (MUST).
- Outside recovery, if an incoming ACK is a duplicate under §12.2, increment DupAcks (MUST), regardless of whether it is a cumulative ACK.
  1. If `DupAcks >= DupThresh`, go to (4). This covers cases where several segments smaller than SMSS were SACKed and IsLost could not become true.
  2. If `DupAcks < DupThresh` but `IsLost(HighACK + 1)`, go to (4).
  3. Otherwise, limited transmit (RFC 5681) may send new data (MAY). Set the amount using pipe and cwnd: (3.1) HighRxt = HighACK, (3.2) SetPipe(), (3.3) if `cwnd − pipe >= 1 SMSS`, new data exists, and the window permits, send up to SMSS bytes starting at `HighData + 1`, update HighData, and return to (3.2), (3.4) finish handling this ACK.
  4. Enter recovery with fast retransmit: (4.1) `RecoveryPoint = HighData`, (4.2) `ssthresh = cwnd = FlightSize / 2` (RFC 5681. Exclude data sent by limited transmit from this FlightSize), (4.3) retransmit the segment starting at `HighACK + 1` and **set both HighRxt and RescueRxt to the highest number in that segment** (prevents repeated retransmissions of the same data and premature rescue), (4.4) SetPipe(), (4.5) go to (C).
- For each ACK during recovery (MUST):
  - (A) If a cumulative ACK has a sequence number above RecoveryPoint, end recovery (MUST). Retain scoreboard information above the new HighACK (SHOULD NOT clear).
  - (B) For an ACK that does not cover RecoveryPoint, (B.1) Update(), (B.2) SetPipe().
  - (C) If `cwnd − pipe >= 1 SMSS`, send (SHOULD). (C.1) Send the NextSeg() range, or stop on failure. (C.2) If any byte sent is below HighData, set HighRxt to the highest number in that segment (exclude data sent by rule 4, MUST). (C.3) If any byte sent is above HighData, update HighData. (C.4) Add the bytes sent to pipe. (C.5) If `cwnd − pipe >= 1 SMSS`, return to (C.1).
  - The RFC says that a large cumulative ACK or many losses near the end of the window can cause (A) and (C) to send a series of segments.
- RFC 6675 gives no rule for growing cwnd during recovery or updating it on exit. Compare pipe with the cwnd from (4.2). Decisions based on SACK are largely separate from congestion control (RFC 6675 1).

### 12.5 Retransmission Timeout and SACK Information (RFC 6675 5.1 and 6, RFC 2018 5, 5.1, and 8)

1. Because the receiver can discard SACKed data, clear collected SACK information on RTO (SHOULD, RFC 2018 5 "turn off all of the SACKed bits", cited by RFC 6675 5.1).
2. Ignore earlier SACK information when deciding what to retransmit after an RTO. RFC 2018 5.1 originally says MUST, but **verified erratum 1610 changes it to SHOULD** (rationale: Linux benefits from retaining SACK information across RTO. It also cautions that reneging and inconsistent scoreboards must be checked robustly). RFC 6675 5.1 also describes the proposal to retain SACK information after RTO with robust reneging detection and says it leaves RFC 2018's rules unchanged.
3. After RTO, retransmit the segment at the left window edge regardless of SACK marking (MUST, RFC 2018 5). Retain a segment in the buffer until the left window edge passes it (MUST NOT in RFC 2018 5 and 8).
4. Use all SACK information received after RTO (SHOULD). NextSeg() is unsuitable for post-RTO recovery. A simple approach that fills reported gaps is sufficient (RFC 6675 5.1 leaves the exact algorithm unspecified).
5. If RTO occurs during recovery, set `RecoveryPoint = HighData`, retain that value, and end recovery (MUST). Do not start a new recovery **until `HighACK >= RecoveryPoint`** (MUST NOT, RFC 6675 5.1).
6. Timer (RFC 6675 6). Either restart whenever the cumulative ACK advances per RFC 6298 (default), or use the more conservative variant that restarts on each retransmission during recovery (MAY). SACK recovery can sustain the ACK clock, allowing a loss event to outlast the RTO and causing the timer to expire early.
7. Congestion control. A single ACK reporting out-of-order delivery does not start recovery. RTO remains the last resort for loss detection even with SACK (RFC 2018 5.1).

### 12.6 Receiving D-SACK (RFC 2883)

- D-SACK has no separate negotiation. A peer with SACK negotiated may send D-SACK. A sender that does not understand it may discard the D-SACK block and process the rest as usual (RFC 2883 2).
- The format is the same. The D-SACK block is **the first block** and reports the contiguous duplicate range carried by the most recent packet. If it is part of a larger block above the cumulative ACK, the second block is that larger block. Report the same duplicate only once (RFC 2883 4 (1)~(5)).
- Recognition. Compare the first block with **the cumulative ACK in the same packet**. Below it means D-SACK. Above it, compare with the second block to decide. Do not compare with `snd.una` (MUST NOT, gives the wrong result if ACKs arrive out of order, RFC 2883 5). The same section notes that the receiver cannot be trusted to send accurate information.
- The RFC leaves the sender's action after detection unspecified (RFC 2883 5). A sender that ignores D-SACK is therefore compliant.

### 12.7 Changes Relative to §§1~11

| Section | Current | With SACK recovery |
| --- | --- | --- |
| 4.7 7 | Duplicate ACK uses RFC 5681 2 definition (no data, same window, etc.) | For a connection with SACK negotiated, RFC 6675 2 definition (new SACK information) governs recovery decisions. Count ACKs carrying data or changing the window |
| 4.7 5 and 6 | Fast retransmit on the third duplicate ACK, `cwnd = ssthresh + 3*SMSS`, inflation on every duplicate ACK, one segment per partial ACK | `IsLost(HighACK + 1)` provides another way to enter recovery. `cwnd = ssthresh = FlightSize/2` with no inflation. Allowance is `cwnd − pipe`, and one ACK can cause retransmission of multiple holes |
| 4.7 6 | NewReno `recover`: enter only if `SEG.ACK − 1 > recover` | After RTO, the constraint is `HighACK >= RecoveryPoint` (5.1). This is one byte looser than NewReno's formula. Under NewReno, loss of the segment immediately after recover (first new data sent during recovery) prevents entry and waits for RTO |
| 4.5 6 | Retransmit the oldest unacknowledged segment on expiration | Same (RFC 2018 5 MUST). Also clear SACK information (SHOULD) and use SACK received after RTO (SHOULD) |
| 4.8 SACK row | "Slower recovery from multiple losses in one window" | Still correct. See [§6 of the M6-10b draft](../contracts/SwiftailNetstack.md#6-size-and-assessment) for an estimate of the difference |
| §11 item 5 | The review did not check the text of RFC 6675 | Read in this section. RFC 8985 is still unread |

### 12.8 Comparison with gVisor

In the Tailscale configuration, gVisor uses this recovery when RACK is off and SACK was negotiated (§5, `gvisor/transport/tcp/snd.go:356-361`). The findings below are from static reading and are unverified by execution.

**Matches the RFC**

- Insert an incoming block only if it is above the cumulative ACK, above SND.UNA, at most SND.NXT, and not already fully SACKed. These conditions exclude D-SACK blocks (`snd.go:1572`).
- On entry to recovery, set HighRxt and RescueRxt to the last sequence number of the first retransmission and call SetPipe (`snd.go:513-537`, RFC 6675 (4.3) and (4.4)). After rescue retransmission, set RescueRxt to `FastRecovery.Last` (RecoveryPoint). Other retransmissions update HighRxt (`sack_recovery.go:88-101`).
- Clear the entire scoreboard on RTO (`snd.go:645-658`. The comment states that it strictly follows the SHOULD in RFC 2018 5). Accumulate SACK received after RTO anew and skip SACKed segments when sending (`snd.go:1118-1123`, the gap-filling approach in RFC 6675 5.1). On RTO set `Last = SND.NXT − 1` (RecoveryPoint = HighData) and end recovery (`snd.go:621-628`).
- Exit recovery when `Last < SEG.ACK` (`snd.go:1603`, RFC 6675 (A)). Clear only the cumulatively acknowledged lower portion, retaining the remainder (`snd.go:1722`).

**Differs from the RFC**

1. **Counts duplicate ACKs more narrowly than RFC 6675.** When SACK is negotiated, new SACK information is required, and all RFC 5681 conditions also apply (no data, no SYN or FIN, `SEG.ACK = SND.UNA`, same window) (`snd.go:1321-1342`, especially `:1326`, `:1333`, `:1341`). RFC 6675 2 says to count ACKs even with data, window changes, or cumulative ACK advancement. Consequently, when gVisor is the **sender**, an ACK with data cannot trigger recovery (source basis for the bidirectional weakness in contract behavior F5 and "Results after the three improvement units").
2. **IsLost uses a `>=` byte threshold**. True for at least `(DupThresh − 1) * SMSS` (`sack_scoreboard.go:265`). The RFC says greater than. SACKing only two full segments is enough to infer loss. The range count is the number of merged blocks in the scoreboard (same location).
3. **On recovery entry, sets cwnd to `ssthresh + 3` (segments)** (`snd.go:1150`). RFC 6675 (4.2) uses `cwnd = ssthresh`. On exit it sets `cwnd = ssthresh` (`snd.go:1186`). Congestion control determines ssthresh (Tailscale uses CUBIC). With Reno, it is half the outstanding segment count, at least 2 (`gvisor/transport/tcp/reno.go:73-78`).
4. **Counts cwnd and pipe in segments**. SetPipe adds 1 for each SMSS-sized unit (`snd.go:1198-1252`). The RFC counts bytes. Sending during recovery compares `Outstanding < SndCwnd` (`sack_recovery.go:46`).
5. **Rule (3) with DupAcks < DupThresh**. Sets HighRxt to `SND.UNA − 1` and calls SetPipe (`snd.go:1290-1296`). SetPipe returns immediately outside recovery (`snd.go:1207-1209`), so sending uses ordinary cwnd rules in place of the RFC's pipe-based limited transmit.
6. The branch intended to use **the conservative timer from RFC 6675 §6** runs only when `err != nil` (send failure) (`snd.go:1827-1838`, condition at `:1831`). Normal successful retransmissions skip this branch. The source appears to differ from the intent (unverified by execution).
7. **Uses NewReno's condition for starting a new recovery**. After RTO or a completed recovery, enter only if `Last < SEG.ACK − 1` (`snd.go:1308`, RFC 6582 3.2 2). This is one byte stricter than the post-RTO condition `HighACK >= RecoveryPoint` (`SEG.ACK − 1 >= Last`) in RFC 6675 5.1. Loss of the segment starting at `Last + 1` prevents entry.
8. NextSeg rule 2 returns the next unsent segment without checking the window. The send function trims to the window (`snd.go:819-827`, `sack_recovery.go:67`).

**gVisor choices where the RFC leaves behavior unspecified**

| Item | gVisor | Reference |
| --- | --- | --- |
| Scoreboard structure | B-tree ordered by starting sequence number, merging overlapping or adjacent blocks | `sack_scoreboard.go:43-146` |
| Scoreboard size limit | 100 ranges. At the limit, **skip inserting any new block**, even a block that would reduce the count by merging | `sack_scoreboard.go:30`, `:76-79` |
| SMSS | Connection's `MaxPayloadSize` (MSS minus option length) | `snd.go:309-312` |
| Retransmission unit | Sent segment boundaries. Split segments larger than SMSS (GSO) into SMSS-sized units | `snd.go:752-754`, `sack_recovery.go:38-43` |
| Out-of-range ACK during recovery | Ignore unless `SND.UNA <= SEG.ACK <= SND.NXT` | `sack_recovery.go:115-117` |
| Size of new data during recovery | At most SMSS | `sack_recovery.go:38-43`, `:65-69` |
| D-SACK | Detect only with RACK enabled and use for statistics and RACK. SACK recovery does not use it | `snd.go:1402-1443`, `:1591-1593` |
| Reneging check | None. Only clearing on RTO | `snd.go:645-658` |
| Blocks sent by receiver | Cover data only (exclude FIN sequence number). Also included on data segments. Receiver list holds 6, one option holds up to 4 | `rcv.go:459`, `:510`, `connect.go:1022-1025`, `:1052-1055`, `sack.go:25`, `gvisor/header/tcp.go:45` |

### 12.9 Untrusted Input

Only the authenticated peer for a connection can send SACK blocks within the tailnet (contract behavior X). The cases below cover incorrect blocks from that peer.

| Input | Possible effects | RFC | gVisor |
| --- | --- | --- | --- |
| Block below SND.UNA | D-SACK or a late ACK. Accepting it marks already discarded data as SACKed | D-SACK may be ignored (RFC 2883 2 and 5) | Skips insertion (`snd.go:1572`) |
| Block above SND.NXT | Claims to SACK unsent data. Accepting it raises HighSACK and distorts loss detection. Skipping those bytes when they are due to be sent can leave them unsent forever | Unspecified | Skips insertion (`snd.go:1572`) |
| Left edge ≥ right edge | A reversed block has a size close to 2³² in 32-bit modular arithmetic | Unspecified | **Unchecked.** Option parsing checks only length (`gvisor/header/tcp.go:540-560`), and the insertion condition (`snd.go:1572`) omits `Start < End`. A reversed block with `Start > SND.UNA` and `End <= SND.NXT` can be inserted, making the SACKed byte count (`sack_scoreboard.go:144`) wrap to a large value (calculated from source, unverified by execution) |
| Overlapping blocks or repeated identical blocks | Harmless if merged. Memory grows in a structure that keeps them separate | Range marking suffices (RFC 6675 3) | Merges them and skips fully covered blocks |
| Inducing thousands of blocks | Each ACK holds up to 4, but different blocks in each ACK can increase the range count. Without a cap, the scoreboard can grow to the number of sent segments (half that with alternating ranges), and SetPipe and NextSeg slow down in proportion to the count | Unspecified | 100-range cap (`sack_scoreboard.go:30`) |
| Reneging (including simulation) | Discard SACKed data or falsely SACK it from the start. Cumulative ACK stalls until RTO unless the sender retransmits that data. Data is lost if the implementation discarded it from its buffer early | Retain until cumulative ACK (MUST NOT, RFC 2018 8, RFC 6675 4). Clear SACK information on RTO (SHOULD). Erratum 1610 requires robust reneging checks | Retains buffered data and clears SACK information on RTO. No separate check |
| Reducing pipe with false SACK | More ranges considered lost reduce pipe, allowing `cwnd − pipe` more data. (4.2) already halved cwnd, and the peer window and send buffer cap in-flight traffic | RFC 6675 8: SACK is more robust against attacks using forged duplicate ACKs to reduce cwnd. The SACK condition blocks attacks inducing duplicate ACKs with forged out-of-window segments (CPNI309) | Same |

### 12.10 Constants

| Value | Origin |
| --- | --- |
| DupThresh 3 | RFC 6675 2(RFC 5681), gVisor `snd.go:45` |
| IsLost byte threshold: greater than `(DupThresh − 1) * SMSS` | RFC 6675 4 and 9. gVisor uses greater than or equal (`sack_scoreboard.go:265`) |
| Blocks in one SACK option: 4, or 3 with timestamps | RFC 2018 3. gVisor `gvisor/header/tcp.go:45` |
| Rescue retransmission: once per recovery, at most 1 SMSS | RFC 6675 4 and 9 |
| gVisor scoreboard cap 100 ranges, receiver block list 6 | `sack_scoreboard.go:30`, `sack.go:25` |

### 12.11 Unverified Items

1. Whether IsLost's "DupThresh discontiguous SACKed sequences" in RFC 6675 means a count of segments or SACK ranges. The source text does not elaborate. gVisor counts merged ranges.
2. The texts of RFC 8985 (RACK and TLP), RFC 6937 (PRR), RFC 5682 (F-RTO), and RFC 3042 (limited transmit). For limited transmit as cited by RFC 6675, only the description in RFC 6675 5 (3) was read.
3. How to implement the "robust reneging detection" mentioned by erratum 1610. The RFC leaves it unspecified. Linux's implementation was unread.
4. Whether XNU (iPhone and macOS kernel) sends SACK-Permitted, SACK blocks, or D-SACK, and whether it reneges. Source and real-device captures were unexamined (same gap as §11 item 2).
5. gVisor runtime behavior. §12.8 difference 6 (timer branch) and the reversed block in §12.9 are conclusions from source. No packet tests were run.
6. Whether gVisor as a receiver with no data to send sends one ACK per segment for a batch of out-of-order segments. The review read as far as `rcv.go:482-515` calling immediate ACK, without tracing whether batching combines the ACKs.
