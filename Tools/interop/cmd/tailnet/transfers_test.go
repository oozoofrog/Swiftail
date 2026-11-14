package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestStream(t *testing.T) {
	const want = "7c00fd43ac6f576c1b1b4a86b38668820eaa972099e1faa5c5579311cd550362"
	s := newStream(1)
	var b [32]byte
	for _, p := range [][]byte{b[:1], b[1:8], b[8:13], b[13:]} {
		if _, err := io.ReadFull(s, p); err != nil {
			t.Fatal(err)
		}
	}
	if hex.EncodeToString(b[:]) != want {
		t.Fatal("씨앗 1의 바이트열이 규약과 다릅니다")
	}
	one := make([]byte, 100003)
	split := make([]byte, len(one))
	newStream(0).Read(one)
	s = newStream(0)
	for start := 0; start < len(split); start += 13 {
		s.Read(split[start:min(start+13, len(split))])
	}
	if !bytes.Equal(one, split) {
		t.Fatal("읽기 크기에 따라 흐름이 바뀝니다")
	}
}

func TestTransferValidation(t *testing.T) {
	n := &network{peers: map[string]*peer{"peer-a": {}}}
	count, seed, timeout := uint64(1), uint64(1), 15
	base := command{Cmd: "peerDial", Name: "peer-a", To: "100.64.0.2", Port: 9100, Send: &count, Seed: &seed, TimeoutSec: &timeout}
	for _, change := range []func(*command){
		func(c *command) { c.Name = "missing" },
		func(c *command) { c.Port = 0 },
		func(c *command) { c.Port = 65536 },
		func(c *command) { c.To = "invalid" },
		func(c *command) { c.To = "fe80::1%lo0" },
		func(c *command) { c.Send = nil },
		func(c *command) { value := maxTransferBytes + 1; c.Send = &value },
		func(c *command) { c.Seed = nil },
		func(c *command) { value := 0; c.TimeoutSec = &value },
		func(c *command) { value := 3601; c.TimeoutSec = &value },
	} {
		c := base
		change(&c)
		if _, err := n.execute(c); err == nil {
			t.Fatal("잘못된 전송 명령을 거절해야 합니다")
		}
	}
	for _, line := range []string{
		`{"send":-1}`, `{"send":1.5}`, `{"send":18446744073709551616}`, `{"seed":-1}`, `{"seed":"1"}`, `{"timeoutSec":1.5}`,
	} {
		var c command
		if json.Unmarshal([]byte(line), &c) == nil {
			t.Fatal("잘못된 숫자를 거절해야 합니다", line)
		}
	}
	r, err := n.execute(command{Cmd: "transfers"})
	if err != nil || len(r["transfers"].([]transferStatus)) != 0 {
		t.Fatal(r, err)
	}
}

func waitTransfers(t *testing.T, n *network, count int) []transferStatus {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		r, err := n.execute(command{Cmd: "transfers"})
		if err != nil {
			t.Fatal(err)
		}
		jobs := r["transfers"].([]transferStatus)
		done := len(jobs) == count
		for _, job := range jobs {
			if job.State == "running" || job.State == "dialing" {
				done = false
			}
		}
		if done {
			return jobs
		}
		if time.Now().After(deadline) {
			t.Fatalf("전송이 끝나지 않았습니다: %+v", jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func streamHash(count, seed uint64) string {
	h := sha256.New()
	io.CopyN(h, newStream(seed), int64(count))
	return hex.EncodeToString(h.Sum(nil))
}

func TestPeerTransfers(t *testing.T) {
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	for _, name := range []string{"peer-a", "peer-b"} {
		if _, err := n.execute(command{Cmd: "addPeer", Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	lc, err := n.peers["peer-b"].server.LocalClient()
	if err != nil {
		t.Fatal(err)
	}
	status, err := lc.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	timeout := 60
	serve := command{Cmd: "peerServe", Name: "peer-b", Port: 9100, TimeoutSec: &timeout}
	if _, err := n.execute(serve); err != nil {
		t.Fatal(err)
	}
	if _, err := n.execute(serve); err == nil {
		t.Fatal("중복 리스너를 거절해야 합니다")
	}
	total := 0
	for _, size := range []uint64{0, 104857600} {
		seed := uint64(1)
		c := command{Cmd: "peerDial", Name: "peer-a", To: status.TailscaleIPs[0].String(), Port: 9100, Send: &size, Seed: &seed, TimeoutSec: &timeout}
		started := time.Now()
		response, err := n.execute(c)
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(started) > time.Second {
			t.Fatal("peerDial이 전송을 기다렸습니다")
		}
		total += 2
		jobs := waitTransfers(t, n, total)
		want := streamHash(size, seed)
		id := response["transferID"].(uint64)
		for _, job := range jobs[total-2:] {
			if job.State != "complete" || job.Error != "" || job.Sent != size || job.Received != size || job.SentSHA256 != want || job.ReceivedSHA256 != want || job.Remote == "" {
				t.Fatalf("전송 불일치: %+v", job)
			}
			if job.Name == "peer-a" && job.ID != id {
				t.Fatal("peerDial의 transferID가 다릅니다")
			}
			t.Logf("%s: sent=%d received=%d SHA256=%s elapsedMs=%d", job.Name, job.Sent, job.Received, job.ReceivedSHA256, job.ElapsedMs)
		}
	}
	// 같은 리스너의 IPv6, 동시 연결, 씨앗 0과 UInt64 최댓값도 검증한다.
	var v6 netip.Addr
	for _, ip := range status.TailscaleIPs {
		if ip.Is6() {
			v6 = ip
		}
	}
	if !v6.IsValid() {
		t.Fatal("IPv6 주소가 없습니다")
	}
	size := uint64(1048576)
	for _, seed := range []uint64{0, ^uint64(0)} {
		if _, err := n.execute(command{Cmd: "peerDial", Name: "peer-a", To: v6.String(), Port: 9100, Send: &size, Seed: &seed, TimeoutSec: &timeout}); err != nil {
			t.Fatal(err)
		}
	}
	total += 4
	jobs := waitTransfers(t, n, total)
	hashes := map[string]int{streamHash(size, 0): 0, streamHash(size, ^uint64(0)): 0}
	for _, job := range jobs[total-4:] {
		if job.State != "complete" || job.Sent != size || job.Received != size || job.SentSHA256 != job.ReceivedSHA256 {
			t.Fatalf("IPv6 동시 전송: %+v", job)
		}
		if _, ok := hashes[job.SentSHA256]; !ok {
			t.Fatal("씨앗과 해시가 다릅니다")
		}
		hashes[job.SentSHA256]++
	}
	for _, count := range hashes {
		if count != 2 {
			t.Fatal("양쪽 전송의 해시가 다릅니다")
		}
	}
	// 거는 쪽이 먼저 FIN을 보내도 반대 방향의 긴 데이터는 끝까지 읽는다.
	conn, err := n.peers["peer-a"].server.Dial(t.Context(), "tcp", net.JoinHostPort(status.TailscaleIPs[0].String(), "9100"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var preface [16]byte
	binary.BigEndian.PutUint64(preface[:8], size)
	binary.BigEndian.PutUint64(preface[8:], 7)
	if err := writeAll(conn, preface[:]); err != nil {
		t.Fatal(err)
	}
	local := n.newTransfer("peer-a", "", "running")
	if err := local.exchange(conn, 3, 9); err != nil {
		t.Fatal(err)
	}
	local.finish(nil)
	total += 2
	jobs = waitTransfers(t, n, total)
	for _, job := range jobs[total-2:] {
		if job.State != "complete" {
			t.Fatalf("반닫힘 실패: %+v", job)
		}
		if job.Name == "peer-a" {
			if job.Sent != 3 || job.Received != size || job.SentSHA256 != streamHash(3, 9) || job.ReceivedSHA256 != streamHash(size, 7) {
				t.Fatal("반닫힘 뒤 수신 또는 머리 제외 규약이 다릅니다")
			}
		} else if job.Sent != size || job.Received != 3 || job.SentSHA256 != streamHash(size, 7) || job.ReceivedSHA256 != streamHash(3, 9) {
			t.Fatal("서버의 비대칭 전송 규약이 다릅니다")
		}
	}
	if _, err := n.execute(command{Cmd: "peerClose", Name: "peer-b", Port: 9100}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.execute(command{Cmd: "peerClose", Name: "peer-b", Port: 9100}); err == nil {
		t.Fatal("없는 리스너를 닫았습니다")
	}
	if _, err := n.execute(serve); err != nil {
		t.Fatal("포트 다시 열기", err)
	}
	// 닫힌 포트의 연결 실패도 비동기 전송 기록으로 남긴다.
	seed := uint64(1)
	if _, err := n.execute(command{Cmd: "peerDial", Name: "peer-a", To: status.TailscaleIPs[0].String(), Port: 9101, Send: &size, Seed: &seed, TimeoutSec: &timeout}); err != nil {
		t.Fatal(err)
	}
	total++
	jobs = waitTransfers(t, n, total)
	if jobs[total-1].State != "error" || jobs[total-1].Error == "" {
		t.Fatal("연결 거절을 기록하지 않았습니다")
	}
	// 진행 중인 Dial을 남겨 두고 removePeer가 취소·회수하는지도 확인한다.
	if _, err := n.execute(command{Cmd: "peerDial", Name: "peer-a", To: "100.64.0.99", Port: 9100, Send: &size, Seed: &seed, TimeoutSec: &timeout}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.execute(command{Cmd: "removePeer", Name: "peer-a"}); err != nil {
		t.Fatal(err)
	}
	total++
	jobs = waitTransfers(t, n, total)
	if jobs[total-1].State != "error" {
		t.Fatal("피어 제거가 Dial을 취소하지 않았습니다")
	}
}

func TestTransferMalformedPreface(t *testing.T) {
	n, err := newNetwork()
	if err != nil {
		t.Fatal(err)
	}
	defer n.close()
	r, err := n.execute(command{Cmd: "addPeer", Name: "peer-a"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.execute(command{Cmd: "peerServe", Name: "peer-a", Port: 9100}); err != nil {
		t.Fatal(err)
	}
	ip := r["addresses"].([]netip.Addr)[0]
	for index, head := range [][]byte{{1, 2, 3}, make([]byte, 16)} {
		if len(head) == 16 {
			binary.BigEndian.PutUint64(head, maxTransferBytes+1)
		}
		conn, err := n.peers["peer-a"].server.Dial(t.Context(), "tcp", net.JoinHostPort(ip.String(), "9100"))
		if err != nil {
			t.Fatal(err)
		}
		if err = writeAll(conn, head); err != nil {
			t.Fatal(err)
		}
		conn.(interface{ CloseWrite() error }).CloseWrite()
		conn.Close()
		jobs := waitTransfers(t, n, index+1)
		if jobs[index].State != "error" {
			t.Fatal("잘못된 전송 머리를 받아들였습니다")
		}
	}
}

func TestTransferCommandsJSON(t *testing.T) {
	input := strings.NewReader(`{"id":1,"cmd":"transfers"}
{"id":2,"cmd":"peerDial","name":"missing","send":-1}
{"id":3,"cmd":"peerServe","name":"missing","port":9100}
{"id":4,"cmd":"peerClose","name":"missing","port":9100}
{"id":5,"cmd":"quit"}
`)
	var output bytes.Buffer
	if err := run(input, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	for i, want := range []string{"ready", "transfers", "error", "error", "error", "quit"} {
		var result struct {
			Event     string           `json:"event"`
			ID        int              `json:"id"`
			Transfers []transferStatus `json:"transfers"`
		}
		if err := decoder.Decode(&result); err != nil {
			t.Fatal(err)
		}
		if result.Event != want || result.ID != i {
			t.Fatal("JSON 사건/id 불일치", result)
		}
		if want == "transfers" && result.Transfers == nil {
			t.Fatal("빈 목록은 []여야 합니다")
		}
	}
}
