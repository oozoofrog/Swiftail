package main

// Tailnet Lock 관문 (가)의 명령(docs/contracts/SwiftailTailnetLock.md 7절).
// Go 피어(tsnet)가 서명 기기 노릇을 하고, testcontrol 사본(internal/testcontrol/tka.go)이
// 서버 쪽 보탬을 맡는다. 끄기 비밀과 감싼 인증 키는 시험 안에서 만든 값이다.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tka"
	"tailscale.com/types/key"
)

// lockTools는 이 도구가 만든 lock 비밀을 쥔다. 출력하지 않는다(감싼 인증 키는 명령의 응답으로만 나간다).
type lockTools struct {
	disablementSecret []byte
	wrappedPrivate    [][]byte // 감싼 인증 키에 든 개인 키(시드 32 ‖ 공개 32). 흔적 찾기에만 쓴다
}

func (n *network) executeLock(c command) (map[string]any, error) {
	switch c.Cmd {
	case "setLockCapability":
		if c.Enabled == nil {
			return nil, errors.New("enabled에 bool이 필요합니다")
		}
		n.control.SetTailnetLockCapability(*c.Enabled)
		return map[string]any{"event": "lockCapability", "enabled": *c.Enabled}, nil
	case "setLockBootstrapFault":
		if c.Enabled == nil {
			return nil, errors.New("enabled에 bool이 필요합니다")
		}
		n.control.SetLockBootstrapFault(*c.Enabled)
		return map[string]any{"event": "lockBootstrapFault", "enabled": *c.Enabled}, nil
	case "lockRequestResign":
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(c.NodeKey)); err != nil {
			return nil, errors.New("nodeKey가 잘못되었습니다")
		}
		if !n.control.RequestResign(k) {
			return nil, errors.New("서명이 있는 등록된 nodeKey가 필요합니다")
		}
		return map[string]any{"event": "lockRequestResign", "nodeKey": c.NodeKey}, nil
	case "lockRegistrations":
		return n.lockRegistrations(), nil
	case "lockRequests":
		requests := []any{}
		for _, r := range n.control.LockRequests() {
			nodeKey := ""
			if !r.NodeKey.IsZero() {
				nodeKey = r.NodeKey.String()
			}
			requests = append(requests, map[string]any{"path": r.Path, "nodeKey": nodeKey, "head": r.Head})
		}
		return map[string]any{"event": "lockRequests", "requests": requests}, nil
	}

	p := n.peers[c.Name]
	if p == nil {
		return nil, errors.New("피어가 없습니다")
	}
	if p.stopped {
		return nil, errors.New("멈춘 피어입니다")
	}
	lc, err := p.server.LocalClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	switch c.Cmd {
	case "lockStatus":
		st, err := lc.TailnetLockStatus(ctx)
		if err != nil {
			return nil, err
		}
		return n.lockStatus("lockStatus", c.Name, st)
	case "lockInit":
		signers := c.Signers
		if len(signers) == 0 {
			signers = []string{c.Name}
		}
		var keys []tka.Key
		for _, name := range signers {
			sp := n.peers[name]
			if sp == nil || sp.stopped {
				return nil, errors.New("signers에 실행 중인 피어가 아닌 이름이 있습니다")
			}
			slc, err := sp.server.LocalClient()
			if err != nil {
				return nil, err
			}
			st, err := slc.TailnetLockStatus(ctx)
			if err != nil {
				return nil, err
			}
			keys = append(keys, tka.Key{Kind: tka.Key25519, Public: st.PublicKey.Verifier(), Votes: 1})
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		if _, err := lc.TailnetLockInit(ctx, keys, [][]byte{tka.DisablementKDF(secret)}, nil); err != nil {
			return nil, err
		}
		n.mu.Lock()
		n.lock.disablementSecret = secret
		n.mu.Unlock()
		// 서명 기기들이 lock을 켜고 서버의 머리에 닿을 때까지 기다린다. 그 전에는 lockSign이 실패한다.
		for _, name := range signers {
			if err := n.awaitLockHead(ctx, name); err != nil {
				return nil, err
			}
		}
		st, err := lc.TailnetLockStatus(ctx)
		if err != nil {
			return nil, err
		}
		return n.lockStatus("lockInit", c.Name, st)
	case "lockSign":
		var k key.NodePublic
		if err := k.UnmarshalText([]byte(c.NodeKey)); err != nil {
			return nil, errors.New("nodeKey가 잘못되었습니다")
		}
		var rotation []byte
		if c.LockKey != "" {
			var nl key.NLPublic
			if err := nl.UnmarshalText([]byte(c.LockKey)); err != nil {
				return nil, errors.New("lockKey가 잘못되었습니다")
			}
			rotation = nl.Verifier()
		}
		if err := lc.TailnetLockSign(ctx, k, rotation); err != nil {
			return nil, err
		}
		return map[string]any{"event": "lockSign", "name": c.Name, "nodeKey": c.NodeKey}, nil
	case "lockWrapAuthKey":
		authKey := n.authKey
		if c.AuthKey != nil {
			authKey = *c.AuthKey
		}
		// 본보기: tailscale.com v1.104.6 cmd/tailscale/cli/tailnet-lock.go wrapAuthKey.
		// credential만을 위한 새 lock 키를 만들고, 그 키로 감싼 뒤 신뢰 키로 더한다(사슬이 한 칸 자란다).
		priv := key.NewNLPrivate()
		wrapped, err := lc.TailnetLockWrapPreauthKey(ctx, authKey, priv)
		if err != nil {
			return nil, err
		}
		k := tka.Key{Kind: tka.Key25519, Public: priv.Public().Verifier(), Votes: 1, Meta: map[string]string{"purpose": "pre-auth key"}}
		if err := lc.TailnetLockModify(ctx, []tka.Key{k}, nil); err != nil {
			return nil, err
		}
		if err := n.awaitLockHead(ctx, c.Name); err != nil {
			return nil, err
		}
		_, suffix, _ := strings.Cut(wrapped, "--TL")
		_, private, _ := strings.Cut(suffix, "-")
		raw, err := base64.RawStdEncoding.DecodeString(private)
		if err != nil || len(raw) != 64 {
			return nil, errors.New("감싼 인증 키의 형식이 예상과 다릅니다")
		}
		n.mu.Lock()
		n.lock.wrappedPrivate = append(n.lock.wrappedPrivate, raw)
		n.mu.Unlock()
		return map[string]any{"event": "lockWrapAuthKey", "name": c.Name, "authKey": wrapped}, nil
	case "lockModify":
		add, err := lockKeys(c.AddKeys)
		if err != nil {
			return nil, err
		}
		remove, err := lockKeys(c.RemoveKeys)
		if err != nil {
			return nil, err
		}
		if len(add) == 0 && len(remove) == 0 {
			return nil, errors.New("addKeys나 removeKeys가 필요합니다")
		}
		if err := lc.TailnetLockModify(ctx, add, remove); err != nil {
			return nil, err
		}
		if err := n.awaitLockHead(ctx, c.Name); err != nil {
			return nil, err
		}
		st, err := lc.TailnetLockStatus(ctx)
		if err != nil {
			return nil, err
		}
		return n.lockStatus("lockModify", c.Name, st)
	case "lockDisable":
		n.mu.Lock()
		secret := n.lock.disablementSecret
		n.mu.Unlock()
		if secret == nil {
			return nil, errors.New("이 도구의 lockInit으로 켠 lock이 아닙니다")
		}
		_, alreadyDisabled, err := n.control.LockState()
		if err != nil {
			return nil, err
		}
		// 서버가 줄 비밀을 먼저 정한다. 서버가 이미 꺼졌으면(앞의 wrongSecret) 피어의 RPC 없이 그것만 바꾼다.
		n.control.SetLockDisablementBehavior(c.WrongSecret, c.OmitTKAInfo)
		if !alreadyDisabled {
			if err := lc.TailnetLockDisable(ctx, secret); err != nil {
				return nil, err
			}
		}
		return map[string]any{"event": "lockDisable", "name": c.Name, "wrongSecret": c.WrongSecret, "omitTKAInfo": c.OmitTKAInfo, "alreadyDisabled": alreadyDisabled}, nil
	}
	return nil, errors.New("알 수 없는 명령입니다")
}

// lockKeys는 `tlpub:`·`nlpub:` 텍스트를 투표 1의 신뢰 키로 바꾼다.
func lockKeys(texts []string) ([]tka.Key, error) {
	var keys []tka.Key
	for _, t := range texts {
		var nl key.NLPublic
		if err := nl.UnmarshalText([]byte(t)); err != nil {
			return nil, errors.New("lock 키가 잘못되었습니다")
		}
		keys = append(keys, tka.Key{Kind: tka.Key25519, Public: nl.Verifier(), Votes: 1})
	}
	return keys, nil
}

// awaitLockHead는 피어가 lock을 켜고 머리가 서버의 머리와 같아질 때까지 기다린다.
// 사슬을 자라게 한 피어가 낡은 머리 위에 다음 AUM을 쌓아 갈래를 만들지 않게 한다.
func (n *network) awaitLockHead(ctx context.Context, name string) error {
	lc, err := n.peers[name].server.LocalClient()
	if err != nil {
		return err
	}
	for {
		want, _, err := n.control.LockState()
		if err != nil {
			return err
		}
		st, err := lc.TailnetLockStatus(ctx)
		if err == nil && st.Enabled && st.Head != nil && tka.AUMHash(*st.Head).String() == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("피어의 lock 머리가 서버의 머리에 닿지 않았습니다")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (n *network) lockStatus(event, name string, st *ipnstate.TailnetLockStatus) (map[string]any, error) {
	controlHead, disabled, err := n.control.LockState()
	if err != nil {
		return nil, err
	}
	head := ""
	if st.Head != nil {
		head = tka.AUMHash(*st.Head).String()
	}
	nodeKey := ""
	if st.NodeKey != nil {
		nodeKey = st.NodeKey.String()
	}
	lockKey := ""
	if !st.PublicKey.IsZero() {
		lockKey = st.PublicKey.CLIString()
	}
	trusted := []string{}
	for _, k := range st.TrustedKeys {
		trusted = append(trusted, k.Key.CLIString())
	}
	peerKeys := func(peers []*ipnstate.TKAPeer) []string {
		out := []string{}
		for _, p := range peers {
			out = append(out, p.NodeKey.String())
		}
		return out
	}
	return map[string]any{
		"event": event, "name": name, "enabled": st.Enabled, "head": head, "nodeKey": nodeKey, "lockKey": lockKey,
		"nodeKeySigned": st.NodeKeySigned, "trustedKeys": trusted,
		"visiblePeers": peerKeys(st.VisiblePeers), "filteredPeers": peerKeys(st.FilteredPeers),
		"controlHead": controlHead, "controlDisabled": disabled,
	}, nil
}

func (n *network) lockRegistrations() map[string]any {
	n.mu.Lock()
	wrapped := append([][]byte{}, n.lock.wrappedPrivate...)
	n.mu.Unlock()
	out := []any{}
	for _, r := range n.control.LockRegistrations() {
		nlKey := ""
		if !r.NLKey.IsZero() {
			nlKey = r.NLKey.CLIString()
		}
		oldNodeKey := ""
		if !r.OldNodeKey.IsZero() {
			oldNodeKey = r.OldNodeKey.String()
		}
		out = append(out, map[string]any{
			"nodeKey": r.NodeKey.String(), "oldNodeKey": oldNodeKey, "nlKey": nlKey,
			"signature": r.Signature, "signatureError": r.SignatureError, "resignRequested": r.ResignRequested,
			"auth": r.Auth, "expiry": expiryText(r.Body), "expiryUnix": expiryUnix(r.Expiry),
			"wrappedKeyTrace": wrappedKeyTrace(r.Body, wrapped),
		})
	}
	return map[string]any{"event": "lockRegistrations", "registrations": out}
}

// expiryText는 등록 요청 JSON의 Expiry 문자열을 선 위의 표기 그대로 돌려준다. 없거나 읽지 못하면 "".
func expiryText(body []byte) string {
	var fields struct{ Expiry string }
	if err := json.Unmarshal(body, &fields); err != nil {
		return ""
	}
	return fields.Expiry
}

// expiryUnix는 Expiry의 Unix 초다. 0 시각이면 0.
func expiryUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// wrappedKeyTrace는 등록 요청 JSON의 문자열 값 가운데 감싼 인증 키의 흔적("--TL", 또는 이 도구가 만든
// 감싼 개인 키나 그 시드의 base64·16진)이 있는지 본다. JSON 이스케이프(`\/`)에 흔들리지 않게 해독한
// 문자열에서 찾는다. credential은 서명의 Nested로 늘 실리는 공개 값이라 보지 않는다.
func wrappedKeyTrace(body []byte, wrapped [][]byte) bool {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return true // 읽지 못하면 흔적이 없다고 말할 수 없다
	}
	needles := []string{"--TL"}
	for _, private := range wrapped {
		for _, b := range [][]byte{private, private[:32]} {
			needles = append(needles, base64.RawStdEncoding.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), hex.EncodeToString(b))
		}
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case string:
			for _, s := range needles {
				if strings.Contains(x, s) {
					return true
				}
			}
		case []any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		case map[string]any:
			for _, e := range x {
				if walk(e) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}
