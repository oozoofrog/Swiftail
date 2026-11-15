// 원본에 없는 보탬: 이 파일 전체가 tailscale.com v1.104.6 testcontrol에 없다.
// Tailnet Lock 관문 (가)(docs/contracts/SwiftailTailnetLock.md 7절, 결정 L15)이 쓰는
// sync/send, disable, 끈 뒤의 bootstrap, 등록 요청의 서명, 재서명 요청, 요청 기록을 더한다.
// 본보기: tailscale.com v1.104.6 tstest/tkatest/tkatest.go(HandleTKASyncSend 등),
// ipn/ipnlocal/tailnet-lock_test.go(TestTKADisablementFlow, TestTKADisable),
// ipn/ipnlocal/tailnet-lock.go(tkaDoDisablement, tkaApplyDisablementLocked).
// 운영 제어 서버의 실제 동작은 소스에 없다. "추측"이라고 적은 곳은 짐작해 쓴 것이다.

package testcontrol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tka"
	"tailscale.com/tstest/tkatest"
	"tailscale.com/types/key"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// lockExtras는 원본에 없는 Tailnet Lock 상태다. s.mu 아래에서 읽고 쓴다.
type lockExtras struct {
	capability bool // 모든 노드의 CapMap에 tailnet-lock을 싣는다

	// disablementSecret은 /machine/tka/disable이 받아들인 끄기 비밀이다.
	// nil이 아니고 tkaStorage가 nil이면 "lock을 껐다"는 뜻이다.
	disablementSecret []byte
	wrongSecret       bool // 끈 뒤의 bootstrap이 틀린 비밀을 준다
	omitInfo          bool // 끈 뒤의 맵 응답에 TKAInfo를 싣지 않는다(아니면 Disabled: true)
	bootstrapFault    bool // lock이 켜진 동안 bootstrap이 깨진 GenesisAUM을 준다

	resign        set.Set[key.NodePublic] // 다음 등록에 재서명을 요청할 node 키(한 번)
	registrations []LockRegistration
	requests      []LockRequest
}

// LockRegistration은 testcontrol이 받은 등록 요청 하나의 Tailnet Lock 관련 기록이다.
type LockRegistration struct {
	NodeKey    key.NodePublic
	OldNodeKey key.NodePublic
	NLKey      key.NLPublic
	// Auth는 요청에 Auth(인증 키)가 실렸는지다. 로그아웃 관문이 Go와 Swift의 요청을 견줄 때 쓴다.
	Auth bool
	// Expiry는 요청의 Expiry다(0이면 없음). 과거 시각이면 로그아웃이다(logout.go).
	Expiry time.Time
	// Signature는 요청의 NodeKeySignature에 대한 판정이다:
	// "none"(없음), "noLock"(lock이 꺼져 있어 보지 않음), "accepted", "rejected".
	Signature      string
	SignatureError string
	// ResignRequested는 이 요청의 응답에 RegisterResponse.NodeKeySignature를 실었는지다.
	ResignRequested bool
	// Body는 해독한 요청 JSON이다. 감싼 인증 키의 흔적을 찾는 데만 쓴다.
	Body []byte
}

// LockRequest는 testcontrol이 받은 /machine/tka/ 요청 하나다.
type LockRequest struct {
	Path    string
	NodeKey key.NodePublic
	Head    string
}

// SetTailnetLockCapability는 맵 응답의 자기 노드 CapMap에 tailnet-lock capability를 싣거나 뺀다.
// 원본은 DefaultNodeCapabilities로 등록 때의 Capabilities에만 실을 수 있다.
func (s *Server) SetTailnetLockCapability(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lock.capability = enabled
	s.updateLocked("SetTailnetLockCapability", s.nodeIDsLocked(0))
}

// SetLockDisablementBehavior는 lock을 끈 뒤 서버가 무엇을 알리는지 정한다.
// wrongSecret이면 bootstrap이 받은 비밀 대신 틀린 비밀을 준다.
// omitInfo면 맵 응답에 TKAInfo를 싣지 않고, 아니면 TKAInfo{Disabled: true}를 싣는다.
func (s *Server) SetLockDisablementBehavior(wrongSecret, omitInfo bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lock.wrongSecret = wrongSecret
	s.lock.omitInfo = omitInfo
	s.updateLocked("SetLockDisablementBehavior", s.nodeIDsLocked(0))
}

// SetLockBootstrapFault가 참이면 lock이 켜진 동안 bootstrap 응답의 GenesisAUM을 한 바이트 잘라 준다.
// 모든 노드에 새 맵을 보낸다(Go 클라이언트는 netmap을 받을 때만 부트스트랩을 다시 시도한다).
func (s *Server) SetLockBootstrapFault(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lock.bootstrapFault = enabled
	s.updateLocked("SetLockBootstrapFault", s.nodeIDsLocked(0))
}

// RequestResign은 nodeKey가 다음에 OldNodeKey 없이 등록할 때 그 응답에
// RegisterResponse.NodeKeySignature(지금의 KeySignature)를 실어 재서명을 요청하게 한다. 한 번만 쓴다.
// 추측: 운영 서버가 언제 이것을 보내는지는 소스에 없다.
func (s *Server) RequestResign(nodeKey key.NodePublic) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.nodes[nodeKey]
	if n == nil || len(n.KeySignature) == 0 {
		return false
	}
	mak.Set(&s.lock.resign, nodeKey, struct{}{})
	return true
}

// LockRegistrations는 받은 등록 요청의 기록을 받은 순서로 돌려준다.
func (s *Server) LockRegistrations() []LockRegistration {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]LockRegistration, len(s.lock.registrations))
	for i, r := range s.lock.registrations {
		r.Body = bytes.Clone(r.Body)
		out[i] = r
	}
	return out
}

// LockRequests는 받은 /machine/tka/ 요청을 받은 순서로 돌려준다.
func (s *Server) LockRequests() []LockRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.lock.requests)
}

// LockState는 서버의 lock 상태다: 켜졌으면 머리(base32), 껐으면 disabled.
func (s *Server) LockState() (head string, disabled bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tkaStorage == nil {
		return "", s.lock.disablementSecret != nil, nil
	}
	a, err := tka.Open(s.tkaStorage)
	if err != nil {
		return "", false, err
	}
	return a.Head().String(), false, nil
}

// recordLockRequest는 요청 본문을 읽어 기록하고, 처리기가 다시 읽도록 되돌린다.
func (s *Server) recordLockRequest(r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, msgLimit))
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return
	}
	var fields struct {
		NodeKey key.NodePublic
		Head    string
	}
	_ = json.Unmarshal(body, &fields)
	s.mu.Lock()
	s.lock.requests = append(s.lock.requests, LockRequest{Path: r.URL.Path, NodeKey: fields.NodeKey, Head: fields.Head})
	s.mu.Unlock()
}

// lockBootstrapOverrideLocked는 원본의 genesis 응답 대신 줄 bootstrap 응답을 만든다.
// s.mu를 쥔 채 부른다.
func (s *Server) lockBootstrapOverrideLocked() (tailcfg.TKABootstrapResponse, bool) {
	if s.tkaStorage == nil && s.lock.disablementSecret != nil {
		secret := bytes.Clone(s.lock.disablementSecret)
		if s.lock.wrongSecret {
			// 본보기: tailnet-lock_test.go TestTKADisablementFlow의 틀린 비밀(0x42 × 32).
			secret = bytes.Repeat([]byte{0x42}, 32)
		}
		return tailcfg.TKABootstrapResponse{DisablementSecret: secret}, true
	}
	return tailcfg.TKABootstrapResponse{}, false
}

// serveTKASyncSend는 /machine/tka/sync/send를 처리한다. 받은 AUM을 검증해 들이고(Inform) 서버의 머리를 답한다.
// 머리가 바뀌면 모든 노드에 새 맵을 보낸다.
func (s *Server) serveTKASyncSend(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tkaStorage == nil {
		http.Error(w, "tailnet lock is not enabled", 400)
		return
	}
	authority, err := tka.Open(s.tkaStorage)
	if err != nil {
		http.Error(w, "unable to open TKA state", 500)
		return
	}
	before := authority.Head()
	if err := tkatest.HandleTKASyncSend(w, r, authority, s.tkaStorage); err != nil {
		s.logf("HandleTKASyncSend: %v", err)
		return
	}
	if authority.Head() != before {
		s.updateLocked("TKASyncSend", s.nodeIDsLocked(0))
	}
}

// serveTKADisable는 /machine/tka/disable을 처리한다. 끄기 비밀을 서버의 상태로 검증하고,
// 맞으면 서버의 lock 상태를 지우고 비밀을 기억한다(뒤의 bootstrap이 그 비밀을 준다).
// 추측: 운영 서버가 머리 일치나 그 밖의 것을 검사하는지는 소스에 없다. 여기서는 비밀만 본다.
func (s *Server) serveTKADisable(w http.ResponseWriter, r *http.Request) {
	req := new(tailcfg.TKADisableRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "decode: "+err.Error(), 400)
		return
	}
	if req.Version != tailcfg.CurrentCapabilityVersion {
		http.Error(w, "wrong capability version", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tkaStorage == nil {
		http.Error(w, "tailnet lock is not enabled", 400)
		return
	}
	authority, err := tka.Open(s.tkaStorage)
	if err != nil {
		http.Error(w, "unable to open TKA state", 500)
		return
	}
	if !authority.ValidDisablement(req.DisablementSecret) {
		http.Error(w, "incorrect disablement secret", 400)
		return
	}
	s.tkaStorage = nil
	s.lock.disablementSecret = bytes.Clone(req.DisablementSecret)
	writeJSON(w, tailcfg.TKADisableResponse{})
	s.updateLocked("TKADisable", s.nodeIDsLocked(0))
}

// applyRegisterLockLocked는 등록 요청의 서명과 재서명 요청을 처리하고 기록을 남긴다.
// node는 nk로 이미 s.nodes에 있다. 재서명 요청이면 응답에 실을 서명을 돌려준다. s.mu를 쥔 채 부른다.
func (s *Server) applyRegisterLockLocked(req *tailcfg.RegisterRequest, body []byte) (resign []byte) {
	nk := req.NodeKey
	rec := LockRegistration{NodeKey: nk, OldNodeKey: req.OldNodeKey, NLKey: req.NLKey, Auth: req.Auth != nil, Expiry: req.Expiry, Signature: "none", Body: bytes.Clone(body)}
	node := s.nodes[nk]
	if len(req.NodeKeySignature) > 0 {
		if s.tkaStorage == nil {
			rec.Signature = "noLock"
		} else if authority, err := tka.Open(s.tkaStorage); err != nil {
			rec.Signature, rec.SignatureError = "rejected", err.Error()
		} else if err := authority.NodeKeyAuthorized(nk, req.NodeKeySignature); err != nil {
			// 추측: 검증되지 않는 서명이 든 등록을 운영 서버가 거절하는지는 소스에 없다. 등록은 그대로 하고 서명만 붙이지 않는다.
			rec.Signature, rec.SignatureError = "rejected", err.Error()
		} else {
			rec.Signature = "accepted"
			node.KeySignature = bytes.Clone(req.NodeKeySignature)
		}
	}
	if req.OldNodeKey.IsZero() && s.lock.resign.Contains(nk) && len(node.KeySignature) > 0 {
		delete(s.lock.resign, nk)
		resign = bytes.Clone(node.KeySignature)
		rec.ResignRequested = true
	}
	if !req.OldNodeKey.IsZero() && rec.Signature == "accepted" && req.Followup == "" {
		// 재서명한 키 교체가 받아들여졌으면 옛 키의 항목을 곧바로 지운다. 원본은 인증 URL을
		// 마친 뒤(Followup)에만 지우므로, 인증이 없는 교체에서는 같은 노드 ID의 항목이 둘 남는다.
		// 추측: 운영 서버는 키를 제자리에서 바꾼다고 보았다.
		if old := s.nodes[req.OldNodeKey]; old != nil && old.ID == node.ID {
			delete(s.nodes, req.OldNodeKey)
			delete(s.users, req.OldNodeKey)
			delete(s.logins, req.OldNodeKey)
		}
	}
	s.lock.registrations = append(s.lock.registrations, rec)
	if rec.Signature == "accepted" {
		s.updateLocked("RegisterSignature", s.nodeIDsLocked(0))
	}
	return resign
}

// applyLockToMapResponseLocked는 맵 응답에 capability와 끈 뒤의 TKAInfo를 싣는다. s.mu를 쥔 채 부른다.
func (s *Server) applyLockToMapResponseLocked(res *tailcfg.MapResponse) {
	if s.lock.capability {
		mak.Set(&res.Node.CapMap, nodecap.TailnetLock, []tailcfg.RawMessage{})
	}
	if s.tkaStorage == nil && s.lock.disablementSecret != nil && !s.lock.omitInfo {
		res.TKAInfo = &tailcfg.TKAInfo{Disabled: true}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.WriteHeader(200)
	_ = json.NewEncoder(w).Encode(v)
}
