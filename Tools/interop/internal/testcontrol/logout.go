// 원본에 없는 보탬: 이 파일 전체가 tailscale.com v1.104.6 testcontrol에 없다.
// 로그아웃 관문(docs/contracts/SwiftailHost.md "로그아웃")이 쓰는, 과거의 Expiry를 실은 등록 요청의 처리를 더한다.
// 근거: tailscale.com v1.104.6 tailcfg/tailcfg.go RegisterRequest.Expiry의 주석("if Expiry is in the past and NodeKey is
// the node's current key, the key is expired"), control/controlclient/direct.go doLogin(loginOpt.Logout).
// 운영 제어 서버의 실제 동작은 소스에 없다. "추측"이라고 적은 곳은 짐작해 쓴 것이다.

package testcontrol

import (
	"time"

	"tailscale.com/tailcfg"
)

// applyRegisterExpiryLocked는 과거의 Expiry를 실은 등록 요청을 로그아웃으로 받아 그 노드의 KeyExpiry를 요청의 값으로
// 두고 모든 노드에 새 맵을 보낸다. 원본은 Expiry를 읽지 않는다. 미래의 Expiry(SetExpirySooner)는 다루지 않는다.
// 노드는 serveRegister가 이미 nk로 s.nodes에 두었다(모르는 키면 원본 코드가 방금 만든 노드다).
// 응답의 NodeKeyExpired는 이 뒤의 원본 검사가 KeyExpiry로 정한다(참). 추측: 운영 서버가 로그아웃에 무엇을 답하는지는
// 소스에 없다. Go 클라이언트(TryLogout)는 Error 밖의 응답을 모두 성공으로 본다. s.mu를 쥔 채 부른다.
func (s *Server) applyRegisterExpiryLocked(req *tailcfg.RegisterRequest) {
	if req.Expiry.IsZero() || !req.Expiry.Before(time.Now()) {
		return
	}
	node := s.nodes[req.NodeKey]
	if node == nil {
		return
	}
	node.KeyExpiry = req.Expiry
	s.updateLocked("Logout", s.nodeIDsLocked(0))
}
