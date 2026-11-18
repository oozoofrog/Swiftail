// Added here: this entire file is absent from tailscale.com v1.104.6 testcontrol.
// Adds handling for registration requests with an Expiry in the past, as used by the logout gate (docs/contracts/SwiftailHost.md, "Logout").
// Basis: the tailscale.com v1.104.6 tailcfg/tailcfg.go comment on RegisterRequest.Expiry ("if Expiry is in the past and NodeKey is
// the node's current key, the key is expired"), control/controlclient/direct.go doLogin(loginOpt.Logout).
// The actual production control server behavior is absent from the source. Places marked "Assumption" are based on guesses.

package testcontrol

import (
	"time"

	"tailscale.com/tailcfg"
)

// applyRegisterExpiryLocked treats a registration request with an Expiry in the past as logout, sets the node's KeyExpiry to the requested value,
// and sends a new map to every node. Upstream does not read Expiry. Future Expiry (SetExpirySooner) is out of scope.
// serveRegister has already stored the node in s.nodes under nk (for an unknown key, upstream just created it).
// The subsequent upstream check derives NodeKeyExpired in the response from KeyExpiry (true). Assumption: the source does not show what the production server
// returns for logout. The Go client (TryLogout) treats every response other than Error as success. Call with s.mu held.
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
