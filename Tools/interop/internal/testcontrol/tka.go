// Added here: this entire file is absent from tailscale.com v1.104.6 testcontrol.
// Adds support for Tailnet Lock gate (a) (docs/contracts/SwiftailTailnetLock.md §7, decision L15):
// sync/send, disable, bootstrap after disablement, signatures on registration requests, re-signing requests, and request logging.
// References: tailscale.com v1.104.6 tstest/tkatest/tkatest.go (HandleTKASyncSend and others),
// ipn/ipnlocal/tailnet-lock_test.go(TestTKADisablementFlow, TestTKADisable),
// ipn/ipnlocal/tailnet-lock.go(tkaDoDisablement, tkaApplyDisablementLocked).
// The actual production control server behavior is absent from the source. Places marked "Assumption" are based on guesses.

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

// lockExtras is Tailnet Lock state absent from upstream. Read and write it under s.mu.
type lockExtras struct {
	capability bool // Include tailnet-lock in the CapMap of every node

	// disablementSecret is the disablement secret accepted by /machine/tka/disable.
	// A non-nil secret with nil tkaStorage means lock was disabled.
	disablementSecret []byte
	wrongSecret       bool // Bootstrap after disablement returns the wrong secret
	omitInfo          bool // Omit TKAInfo from map responses after disablement (otherwise Disabled: true)
	bootstrapFault    bool // Bootstrap returns a malformed GenesisAUM while lock is enabled

	resign        set.Set[key.NodePublic] // Node keys to request re-signing for on their next registration (once)
	registrations []LockRegistration
	requests      []LockRequest
}

// LockRegistration records the Tailnet Lock details of one registration request received by testcontrol.
type LockRegistration struct {
	NodeKey    key.NodePublic
	OldNodeKey key.NodePublic
	NLKey      key.NLPublic
	// Auth indicates whether the request included Auth (an auth key). The logout gate uses it to compare Go and Swift requests.
	Auth bool
	// Expiry is the request's Expiry (0 means absent). A past timestamp means logout (logout.go).
	Expiry time.Time
	// Signature is the verdict on the request's NodeKeySignature:
	// "none" (absent), "noLock" (unchecked because lock is disabled), "accepted", or "rejected".
	Signature      string
	SignatureError string
	// ResignRequested indicates whether the response to this request included RegisterResponse.NodeKeySignature.
	ResignRequested bool
	// Body is the decoded request JSON. It is used only to check for traces of a wrapped auth key.
	Body []byte
}

// LockRequest is one /machine/tka/ request received by testcontrol.
type LockRequest struct {
	Path    string
	NodeKey key.NodePublic
	Head    string
}

// SetTailnetLockCapability adds or removes the tailnet-lock capability in the self node's CapMap in map responses.
// Upstream can include it only in registration-time Capabilities through DefaultNodeCapabilities.
func (s *Server) SetTailnetLockCapability(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lock.capability = enabled
	s.updateLocked("SetTailnetLockCapability", s.nodeIDsLocked(0))
}

// SetLockDisablementBehavior controls what the server reports after disabling lock.
// If wrongSecret is set, bootstrap returns the wrong secret in place of the secret it received.
// If omitInfo is set, omit TKAInfo from map responses. Otherwise include TKAInfo{Disabled: true}.
func (s *Server) SetLockDisablementBehavior(wrongSecret, omitInfo bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lock.wrongSecret = wrongSecret
	s.lock.omitInfo = omitInfo
	s.updateLocked("SetLockDisablementBehavior", s.nodeIDsLocked(0))
}

// SetLockBootstrapFault, when true, removes one byte from the bootstrap response's GenesisAUM while lock is enabled.
// It sends a new map to all nodes (the Go client retries bootstrap only on receiving a netmap).
func (s *Server) SetLockBootstrapFault(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lock.bootstrapFault = enabled
	s.updateLocked("SetLockBootstrapFault", s.nodeIDsLocked(0))
}

// RequestResign arranges for the next registration of nodeKey without OldNodeKey to receive
// RegisterResponse.NodeKeySignature (the current KeySignature) to request re-signing. Used once.
// Assumption: the source does not show when the production server sends this.
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

// LockRegistrations returns the registration request records in receipt order.
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

// LockRequests returns the received /machine/tka/ requests in receipt order.
func (s *Server) LockRequests() []LockRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.lock.requests)
}

// LockState is the server's lock state: the head (base32) if enabled, or disabled otherwise.
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

// recordLockRequest reads and records the request body, then restores it for the handler.
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

// lockBootstrapOverrideLocked builds a bootstrap response to use in place of the upstream genesis response.
// Call with s.mu held.
func (s *Server) lockBootstrapOverrideLocked() (tailcfg.TKABootstrapResponse, bool) {
	if s.tkaStorage == nil && s.lock.disablementSecret != nil {
		secret := bytes.Clone(s.lock.disablementSecret)
		if s.lock.wrongSecret {
			// Reference: the wrong secret (0x42 × 32) in TestTKADisablementFlow in tailnet-lock_test.go.
			secret = bytes.Repeat([]byte{0x42}, 32)
		}
		return tailcfg.TKABootstrapResponse{DisablementSecret: secret}, true
	}
	return tailcfg.TKABootstrapResponse{}, false
}

// serveTKASyncSend handles /machine/tka/sync/send. It verifies and accepts incoming AUMs (Inform) and returns the server's head.
// When the head changes, it sends a new map to all nodes.
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

// serveTKADisable handles /machine/tka/disable. It verifies the disablement secret against the server's state
// and, if correct, clears the server's lock state and remembers the secret (subsequent bootstrap returns it).
// Assumption: the source does not show whether the production server checks that the heads match or performs other checks. Here, check only the secret.
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

// applyRegisterLockLocked handles and records registration request signatures and re-signing requests.
// node is already in s.nodes under nk. For a re-signing request, return the signature to put in the response. Call with s.mu held.
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
			// Assumption: the source does not show whether the production server rejects registrations with unverifiable signatures. Register normally and omit the signature.
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
		// If the re-signed key replacement was accepted, remove the old key's entry immediately. Upstream removes it only after completing
		// the auth URL flow (Followup), so a replacement without authentication would leave two entries with the same node ID.
		// Assumption: the production server replaces the key in place.
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

// applyLockToMapResponseLocked adds the capability and post-disablement TKAInfo to a map response. Call with s.mu held.
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
