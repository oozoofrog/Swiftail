// AUM 하나의 검증과 상태 적용. 노트 4.1·4.2, 계약 동작 A2~A7·F1.
//
// 검사의 차례와 종류별 적용 규칙, 서명 가중치는 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.7 `tka/tka.go`(`aumVerify`, `checkParent`), `tka/verify.go`(`signatureVerify`),
// `tka/state.go`(`GetKey`, `parentMatches`, `applyVerifiedAUM`), `tka/aum.go`(`Weight`).
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

import SwiftailCrypto

extension AuthorityState {
    /// 검증된 AUM을 적용한 새 상태(Go `applyVerifiedAUM`, 동작 A6). 결과의 `lastAUMHash`는 그 AUM의 해시다.
    ///
    /// 서명과 정적 검사는 보지 않는다. 받아들일지 판정하는 쪽은 `Authority`다.
    package func applying(_ update: AUM) throws(TKAError) -> AuthorityState {
        try applying(update, hash: update.hash)
    }

    /// `applying(_:)`과 같다. 이미 계산한 해시를 받아 다시 인코딩하지 않는다.
    func applying(_ update: AUM, hash: AUMHash) throws(TKAError) -> AuthorityState {
        // 부모가 있는 상태면 `PrevAUMHash`가 바이트까지 같아야 한다(Go `parentMatches`).
        if let lastAUMHash, lastAUMHash.bytes != update.prevAUMHash ?? [] { throw .rejectedUpdate }
        var next = self
        next.lastAUMHash = hash

        switch update.messageKind {
        case AUM.Kind.checkpoint:
            guard var checkpoint = update.state, checkpoint.stateID1 == stateID1, checkpoint.stateID2 == stateID2
            else { throw .rejectedUpdate }
            checkpoint.lastAUMHash = hash
            return checkpoint
        case AUM.Kind.addKey:
            // 512개 상한은 여기에 없다(노트 4.2).
            guard let key = update.key, let keyID = key.keyID, self.key(withID: keyID) == nil else { throw .rejectedUpdate }
            next.keys.append(key)
        case AUM.Kind.updateKey:
            let keyID = update.keyID ?? []
            guard var key = self.key(withID: keyID) else { throw .rejectedUpdate }
            if let votes = update.votes { key.votes = votes }
            if let meta = update.meta { key.meta = meta }
            do { try key.validate() } catch { throw .rejectedUpdate }
            for index in next.keys.indices where next.keys[index].keyID == keyID {
                next.keys[index] = key
            }
        case AUM.Kind.removeKey:
            guard let index = keys.firstIndex(where: { $0.keyID == update.keyID ?? [] }) else { throw .rejectedUpdate }
            next.keys.remove(at: index)
        default:
            // NoOp, 종류 0(`AUMInvalid`), 모르는 종류: 상태를 그대로 둔다(옛 클라이언트는 무시해도 된다는 Go의 계약, 결정 L10).
            break
        }
        return next
    }

    /// 이 상태를 부모 상태로 삼아 AUM을 받아들일 수 있는지 본다(Go `aumVerify`, 동작 A1~A5).
    ///
    /// 부트스트랩(`isBootstrap`)은 부모를 보지 않는다: 체크포인트 자신의 상태로 그 서명을 검증한다(동작 F5).
    /// 투표 문턱은 없다. 신뢰 키 하나의 서명으로 충분하다(동작 A4).
    func verify(_ update: AUM, isBootstrap: Bool) throws(TKAError) {
        try update.validate()
        try verifyParentAndSignatures(of: update, isBootstrap: isBootstrap)
    }

    /// `verify(_:isBootstrap:)`에서 정적 검사(동작 A1)를 뺀 나머지: 부모, 서명, 마지막 키 제거(동작 A2~A5).
    ///
    /// 저장소를 다시 열 때는 이것만 본다(TL-11a 항목 2). 정적 검사를 통과하지 않은 AUM이 와도 트랩하지 않는다: 서명의 길이는
    /// 검증이 떨어뜨리고, 적용(`applying`)은 필드가 없으면 거절하고, 가중치는 Go와 같이 넘쳐도 감긴다.
    func verifyParentAndSignatures(of update: AUM, isBootstrap: Bool) throws(TKAError) {
        if !isBootstrap {
            guard let parent = update.prevAUMHash, !parent.isEmpty else { throw .missingParent }
            guard let lastAUMHash, lastAUMHash.bytes == parent else { throw .rejectedUpdate }
        }

        guard !update.signatures.isEmpty else { throw .unsigned }
        let signatureHash = update.signatureHash
        // 이미 검증한 (KeyID, 서명) 쌍. 같은 쌍은 판정도 같으므로 한 번만 검증한다. Go는 되풀이한 만큼 검증하는데,
        // 그러면 신뢰 키의 서명 하나를 수천 번 되풀이한 AUM 하나가 받는 쪽을 수십 초 붙잡는다.
        var verified: Set<AUMSignature> = []
        for signature in update.signatures where verified.insert(signature).inserted {
            // 공개 키는 KeyID가 아니라 상태 안의 값을 쓴다: KeyID는 보낸 쪽이 정한다(Go `signatureVerify`의 주석).
            guard let key = key(withID: signature.keyID) else { throw .untrustedSigner }
            guard key.kind == TrustedKey.ed25519Kind, let publicKey = key.publicKey, publicKey.count == 32,
                Ed25519Verification.isValidZIP215(
                    signature: signature.signature, message: signatureHash, publicKey: publicKey
                )
            else { throw .invalidSignature }
        }

        if update.messageKind == AUM.Kind.removeKey, keys.count == 1, keys[0].keyID == update.keyID ?? [] {
            throw .rejectedUpdate
        }
    }

    /// 갈래 해소의 서명 가중치(Go `AUM.Weight`): 서명한 신뢰 키의 `Votes` 합. 같은 키의 서명은 한 번만, 모르는 키는 0이다.
    func weight(of update: AUM) -> UInt64 {
        var counted: Set<[UInt8]> = []
        var weight: UInt64 = 0
        for signature in update.signatures {
            guard let key = key(withID: signature.keyID), counted.insert(signature.keyID).inserted else { continue }
            // 받아들인 상태의 키는 `Votes`가 4,096 이하라(정적 검사) 넘치지 않는다. 다시 연 저장소의 상태는 정적 검사를 거치지
            // 않았으므로, Go `uint`와 같이 감기게 더한다(트랩하지 않는다).
            weight &+= key.votes
        }
        return weight
    }

    /// KeyID가 같은 신뢰 키(Go `GetKey`). null 공개 키와 빈 공개 키는 같은 KeyID다(동작 E6).
    ///
    /// Go와 같이 앞에서부터 찾고, KeyID가 없는 키(`Key25519`가 아님)를 먼저 만나면 거기서 실패한다. 받아들인 상태에는 그런 키가
    /// 없다(정적 검사). 정적 검사를 거치지 않는 다시 열기(TL-11a 항목 2)에서만 닿는다.
    func key(withID keyID: [UInt8]) -> TrustedKey? {
        keys.first { $0.keyID == nil || $0.keyID == keyID }.flatMap { $0.keyID == nil ? nil : $0 }
    }
}
