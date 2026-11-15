// 끄기 비밀 검증. 노트 4.5·5절, 계약 동작 X.
// 출처: tailscale.com v1.104.7 `tka/state.go`(`DisablementKDF`, `checkDisablement`). 인자를 옮겼다.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

import SwiftailCrypto

extension Authority {
    /// 끄기 비밀이 맞는가(Go `ValidDisablement`, 동작 X1·X2). 참이면 부르는 쪽이 lock 상태를 지운다.
    ///
    /// Argon2i(솔트 "tailscale network-lock disablement salt", 4패스, 16MiB, 병렬도 4, 32바이트)의 결과가 상태의 끄기 값
    /// 가운데 하나와 상수 시간 비교로 같을 때 참이다. 빈 비밀도 그대로 KDF에 넣는다. 16MiB를 한 번 잡고 끝나면 놓는다.
    /// 비밀과 KDF 출력은 남기지 않는다.
    package func isValidDisablement(secret: [UInt8]) -> Bool {
        let derived: [UInt8]
        do {
            derived = try Argon2i.derive(
                password: secret, salt: Self.disablementSalt, iterations: 4, memoryKiB: 16 * 1_024, parallelism: 4,
                outputByteCount: AuthorityState.disablementValueByteCount
            )
        } catch {
            // 인자가 고정이라 비밀이 4GiB를 넘을 때만 닿는다. 확인하지 못한 비밀은 맞지 않는 것이다.
            return false
        }
        return state.disablementValues.contains { constantTimeEqual(derived, $0) }
    }

    /// 끄기 비밀 KDF의 솔트(ASCII 39바이트).
    static let disablementSalt = Array("tailscale network-lock disablement salt".utf8)
}
