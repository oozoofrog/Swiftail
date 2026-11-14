import SwiftailBase

/// tailnet lock에서 노드가 서명에 쓰는 공개 키의 쓰임. 텍스트는 `"nlpub:" + 16진 64자리`다.
///
/// Swiftail은 tailnet lock을 구현하지 않지만, Go 클라이언트는 등록 요청의 `NLKey`를 늘 채워 보낸다
/// (`docs/protocol-notes/control-map.md` 3.2, 4.6). 그 자리의 타입이다.
public enum NLKeyKind: KeyKind { public static let prefix = "nlpub:" }

public typealias NLPublicKey = PrefixedKey<NLKeyKind>
