import Swiftail
import SwiftailPairing

// 라이브러리의 오류를 사용자가 다음에 할 일로 옮긴다.

extension PairingError {
    var guidance: String {
        switch self {
        case .invalidConfiguration(let message):
            "설정이 맞지 않습니다: \(message). 기기 이름은 1~64바이트이고 제어 문자가 없어야 합니다."
        case .invalidAuthKey:
            "이 인증 키는 제안에 실을 수 없습니다. tskey-auth-로 시작하는 1회용 키를 쓰세요(tailnet lock의 서명된 키는 실을 수 없습니다)."
        case .notRunning:
            "노드가 아직 tailnet에 연결되지 않았습니다. 상태가 '연결됨'이 된 뒤 다시 시도하세요."
        case .storeUnreadable:
            "짝 목록 파일을 읽지 못했습니다. 파일이 깨졌으면 앱 데이터를 지우고 다시 짝을 맺으세요."
        case .storeInUse:
            "짝 목록을 이미 쓰고 있습니다. 앱을 다시 띄우세요."
        case .storeWriteFailed:
            "짝 목록을 저장하지 못했습니다. 저장 공간을 확인하세요."
        case .unreachable:
            "60초 안에 여는 쪽에 닿지 못했습니다. 두 기기가 같은 tailnet에 있는지 확인하세요. tailnet lock이 켜져 있으면 이 기기가 서명된 뒤 같은 제안으로 다시 시도하세요."
        case .notOnTailnet:
            "연결이 tailnet을 거치지 않았습니다. 노드가 연결된 뒤 다시 시도하세요."
        case .rejected:
            "제안이 닫혔거나, 만료됐거나, 이미 쓰였습니다. 여는 쪽에서 새 제안을 열어 다시 읽으세요."
        case .hostNotVerified:
            "여는 쪽을 확인하지 못했습니다. 제안을 낸 기기가 아닐 수 있습니다. 새 제안으로 다시 시도하세요."
        case .denied:
            "여는 쪽에서 거절했습니다."
        case .timedOut:
            "여는 쪽이 제때 승인하지 않았습니다. 새 제안으로 다시 시도하세요."
        case .protocolViolation:
            "여는 쪽과 절차가 맞지 않습니다. 두 앱이 같은 판인지 확인하세요."
        case .cancelled:
            "취소했습니다."
        }
    }
}

extension PairingOfferError {
    var guidance: String {
        switch self {
        case .notAnOffer:
            "페어링 제안이 아닙니다. 여는 쪽 화면의 QR이나 링크를 다시 읽으세요."
        case .wrappedAuthKey:
            "tailnet lock의 서명된 인증 키가 실린 제안은 받지 않습니다. 여는 쪽에서 1회용 키로 다시 여세요."
        case .invalidHost, .invalidPort, .invalidSecret, .invalidExpiry, .invalidAuthKey:
            "제안의 내용이 올바르지 않습니다. 링크가 잘렸는지 확인하고 다시 읽으세요."
        }
    }
}

extension AuthKeyIssueError {
    var guidance: String {
        switch self {
        case .invalidClient:
            "클라이언트 ID나 비밀값의 모양이 맞지 않습니다. 비밀값은 tskey-client-로 시작합니다."
        case .invalidTags:
            "태그는 tag:이름 꼴로 하나 이상 넣으세요(쉼표로 가릅니다)."
        case .invalidLifetime, .invalidBaseURL:
            "키를 요청할 수 없는 설정입니다."
        case .clientRejected:
            "Tailscale이 OAuth 클라이언트를 받지 않았습니다. ID와 비밀값을 확인하세요."
        case .unauthorized:
            "받은 토큰이 거절됐습니다. OAuth 클라이언트가 지워지지 않았는지 확인하세요."
        case .forbidden:
            "권한이 없습니다. OAuth 클라이언트에 auth_keys 쓰기 권한과 이 태그가 있는지 확인하세요."
        case .http(let status):
            "Tailscale 관리 API가 \(status)로 답했습니다. 잠시 뒤 다시 시도하세요."
        case .invalidResponse:
            "Tailscale 관리 API의 응답을 읽지 못했습니다."
        case .network:
            "Tailscale 관리 API에 닿지 못했습니다. 인터넷 연결을 확인하세요."
        case .cancelled:
            "취소했습니다."
        }
    }
}

extension ConnectionError {
    var guidance: String {
        switch self {
        case .notRunning:
            "노드가 tailnet에 연결되지 않았습니다. 상태가 '연결됨'이 된 뒤 다시 시도하세요."
        case .unknownHost:
            "여는 쪽이 tailnet에 보이지 않습니다. 여는 쪽 노드가 켜져 있는지 확인하세요."
        case .refused:
            "여는 쪽 앱이 듣고 있지 않습니다. 여는 쪽 앱을 '여는 쪽' 역할로 띄우세요."
        case .reset:
            "여는 쪽이 연결을 끊었습니다. 여는 쪽의 짝 목록에 이 기기가 없습니다. 다시 짝을 맺으세요."
        case .timedOut:
            "여는 쪽이 답하지 않습니다. 여는 쪽 기기가 켜져 있고 네트워크에 있는지 확인하세요."
        case .peerRemoved:
            "여는 쪽이 tailnet에서 빠졌습니다."
        case .invalidConfiguration, .addressInUse, .limitReached, .closed, .cancelled, .concurrentUse:
            "연결하지 못했습니다(\(self))."
        }
    }
}
