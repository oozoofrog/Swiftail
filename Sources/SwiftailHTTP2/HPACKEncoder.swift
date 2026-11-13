/// HPACK 압축기: 헤더 필드를 헤더 블록 바이트로 만든다.
///
/// 가장 단순하고 규격상 유효한 표현만 쓴다. 모든 필드를 "표에 넣지 않는 리터럴, 새 이름"(RFC 7541 §6.2.2,
/// 첫 바이트 `0x00`)으로 적고 문자열은 허프만 없이 보낸다. 동적 표를 쓰지 않으므로 압축기에는 상태가
/// 없고, 상대의 SETTINGS_HEADER_TABLE_SIZE에 맞출 일도 없다.
///
/// shortcut: 정적 표 색인과 동적 표를 쓰지 않는다(요청마다 헤더가 조금 길어진다), 요청이 많아 헤더 크기가 문제가 될 때 올린다.
enum HPACKEncoder {
    static func encode(_ fields: [HeaderField]) -> [UInt8] {
        var block: [UInt8] = []
        for field in fields {
            block.append(0x00)
            HPACKEncoding.appendString(field.name, to: &block)
            HPACKEncoding.appendString(field.value, to: &block)
        }
        return block
    }
}
