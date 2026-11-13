/// HPACK 허프만 문자열 해제.
///
/// 정적 허프만 부호표(`HPACKHuffmanTable`)로 줄인 문자열을 되돌린다. 부호는 길이가 제각각이라
/// 비트를 하나씩 읽으며 이진 트리를 내려가고, 잎에 닿으면 기호 하나를 내놓고 뿌리로 돌아간다.
/// 처리량보다 읽기 쉬움을 골랐다.
///
/// 문자열 끝의 남는 비트는 EOS 부호의 앞부분(모두 1)으로 채운다. 규칙(RFC 7541 §5.2):
/// 패딩은 7비트 이하여야 하고 모두 1이어야 하며, EOS 기호 자체가 문자열에 나오면 오류다.
enum HPACKHuffman {
    /// 부호표를 트리로 만든 것. 노드 0이 뿌리다.
    private struct Node {
        var children: [Int?] = [nil, nil]
        var symbol: Int?
    }

    private static let tree: [Node] = {
        var nodes = [Node()]
        for (symbol, code) in HPACKHuffmanTable.codes.enumerated() {
            var current = 0
            for shift in stride(from: Int(code.bitCount) - 1, through: 0, by: -1) {
                let bit = Int(code.bits >> UInt32(shift) & 1)
                if let next = nodes[current].children[bit] {
                    current = next
                } else {
                    nodes.append(Node())
                    nodes[current].children[bit] = nodes.count - 1
                    current = nodes.count - 1
                }
            }
            nodes[current].symbol = symbol
        }
        return nodes
    }()

    static func decode(_ input: ArraySlice<UInt8>) throws(HPACKError) -> [UInt8] {
        var output: [UInt8] = []
        var current = 0
        // 마지막 기호 뒤에 읽은 비트 수와 그 비트가 모두 1인지.
        var pendingBits = 0
        var pendingAreAllOnes = true
        for byte in input {
            for shift in stride(from: 7, through: 0, by: -1) {
                let bit = Int(byte >> UInt8(shift) & 1)
                guard let next = tree[current].children[bit] else { throw .invalidHuffman }
                pendingBits += 1
                pendingAreAllOnes = pendingAreAllOnes && bit == 1
                guard let symbol = tree[next].symbol else {
                    current = next
                    continue
                }
                guard symbol != HPACKHuffmanTable.endOfString else { throw .invalidHuffman }
                output.append(UInt8(truncatingIfNeeded: symbol))
                current = 0
                pendingBits = 0
                pendingAreAllOnes = true
            }
        }
        guard pendingBits <= 7, pendingAreAllOnes else { throw .invalidHuffman }
        return output
    }
}
