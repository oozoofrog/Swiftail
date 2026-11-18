/// HPACK Huffman string decoding.
///
/// Decodes strings compressed with the static Huffman code table (`HPACKHuffmanTable`). Since codes vary in length,
/// the decoder walks a binary tree one bit at a time. At a leaf, it emits one symbol and returns to the root.
/// This favors readability over throughput.
///
/// The remaining bits at the end of a string are padded with the prefix of the EOS code (all ones). Under RFC 7541 §5.2,
/// padding must be at most 7 bits and all ones. The EOS symbol itself is a decoding error if it appears in the string.
enum HPACKHuffman {
    /// The code table as a tree. Node 0 is the root.
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
        // The number of bits read since the last symbol and whether they are all ones.
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
