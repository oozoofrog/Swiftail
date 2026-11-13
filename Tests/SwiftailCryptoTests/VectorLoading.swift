import Foundation

struct CryptoVector: Decodable {
    let kind: String
    let key: String
    let input: String
    let output: String
    let nonce: String?
    let aad: String?
    let `public`: String?
    let outputs: [String]?
}

func bytes(_ hex: String) -> [UInt8] {
    precondition(hex.count.isMultiple(of: 2))
    var result: [UInt8] = []
    var index = hex.startIndex
    while index < hex.endIndex {
        let end = hex.index(index, offsetBy: 2)
        result.append(UInt8(hex[index..<end], radix: 16)!)
        index = end
    }
    return result
}

func loadVectors(_ name: String) throws -> [CryptoVector] {
    let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Vectors")!
    return try JSONDecoder().decode([CryptoVector].self, from: Data(contentsOf: url))
}
