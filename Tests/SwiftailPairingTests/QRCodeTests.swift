import CoreGraphics
import CoreImage
import Foundation
import Testing
@testable import SwiftailPairing

/// 제안의 QR(계약 동작 O5. 7절 시험 1의 "가장 긴 링크의 QR"과 시험 6).
@Suite("제안의 QR")
struct QRCodeTests {
    private static func base() throws -> URL {
        try #require(URL(string: "https://example.com/pair"))
    }

    /// 그림의 화소(어두우면 참)와 한 변의 길이.
    private static func pixels(_ image: CGImage) throws -> (side: Int, isDark: (Int, Int) -> Bool) {
        #expect(image.width == image.height)
        #expect(image.bitsPerPixel == 8 && image.bytesPerRow == image.width, "화소 하나가 회색 한 바이트다")
        let data = try #require(image.dataProvider?.data as Data?)
        return (image.width, { x, y in data[data.startIndex + y * image.width + x] < 128 })
    }

    /// 시스템 검출기로 읽은 QR의 글. 화소 하나짜리 모듈을 보간 없이 키워서 넘긴다.
    private static func decode(_ image: CGImage) throws -> [String] {
        let scaled = CIImage(cgImage: image).samplingNearest().transformed(by: CGAffineTransform(scaleX: 6, y: 6))
        let detector = try #require(
            CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        return detector.features(in: scaled).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }

    @Test("만든 그림을 시스템 검출기로 읽으면 링크와 같다")
    func decodesToLink() throws {
        let offer = Sample.offer(authKey: Sample.authKey)
        let image = try #require(offer.qrCode(base: try Self.base()))
        #expect(try Self.decode(image) == [offer.url(base: try Self.base()).absoluteString])
    }

    @Test("모듈 하나가 한 화소이고 둘레에 4모듈의 흰 여백이 있다")
    func hasQuietZone() throws {
        let image = try #require(Sample.offer().qrCode(base: try Self.base()))
        let (side, isDark) = try Self.pixels(image)
        let symbol = side - 8
        #expect(symbol >= 21 && (symbol - 17).isMultiple(of: 4), "QR 기호의 한 변은 17 + 4·판 모듈이다")
        for offset in 0..<side {
            for margin in 0..<4 {
                #expect(!isDark(offset, margin) && !isDark(offset, side - 1 - margin))
                #expect(!isDark(margin, offset) && !isDark(side - 1 - margin, offset))
            }
        }
        // 여백 바로 안쪽은 위치 찾기 무늬다: 세 모서리에서 7모듈의 어두운 띠, 넷째 모서리에는 없다.
        for index in 4..<11 {
            #expect(isDark(index, 4) && isDark(4, index), "왼쪽 위")
            #expect(isDark(side - 1 - index, 4) && isDark(side - 5, index), "오른쪽 위")
            #expect(isDark(index, side - 5) && isDark(4, side - 1 - index), "왼쪽 아래")
        }
        #expect(!(4..<11).allSatisfy { isDark(side - 1 - $0, side - 5) })
    }

    @Test("가장 긴 링크도 QR 한 장에 들고 그대로 읽힌다")
    func encodesLongestLink() throws {
        let host = [63, 63, 63, 61].map { String(repeating: "a", count: $0) }.joined(separator: ".")
        let offer = Sample.offer(authKey: "tskey-auth-" + String(repeating: "A", count: 245), host: host, port: 65535)
        let link = offer.url(base: try Self.base()).absoluteString
        #expect(try PairingOffer(link: link).authKey?.utf8.count == 256)
        let image = try #require(offer.qrCode(base: try Self.base()))
        #expect(try Self.decode(image) == [link])
    }

    @Test("QR 한 장에 들지 않으면 nil이다")
    func returnsNilWhenTooLong() throws {
        let base = try #require(URL(string: "https://example.com/" + String(repeating: "a", count: 3000)))
        #expect(Sample.offer().qrCode(base: base) == nil)
    }

    @Test("기호 떼어 내기: 여백이 몇이든 어두운 모듈의 테두리를 찾는다", arguments: [0, 1, 4, 7])
    func normalizesQuietZone(margin: Int) throws {
        let image = try #require(Sample.offer().qrCode(base: try Self.base()))
        let symbol = try #require(QRSymbol(image))
        let padded = try #require(symbol.image(quietZone: margin))
        #expect(padded.width == symbol.side + 2 * margin)
        let again = try #require(QRSymbol(padded))
        #expect(again.side == symbol.side && again.modules == symbol.modules)
    }
}
