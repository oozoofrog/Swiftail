import CoreGraphics
import CoreImage
import Foundation
import Testing
@testable import SwiftailPairing

/// Tests the offer QR code (contract behavior O5, §7 test 1's longest-link QR code and test 6).
@Suite("Offer QR code")
struct QRCodeTests {
    private static func base() throws -> URL {
        try #require(URL(string: "https://example.com/pair"))
    }

    /// The image pixels (true when dark) and side length.
    private static func pixels(_ image: CGImage) throws -> (side: Int, isDark: (Int, Int) -> Bool) {
        #expect(image.width == image.height)
        #expect(image.bitsPerPixel == 8 && image.bytesPerRow == image.width, "Each pixel is one grayscale byte")
        let data = try #require(image.dataProvider?.data as Data?)
        return (image.width, { x, y in data[data.startIndex + y * image.width + x] < 128 })
    }

    /// Reads the QR text using the system detector. Scales single-pixel modules without interpolation before passing the image to the detector.
    private static func decode(_ image: CGImage) throws -> [String] {
        let scaled = CIImage(cgImage: image).samplingNearest().transformed(by: CGAffineTransform(scaleX: 6, y: 6))
        let detector = try #require(
            CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        return detector.features(in: scaled).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }

    @Test("The system detector reads the generated image as the original link")
    func decodesToLink() throws {
        let offer = Sample.offer(authKey: Sample.authKey)
        let image = try #require(offer.qrCode(base: try Self.base()))
        #expect(try Self.decode(image) == [offer.url(base: try Self.base()).absoluteString])
    }

    @Test("Each module is one pixel, with a 4-module white margin around the symbol")
    func hasQuietZone() throws {
        let image = try #require(Sample.offer().qrCode(base: try Self.base()))
        let (side, isDark) = try Self.pixels(image)
        let symbol = side - 8
        #expect(symbol >= 21 && (symbol - 17).isMultiple(of: 4), "A QR symbol is 17 + 4 × version modules on each side")
        for offset in 0..<side {
            for margin in 0..<4 {
                #expect(!isDark(offset, margin) && !isDark(offset, side - 1 - margin))
                #expect(!isDark(margin, offset) && !isDark(side - 1 - margin, offset))
            }
        }
        // Just inside the margin are the finder patterns, with a 7-module dark band in three corners and none in the fourth.
        for index in 4..<11 {
            #expect(isDark(index, 4) && isDark(4, index), "Top left")
            #expect(isDark(side - 1 - index, 4) && isDark(side - 5, index), "Top right")
            #expect(isDark(index, side - 5) && isDark(4, side - 1 - index), "Bottom left")
        }
        #expect(!(4..<11).allSatisfy { isDark(side - 1 - $0, side - 5) })
    }

    @Test("The longest link fits in a single QR code and decodes unchanged")
    func encodesLongestLink() throws {
        let host = [63, 63, 63, 61].map { String(repeating: "a", count: $0) }.joined(separator: ".")
        let offer = Sample.offer(authKey: "tskey-auth-" + String(repeating: "A", count: 245), host: host, port: 65535)
        let link = offer.url(base: try Self.base()).absoluteString
        #expect(try PairingOffer(link: link).authKey?.utf8.count == 256)
        let image = try #require(offer.qrCode(base: try Self.base()))
        #expect(try Self.decode(image) == [link])
    }

    @Test("Returns nil if the link does not fit in a single QR code")
    func returnsNilWhenTooLong() throws {
        let base = try #require(URL(string: "https://example.com/" + String(repeating: "a", count: 3000)))
        #expect(Sample.offer().qrCode(base: base) == nil)
    }

    @Test("Symbol extraction finds the boundary of the dark modules regardless of margin size", arguments: [0, 1, 4, 7])
    func normalizesQuietZone(margin: Int) throws {
        let image = try #require(Sample.offer().qrCode(base: try Self.base()))
        let symbol = try #require(QRSymbol(image))
        let padded = try #require(symbol.image(quietZone: margin))
        #expect(padded.width == symbol.side + 2 * margin)
        let again = try #require(QRSymbol(padded))
        #expect(again.side == symbol.side && again.modules == symbol.modules)
    }
}
