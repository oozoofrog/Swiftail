import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation

extension PairingOffer {
    /// The surrounding quiet zone, in modules. ISO/IEC 18004 guarantees this value to readers.
    static let quietZoneModules = 4

    /// A QR image encoding this offer's link (`url(base:)`). Encodes the link's UTF-8 bytes with error correction M (behavior O5).
    ///
    /// One pixel per module, with a 4-module white quiet zone. Apps scale it without interpolation (SwiftUI `.interpolation(.none)`).
    /// The image is a secret. Display it on screen only and keep it out of storage and sharing.
    ///
    /// - Returns: nil if the link cannot fit in a single QR code or the image cannot be created.
    public func qrCode(base: URL) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(url(base: base).absoluteString.utf8)
        filter.correctionLevel = "M"
        // An image of a few thousand pixels needs no GPU. The software renderer produces the same result in headless environments.
        let context = CIContext(options: [.useSoftwareRenderer: true])
        guard let output = filter.outputImage,
              let rendered = context.createCGImage(
                  output, from: output.extent, format: .L8, colorSpace: CGColorSpaceCreateDeviceGray()),
              let symbol = QRSymbol(rendered)
        else { return nil }
        return symbol.image(quietZone: Self.quietZoneModules)
    }
}

/// The module grid of one QR symbol (true for dark modules).
///
/// `CIQRCodeGenerator`'s quiet zone is undocumented (it was 1 module on macOS in 2026-11). Find the bounds of dark
/// modules in the image, extract just the symbol, and add the quiet zone defined here. Finder patterns in three symbol corners make
/// the dark pixel bounds the symbol bounds.
struct QRSymbol {
    /// The number of modules per side.
    let side: Int
    /// The modules in row-major order.
    let modules: [Bool]

    /// Extracts the symbol from an 8-bit grayscale image with one pixel per module. Returns nil for another image type or if the dark pixels do not
    /// bound a square.
    init?(_ image: CGImage) {
        guard image.bitsPerComponent == 8, image.bitsPerPixel == 8, let data = image.dataProvider?.data as Data?,
              data.count >= image.bytesPerRow * (image.height - 1) + image.width
        else { return nil }
        let isDark = { (x: Int, y: Int) in data[data.startIndex + y * image.bytesPerRow + x] < 128 }
        let rows = (0..<image.height).filter { y in (0..<image.width).contains { isDark($0, y) } }
        let columns = (0..<image.width).filter { x in (0..<image.height).contains { isDark(x, $0) } }
        guard let top = rows.first, let bottom = rows.last, let left = columns.first, let right = columns.last,
              bottom - top == right - left
        else { return nil }
        side = bottom - top + 1
        modules = (top...bottom).flatMap { y in (left...right).map { isDark($0, y) } }
    }

    /// An image with a white quiet zone of `quietZone` modules, with one pixel per module.
    func image(quietZone: Int) -> CGImage? {
        let size = side + 2 * quietZone
        var pixels = [UInt8](repeating: 0xFF, count: size * size)
        for (index, isDark) in modules.enumerated() where isDark {
            pixels[(index / side + quietZone) * size + index % side + quietZone] = 0
        }
        guard let provider = CGDataProvider(data: Data(pixels) as CFData) else { return nil }
        return CGImage(
            width: size, height: size, bitsPerComponent: 8, bitsPerPixel: 8, bytesPerRow: size,
            space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGBitmapInfo(rawValue: CGImageAlphaInfo.none.rawValue),
            provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent)
    }
}
