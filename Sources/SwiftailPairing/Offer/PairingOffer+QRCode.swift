import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation

extension PairingOffer {
    /// 둘레의 여백(모듈 수). QR 규격(ISO/IEC 18004)이 읽는 쪽에 보장하는 값이다.
    static let quietZoneModules = 4

    /// 이 제안의 링크(`url(base:)`)를 적은 QR 그림. 링크 문자열의 UTF-8 바이트를 오류 정정 M으로 적는다(동작 O5).
    ///
    /// 모듈 하나가 한 화소이고 둘레에 4모듈의 흰 여백이 있다. 앱이 보간 없이 키워 쓴다(SwiftUI `.interpolation(.none)`).
    /// 그림은 비밀이다. 화면에만 내고 저장하거나 공유하지 않는다.
    ///
    /// - Returns: 링크가 QR 한 장에 들지 않거나 그림을 만들지 못하면 nil.
    public func qrCode(base: URL) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(url(base: base).absoluteString.utf8)
        filter.correctionLevel = "M"
        // 화소 몇천 개짜리 그림이라 GPU가 필요 없다. 소프트웨어 렌더러는 화면이 없는 곳에서도 같은 결과를 낸다.
        let context = CIContext(options: [.useSoftwareRenderer: true])
        guard let output = filter.outputImage,
              let rendered = context.createCGImage(
                  output, from: output.extent, format: .L8, colorSpace: CGColorSpaceCreateDeviceGray()),
              let symbol = QRSymbol(rendered)
        else { return nil }
        return symbol.image(quietZone: Self.quietZoneModules)
    }
}

/// QR 기호 하나의 모듈 격자(어두운 모듈이 참).
///
/// `CIQRCodeGenerator`가 둘레에 두는 여백은 문서에 없다(2026-11 macOS에서는 1모듈이었다). 그래서 받은 그림에서 어두운
/// 모듈의 테두리를 찾아 기호만 떼어 내고, 여백은 여기서 정한 만큼 다시 두른다. 기호의 세 모서리에는 위치 찾기 무늬가 있어
/// 어두운 화소의 테두리가 곧 기호의 테두리다.
struct QRSymbol {
    /// 한 변의 모듈 수.
    let side: Int
    /// 행 우선으로 늘어놓은 모듈.
    let modules: [Bool]

    /// 화소 하나가 모듈 하나인 8비트 회색 그림에서 기호를 떼어 낸다. 그런 그림이 아니거나 어두운 화소가 정사각형을
    /// 이루지 않으면 nil.
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

    /// 둘레에 `quietZone`모듈의 흰 여백을 두른 그림. 모듈 하나가 한 화소다.
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
