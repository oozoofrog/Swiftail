#if os(iOS)
import AVFoundation
import SwiftUI
import VisionKit

/// 카메라로 QR 하나를 읽는다. 읽은 문자열은 OS의 링크 배달을 거치지 않고 앱 안에서만 쓰인다(계약 3절).
struct QRScanner: UIViewControllerRepresentable {
    let onRead: (String) -> Void

    /// 카메라 접근을 묻고, 이 기기에서 읽을 수 있는지 돌려준다.
    static func requestAccess() async -> Bool {
        guard DataScannerViewController.isSupported else { return false }
        return await AVCaptureDevice.requestAccess(for: .video)
    }

    func makeCoordinator() -> Coordinator { Coordinator(onRead: onRead) }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])])
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}

    final class Coordinator: DataScannerViewControllerDelegate {
        private let onRead: (String) -> Void

        init(onRead: @escaping (String) -> Void) {
            self.onRead = onRead
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let barcode) in addedItems {
                guard let text = barcode.payloadStringValue else { continue }
                dataScanner.stopScanning()
                onRead(text)
                return
            }
        }
    }
}
#endif
