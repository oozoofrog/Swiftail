#if os(iOS)
import AVFoundation
import SwiftUI
import VisionKit

/// Reads one QR code with the camera. The decoded string stays in the app and bypasses OS link delivery (contract §3).
struct QRScanner: UIViewControllerRepresentable {
    let onRead: (String) -> Void

    /// Requests camera access and returns whether this device can scan.
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
