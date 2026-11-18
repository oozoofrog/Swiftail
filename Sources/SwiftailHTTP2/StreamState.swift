/// An open stream tracked by the connection (RFC 9113 §5.1).
///
/// The request and response end independently. The request side ends when `unsentBody` becomes `nil` (when END_STREAM is sent).
/// Receiving END_STREAM finishes the response. The connection removes the stream and cancels any unsent request body. It also removes streams reset
/// with RST_STREAM. Later frames are handled as frames for a closed stream.
struct StreamState {
    enum Receiving: Equatable {
        /// Waiting for the response head.
        case awaitingHead
        /// The head has arrived, and the body is being received.
        case receivingBody
        /// END_STREAM has been received.
        case ended
    }

    var receiving = Receiving.awaitingHead
    var sendWindow: FlowControlWindow
    /// The request body still to be sent. A value of `nil` indicates that the request side has ended.
    var unsentBody: ArraySlice<UInt8>?
    /// Whether this is a HEAD request. The response's `content-length` does not describe the body length (RFC 9110 §9.3.2).
    let isHeadRequest: Bool
    /// The body length declared by the response in `content-length`. A value of `nil` means the length was omitted or the response has no body (HEAD, 204, 304).
    var declaredBodyLength: Int?
    /// The total DATA payload received so far, excluding padding. Checked against `declaredBodyLength` (§8.1.1).
    var receivedBodyLength = 0
    /// The stream window credit to return for received DATA. `takeOutboundBytes()` emits it in one WINDOW_UPDATE.
    var pendingWindowCredit = 0

    init(sendWindowSize: Int, body: [UInt8]?, isHeadRequest: Bool) {
        sendWindow = FlowControlWindow(sendWindowSize)
        unsentBody = body?[...]
        self.isHeadRequest = isHeadRequest
    }
}
