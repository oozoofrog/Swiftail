import Foundation
import SwiftailControl

extension TailnetNode {
    /// `stateDirectory`에 등록을 마친 신원이 저장되어 있는가. 앱이 노드를 띄우기 전에 "저장된 신원으로 스스로 이을지, 인증
    /// 키나 로그인을 받을지"를 정할 때 묻는다. 파일·소켓을 만들지 않고 신원 파일을 읽기만 한다.
    ///
    /// 파일이 있는지만 보지 않고 `run()`과 같은 규칙으로 읽어 형식까지 본다(심볼릭 링크를 따라가지 않음, 정규 파일만,
    /// 64KiB까지). 있기만 하고 읽을 수 없는 파일은 `run()`도 `control(.storage)`로 끝나므로, 여기서 같은 실패를 먼저 알려야
    /// 앱이 인증 키를 받아 놓고 시작에서 실패하는 일이 없다. 그리고 node 키가 있어야 참이다. machine 키만 있는 파일은 등록을
    /// 마치기 전에 멈춘 것이라(`run()`은 등록 전에 machine 키를 저장한다) 인증 키나 로그인이 다시 필요하다.
    ///
    /// 참이어도 제어 서버가 그 노드를 지웠거나 node 키가 만료됐으면 `run()`이 `.needsLogin`이나 `control(_:)` 실패로
    /// 알린다. 그것은 서버에 물어야 안다. 신원의 내용(키)은 내보내지 않는다.
    ///
    /// - Parameter stateDirectory: `NodeConfiguration.stateDirectory`에 줄 디렉터리.
    /// - Returns: 등록을 마친 신원이 있으면 true. 신원 파일이 없거나 등록 전의 것이면 false.
    /// - Throws: 파일 URL이 아니면 `invalidConfiguration`. 신원 파일이 심볼릭 링크이거나, 정규 파일이 아니거나, 한도보다
    ///   크거나, 읽을 수 없거나, 형식이 맞지 않으면 `control(.storage)`.
    public static func hasSavedIdentity(in stateDirectory: URL) throws(NodeError) -> Bool {
        guard stateDirectory.isFileURL else { throw .invalidConfiguration("상태 디렉터리는 파일 URL이어야 한다") }
        do throws(ControlError) {
            return try NodeIdentityStore(directory: stateDirectory).load()?.nodeKey != nil
        } catch {
            throw NodeError(error)
        }
    }
}
