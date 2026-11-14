/// 실패 뒤 다시 시도하기까지 기다릴 시간. 시계도 난수도 갖지 않는 순수 계산이다.
///
/// 제어 서버(상한 30초)와 DERP 서버(상한 5초)의 재연결이 같은 식에 상한만 다르게 쓴다.
///
/// 연속 실패 n번째에 `min(n² × 10ms, maximum) × [0.5, 1.5)`. 2ⁿ보다 완만하게 늘고, 곱하는 난수가 여러 노드가
/// 한꺼번에 다시 붙는 것을 흩는다. 성공하면 부르는 쪽이 n을 0으로 되돌린다.
///
/// (출처: tailscale.com `util/backoff/backoff.go`, BSD-3-Clause).
package enum Backoff {
    /// 연속 실패 `failures`번째 뒤의 대기. 0번 이하면 기다리지 않는다. `jitter`는 [0, 1)의 난수다.
    package static func delay(failures: Int, maximum: Duration, jitter: Double) -> Duration {
        let n = min(max(failures, 0), 1_000)
        let base = min(Duration.milliseconds(n * n * 10), maximum)
        return base * (0.5 + jitter)
    }
}
