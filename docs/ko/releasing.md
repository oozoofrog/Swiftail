> 이 문서는 한국어 참고용 번역입니다. [영문 원본](../releasing.md)을 기준으로 합니다.

# Swiftail 릴리스 절차

1.0 이전에는 어느 제품에서든 소스 호환성이 깨지거나 정상적인 사용의 동작이 달라질 수 있는 변경이 있으면 MINOR 버전을 올립니다. 공개 심벌을 삭제하거나 이름을 바꾸는 경우, 시그니처를 바꾸는 경우, 정상적인 사용에 대해 문서에 명시된 동작 범위를 좁히는 경우가 이에 해당합니다. Swiftail은 library evolution 없이 빌드하므로 공개 `enum`에 케이스를 추가하면 모든 케이스를 명시한 `switch`가 깨집니다. 호환성을 유지하는 수정이나 기존 API를 건드리지 않고 새 API를 추가하는 변경에는 PATCH 버전을 올립니다.

아래 조건을 충족하면 총괄 세션은 PATCH 릴리스 태그를 만들고 푸시할 수 있습니다. MINOR 및 1.0 릴리스와 기존 태그에 대한 모든 작업은 소유자의 지시가 필요합니다. 다른 세션은 태그를 만들거나 푸시할 수 없습니다.

- [ ] 이전 태그 이후의 변경 내역을 확인하고 위 규칙에 따라 버전을 정합니다.
- [ ] `README.md`의 설치 예제, `Sources/SwiftailCertificates/ACME/URLSessionACMETransport.swift`의 `User-Agent`, `Tests/SwiftailCertificatesTests/ACME/URLSessionACMETransportTests.swift`의 해당 기댓값, `docs/contracts/SwiftailHost.md`의 `User-Agent` 예제에 직접 적힌 버전을 갱신합니다.
- [ ] `README.md`, `SECURITY.md`, `docs/releasing.md` 가운데 바뀐 문서가 있으면 `docs/ko/`에서 해당 한국어 참고본도 갱신합니다.
- [ ] 로컬 검증을 통과합니다. `-warnings-as-errors`로 빌드해 경고가 없어야 하며, 모든 단위 테스트와 로컬 상호 운용 테스트를 통과해야 합니다.
- [ ] `main`의 GitHub CI `push` 실행이 태그를 붙이려는 바로 그 커밋 SHA에서 성공했는지 확인합니다.

`v` 접두사 없이 주석이 있는 태그를 만듭니다. `<notes-file>`에 영어로 릴리스 노트를 작성해 태그 메시지로 사용하고, GitHub Release에도 같은 메시지를 사용합니다.

```sh
git tag -a <ver> -F <notes-file>
git push origin <ver>
gh release create <ver> --verify-tag --notes-from-tag
```

푸시한 태그를 옮기거나 삭제하지 않습니다. 문제가 있는 릴리스는 새 PATCH 릴리스로 수정합니다. `0.1.0`의 GitHub Release를 소급해서 만들지 않습니다.
