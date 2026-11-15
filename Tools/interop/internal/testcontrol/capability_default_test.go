// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// 출처: tailscale.com v1.104.6 tstest/integration/testcontrol/capability_default_test.go를 옮겨 적었다(라이선스: 같은 디렉터리의 LICENSE).
// 원본과 다른 곳은 "원본과 다름" 또는 "원본에 없는 보탬" 주석으로 표시한다. 목록은 Tools/interop/README.md의 tailnet 절에 있다.

// 원본과 다름: experiment.reco 대체 구현(reco-experiment.go)을 옮기지 않아 빌드 태그를 지웠다.

package testcontrol_test

// The original test server also implements legacy map protocol versions.
const minTestControlCapabilityVersion = 0
