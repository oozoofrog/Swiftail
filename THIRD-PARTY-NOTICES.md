# 제3자 고지

Swiftail의 코드는 `LICENSE`(BSD-3-Clause)를 따른다. 일부 파일은 아래 프로젝트의 코드를 Swift로 옮겨 적었거나 그 규칙을 따랐다. 그런 파일은 머리말에 출처(프로젝트, 버전, 파일, 함수)와 라이선스를 적었다. 이 문서는 그 라이선스들의 원문을 한곳에 모은 것이다.

Swiftail의 라이브러리(`Sources/`)는 외부 패키지에 의존하지 않는다. 아래 "시험 도구의 의존"은 `Tools/interop`의 Go 시험 도구가 빌드할 때 Go 모듈로 받는 것이고, 이 저장소에 그 코드가 들어 있지는 않다(`Tools/interop/internal/testcontrol`은 예외: Tailscale의 시험용 제어 서버를 옮겨 적은 사본이다).

## 옮겨 적은 코드

| 출처 | 라이선스 | 쓰인 곳 |
| --- | --- | --- |
| Tailscale (`tailscale.com`) | BSD-3-Clause | 제어 프로토콜, DERP, magicsock, Tailnet Lock, DNS, 인증서 발급의 규칙과 일부 함수. `Tools/interop/internal/testcontrol`의 사본 |
| Go 표준 라이브러리와 `golang.org/x/net` | BSD-3-Clause | edwards25519 연산, JSON 인코딩 규칙, DNS 이름 해석 |
| wireguard-go (`github.com/tailscale/wireguard-go`) | MIT | WireGuard 타이머와 재전송 방지 창의 규칙 |
| `github.com/fxamacker/cbor` | MIT | CBOR 디코딩의 판정 규칙 |

### Tailscale

```
BSD 3-Clause License

Copyright (c) 2020 Tailscale Inc & contributors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### Go 표준 라이브러리, `golang.org/x/net`

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

### wireguard-go

옮긴 파일의 머리말에 있는 저작권 표기: `Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.`

```
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### fxamacker/cbor

```
MIT License

Copyright (c) 2019-present Faye Amacker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 시험 도구의 의존

`Tools/interop/go.mod`의 직접 의존이다. 저장소에 코드가 들어 있지 않고 빌드할 때 받는다. 각 모듈의 라이선스는 그 모듈의 `LICENSE` 파일을 따른다.

| 모듈 | 라이선스 |
| --- | --- |
| `tailscale.com` | BSD-3-Clause |
| `github.com/tailscale/wireguard-go` | MIT |
| `golang.org/x/net` | BSD-3-Clause |
| `filippo.io/edwards25519` | BSD-3-Clause |
| `github.com/hdevalence/ed25519consensus` | BSD-3-Clause |
| `github.com/miekg/dns` | BSD-3-Clause |
| `github.com/letsencrypt/pebble/v2` | MPL-2.0 |
| `github.com/letsencrypt/challtestsrv` | MPL-2.0 |
