// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// 출처: tailscale.com v1.104.6 tka/aum_test.go:178-181(TestDeserializeExistingAUMs의 "genesis-aum-2025-11-07").
// 그 시험 자료의 base64 문자열을 그대로 옮겼다. main_test.go가 원본 파일에 같은 문자열이 있는지 확인한다.

package main

// goTestGenesis는 Go 시험이 쓰는 genesis 체크포인트(558바이트, 끄기 값 10개, 키 2개, 서명 1개)다.
const goTestGenesis = "pAEFAvYFpQH2AopYII0sLaLSEZU3W5DT1dG2WYnzjCBr4tXtVbCT2LvA9LS6WCAQhwVGDiUGRiu3P63gucZ/8otjt2DXyk+OBjbh5iWx1Fgg5VU4oRQiMoq5qK00McfpwtmjcheVammLCRwzdp2Zje9YIHDoOXe4ogPSy7lfA/veyPCKM6iZe3PTgzhQZ4W5Sh7wWCBYQtiQ6NcRlyVARJxgAj1BbbvdJQ0t4m+vHqU1J02oDlgg2sksJA+COfsBkrohwHBWlbKrpS8Mvigpl+enuHw9rIJYIB/+CUBBBLUz0KeHu7NKrg5ZEhjjPUWhNcf9QTNHjuNWWCCJuxqPZ6/IASPTmAERaoKnBNH/D+zY4p4TUGHR4fACjFggMtDAipPutgcxKnU9Tg2663gP3KlTQfztV3hBwiePZdRYIGYeD2erBkRouSL20lOnWHHlRq5kmNfN6xFb2CTaPjnXA4KjAQECAQNYIADftG3yaitV/YMoKSBP45zgyeodClumN9ZaeQg/DmCEowEBAgEDWCBRKbmWSzOyHXbHJuYn8s7dmMPDzxmIjgBoA80cBYgItAQbEWOrxfqJzIkFG/5uNUp0s/ScF4GiAVggAN+0bfJqK1X9gygpIE/jnODJ6h0KW6Y31lp5CD8OYIQCWEAENvzblKV2qx6PED5YdGy8kWa7nxEnaeuMmS5Wkx0n7CXs0XxD5f2NIE+pSv9cOsNkfYNndQkYD7ne33hQOsQM"

// goTestWrappedAuthKey는 tka/sig_test.go:479(TestDecodeWrappedAuthkey)의 서명된 인증 키 문자열이다.
// 인증 키·개인 키 모두 Go 저장소에 공개된 시험 값이다.
const goTestWrappedAuthKey = "tskey-auth-k7UagY1CNTRL-ZZZZZ--TLpAEDA1ggnXuw4/fWnNWUwcoOjLemhOvml1juMl5lhLmY5sBUsj8EWEAfL2gdeD9g8VDw5tgcxCiHGlEb67BgU2DlFzZApi4LheLJraA+pYjTGChVhpZz1iyiBPD+U2qxDQAbM3+WFY0EBlggxmVqG53Hu0Rg+KmHJFMlUhfgzo+AQP6+Kk9GzvJJOs4-k36RdoSFqaoARfQo0UncHAV0t3YTqrkD5r/z2jTrE43GZWobnce7RGD4qYckUyVSF+DOj4BA/r4qT0bO8kk6zg"
