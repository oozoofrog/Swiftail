package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixturesMatchGo(t *testing.T) {
	actual, err := actualMaps(scenarios())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "Tests", "SwiftailControlTests", "Fixtures", "map-sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatal("저장 자료와 실제 mapSession 결과가 다릅니다. mapfixtures로 재생성하세요")
	}
	requests, err := json.MarshalIndent(requestFixtures(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err = os.ReadFile(filepath.Join("..", "..", "..", "..", "Tests", "SwiftailControlTests", "Fixtures", "requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(requests, '\n'), want) {
		t.Fatal("저장 자료와 Go 요청 부호화가 다릅니다")
	}
}

func TestResponsesPreserveJSON(t *testing.T) {
	var empty, omitted, null bool
	for _, session := range scenarios() {
		for _, step := range session.Steps {
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(step.Response), &raw); err != nil {
				t.Fatal(err)
			}
			if step.Name == "Peers 빈 배열" {
				empty = string(raw["Peers"]) == "[]"
			}
			if step.Name == "Peers 키 생략" {
				_, found := raw["Peers"]
				omitted = !found
			}
			if step.Name == "Peers null" {
				null = string(raw["Peers"]) == "null"
			}
		}
	}
	if !empty || !omitted || !null {
		t.Fatal("Peers의 빈 배열·생략·null을 보존하지 않았습니다")
	}
}

func TestRequestZeroAndStatusFields(t *testing.T) {
	for _, fixture := range requestFixtures() {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(fixture.JSON), &fields); err != nil {
			t.Fatal(err)
		}
		switch fixture.Name {
		case "zero 등록":
			if string(fields["Expiry"]) != `"0001-01-01T00:00:00Z"` || string(fields["Hostinfo"]) != "null" || string(fields["NodeKeySignature"]) != "null" {
				t.Fatal("필수 zero 필드 불일치")
			}
			if !strings.Contains(string(fields["NodeKey"]), strings.Repeat("0", 64)) {
				t.Fatal("zero 공개 키 불일치")
			}
			if _, found := fields["Auth"]; found {
				t.Fatal("Auth는 생략해야 합니다")
			}
		case "상태 갱신":
			if _, found := fields["Stream"]; found {
				t.Fatal("false Stream은 생략해야 합니다")
			}
			if string(fields["OmitPeers"]) != "true" || len(fields["Endpoints"]) == 0 || len(fields["EndpointTypes"]) == 0 {
				t.Fatal("상태 갱신 필드 불일치")
			}
		}
	}
}
