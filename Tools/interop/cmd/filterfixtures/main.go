// Go 기준 구현을 직접 호출한다. 필터 판정 로직은 이 도구에 복제하지 않는다.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"

	"go4.org/netipx"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

const reference = "tailscale.com v1.104.6"

type fixture struct {
	Reference string     `json:"reference"`
	Scenarios []scenario `json:"scenarios"`
}

type scenario struct {
	Name              string   `json:"name"`
	Rules             string   `json:"rules"`
	LocalAddresses    []string `json:"localAddresses"`
	CapabilitySources []string `json:"capabilitySources,omitempty"`
	ConversionError   string   `json:"conversionError,omitempty"`
	Steps             []step   `json:"steps"`
}

type step struct {
	Name             string   `json:"name"`
	Direction        string   `json:"direction"`
	Packet           string   `json:"packet,omitempty"`
	Verdict          string   `json:"verdict,omitempty"`
	Rules            string   `json:"rules,omitempty"`
	LocalAddresses   []string `json:"localAddresses,omitempty"`
	ConversionError  string   `json:"conversionError,omitempty"`
	SwiftailDiffers  string   `json:"swiftailDiffers,omitempty"`
	SwiftailExpected string   `json:"swiftailExpected,omitempty"`
}

func install(raw string, locals, capabilitySources []string, previous *filter.Filter) (*filter.Filter, string, error) {
	var rules []tailcfg.FilterRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, "", err
	}
	matches, conversionErr := filter.MatchesFromFilterRules(rules)
	// 주소 오류는 부분 결과를 보존한다. SrcBits·DstPorts.Bits 오류의 nil도 그대로 설치한다.
	var conversion string
	if conversionErr != nil {
		conversion = conversionErr.Error()
	}
	var localNets netipx.IPSetBuilder
	for _, text := range locals {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil, "", err
		}
		localNets.Add(addr)
	}
	nets, err := localNets.IPSet()
	if err != nil {
		return nil, "", err
	}
	var capTest filter.CapTestFunc
	if len(capabilitySources) != 0 {
		sources := make(map[netip.Addr]bool)
		for _, text := range capabilitySources {
			addr, err := netip.ParseAddr(text)
			if err != nil {
				return nil, "", err
			}
			sources[addr] = true
		}
		capTest = func(addr netip.Addr, cap nodecap.Cap) bool {
			return sources[addr] && cap == nodecap.Cap("fixture:test")
		}
	}
	return filter.New(matches, capTest, nets, nil, previous, logger.Discard), conversion, nil
}

func evaluate() (fixture, error) {
	result := fixture{Reference: reference, Scenarios: scenarios()}
	for i := range result.Scenarios {
		s := &result.Scenarios[i]
		f, conversion, err := install(s.Rules, s.LocalAddresses, s.CapabilitySources, nil)
		if err != nil {
			return fixture{}, fmt.Errorf("%s: %w", s.Name, err)
		}
		s.ConversionError = conversion
		for j := range s.Steps {
			st := &s.Steps[j]
			if st.Direction == "replace" {
				f, st.ConversionError, err = install(st.Rules, st.LocalAddresses, s.CapabilitySources, f)
				if err != nil {
					return fixture{}, fmt.Errorf("%s 단계 %d: %w", s.Name, j+1, err)
				}
				continue
			}
			b, err := hex.DecodeString(st.Packet)
			if err != nil {
				return fixture{}, err
			}
			// 매 패킷마다 새 Parsed를 쓴다. 재사용 필드가 다음 판정에 스며들지 않는다.
			var q packet.Parsed
			q.Decode(b)
			switch st.Direction {
			case "in":
				verdict := f.RunIn(&q, 0)
				if verdict == filter.Accept {
					st.Verdict = "accept"
				} else if verdict.IsDrop() {
					st.Verdict = "drop"
				} else {
					return fixture{}, fmt.Errorf("%s 단계 %d: 최종 판정이 아님", s.Name, j+1)
				}
			case "out":
				verdict, _ := f.RunOut(&q, 0)
				if verdict != filter.Accept {
					return fixture{}, fmt.Errorf("%s 단계 %d: 송신 기준 패킷 거절", s.Name, j+1)
				}
			default:
				return fixture{}, fmt.Errorf("잘못된 방향: %s", st.Direction)
			}
		}
	}
	return result, nil
}

func generate(dir string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("Go 모듈 빌드 정보 없음")
	}
	found := false
	for _, dep := range info.Deps {
		if dep.Path == "tailscale.com" {
			found = dep.Version == "v1.104.6" && dep.Replace == nil
		}
	}
	if !found {
		return fmt.Errorf("기준 tailscale.com 버전 또는 replace가 다릅니다")
	}
	first, err := evaluate()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(first, "", "  ")
	if err != nil {
		return err
	}
	// 새 필터들로 같은 패킷 열을 다시 실행하여 모든 판정·변환 오류·순서를 확인한다.
	second, err := evaluate()
	if err != nil {
		return err
	}
	repeated, err := json.MarshalIndent(second, "", "  ")
	if err != nil {
		return err
	}
	if !bytes.Equal(data, repeated) {
		return fmt.Errorf("동일 입력의 Go 판정이 재현되지 않음")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "filter-verdicts.json"), append(data, '\n'), 0644)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "사용법: filterfixtures <Engine Fixtures 폴더>")
		os.Exit(1)
	}
	if err := generate(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
