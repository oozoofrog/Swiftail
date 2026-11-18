// Calls the Go reference implementation directly. This tool does not duplicate the filter decision logic.
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
	// Preserve partial results on address errors. Install nil from SrcBits and DstPorts.Bits errors as is.
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
					return fixture{}, fmt.Errorf("%s step %d: %w", s.Name, j+1, err)
				}
				continue
			}
			b, err := hex.DecodeString(st.Packet)
			if err != nil {
				return fixture{}, err
			}
			// Use a fresh Parsed for each packet so reused fields do not leak into the next verdict.
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
					return fixture{}, fmt.Errorf("%s step %d: verdict is not final", s.Name, j+1)
				}
			case "out":
				verdict, _ := f.RunOut(&q, 0)
				if verdict != filter.Accept {
					return fixture{}, fmt.Errorf("%s step %d: outbound reference packet rejected", s.Name, j+1)
				}
			default:
				return fixture{}, fmt.Errorf("invalid direction: %s", st.Direction)
			}
		}
	}
	return result, nil
}

func generate(dir string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Errorf("Go module build information is missing")
	}
	found := false
	for _, dep := range info.Deps {
		if dep.Path == "tailscale.com" {
			found = dep.Version == "v1.104.6" && dep.Replace == nil
		}
	}
	if !found {
		return fmt.Errorf("reference tailscale.com version or replace differs")
	}
	first, err := evaluate()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(first, "", "  ")
	if err != nil {
		return err
	}
	// Run the same packet sequence again with new filters to check every verdict, conversion error, and their order.
	second, err := evaluate()
	if err != nil {
		return err
	}
	repeated, err := json.MarshalIndent(second, "", "  ")
	if err != nil {
		return err
	}
	if !bytes.Equal(data, repeated) {
		return fmt.Errorf("Go verdicts were not reproduced for identical input")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "filter-verdicts.json"), append(data, '\n'), 0644)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: filterfixtures <Engine Fixtures directory>")
		os.Exit(1)
	}
	if err := generate(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
