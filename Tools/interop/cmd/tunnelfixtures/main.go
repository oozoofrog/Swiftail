package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed bridge.go.txt
var bridge []byte

//go:embed worker.go.txt
var worker []byte

func evaluate() ([]byte, error) {
	cmd := exec.Command("go", "list", "-m", "-json", "tailscale.com")
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("look up reference module: %w", err)
	}
	var module struct {
		Dir, Version string
		Replace      any
	}
	if err := json.Unmarshal(data, &module); err != nil {
		return nil, err
	}
	if module.Version != "v1.104.6" || module.Replace != nil {
		return nil, errors.New("reference tailscale.com version differs")
	}
	build, err := exec.Command("eyebuild", "dir", "interop-tools").Output()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(strings.TrimSpace(string(build)), "tunnelfixtures-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	bridgePath := filepath.Join(dir, "bridge.go")
	workerPath := filepath.Join(dir, "main.go")
	overlayPath := filepath.Join(dir, "overlay.json")
	// Go forbids overlays inside the module cache. Overlay only a temporary copy of the original.
	reference := filepath.Join(dir, "tailscale")
	if err := os.CopyFS(reference, os.DirFS(module.Dir)); err != nil {
		return nil, err
	}
	modfile := filepath.Join(dir, "go.mod")
	moduleFile, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return nil, err
	}
	sourceModfile := strings.TrimSpace(string(moduleFile))
	mod, err := os.ReadFile(sourceModfile)
	if err != nil {
		return nil, err
	}
	mod = append(mod, []byte("\nreplace tailscale.com => "+fmt.Sprintf("%q", reference)+"\n")...)
	if err := os.WriteFile(modfile, mod, 0600); err != nil {
		return nil, err
	}
	sum, err := os.ReadFile(filepath.Join(filepath.Dir(sourceModfile), "go.sum"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0600); err != nil {
		return nil, err
	}
	virtualPath := filepath.Join(reference, "ipn", "ipnlocal", "swiftail_fixtures.go")
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{virtualPath: bridgePath}})
	if err != nil {
		return nil, err
	}
	for path, content := range map[string][]byte{bridgePath: bridge, workerPath: worker, overlayPath: overlay} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			return nil, err
		}
	}
	cmd = exec.Command("go", "run", "-modfile", modfile, "-overlay", overlayPath, workerPath)
	cmd.Stderr = os.Stderr
	data, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("run actual Go reference implementation: %w", err)
	}
	return data, nil
}
func generate(dir string) error {
	data, err := evaluate()
	if err != nil {
		return err
	}
	if !json.Valid(data) {
		return errors.New("Go output is not JSON")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "tunnel-settings-fixtures.json"), data, 0644)
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: tunnelfixtures <Engine Fixtures directory>")
		os.Exit(1)
	}
	if err := generate(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
