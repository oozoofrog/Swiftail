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
		return nil, fmt.Errorf("기준 모듈 조회: %w", err)
	}
	var module struct {
		Dir, Version string
		Replace      any
	}
	if err := json.Unmarshal(data, &module); err != nil {
		return nil, err
	}
	if module.Version != "v1.104.6" || module.Replace != nil {
		return nil, errors.New("기준 tailscale.com 버전이 다릅니다")
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
	// Go는 모듈 캐시 내부 overlay를 금지한다. 원본의 임시 복사본에만 얹는다.
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
		return nil, fmt.Errorf("실제 Go 기준 구현 실행: %w", err)
	}
	return data, nil
}
func generate(dir string) error {
	data, err := evaluate()
	if err != nil {
		return err
	}
	if !json.Valid(data) {
		return errors.New("Go 결과가 JSON이 아닙니다")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "tunnel-settings-fixtures.json"), data, 0644)
}
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "사용법: tunnelfixtures <Engine Fixtures 폴더>")
		os.Exit(1)
	}
	if err := generate(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
