package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The RPC import closure is narrower than the selected module graph. In
// particular, tidy drops unused security floors and reselects old upstream
// crypto/net/grpc requirements. Check the actual selected graph, not go.sum
// membership or an assertion that those packages execute in this example.
func TestSelectedModuleGraphSecurityFloors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"),
		"list", "-mod=readonly", "-m", "-json", "all")
	command.Env = append(os.Environ(), "GOPROXY=off", "GOTOOLCHAIN=local")
	raw, err := command.Output()
	if err != nil || len(raw) > 1<<20 {
		t.Fatal("selected offline module graph unavailable")
	}
	want := map[string]string{
		"github.com/ethereum/go-ethereum": "v1.17.0",
		"github.com/gorilla/websocket":    "v1.5.3",
		"golang.org/x/crypto":             "v0.52.0",
		"golang.org/x/net":                "v0.55.0",
		"google.golang.org/grpc":          "v1.83.1",
	}
	seen := make(map[string]bool)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	for {
		var module struct {
			Path    string
			Version string
			Replace json.RawMessage
		}
		if err := decoder.Decode(&module); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal("selected module graph malformed")
		}
		if version, ok := want[module.Path]; ok {
			if seen[module.Path] || module.Version != version || len(module.Replace) != 0 {
				t.Fatal("selected security floor changed or replaced")
			}
			seen[module.Path] = true
		}
	}
	if len(seen) != len(want) {
		t.Fatal("selected security floor missing")
	}
}
