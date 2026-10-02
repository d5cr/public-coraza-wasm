// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tetratelabs/wabin/binary"
	"github.com/tetratelabs/wabin/wasm"
)

func TestMinimumVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		version string
		accept  bool
	}{
		{"1.27.1", true}, {"1.27.2", true}, {"1.28.0", true}, {"2.0.0", true},
		{"1.27.0", false}, {"1.26.9", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\nprintf 'go version go"+tc.version+" linux/amd64\\n'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			err := checkVersion("go", "1.27.1")
			if (err == nil) != tc.accept {
				t.Fatalf("version %s: accept=%v, error=%v", tc.version, tc.accept, err)
			}
		})
	}
}

func TestBuildRejectsAffectedCompiler(t *testing.T) {
	for _, version := range []string{"0.41.0", "0.41.1", "0.43.0-dev-881da3ee"} {
		t.Run(version, func(t *testing.T) {
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "tinygo"), []byte("#!/bin/sh\nprintf 'tinygo version "+version+" linux/amd64\\n'\n"), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			if err := Build(); err == nil || !strings.Contains(err.Error(), "build requires TinyGo "+requiredTinygoVersion) {
				t.Fatalf("expected compiler rejection, got %v", err)
			}
		})
	}
}

func TestBuildRejectsInvalidInitialPages(t *testing.T) {
	for _, value := range []string{"-1", "0", "65537", "4294967296", "invalid"} {
		t.Run(value, func(t *testing.T) {
			bin := t.TempDir()
			compiler := "#!/bin/sh\nif [ \"$1\" = version ]; then echo 'tinygo version " + requiredTinygoVersion + " linux/amd64'; else echo 'unexpected compiler invocation' >&2; exit 1; fi\n"
			if err := os.WriteFile(filepath.Join(bin, "tinygo"), []byte(compiler), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("INITIAL_PAGES", value)
			if err := Build(); err == nil || !strings.Contains(err.Error(), "INITIAL_PAGES") {
				t.Fatalf("expected INITIAL_PAGES rejection, got %v", err)
			}
		})
	}
}

func TestPatchWasmInitialPages(t *testing.T) {
	for _, pages := range []uint32{1, 2100, 65536} {
		dir := t.TempDir()
		input, output := filepath.Join(dir, "input.wasm"), filepath.Join(dir, "output.wasm")
		raw := binary.EncodeModule(&wasm.Module{MemorySection: &wasm.Memory{Min: 1}})
		if err := os.WriteFile(input, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := patchWasm(input, output, pages); err != nil {
			t.Fatal(err)
		}
		patched, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		module, err := binary.DecodeModule(patched, wasm.CoreFeaturesV2)
		if err != nil {
			t.Fatal(err)
		}
		if module.MemorySection.Min != pages {
			t.Fatalf("memory minimum = %d, want %d", module.MemorySection.Min, pages)
		}
	}
}
