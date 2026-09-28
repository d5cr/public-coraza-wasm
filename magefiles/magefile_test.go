// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
