// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
)

func TestPublishedModuleAllocationABI(t *testing.T) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)
	module, err := os.ReadFile("build/main.wasm")
	require.NoError(t, err)
	compiled, err := runtime.CompileModule(ctx, module)
	require.NoError(t, err)
	exports := compiled.ExportedFunctions()
	require.Contains(t, exports, "proxy_on_memory_allocate")
	// Envoy prefers malloc when present and never frees those host buffers.
	// Inspect the published artifact, since raw TinyGo output still needs libc.
	for _, name := range []string{"malloc", "free", "calloc", "realloc"} {
		require.NotContains(t, exports, name)
	}
}
