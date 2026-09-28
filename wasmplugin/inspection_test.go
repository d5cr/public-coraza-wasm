// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	ctypes "github.com/corazawaf/coraza/v3/types"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

type inspectionTestVM struct {
	vmContext
	stream *httpContext
}

type inspectionTestPlugin struct {
	corazaPlugin
	vm *inspectionTestVM
}

func (vm *inspectionTestVM) NewPluginContext(uint32) types.PluginContext {
	return &inspectionTestPlugin{vm: vm}
}

func (p *inspectionTestPlugin) NewHttpContext(id uint32) types.HttpContext {
	p.vm.stream = p.corazaPlugin.NewHttpContext(id).(*httpContext)
	return p.vm.stream
}

// The engine can fail independently of the host buffer. Keep a real transaction
// for lifecycle and rule state, and inject errors only at the selected boundary.
type failingTransaction struct {
	ctypes.Transaction
	boundary string
}

func (tx failingTransaction) WriteRequestBody(b []byte) (*ctypes.Interruption, int, error) {
	if tx.boundary == "request write" {
		return nil, 0, errors.New("request buffer unavailable")
	}
	return tx.Transaction.WriteRequestBody(b)
}

func (tx failingTransaction) ProcessRequestBody() (*ctypes.Interruption, error) {
	if tx.boundary == "request evaluation" {
		return nil, errors.New("request evaluation unavailable")
	}
	return tx.Transaction.ProcessRequestBody()
}

func (tx failingTransaction) WriteResponseBody(b []byte) (*ctypes.Interruption, int, error) {
	if tx.boundary == "response write" {
		return nil, 0, errors.New("response buffer unavailable")
	}
	return tx.Transaction.WriteResponseBody(b)
}

func (tx failingTransaction) ProcessResponseBody() (*ctypes.Interruption, error) {
	if tx.boundary == "response evaluation" {
		return nil, errors.New("response evaluation unavailable")
	}
	return tx.Transaction.ProcessResponseBody()
}

func TestInspectionEngineFailures(t *testing.T) {
	for _, boundary := range []string{"request write", "request evaluation", "response write", "response evaluation"} {
		t.Run(boundary, func(t *testing.T) {
			vm := &inspectionTestVM{}
			host, reset := proxytest.NewHostEmulator(proxytest.NewEmulatorOption().WithVMContext(vm).WithPluginConfiguration([]byte(`{"directives_map":{"default":["SecRuleEngine On","SecRequestBodyAccess On","SecResponseBodyAccess On","SecResponseBodyMimeType text/plain"]},"default_directives":"default"}`)))
			t.Cleanup(reset)
			require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
			id := host.InitializeHttpContext()
			host.CallOnRequestHeaders(id, [][2]string{{":authority", "example.com"}, {":method", "POST"}, {":path", "/"}}, false)
			vm.stream.tx = failingTransaction{vm.stream.tx, boundary}
			action := host.CallOnRequestBody(id, []byte("body"), true)
			if strings.HasPrefix(boundary, "request") {
				require.Equal(t, types.ActionPause, action)
				response := host.GetSentLocalResponse(id)
				require.NotNil(t, response)
				require.Equal(t, uint32(500), response.StatusCode)
			} else {
				require.Equal(t, types.ActionContinue, action)
				host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}, {"content-type", "text/plain"}}, false)
				action = host.CallOnResponseBody(id, []byte("sensitive"), false)
				if boundary == "response evaluation" {
					require.Equal(t, types.ActionPause, action)
					host.CallOnResponseBody(id, []byte(" content"), true)
					require.Equal(t, bytes.Repeat([]byte{0}, len("sensitive content")), host.GetCurrentResponseBody(id))
				} else {
					require.Equal(t, bytes.Repeat([]byte{0}, len("sensitive")), host.GetCurrentResponseBody(id))
				}
				// A later callback must not resume forwarding after the initial error.
				host.CallOnResponseBody(id, []byte("more"), true)
				require.Equal(t, []byte{0, 0, 0, 0}, host.GetCurrentResponseBody(id))
			}
			host.CompleteHttpContext(id)
		})
	}
}
