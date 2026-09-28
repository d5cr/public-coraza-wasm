// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func TestRetrieveAddressInfo(t *testing.T) {
	testCases := map[string]struct {
		address          []byte
		port             []byte
		expectedTargetIP string
		expectedPort     int
	}{
		"empty": {
			expectedTargetIP: "",
			expectedPort:     0,
		},
		"127.0.0.1:8080": {
			address:          []byte("127.0.0.10:8080"),
			expectedTargetIP: "127.0.0.10",
			expectedPort:     8080,
		},
		"127.0.0.1:8080 with port": {
			address:          []byte("127.0.0.11:8080"),
			port:             []byte{5, 10, 0, 0, 0, 0, 0, 0}, // 256*10 + 5
			expectedTargetIP: "127.0.0.11",
			expectedPort:     2565,
		},
	}

	for _, target := range []string{"source", "destination"} {
		t.Run(target, func(t *testing.T) {
			for name, tCase := range testCases {
				t.Run(name, func(t *testing.T) {
					opt := proxytest.
						NewEmulatorOption().
						WithVMContext(NewVMContext())

					host, reset := proxytest.NewHostEmulator(opt)
					defer reset()

					require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())

					id := host.InitializeHttpContext()

					if len(tCase.address) > 0 {
						err := host.SetProperty([]string{target, "address"}, []byte(tCase.address))
						require.NoError(t, err)
					}

					if len(tCase.port) > 0 {
						err := host.SetProperty([]string{target, "port"}, []byte(tCase.port))
						require.NoError(t, err)
					}

					targetIP, port := retrieveAddressInfo(debuglog.Noop(), target)
					assert.Equal(t, tCase.expectedTargetIP, targetIP)
					assert.Equal(t, tCase.expectedPort, port)

					host.CompleteHttpContext(id)
				})
			}
		})
	}
}

func TestBodylessRequestPhase2BeforeForwarding(t *testing.T) {
	for _, method := range []string{"GET", "HEAD", "POST"} {
		t.Run(method, func(t *testing.T) {
			host := decisionHost(t, false, "SecRuleEngine On", `SecAction "id:190099,phase:2,deny,status:403"`)
			id := host.InitializeHttpContext()
			require.NoError(t, host.SetProperty([]string{"request", "protocol"}, []byte("HTTP/2.0")))
			action := host.CallOnRequestHeaders(id, [][2]string{{":authority", "example.com"}, {":method", method}, {":path", "/"}, {"content-length", "0"}}, true)
			require.Equal(t, types.ActionPause, action)
			response := host.GetSentLocalResponse(id)
			require.NotNil(t, response, "deny must precede any upstream response")
			require.Equal(t, uint32(403), response.StatusCode)
			host.CompleteHttpContext(id)
		})
	}
}

func TestResponseBodyAfterPartialRequest(t *testing.T) {
	for _, tc := range []struct {
		name, lastChunk, response string
		blocked                   bool
	}{
		{"partial request, denied response", "bbbb", "LEAKxx", true},
		{"complete request, denied response", "b", "LEAKxx", true},
		{"partial request, allowed response", "bbbb", "safe", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := decisionHost(t, false, "SecRuleEngine On", "SecRequestBodyAccess On", "SecRequestBodyLimit 6", "SecRequestBodyLimitAction ProcessPartial", "SecResponseBodyAccess On", "SecResponseBodyMimeType text/plain", `SecRule RESPONSE_BODY "@beginsWith LEAK" "id:190100,phase:4,deny,status:403"`)
			id := host.InitializeHttpContext()
			require.NoError(t, host.SetProperty([]string{"request", "protocol"}, []byte("HTTP/2.0")))
			host.CallOnRequestHeaders(id, [][2]string{{":authority", "example.com"}, {":method", "POST"}, {":path", "/"}, {"content-type", "text/plain"}}, false)
			require.Equal(t, types.ActionPause, host.CallOnRequestBody(id, []byte("aaaa"), false))
			require.Equal(t, types.ActionContinue, host.CallOnRequestBody(id, []byte(tc.lastChunk), true))
			host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}, {"content-type", "text/plain"}}, false)
			host.CallOnResponseBody(id, []byte(tc.response), true)
			expected := []byte(tc.response)
			if tc.blocked {
				expected = bytes.Repeat([]byte{0}, len(tc.response))
			}
			require.Equal(t, expected, host.GetCurrentResponseBody(id))
			host.CompleteHttpContext(id)
		})
	}
}

func TestInspectionMetadataFailure(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	for _, missing := range []string{":authority", ":method", ":path"} {
		t.Run(missing, func(t *testing.T) {
			host := decisionHost(t, true, "SecRuleEngine On")
			id := host.InitializeHttpContext()
			headers := [][2]string{}
			for _, h := range [][2]string{{":authority", "example.com"}, {":method", "GET"}, {":path", "/"}} {
				if h[0] != missing {
					headers = append(headers, h)
				}
			}
			require.Equal(t, types.ActionPause, host.CallOnRequestHeaders(id, headers, true))
			response := host.GetSentLocalResponse(id)
			require.NotNil(t, response)
			require.Equal(t, uint32(500), response.StatusCode)
			if missing != ":authority" {
				require.Equal(t, "v1;b=1;s=0;r=0", openDecision(t, headerValue(t, response.Headers)))
			}
			host.CallOnResponseHeaders(id, response.Headers, true)
			host.CompleteHttpContext(id)
		})
	}
}

func TestRequestBodyWriteFailure(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	// Remove a valid spill directory after configuration validation to force
	// a real native buffer failure. Wasm rejects this at its memory limit.
	spillDir := t.TempDir()
	t.Setenv("TMPDIR", spillDir)
	host := decisionHost(t, true, "SecRuleEngine On", "SecRequestBodyAccess On", "SecRequestBodyLimit 1024", "SecRequestBodyInMemoryLimit 2")
	require.NoError(t, os.Remove(spillDir))
	id := decisionRequest(t, host, "/", []byte(`{"q":"attack"}`))
	response := host.GetSentLocalResponse(id)
	require.NotNil(t, response)
	require.Equal(t, uint32(500), response.StatusCode)
	require.Equal(t, "v1;b=1;s=0;r=0", openDecision(t, headerValue(t, response.Headers)))
	host.CompleteHttpContext(id)
}

func TestResponseCodeProperty(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "serialized integer", true: "malformed property"}[invalid], func(t *testing.T) {
			host := decisionHost(t, false, "SecRuleEngine On", `SecRule RESPONSE_STATUS "@streq 418" "id:190104,phase:3,deny,status:403"`)
			id := decisionRequest(t, host, "/", nil)
			code := make([]byte, 8)
			binary.LittleEndian.PutUint64(code, 418)
			if invalid {
				code = []byte("418")
			}
			require.NoError(t, host.SetProperty([]string{"response", "code"}, code))
			require.Equal(t, types.ActionPause, host.CallOnResponseHeaders(id, nil, true))
			response := host.GetSentLocalResponse(id)
			require.NotNil(t, response)
			status := uint32(403)
			if invalid {
				status = 500
			}
			require.Equal(t, status, response.StatusCode)
			host.CompleteHttpContext(id)
		})
	}
}

func TestRequestHeadersWaitForInspection(t *testing.T) {
	for _, tc := range []struct {
		name, directive string
		want            types.Action
	}{
		{"body inspection", "SecRequestBodyAccess On", types.ActionPause},
		{"body inspection disabled", "SecRequestBodyAccess Off", types.ActionContinue},
		{"engine disabled", "SecRuleEngine Off", types.ActionContinue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := decisionHost(t, false, "SecRuleEngine On", tc.directive)
			id := host.InitializeHttpContext()
			require.Equal(t, tc.want, host.CallOnRequestHeaders(id, [][2]string{{":authority", "example.com"}, {":method", "POST"}, {":path", "/"}}, false))
			host.CompleteHttpContext(id)
		})
	}
	t.Run("phase two with body inspection disabled", func(t *testing.T) {
		host := decisionHost(t, false, "SecRuleEngine On", "SecRequestBodyAccess Off", `SecAction "id:190105,phase:2,deny,status:403"`)
		id := host.InitializeHttpContext()
		require.Equal(t, types.ActionPause, host.CallOnRequestHeaders(id, [][2]string{{":authority", "example.com"}, {":method", "POST"}, {":path", "/"}}, false))
		require.Equal(t, uint32(403), host.GetSentLocalResponse(id).StatusCode)
		host.CompleteHttpContext(id)
	})
}
