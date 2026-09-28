// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
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
