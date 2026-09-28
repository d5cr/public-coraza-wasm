// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/proxytest"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

const testDecisionKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func decisionHost(t *testing.T, enabled bool, rules ...string) proxytest.HostEmulator {
	t.Helper()
	config, err := json.Marshal(map[string]interface{}{
		"encrypted_decision_header": enabled,
		"directives_map":            map[string][]string{"default": rules},
		"default_directives":        "default",
	})
	require.NoError(t, err)
	host, reset := proxytest.NewHostEmulator(proxytest.NewEmulatorOption().WithVMContext(NewVMContext()).WithPluginConfiguration(config))
	t.Cleanup(reset)
	require.Equal(t, types.OnPluginStartStatusOK, host.StartPlugin())
	return host
}

func decisionRequest(t *testing.T, host proxytest.HostEmulator, path string, body []byte) uint32 {
	t.Helper()
	id := host.InitializeHttpContext()
	require.NoError(t, host.SetProperty([]string{"request", "protocol"}, []byte("HTTP/2.0")))
	method := "GET"
	if len(body) != 0 {
		method = "POST"
	}
	headers := [][2]string{{":authority", "example.com"}, {":method", method}, {":path", path}, {"accept", "*/*"}, {"user-agent", "Mozilla/5.0"}, {"content-type", "application/json"}, {decisionHeader, "client-spoof"}}
	host.CallOnRequestHeaders(id, headers, len(body) == 0)
	if len(body) != 0 && host.GetSentLocalResponse(id) == nil {
		host.CallOnRequestBody(id, body, true)
	}
	return id
}

func headerValue(t *testing.T, headers [][2]string) string {
	t.Helper()
	var tokens []string
	for _, header := range headers {
		if strings.EqualFold(header[0], decisionHeader) {
			tokens = append(tokens, header[1])
		}
	}
	require.Len(t, tokens, 1)
	return tokens[0]
}

func openDecision(t *testing.T, token string) string {
	t.Helper()
	require.True(t, strings.HasPrefix(token, "v1."))
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "v1."))
	require.NoError(t, err)
	aead, err := newDecisionCipher()
	require.NoError(t, err)
	require.Len(t, data, aead.NonceSize()+64+aead.Overhead())
	plain, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], []byte(decisionAAD))
	require.NoError(t, err)
	return string(bytes.TrimRight(plain, "\x00"))
}

func TestEncryptedDecisionHeader(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	rules := []string{
		"Include @recommended-conf", "SecRuleEngine On", "SecResponseBodyAccess Off", "Include @crs-setup-conf",
		`SecAction "id:100000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2,setvar:tx.early_blocking=1"`,
		"Include @owasp_crs/REQUEST-*.conf",
	}
	for _, tc := range []struct {
		name, path, body string
		blocked          bool
	}{
		{"clean", "/", "", false},
		{"SQL injection", "/?id=1%27%20OR%20%271%27=%271", "", true},
		{"XSS", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", true},
		{"JSON attack", "/api", `{"name":"<script>alert(1)</script>"}`, true},
		{"normal JSON", "/api", `{"name":"Alice","enabled":true}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := decisionHost(t, true, rules...)
			id := decisionRequest(t, host, tc.path, []byte(tc.body))
			for _, header := range host.GetCurrentRequestHeaders(id) {
				require.NotEqual(t, decisionHeader, strings.ToLower(header[0]))
			}
			response := host.GetSentLocalResponse(id)
			if tc.blocked {
				// Without multiphase evaluation, bodyless requests finish phase 2
				// when response headers arrive. The header must report that deny too.
				if response == nil {
					host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}}, true)
					response = host.GetSentLocalResponse(id)
				}
				require.NotNil(t, response)
				require.Equal(t, uint32(403), response.StatusCode)
				plain := openDecision(t, headerValue(t, response.Headers))
				require.Contains(t, plain, "v1;b=1;")
				require.NotContains(t, plain, ";s=0;")
				require.Regexp(t, `;r=9[0-9]{5}$`, plain)
				require.NotContains(t, plain, ";r=949")
			} else {
				require.Nil(t, response)
				// Application 403s must not be reported as WAF blocks.
				host.CallOnResponseHeaders(id, [][2]string{{":status", "403"}, {"content-type", "text/event-stream"}, {decisionHeader, "upstream-spoof"}, {decisionHeader, "another-spoof"}, {decisionHeader, "third-spoof"}}, false)
				require.Equal(t, "v1;b=0;s=0;r=0", openDecision(t, headerValue(t, host.GetCurrentResponseHeaders(id))))
				require.Equal(t, types.ActionContinue, host.CallOnResponseBody(id, []byte("data: hello\n\n"), false))
			}
			host.CompleteHttpContext(id)
		})
	}
}

func TestDecisionScoreBeforeAggregation(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	for _, tc := range []struct{ name, action, expected string }{
		{"below threshold", "pass", "v1;b=0;s=3;r=101"},
		{"direct interruption", "deny,status:403", "v1;b=1;s=3;r=101"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := decisionHost(t, true, "SecRuleEngine On", `SecRule REQUEST_URI "@streq /match" "id:101,phase:1,`+tc.action+`,msg:'test match',setvar:tx.inbound_anomaly_score_pl1=+3"`)
			id := decisionRequest(t, host, "/match", nil)
			var token string
			if response := host.GetSentLocalResponse(id); response != nil {
				token = headerValue(t, response.Headers)
			} else {
				host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}}, true)
				token = headerValue(t, host.GetCurrentResponseHeaders(id))
			}
			require.Equal(t, tc.expected, openDecision(t, token))
			host.CompleteHttpContext(id)
		})
	}
}

func TestDecisionSkipsCRSInitialization(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	for _, path := range []string{"/", "/attack"} {
		t.Run(path, func(t *testing.T) {
			host := decisionHost(t, true,
				"SecRuleEngine On",
				`SecRule REQUEST_URI "@rx ." "id:901340,phase:1,pass,nolog,msg:'Enabling body inspection',tag:'OWASP_CRS'"`,
				`SecRule REQUEST_URI "@streq /attack" "id:942100,phase:1,deny,status:403,msg:'SQL Injection',tag:'OWASP_CRS',tag:'paranoia-level/1',setvar:tx.inbound_anomaly_score_pl1=+5"`,
			)
			id := decisionRequest(t, host, path, nil)
			if path == "/attack" {
				response := host.GetSentLocalResponse(id)
				require.NotNil(t, response)
				require.Equal(t, "v1;b=1;s=5;r=942100", openDecision(t, headerValue(t, response.Headers)))
			} else {
				host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}}, true)
				require.Equal(t, "v1;b=0;s=0;r=0", openDecision(t, headerValue(t, host.GetCurrentResponseHeaders(id))))
			}
			host.CompleteHttpContext(id)
		})
	}
}

func TestDecisionNonceAndAuthentication(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	host := decisionHost(t, true, "SecRuleEngine On")
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		id := decisionRequest(t, host, "/", nil)
		host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}}, true)
		token := headerValue(t, host.GetCurrentResponseHeaders(id))
		require.False(t, seen[token])
		seen[token] = true
		require.Equal(t, "v1;b=0;s=0;r=0", openDecision(t, token))
		data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "v1."))
		require.NoError(t, err)
		aead, err := newDecisionCipher()
		require.NoError(t, err)
		_, err = aead.Open(nil, data[:12], data[12:], []byte("wrong-purpose"))
		require.Error(t, err)
		data[len(data)-1] ^= 1
		_, err = aead.Open(nil, data[:12], data[12:], []byte(decisionAAD))
		require.Error(t, err)
		host.CompleteHttpContext(id)
	}
}

func TestDecisionHeaderRequiresValidKey(t *testing.T) {
	for _, key := range []string{"", "invalid", "c2hvcnQ="} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("CORAZA_WAF_HEADER_KEY", key)
			host, reset := proxytest.NewHostEmulator(proxytest.NewEmulatorOption().WithVMContext(NewVMContext()).WithPluginConfiguration([]byte(`{"encrypted_decision_header":true}`)))
			defer reset()
			require.Equal(t, types.OnPluginStartStatusFailed, host.StartPlugin())
		})
	}
	t.Setenv("CORAZA_WAF_HEADER_KEY", "")
	host := decisionHost(t, false, "SecRuleEngine On")
	id := decisionRequest(t, host, "/", nil)
	host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}, {decisionHeader, "unchanged"}}, true)
	require.Equal(t, "unchanged", headerValue(t, host.GetCurrentResponseHeaders(id)))
	host.CompleteHttpContext(id)
	_, err := parsePluginConfiguration([]byte(`{"encrypted_decision_header":"true"}`), func(string) {})
	require.Error(t, err)
}

func TestDecisionExcludesDetectionOnlyLevelsAndResponseRules(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	host := decisionHost(t, true,
		"SecRuleEngine On",
		`SecAction "id:1,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1"`,
		`SecRule REQUEST_URI "@streq /" "id:102,phase:1,pass,msg:'detection-only match',tag:'paranoia-level/2',setvar:tx.inbound_anomaly_score_pl2=+5"`,
		`SecRule REQUEST_URI "@streq /" "id:101,phase:1,pass,msg:'scored match',tag:'paranoia-level/1',setvar:tx.inbound_anomaly_score_pl1=+3"`,
		`SecRule RESPONSE_STATUS "@streq 200" "id:103,phase:3,deny,status:403,msg:'response match'"`,
	)
	id := decisionRequest(t, host, "/", nil)
	host.CallOnResponseHeaders(id, [][2]string{{":status", "200"}}, true)
	response := host.GetSentLocalResponse(id)
	require.NotNil(t, response)
	require.Equal(t, "v1;b=0;s=3;r=101", openDecision(t, headerValue(t, response.Headers)))
	host.CompleteHttpContext(id)
}
