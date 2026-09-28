//go:build envoy

// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Run with a built plugin: ENVOY_IMAGE=istio/proxyv2:1.31.1 go test -tags=envoy ./wasmplugin -run TestDecisionHeaderEnvoy -count=1.
func TestDecisionHeaderEnvoy(t *testing.T) {
	t.Setenv("CORAZA_WAF_HEADER_KEY", testDecisionKey)
	image := os.Getenv("ENVOY_IMAGE")
	require.NotEmpty(t, image, "ENVOY_IMAGE must name the proxy image to test")
	var calls atomic.Int32
	streamDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Envoy can forward headers before the WAF finishes inspecting a body.
		// Count only complete requests, as an application consuming the body does.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		calls.Add(1)
		if r.Header.Get(decisionHeader) != "" {
			t.Error("client WAF header reached upstream")
		}
		w.Header().Add(decisionHeader, "spoof-one")
		w.Header().Add(decisionHeader, "spoof-two")
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: first\n\n")
			w.(http.Flusher).Flush()
			select {
			case <-streamDone:
			case <-r.Context().Done():
			}
			return
		}
		if r.URL.Path == "/application-denied" {
			w.WriteHeader(http.StatusForbidden)
		}
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	defer close(streamDone)
	_, upstreamPortText, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	require.NoError(t, err)
	portLease, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := portLease.Addr().(*net.TCPAddr).Port
	require.NoError(t, portLease.Close())
	wasm, err := filepath.Abs("../build/main.wasm")
	require.NoError(t, err)
	_, err = os.Stat(wasm)
	require.NoError(t, err)
	config, err := json.Marshal(map[string]interface{}{
		"encrypted_decision_header": true,
		"default_directives":        "default",
		"directives_map": map[string][]string{"default": {
			"Include @recommended-conf", "SecRuleEngine On", "SecResponseBodyAccess Off", "Include @crs-setup-conf",
			`SecAction "id:100000,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=2,setvar:tx.early_blocking=1"`,
			"Include @owasp_crs/REQUEST-*.conf",
			`SecRule REQUEST_URI "@streq /blocked" "id:190001,phase:1,deny,status:403,msg:'header block',setvar:tx.inbound_anomaly_score_pl1=+5"`,
		}},
	})
	require.NoError(t, err)
	bootstrap := fmt.Sprintf(`static_resources:
  listeners:
  - address:
      socket_address: {address: 127.0.0.1, port_value: %d}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: test
          route_config:
            virtual_hosts:
            - name: test
              domains: ["*"]
              routes:
              - match: {prefix: /}
                route: {cluster: upstream, timeout: 0s}
          http_filters:
          - name: envoy.filters.http.wasm
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
              config:
                name: coraza
                configuration:
                  "@type": type.googleapis.com/google.protobuf.StringValue
                  value: %s
                vm_config:
                  vm_id: coraza
                  runtime: envoy.wasm.runtime.v8
                  environment_variables:
                    host_env_keys: [CORAZA_WAF_HEADER_KEY]
                  code:
                    local: {filename: /plugin.wasm}
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: upstream
    type: STATIC
    connect_timeout: 1s
    load_assignment:
      cluster_name: upstream
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: {address: 127.0.0.1, port_value: %s}
`, port, strconv.Quote(string(config)), upstreamPortText)
	path := filepath.Join(t.TempDir(), "envoy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(bootstrap), 0644))
	container, err := exec.Command("docker", "run", "--detach", "--network", "host", "--env", "CORAZA_WAF_HEADER_KEY="+testDecisionKey,
		"--volume", path+":/envoy.yaml:ro", "--volume", wasm+":/plugin.wasm:ro", "--entrypoint", "/usr/local/bin/envoy",
		image, "-c", "/envoy.yaml", "--concurrency", "1", "--disable-hot-restart", "--log-level", "warn").CombinedOutput()
	require.NoError(t, err, "%s", container)
	id := strings.TrimSpace(string(container))
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("Envoy logs: %s", logs)
		}
		_ = exec.Command("docker", "rm", "--force", id).Run()
	})
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 5 * time.Second}
	require.Eventually(t, func() bool {
		response, err := client.Get(base + "/")
		if err != nil {
			return false
		}
		_ = response.Body.Close()
		return response.StatusCode == 200
	}, 45*time.Second, 250*time.Millisecond)
	seen := map[string]bool{}
	for _, tc := range []struct {
		path, body string
		blocked    bool
	}{
		{"/", "", false}, {"/application-denied", "", false}, {"/blocked", "", true},
		{"/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", true},
		{"/api", `{"q":"<script>alert(1)</script>"}`, true},
		{"/stream", "", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			before := calls.Load()
			method := "GET"
			if tc.body != "" {
				method = "POST"
			}
			request, err := http.NewRequest(method, base+tc.path, strings.NewReader(tc.body))
			require.NoError(t, err)
			request.Host = "example.com"
			if tc.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			request.Header.Set("Accept", "*/*")
			request.Header.Set("User-Agent", "Mozilla/5.0")
			request.Header.Set(decisionHeader, "spoofed-client")
			response, err := client.Do(request)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Len(t, response.Header.Values(decisionHeader), 1)
			token := response.Header.Get(decisionHeader)
			require.False(t, seen[token])
			seen[token] = true
			plain := openDecision(t, token)
			if tc.blocked {
				require.Equal(t, 403, response.StatusCode)
				require.Equal(t, "text/plain; charset=utf-8", response.Header.Get("Content-Type"))
				require.Equal(t, "no-store", response.Header.Get("Cache-Control"))
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, "403 FIREWALL "+token+" IF UNEXPECTED FORWARD TO security@d-roy.ca\n", string(body))
				require.Contains(t, plain, "v1;b=1;")
				require.NotContains(t, plain, ";s=0;")
				require.NotContains(t, plain, ";r=949")
				require.NotContains(t, plain, ";r=901")
				if tc.body != "" || tc.path == "/blocked" {
					require.Equal(t, before, calls.Load(), "blocked request completed upstream")
				}
			} else {
				require.Equal(t, "v1;b=0;s=0;r=0", plain)
				if tc.path == "/application-denied" {
					require.Equal(t, 403, response.StatusCode)
					body, err := io.ReadAll(response.Body)
					require.NoError(t, err)
					require.Equal(t, "upstream", string(body))
				} else {
					require.Equal(t, 200, response.StatusCode)
				}
				if tc.path == "/stream" {
					line, err := bufio.NewReader(response.Body).ReadString('\n')
					require.NoError(t, err)
					require.Equal(t, "data: first\n", line)
				}
			}
		})
	}
}
