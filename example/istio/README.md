# Coraza in Istio

Request-body inspection holds request headers until evaluation finishes. Envoy
must set `allow_on_headers_stop_iteration: true` for that to work: its default
Proxy-Wasm header-pause behavior also stops body callbacks. Omitting the setting
can stall inspected requests. Explicit `SecRequestBodyAccess Off` policies still
stream and evaluate phase 2 before forwarding headers.

Istio's `WasmPlugin` API does not expose this host option. Use an `EnvoyFilter`
that adds a complete ECDS extension and references it from the HTTP filter chain.
An `EXTENSION_CONFIG` MERGE patch cannot modify the generated WasmPlugin resource;
Istio handles ADD for these extension configurations. Do not install both
integrations for the same workload.

## Gateway configuration

Replace the namespace, workload selector and release tag below. Pin an immutable
OCI digest in production. The Istio agent downloads the OCI module and replaces
the remote source with a local file before Envoy receives the extension.
`sha256: nil` is Istio's sentinel for an unset module checksum; an OCI digest pin
still fixes the artifact identity.

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: coraza
  namespace: istio-ingress
spec:
  workloadSelector:
    labels:
      istio: ingressgateway
  configPatches:
    - applyTo: EXTENSION_CONFIG
      match:
        context: GATEWAY
      patch:
        operation: ADD
        value:
          name: istio-ingress.coraza
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
            config:
              name: coraza
              allow_on_headers_stop_iteration: true
              failure_policy: FAIL_CLOSED
              vm_config:
                vm_id: coraza
                runtime: envoy.wasm.runtime.v8
                code:
                  remote:
                    http_uri:
                      uri: oci://ghcr.io/d5cr/public-coraza-wasm:<release-tag>
                      cluster: _
                      timeout: 30s
                    sha256: nil
              configuration:
                "@type": type.googleapis.com/google.protobuf.StringValue
                value: |
                  {
                    "default_directives": "default",
                    "directives_map": {
                      "default": [
                        "Include @recommended-conf",
                        "SecRuleEngine On",
                        "SecResponseBodyAccess Off",
                        "Include @crs-setup-conf",
                        "Include @owasp_crs/REQUEST-*.conf"
                      ]
                    }
                  }
    - applyTo: HTTP_FILTER
      match:
        context: GATEWAY
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
      patch:
        operation: INSERT_FIRST
        value:
          name: istio-ingress.coraza
          config_discovery:
            config_source:
              ads: {}
              initial_fetch_timeout: 0s
              resource_api_version: V3
            type_urls:
              - type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
```

The extension and HTTP-filter names must match. Check the resulting filter order
when other EnvoyFilters insert authentication or rate-limit filters. For inbound
sidecar inspection, use `SIDECAR_INBOUND` for both contexts and select the
application workloads in their namespace instead.

## Verify the integration

Inspect the proxy's effective configuration, not only the Kubernetes manifest:

```sh
istioctl proxy-config ecds <gateway-pod> -n istio-ingress -o json
```

The extension must show `allow_on_headers_stop_iteration: true` and local Wasm
code supplied by the agent. Send allowed requests and attack-shaped requests to
a disposable test backend, including a backend that responds before reading the
request body. A body rejected by phase 2 must not deliver its headers upstream.
Also verify streaming endpoints that intentionally disable body inspection.
Rule violations appear in the proxy logs. Host download or startup failures are
closed by the configured failure policy.

## Encrypted request decisions

This fork can return an encrypted `X-D5C-WAF` response header. Enable it in the
plugin configuration and pass `CORAZA_WAF_HEADER_KEY` from the proxy's environment:

Set `encrypted_decision_header` to `true` inside the JSON `configuration.value`
and add the host environment mapping to the extension's `config`:

```yaml
vm_config:
  environment_variables:
    host_env_keys:
      - CORAZA_WAF_HEADER_KEY
```

Set that environment variable on the gateway container using a Kubernetes
`secretKeyRef`. Its value must be a base64-encoded, randomly generated 32-byte
key. Keep the key in your secret manager; do not put it in the EnvoyFilter,
container image, repository, or browser. When enabled, a missing or malformed
key prevents plugin startup. Restart the gateway proxies when rotating the key.
The feature is disabled by default and leaves upstream behavior unchanged.

The wire format is `v1.<base64url-without-padding>`. The encoded bytes contain a
12-byte random nonce followed by 64 bytes of ciphertext and a 16-byte AES-256-GCM
authentication tag. The associated data is the UTF-8 string `x-d5c-waf:v1`.
The plaintext is `v1;b=<0|1>;s=<score>;r=<rule ID>`, padded with zero bytes to
64 bytes. Padding keeps score and rule-ID lengths out of the public header.
The token is diagnostic data, not an authorization credential or replay proof.

`b` records a request-phase WAF interruption, not an application's HTTP status.
`s` sums the inbound CRS anomaly counters through the blocking paranoia level,
including scores accrued before early blocking. `r` is the first matching
request rule with a message, excluding CRS initialization, score gates, reporting rules, and
rules above the blocking paranoia level. It falls back to the interrupting rule
ID; zero means no such rule is available. Engine limits can block without a rule
or anomaly score. The header is a request-inspection snapshot; response rules
that execute later cannot change a header already sent to the client.

The filter removes client-supplied copies and replaces all upstream copies of
this header. Both allowed and locally blocked requests receive a token. The
feature adds no response-body buffering. Configure `SecResponseBodyAccess Off`
when only incoming traffic should be inspected and responses must stream.

With this feature enabled, WAF-generated 403 responses use
`Content-Type: text/plain; charset=utf-8` and `Cache-Control: no-store`:

```text
403 FIREWALL <encrypted token> IF UNEXPECTED FORWARD TO security@d-roy.ca
```

The body and `X-D5C-WAF` carry the same token. Application-generated 403 bodies
and other WAF status codes keep their existing behavior.

Inspection failures return HTTP 500 instead of forwarding an uninspected
request. When a transaction exists, its encrypted request decision records
`b=1` with `r=0` if no rule caused the failure. Response-body inspection
failures suppress the remaining response content because its headers may
already have been sent. Keep the host's failure policy closed: if the host
cannot replace forbidden response bytes, the plugin traps to stop the stream.

An authority without a matching or default policy also returns HTTP 500.
To intentionally allow unmatched authorities without inspection, configure an
explicit default policy with `SecRuleEngine Off`.
