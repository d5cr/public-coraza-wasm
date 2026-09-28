# Coraza Proxy WASM as WasmPlugin for Istio

WasmPlugins allow the Istio proxy to be enhanced with WebAssembly filters. 
The coraza proxy wasm acts as one of these filters, adding WAF features to Istio. 
The execution order within Envoy's filter chain is set by phase and priority, facilitating 
intricate interactions between user-provided WasmPlugins and Istio's built-in filters.

## Istio Setup

Given a multitude of possible Istio setups, we will only cover the most common one with the following assumptions:

- Istio is installed in the `istio-system` namespace
- The mesh has an entrypoint served by a `istio-ingressgateway` service
- Services served by Istio have an `istio-proxy` sidecar

## Getting started

The coraza proxy wasm can filter traffic inside the mesh at multiple locations.

### At Ingress gateway for all incoming traffic

The envoy pod of the ingress-gateway can be configured to use the coraza proxy wasm as a filter, thus 
filtering all incoming traffic.

The following example shows how to configure embedded [Core Rule Set](https://github.com/coreruleset/coreruleset)
at the ingress gateway and use the coraza proxy wasm as a filter.

It utilizes the 
[WasmPlugin](https://istio.io/latest/docs/reference/config/proxy_extensions/wasm-plugin/) resource of Istio.
This way the filter can be configured via the `pluginConfig` field and envoy configuration is abstracted away.

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: coraza-ingressgateway
  namespace: istio-ingress
spec:
  imagePullPolicy: IfNotPresent
  phase: AUTHN
  pluginConfig:
    default_directives: default
    directives_map:
      default:
      - Include @demo-conf
      - SecDebugLogLevel 9
      - SecRuleEngine On
      - Include @crs-setup-conf
      - Include @owasp_crs/*.conf
  selector:
    matchLabels:
      app: istio-ingressgateway
      istio: ingressgateway
  url: oci://ghcr.io/corazawaf/coraza-proxy-wasm
```

The `selector` needs to match labels attached to the pods of the ingress gateway.
The `url` points to the OCI image of the coraza proxy wasm, which is provided by the project.

All traffic entering the mesh via the ingress gateway will now be filtered by the coraza proxy wasm 
and violations will be logged to the istio-proxy's log and a `403 Forbidden` response will be returned to the client.

### At each namespace individually

Traffic which has successfully passed the ingress gateway can be filtered at each namespace individually using
a similar approach as above. 
The following example will show how to load the entire [Core Rule Set](https://github.com/coreruleset/coreruleset).

```yaml
apiVersion: extensions.istio.io/v1alpha1
kind: WasmPlugin
metadata:
  name: coraza-core-rule-set
  namespace: my-app
spec:
  imagePullPolicy: IfNotPresent
  phase: AUTHN
  pluginConfig:
    default_directives: default
    directives_map:
      default:
      - Include @demo-conf
      - SecDebugLogLevel 9
      - SecRuleEngine On
      - Include @crs-setup-conf
      - Include @owasp_crs/*.conf
  selector:
    matchLabels:
      app: my-app
  url: oci://ghcr.io/corazawaf/coraza-proxy-wasm
```

The `selector` needs to match labels attached to the pods of the namespace where filtering is desired.
The `namespace` field needs to match the namespace of the pods.

All traffic entering the namespace  will now be filtered by the coraza proxy wasm using the
entire [Core Rule Set](https://github.com/coreruleset/coreruleset) and 
violations will be logged to the istio-proxy's log and a `403 Forbidden` response will be returned to the client.

Traffic which has already been filtered by the ingress gateway will not reach the namespace and will only be 
logged to the istio-proxy's log in the namespace of the ingress-gateway.

## Testing and Logs

The coraza proxy wasm logs violations to the istio-proxy's log.

The following example shows a violation to the rule `REQUEST-941-APPLICATION-ATTACK-XSS` which is included in the
istio-ingressgateways filter configuration.

```bash
curl 'https://my-app.my-domain.com/anything?arg=<script>alert(0)</script>' -IL
HTTP/2 403
vary: Accept-Encoding
date: Tue, 10 Oct 2023 13:45:47 GMT
server: istio-envoy
```

Depending on your configuration a log in the istio-proxy's log will look like this:

```text
envoy wasm external/envoy/source/extensions/common/wasm/context.cc:1157	
wasm log istio-ingress.coraza-ingressgateway: [client "my-client"] 
Coraza: Warning. Javascript method detected [file "@owasp_crs/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] 
[line "7982"] [id "941390"] [rev ""] [msg "Javascript method detected"] 
[data "Matched Data: alert( found within ARGS_GET:arg: <script>alert(0)</script>"] 
[severity "critical"] [ver "OWASP_CRS/4.0.0-rc1"] [maturity "0"] [accuracy "0"] 
[tag "application-multi"] [tag "language-multi"] [tag "attack-xss"] [tag "paranoia-level/1"] 
[tag "OWASP_CRS"] [tag "capec/1000/152/242"] [hostname "my-hostname"] [uri "/anything/?arg=<script>alert(0)</script>"] 
[unique_id "wTueIQloYpvpWNLzVfy"]	thread=27
```

## Encrypted request decisions

This fork can return an encrypted `X-D5C-WAF` response header. Enable it in the
plugin configuration and pass `CORAZA_WAF_HEADER_KEY` from the proxy's environment:

```yaml
spec:
  failStrategy: FAIL_CLOSE
  vmConfig:
    env:
      - name: CORAZA_WAF_HEADER_KEY
        valueFrom: HOST
  pluginConfig:
    encrypted_decision_header: true
    # Keep the existing directives_map and default_directives here.
```

Set that environment variable on the gateway container using a Kubernetes
`secretKeyRef`. Its value must be a base64-encoded, randomly generated 32-byte
key. Keep the key in your secret manager; do not put it in the WasmPlugin,
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
