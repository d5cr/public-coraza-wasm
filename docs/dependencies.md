# Dependency updates

The root and `magefiles` Go modules are separate. Update both with `GOWORK=off`,
run `go mod tidy` in each directory, then run `go work sync` from the root.
Check the embedded CRS version, the recommended Coraza configuration, the images
in the Compose files, and the pinned tools and actions in the build workflow.

The Coraza v3.8.1 recommended rules are embedded in
`wasmplugin/rules/coraza.conf-recommended.conf`. They include argument-limit rules
200004 and 200005 and URI parsing rule 200009. The deployment configuration must
select `SecRuleEngine` explicitly after its public rule includes. The embedded
recommended configuration does not choose detection-only or blocking mode.
Coraza defaults to On if a deployment omits this directive. Before upgrading,
set the intended mode explicitly; deployments that relied on the old embedded
DetectionOnly setting would otherwise begin blocking.

The fork defaults full transaction audit logging to Off. Wasm supports these
records through the proxy's info-level log via the serial audit writer; Off is
not a runtime requirement. The deployment configuration owns the audit policy.
Rule-match logging is separate from full transaction audit logging.

The following compatibility pins remain necessary:

- Go 1.26.8 and TinyGo 0.41.1 with the GC liveness repair from
  [tinygo-org/tinygo#5751](https://github.com/tinygo-org/tinygo/pull/5751).
  The workflow builds the pinned compiler source and verifies its regression.
  TinyGo 0.42 adds runtime requirements that the existing Envoy integration
  cannot satisfy. The build checks the repaired compiler identity.
- `github.com/wasilibs/go-re2` v1.7.0 supplies the TinyGo static libraries used
  by the custom Wasm target. Later releases change that integration and require
  separate runtime and memory validation.
- `github.com/kaptinlin/jsonschema` v0.9.8 supports the Go 1.26 toolchain.
  Versions 0.9.9 and 0.9.10 require Go 1.27.

Before relaxing these pins, run the compiled module tests and real Envoy checks
in both evaluation modes. Native Go tests alone do not check Wasm startup,
imports, allocation, or request streaming. The release workflow verifies both
modes and publishes the default multiphase module only after verification passes.
