// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"
)

// The real-proxy test runs these same rules against the compiled module. Keeping
// this independent of CRS separates operator changes from rule-set updates.
var operatorCases = []struct {
	name, operator, value string
	match                 bool
	capture               string
}{
	{"regex multiline", "@rx ^alpha.*omega$", "before\nalpha\nmiddle\nomega\nafter", true, ""},
	{"regex case fold", "@rx (?i)^alphabet$", "AlPhAbEt", true, ""},
	{"regex clean", "@rx ^alphabet$", "ordinary", false, ""},
	{"regex binary bytes", `@rx \xac\xed\x00\x05`, "\xac\xed\x00\x05", true, ""},
	{"regex binary mismatch", `@rx \xac\xed\x00\x05`, "\xac\xed\x00\x04", false, ""},
	{"phrase overlap", "@pm alpha alphabet", "the ALPHABET", true, ""},
	{"phrase capture", "@pm alpha alphabet", "the ALPHABET", true, "ALPHABET"},
	{"regex capture", "@rx alpha(bet)", "the alphabet", true, "alphabet"},
	{"phrase clean", "@pm alpha alphabet", "ordinary", false, ""},
	{"SQLi", "@detectSQLi", "1' OR '1'='1", true, ""},
	{"SQLi clean", "@detectSQLi", "ordinary words", false, ""},
	{"XSS", "@detectXSS", "<script>alert(1)</script>", true, ""},
	{"XSS clean", "@detectXSS", "ordinary words", false, ""},
}

func operatorDirectives(index int) []string {
	tc := operatorCases[index]
	directives := []string{"SecRuleEngine On", "SecRequestBodyAccess Off", "SecResponseBodyAccess Off"}
	if tc.capture != "" {
		return append(directives,
			fmt.Sprintf(`SecRule ARGS:value "%s" "id:190199,phase:2,pass,capture"`, tc.operator),
			fmt.Sprintf(`SecRule TX:0 "@streq %s" "id:190200,phase:2,deny,status:403,msg:'operator capture',setvar:tx.inbound_anomaly_score_pl1=+5"`, tc.capture))
	}
	return append(directives,
		fmt.Sprintf(`SecRule ARGS:value "%s" "id:190200,phase:2,deny,status:403,msg:'operator match',setvar:tx.inbound_anomaly_score_pl1=+5"`, tc.operator))
}

func TestOperatorCompatibility(t *testing.T) {
	for index, tc := range operatorCases {
		t.Run(tc.name, func(t *testing.T) {
			config := coraza.NewWAFConfig()
			for _, directive := range operatorDirectives(index) {
				config = config.WithDirectives(directive)
			}
			waf, err := coraza.NewWAF(config)
			require.NoError(t, err)
			tx := waf.NewTransaction()
			defer tx.Close()
			tx.ProcessURI("/?value="+url.QueryEscape(tc.value), "GET", "HTTP/1.1")
			interruption := tx.ProcessRequestHeaders()
			if interruption == nil {
				interruption, err = tx.ProcessRequestBody()
				require.NoError(t, err)
			}
			require.Equal(t, tc.match, interruption != nil)
			if interruption != nil {
				require.Equal(t, 190200, interruption.RuleID)
			}
		})
	}
}
