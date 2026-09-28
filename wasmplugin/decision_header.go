// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

const decisionHeader = "x-d5c-waf"
const decisionAAD = "x-d5c-waf:v1"

func newDecisionCipher() (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(os.Getenv("CORAZA_WAF_HEADER_KEY"))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("CORAZA_WAF_HEADER_KEY must be a base64-encoded 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// requestDecision describes request inspection, never an application's status
// or a response-body decision made after the response headers have been sent.
func (ctx *httpContext) requestDecision() string {
	blocked, score, ruleID := 0, 0, 0
	if ctx.interruptedAt == interruptionPhaseHttpRequestHeaders || ctx.interruptedAt == interruptionPhaseHttpRequestBody {
		blocked = 1
		if interruption := ctx.tx.Interruption(); interruption != nil {
			ruleID = interruption.RuleID
		}
	}
	vars := ctx.tx.(plugintypes.TransactionState).Variables().TX()
	level := 1
	if values := vars.Get("blocking_paranoia_level"); len(values) != 0 {
		level, _ = strconv.Atoi(values[0])
	}
	// Early interruptions can precede CRS's final score aggregation.
	for pl := 1; pl <= level && pl <= 4; pl++ {
		if values := vars.Get(fmt.Sprintf("inbound_anomaly_score_pl%d", pl)); len(values) != 0 {
			value, _ := strconv.Atoi(values[0])
			score += value
		}
	}
	// The first matching request rule with a message is the primary rule.
	// Skip bookkeeping and matches from detection-only paranoia levels.
	for _, match := range ctx.tx.MatchedRules() {
		if match.Rule().Phase() > 2 || match.Message() == "" {
			continue
		}
		skip, crs, detection := false, false, false
		for _, tag := range match.Rule().Tags() {
			if tag == "OWASP_CRS" {
				crs = true
			}
			if tag == "anomaly-evaluation" || tag == "reporting" {
				skip = true
			}
			if strings.HasPrefix(tag, "paranoia-level/") {
				detection = true
				pl, _ := strconv.Atoi(strings.TrimPrefix(tag, "paranoia-level/"))
				if pl > level {
					skip = true
				}
			}
		}
		// CRS initialization and exclusion rules can have messages too, but
		// only detection rules carry a paranoia-level tag.
		if !skip && (!crs || detection) {
			ruleID = match.Rule().ID()
			break
		}
	}
	return fmt.Sprintf("v1;b=%d;s=%d;r=%d", blocked, score, ruleID)
}

func (ctx *httpContext) encryptedDecision() string {
	if ctx.decisionToken != "" {
		return ctx.decisionToken
	}
	// Padding hides differences in the lengths of scores and rule IDs.
	plain := make([]byte, 64)
	decision := ctx.requestDecision()
	if len(decision) > len(plain) {
		panic("WAF decision exceeds its envelope")
	}
	copy(plain, decision)
	nonce := make([]byte, ctx.decisionAEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic("WAF decision nonce generation failed")
	}
	token := ctx.decisionAEAD.Seal(nonce, nonce, plain, []byte(decisionAAD))
	ctx.decisionToken = "v1." + base64.RawURLEncoding.EncodeToString(token)
	return ctx.decisionToken
}

func (ctx *httpContext) writeDecisionHeader() {
	if ctx.decisionAEAD == nil {
		return
	}
	headers, err := proxywasm.GetHttpResponseHeaders()
	if err != nil {
		panic("WAF decision response headers unavailable")
	}
	clean := headers[:0]
	for _, header := range headers {
		if !strings.EqualFold(header[0], decisionHeader) {
			clean = append(clean, header)
		}
	}
	if ctx.tx != nil {
		clean = append(clean, [2]string{decisionHeader, ctx.encryptedDecision()})
	}
	if err := proxywasm.ReplaceHttpResponseHeaders(clean); err != nil {
		panic("WAF decision response header failed")
	}
}
