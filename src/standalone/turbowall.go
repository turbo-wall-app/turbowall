package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"database/sql"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const MaxBodySize = 128 * 1024 // 128 KB limit

func init() {
	caddy.RegisterModule(WAF{})
	httpcaddyfile.RegisterHandlerDirective("custom_waf", parseCaddyfile)
}

// WAF implements an HTTP middleware that evaluates rules.
type WAF struct {
	RulesRaw  string `json:"rules,omitempty"`
	RulesFile string `json:"rules_file,omitempty"`
	DbPath    string `json:"db_path,omitempty"`

	rules     []Rule
	rulesLock sync.RWMutex
	logger    *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (WAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.custom_waf",
		New: func() caddy.Module { return new(WAF) },
	}
}

// Provision sets up the WAF by parsing the JSON rules.
func (w *WAF) Provision(ctx caddy.Context) error {
	w.logger = ctx.Logger()

	if w.DbPath != "" {
		db, err := InitDB(w.DbPath)
		if err != nil {
			return fmt.Errorf("failed to init db: %v", err)
		}
		rules, err := LoadRulesFromDB(db)
		if err != nil {
			w.logger.Error("failed to load initial rules from db", zap.Error(err))
		} else {
			w.rules = rules
		}
		InitLogger(db)
		InitRateLimiter(db)
		go w.pollRulesFromDB(db)
	} else if w.RulesFile != "" {
		data, err := os.ReadFile(w.RulesFile)
		if err != nil {
			return fmt.Errorf("failed to read WAF rules file %s: %v", w.RulesFile, err)
		}
		if err := json.Unmarshal(data, &w.rules); err != nil {
			return fmt.Errorf("failed to parse WAF rules from file: %v", err)
		}
	} else if w.RulesRaw != "" {
		if err := json.Unmarshal([]byte(w.RulesRaw), &w.rules); err != nil {
			return fmt.Errorf("failed to parse inline WAF rules: %v", err)
		}
	}
	return nil
}

func (w *WAF) pollRulesFromDB(db *sql.DB) {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		rules, err := LoadRulesFromDB(db)
		if err != nil {
			w.logger.Error("failed to poll rules from db", zap.Error(err))
			continue
		}
		w.rulesLock.Lock()
		w.rules = rules
		w.rulesLock.Unlock()
	}
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (w *WAF) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// ==========================================
	// PHASE 1: REQUEST EVALUATION
	// ==========================================
	reqBodyText := safelyReadBody(&r.Body)

	ipSrc := r.Header.Get("CF-Connecting-IP")
	if ipSrc == "" {
		ipSrc = r.RemoteAddr
	}

	reqContext := map[string]string{
		"ip.src":                ipSrc,
		"http.request.uri.path": r.URL.Path,
		"http.request.method":   r.Method,
		"http.user_agent":       r.UserAgent(),
		"http.host":             r.Host,
		"http.request.body":     reqBodyText,
	}

	reqResult := w.runWafEngine("request", reqContext)
	if reqResult.Blocked {
		w.logger.Warn("Blocked by WAF at request phase", zap.String("path", r.URL.Path))
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("403 Forbidden - Blocked by WAF"))
		return nil // Stop chain
	}

	// ==========================================
	// PREPARE FOR ORIGIN
	// ==========================================
	// CRITICAL: Strip compression headers so the origin responds in plain text!
	// If the origin sends GZIP, the WAF cannot inspect the body.
	r.Header.Del("Accept-Encoding")

	// Intercept the response safely into our custom buffer
	rb := newResponseBuffer(rw, w, reqContext, r)

	// Call the reverse_proxy
	err := next.ServeHTTP(rb, r)
	if err != nil {
		return err
	}
	
	// If the origin finished responding and we never filled the buffer enough to trigger evaluation
	if !rb.wafEvaluated {
		rb.evaluateWAF()
		
		if !rb.wafBlocked {
			// WAF allowed the small response. Flush it to the client.
			rb.flushHeaders()
			if rb.status == 0 {
				rb.status = http.StatusOK
			}
			rw.WriteHeader(rb.status)
			rw.Write(rb.buf.Bytes())
		}
	}

	return nil
}

// ---------------------------------------------------------
// HELPER: Custom Response Interceptor
// ---------------------------------------------------------
type responseBuffer struct {
	http.ResponseWriter
	status      int
	buf         bytes.Buffer
	wroteHeader bool
	headers     http.Header
	
	// Streaming support
	waf          *WAF
	reqContext   map[string]string
	request      *http.Request
	wafEvaluated bool
	wafBlocked   bool
	bytesWritten int
}

func newResponseBuffer(w http.ResponseWriter, waf *WAF, reqContext map[string]string, request *http.Request) *responseBuffer {
	return &responseBuffer{
		ResponseWriter: w,
		headers:        make(http.Header),
		waf:            waf,
		reqContext:     reqContext,
		request:        request,
	}
}

// Intercept Header() so reverse_proxy writes to our map, not directly to the client
func (rb *responseBuffer) Header() http.Header {
	return rb.headers
}

func (rb *responseBuffer) WriteHeader(code int) {
	if rb.wroteHeader {
		return
	}
	rb.status = code
	rb.wroteHeader = true
}

func (rb *responseBuffer) Write(b []byte) (int, error) {
	if !rb.wroteHeader {
		rb.WriteHeader(http.StatusOK)
	}

	// If WAF already evaluated and blocked, discard
	if rb.wafEvaluated && rb.wafBlocked {
		return len(b), nil
	}

	// If WAF evaluated and allowed, stream directly to client
	if rb.wafEvaluated && !rb.wafBlocked {
		return rb.ResponseWriter.Write(b)
	}

	// WAF not yet evaluated, we are buffering
	spaceLeft := MaxBodySize - rb.bytesWritten
	
	// If the new chunk fits entirely in the remaining buffer
	if len(b) <= spaceLeft {
		rb.buf.Write(b)
		rb.bytesWritten += len(b)
		return len(b), nil
	}

	// The chunk exceeds the remaining buffer.
	// Fill the buffer up to the max size.
	rb.buf.Write(b[:spaceLeft])
	rb.bytesWritten += spaceLeft
	
	// Evaluate WAF NOW because buffer is full
	rb.evaluateWAF()

	if rb.wafBlocked {
		return len(b), nil // Drop the rest
	}

	// Allowed! Write everything buffered so far to the real client
	rb.flushHeaders()
	rb.ResponseWriter.WriteHeader(rb.status)
	rb.ResponseWriter.Write(rb.buf.Bytes())

	// Write the remainder of the current chunk
	remainder := b[spaceLeft:]
	n, err := rb.ResponseWriter.Write(remainder)
	return spaceLeft + n, err
}

func (rb *responseBuffer) evaluateWAF() {
	rb.wafEvaluated = true

	resContext := make(map[string]string)
	for k, v := range rb.reqContext {
		resContext[k] = v
	}

	resContext["http.response.body"] = rb.buf.String()
	resContext["http.response.code"] = fmt.Sprintf("%d", rb.status)

	resResult := rb.waf.runWafEngine("response", resContext)
	if resResult.Blocked {
		rb.wafBlocked = true
		rb.waf.logger.Warn("Blocked by WAF at response phase (buffered)", zap.String("path", rb.request.URL.Path))
		
		// Send 403 to real client
		rb.ResponseWriter.Header().Set("Content-Type", "text/plain")
		rb.ResponseWriter.WriteHeader(http.StatusForbidden)
		rb.ResponseWriter.Write([]byte("403 Forbidden - Blocked by WAF"))
	}
}

func (rb *responseBuffer) flushHeaders() {
	for k, vv := range rb.headers {
		for _, v := range vv {
			rb.ResponseWriter.Header().Add(k, v)
		}
	}
}

// Unwrap allows Caddy internal modules to access the underlying writer
func (rb *responseBuffer) Unwrap() http.ResponseWriter {
	return rb.ResponseWriter
}

// ---------------------------------------------------------
// ENGINE LOGIC & AST (No changes needed here)
// ---------------------------------------------------------
type Rule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Phase      string `json:"phase"`
	Expression string `json:"expression"`
	Limit      int    `json:"limit,omitempty"`
	Window     int    `json:"window,omitempty"`
}

type WafResult struct{ Blocked bool }

func (w *WAF) runWafEngine(currentPhase string, context map[string]string) WafResult {
	w.rulesLock.RLock()
	rules := w.rules
	w.rulesLock.RUnlock()

	for _, rule := range rules {
		if rule.Phase != currentPhase {
			continue
		}
		if evaluateExpression(rule.Expression, context) {
			switch rule.Action {
			case "block":
				w.logger.Info("WAF BLOCK", zap.String("phase", currentPhase), zap.String("rule", rule.ID))
				LogRequest(LogEvent{RuleID: rule.ID, Action: "block", Phase: currentPhase, IP: context["ip.src"], Path: context["http.request.uri.path"]})
				return WafResult{Blocked: true}
			case "allow":
				w.logger.Info("WAF ALLOW", zap.String("phase", currentPhase), zap.String("rule", rule.ID))
				LogRequest(LogEvent{RuleID: rule.ID, Action: "allow", Phase: currentPhase, IP: context["ip.src"], Path: context["http.request.uri.path"]})
				return WafResult{Blocked: false}
			case "log":
				w.logger.Info("WAF LOG", zap.String("phase", currentPhase), zap.String("rule", rule.ID))
				LogRequest(LogEvent{RuleID: rule.ID, Action: "log", Phase: currentPhase, IP: context["ip.src"], Path: context["http.request.uri.path"]})
				continue
			case "rate_limit":
				if rule.Limit > 0 {
					key := rule.ID + ":" + context["ip.src"]
					if !AllowRequest(key, rule.Limit, rule.Window) {
						w.logger.Warn("RATE LIMIT EXCEEDED", zap.String("phase", currentPhase), zap.String("rule", rule.ID))
						LogRequest(LogEvent{RuleID: rule.ID, Action: "rate_limit", Phase: currentPhase, IP: context["ip.src"], Path: context["http.request.uri.path"]})
						return WafResult{Blocked: true}
					}
				}
				continue
			}
		}
	}
	return WafResult{Blocked: false}
}

func safelyReadBody(bodyReader *io.ReadCloser) string {
	if bodyReader == nil || *bodyReader == nil {
		return ""
	}
	buf := new(bytes.Buffer)
	limitReader := io.LimitReader(*bodyReader, MaxBodySize)
	_, _ = io.Copy(buf, limitReader)
	remainingBody := io.MultiReader(bytes.NewReader(buf.Bytes()), *bodyReader)
	*bodyReader = io.NopCloser(remainingBody)
	return buf.String()
}

type Token struct{ Type, Value string }
type ASTNode struct {
	Type             string
	Left, Right      *ASTNode
	Field, Op, Value string
}

var tokenRegex = regexp.MustCompile(`(?i)\s*(?:(\()|(\))|(and|or|==|!=|contains|matches)|"([^"]*)"|'([^']*)'|([a-zA-Z0-9_.-]+))\s*`)

func tokenize(expr string) []Token {
	var tokens []Token
	matches := tokenRegex.FindAllStringSubmatch(expr, -1)
	for _, match := range matches {
		if match[1] != "" {
			tokens = append(tokens, Token{"LPAREN", "("})
		} else if match[2] != "" {
			tokens = append(tokens, Token{"RPAREN", ")"})
		} else if match[3] != "" {
			tokens = append(tokens, Token{"OP", strings.ToLower(match[3])})
		} else if match[4] != "" {
			tokens = append(tokens, Token{"STRING", match[4]})
		} else if match[5] != "" {
			tokens = append(tokens, Token{"STRING", match[5]})
		} else if match[6] != "" {
			tokens = append(tokens, Token{"IDENT", match[6]})
		}
	}
	return tokens
}

type Parser struct {
	tokens []Token
	pos    int
}

func parseTokens(tokens []Token) *ASTNode {
	p := &Parser{tokens: tokens, pos: 0}
	return p.parseExpr()
}
func (p *Parser) parseExpr() *ASTNode {
	node := p.parseTerm()
	for p.pos < len(p.tokens) && p.tokens[p.pos].Value == "or" {
		p.pos++
		node = &ASTNode{Type: "OR", Left: node, Right: p.parseTerm()}
	}
	return node
}
func (p *Parser) parseTerm() *ASTNode {
	node := p.parseFactor()
	for p.pos < len(p.tokens) && p.tokens[p.pos].Value == "and" {
		p.pos++
		node = &ASTNode{Type: "AND", Left: node, Right: p.parseFactor()}
	}
	return node
}
func (p *Parser) parseFactor() *ASTNode {
	if p.pos >= len(p.tokens) {
		return nil
	}
	if p.tokens[p.pos].Type == "LPAREN" {
		p.pos++
		node := p.parseExpr()
		if p.pos < len(p.tokens) && p.tokens[p.pos].Type == "RPAREN" {
			p.pos++
		}
		return node
	}
	if p.pos+2 >= len(p.tokens) {
		return &ASTNode{Type: "ERROR"}
	}
	field, op, val := p.tokens[p.pos], p.tokens[p.pos+1], p.tokens[p.pos+2]
	p.pos += 3
	return &ASTNode{Type: "COND", Field: field.Value, Op: op.Value, Value: val.Value}
}

func evaluateExpression(expr string, ctx map[string]string) bool {
	tokens := tokenize(expr)
	if len(tokens) == 0 {
		return false
	}
	return evaluateAST(parseTokens(tokens), ctx)
}

func evaluateAST(node *ASTNode, ctx map[string]string) bool {
	if node == nil || node.Type == "ERROR" {
		return false
	}
	if node.Type == "OR" {
		return evaluateAST(node.Left, ctx) || evaluateAST(node.Right, ctx)
	}
	if node.Type == "AND" {
		return evaluateAST(node.Left, ctx) && evaluateAST(node.Right, ctx)
	}
	if node.Type == "COND" {
		rawFieldVal := ctx[node.Field]
		lowerFieldVal, targetVal := strings.ToLower(rawFieldVal), node.Value
		lowerTargetVal := strings.ToLower(targetVal)

		switch node.Op {
		case "==":
			if strings.Contains(targetVal, "*") {
				return wildcardMatch(lowerTargetVal, lowerFieldVal)
			}
			return lowerFieldVal == lowerTargetVal
		case "!=":
			if strings.Contains(targetVal, "*") {
				return !wildcardMatch(lowerTargetVal, lowerFieldVal)
			}
			return lowerFieldVal != lowerTargetVal
		case "contains":
			return strings.Contains(lowerFieldVal, lowerTargetVal)
		case "matches":
			cleanRegexStr := targetVal
			if strings.HasPrefix(targetVal, "(?i)") {
				cleanRegexStr = targetVal
			} else {
				cleanRegexStr = "(?i)" + cleanRegexStr
			}
			matched, err := regexp.MatchString(cleanRegexStr, rawFieldVal)
			if err != nil {
				return false
			}
			return matched
		}
	}
	return false
}

func wildcardMatch(pattern, str string) bool {
	replacer := strings.NewReplacer(".", `\.`, "+", `\+`, "?", `\?`, "^", `\^`, "$", `\$`, "(", `\(`, ")", `\)`, "[", `\[`, "]", `\]`, "{", `\{`, "}", `\}`, "|", `\|`, "\\", `\\`)
	regexStr := "^" + strings.ReplaceAll(replacer.Replace(pattern), "*", ".*") + "$"
	matched, _ := regexp.MatchString("(?i)"+regexStr, str)
	return matched
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var w WAF
	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "rules":
				if !h.Args(&w.RulesRaw) {
					return nil, h.ArgErr()
				}
			case "rules_file":
				if !h.Args(&w.RulesFile) {
					return nil, h.ArgErr()
				}
			case "db_path":
				if !h.Args(&w.DbPath) {
					return nil, h.ArgErr()
				}
			default:
				return nil, h.Errf("unrecognized custom_waf subdirective: %s", h.Val())
			}
		}
	}
	return &w, nil
}

var (
	_ caddy.Provisioner           = (*WAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*WAF)(nil)
)
