package tools

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// tri is a three-valued logic result: a rule can match, not match, or depend on
// request properties we do not know (headers, client IP, query, ...).
type tri int

const (
	triNo tri = iota
	triYes
	triUnknown
)

func (t tri) String() string {
	switch t {
	case triYes:
		return "yes"
	case triNo:
		return "no"
	default:
		return "unknown"
	}
}

func triAnd(a, b tri) tri {
	if a == triNo || b == triNo {
		return triNo
	}
	if a == triUnknown || b == triUnknown {
		return triUnknown
	}
	return triYes
}

func triOr(a, b tri) tri {
	if a == triYes || b == triYes {
		return triYes
	}
	if a == triUnknown || b == triUnknown {
		return triUnknown
	}
	return triNo
}

func triNot(a tri) tri {
	switch a {
	case triYes:
		return triNo
	case triNo:
		return triYes
	}
	return triUnknown
}

// ruleNode is a parsed Traefik rule expression.
type ruleNode struct {
	op       string // "&&", "||", "!", "call"
	fn       string
	args     []string
	children []*ruleNode
}

type ruleToken struct {
	kind string // ident, str, (, ), ",", &&, ||, !
	val  string
}

func tokenizeRule(s string) ([]ruleToken, error) {
	var out []ruleToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(' || c == ')' || c == ',' || c == '!':
			out = append(out, ruleToken{kind: string(c)})
			i++
		case strings.HasPrefix(s[i:], "&&"):
			out = append(out, ruleToken{kind: "&&"})
			i += 2
		case strings.HasPrefix(s[i:], "||"):
			out = append(out, ruleToken{kind: "||"})
			i += 2
		case c == '`' || c == '"':
			end := strings.IndexByte(s[i+1:], c)
			if end < 0 {
				return nil, errors.New("unterminated string")
			}
			out = append(out, ruleToken{kind: "str", val: s[i+1 : i+1+end]})
			i += end + 2
		case unicode.IsLetter(rune(c)):
			j := i
			for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j]))) {
				j++
			}
			out = append(out, ruleToken{kind: "ident", val: s[i:j]})
			i = j
		default:
			return nil, fmt.Errorf("unexpected character %q", c)
		}
	}
	return out, nil
}

// Limits for upstream-controlled rule strings: the parser and the evaluators
// recurse, and a Go stack overflow is fatal (cannot be recovered).
const (
	maxRuleLen   = 64 << 10 // bytes
	maxRuleDepth = 100      // nesting of ! and ( )
)

type ruleParser struct {
	toks  []ruleToken
	pos   int
	depth int
}

func (p *ruleParser) enter() error {
	p.depth++
	if p.depth > maxRuleDepth {
		return fmt.Errorf("rule nested deeper than %d levels", maxRuleDepth)
	}
	return nil
}

func (p *ruleParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos].kind
	}
	return ""
}

func (p *ruleParser) or() (*ruleNode, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek() == "||" {
		p.pos++
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		left = &ruleNode{op: "||", children: []*ruleNode{left, right}}
	}
	return left, nil
}

func (p *ruleParser) and() (*ruleNode, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.peek() == "&&" {
		p.pos++
		right, err := p.unary()
		if err != nil {
			return nil, err
		}
		left = &ruleNode{op: "&&", children: []*ruleNode{left, right}}
	}
	return left, nil
}

func (p *ruleParser) unary() (*ruleNode, error) {
	switch p.peek() {
	case "!":
		p.pos++
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer func() { p.depth-- }()
		n, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &ruleNode{op: "!", children: []*ruleNode{n}}, nil
	case "(":
		p.pos++
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer func() { p.depth-- }()
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, errors.New("missing )")
		}
		p.pos++
		return n, nil
	case "ident":
		fn := p.toks[p.pos].val
		p.pos++
		if p.peek() != "(" {
			return nil, fmt.Errorf("expected ( after %s", fn)
		}
		p.pos++
		n := &ruleNode{op: "call", fn: fn}
		for p.peek() != ")" {
			if p.peek() != "str" {
				return nil, fmt.Errorf("expected string argument in %s", fn)
			}
			n.args = append(n.args, p.toks[p.pos].val)
			p.pos++
			if p.peek() == "," {
				p.pos++
			}
		}
		p.pos++
		return n, nil
	}
	return nil, fmt.Errorf("unexpected token %q", p.peek())
}

func parseRule(rule string) (*ruleNode, error) {
	if len(rule) > maxRuleLen {
		return nil, fmt.Errorf("rule longer than %d bytes", maxRuleLen)
	}
	toks, err := tokenizeRule(rule)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, errors.New("empty rule")
	}
	p := &ruleParser{toks: toks}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(toks) {
		return nil, fmt.Errorf("unexpected trailing token %q", toks[p.pos].kind)
	}
	return n, nil
}

// requestInfo is what we know about the hypothetical request.
type requestInfo struct {
	host   string // lower-case, without port
	path   string
	method string
	// tcp: the connection carries TLS (SNI = host)
	tls bool
}

// templateToRegexp converts Traefik v2 / gorilla-mux templates such as
// `{sub:[a-z]+}.example.com` into an anchored regular expression.
func templateToRegexp(tpl, defaultVar string) string {
	var b strings.Builder
	b.WriteString("^")
	for len(tpl) > 0 {
		open := strings.IndexByte(tpl, '{')
		if open < 0 {
			b.WriteString(regexp.QuoteMeta(tpl))
			break
		}
		b.WriteString(regexp.QuoteMeta(tpl[:open]))
		depth, end := 0, -1
		for i := open; i < len(tpl); i++ {
			if tpl[i] == '{' {
				depth++
			} else if tpl[i] == '}' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			b.WriteString(regexp.QuoteMeta(tpl[open:]))
			break
		}
		inner := tpl[open+1 : end]
		if _, pat, ok := strings.Cut(inner, ":"); ok {
			b.WriteString("(" + pat + ")")
		} else {
			b.WriteString("(" + defaultVar + ")")
		}
		tpl = tpl[end+1:]
	}
	b.WriteString("$")
	return b.String()
}

// v2TemplateRe detects gorilla-mux style variables ({name} or {name:pattern}).
var v2TemplateRe = regexp.MustCompile(`\{[A-Za-z_][A-Za-z0-9_]*[:}]`)

func matchRegexp(pattern, value string, caseInsensitive bool) tri {
	if v2TemplateRe.MatchString(pattern) {
		pattern = templateToRegexp(pattern, `[^.]+`)
	}
	if caseInsensitive {
		pattern = "(?i)" + pattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return triUnknown
	}
	if re.MatchString(value) {
		return triYes
	}
	return triNo
}

func anyArg(args []string, f func(string) tri) tri {
	res := triNo
	for _, a := range args {
		res = triOr(res, f(a))
	}
	return res
}

// evalHTTP evaluates an HTTP router rule.
func (n *ruleNode) evalHTTP(r requestInfo) tri {
	switch n.op {
	case "&&":
		return triAnd(n.children[0].evalHTTP(r), n.children[1].evalHTTP(r))
	case "||":
		return triOr(n.children[0].evalHTTP(r), n.children[1].evalHTTP(r))
	case "!":
		return triNot(n.children[0].evalHTTP(r))
	}
	switch strings.ToLower(n.fn) {
	case "host":
		return anyArg(n.args, func(a string) tri {
			if strings.EqualFold(strings.TrimSuffix(a, "."), r.host) {
				return triYes
			}
			return triNo
		})
	case "hostregexp":
		return anyArg(n.args, func(a string) tri { return matchRegexp(a, r.host, true) })
	case "path":
		return anyArg(n.args, func(a string) tri {
			if strings.Contains(a, "{") {
				return matchRegexp(templateToRegexp(a, `[^/]+`), r.path, false)
			}
			if a == r.path {
				return triYes
			}
			return triNo
		})
	case "pathprefix":
		return anyArg(n.args, func(a string) tri {
			if strings.Contains(a, "{") {
				return matchRegexp(strings.TrimSuffix(templateToRegexp(a, `[^/]+`), "$"), r.path, false)
			}
			if strings.HasPrefix(r.path, a) {
				return triYes
			}
			return triNo
		})
	case "pathregexp":
		return anyArg(n.args, func(a string) tri { return matchRegexp(a, r.path, false) })
	case "method":
		return anyArg(n.args, func(a string) tri {
			if strings.EqualFold(a, r.method) {
				return triYes
			}
			return triNo
		})
	}
	// Header, HeaderRegexp, Headers, Query, QueryRegexp, ClientIP, ...
	return triUnknown
}

// evalTCP evaluates a TCP router rule for a connection.
func (n *ruleNode) evalTCP(r requestInfo) tri {
	switch n.op {
	case "&&":
		return triAnd(n.children[0].evalTCP(r), n.children[1].evalTCP(r))
	case "||":
		return triOr(n.children[0].evalTCP(r), n.children[1].evalTCP(r))
	case "!":
		return triNot(n.children[0].evalTCP(r))
	}
	switch strings.ToLower(n.fn) {
	case "hostsni":
		return anyArg(n.args, func(a string) tri {
			if a == "*" {
				return triYes
			}
			if r.tls && strings.EqualFold(a, r.host) {
				return triYes
			}
			return triNo
		})
	case "hostsniregexp":
		if !r.tls {
			return triNo
		}
		return anyArg(n.args, func(a string) tri { return matchRegexp(a, r.host, true) })
	}
	// ClientIP, ALPN, ...
	return triUnknown
}

// unknownMatchers lists matcher names in a rule that cannot be evaluated.
func (n *ruleNode) unknownMatchers(tcp bool) []string {
	var out []string
	var walk func(*ruleNode)
	walk = func(x *ruleNode) {
		if x.op == "call" {
			fn := strings.ToLower(x.fn)
			known := map[string]bool{"host": true, "hostregexp": true, "path": true, "pathprefix": true, "pathregexp": true, "method": true}
			if tcp {
				known = map[string]bool{"hostsni": true, "hostsniregexp": true}
			}
			if !known[fn] {
				out = append(out, x.fn)
			}
			return
		}
		for _, c := range x.children {
			walk(c)
		}
	}
	walk(n)
	return out
}

var singleHostRe = regexp.MustCompile("^Host\\(`([^`]+)`\\)$")

// ghostHost returns the host name when the rule is a single Host() matcher
// without a dot, which is what Traefik's Docker provider generates by default
// (Host(`<service>-<project>`)) when a router has no rule label.
func ghostHost(rule string) (string, bool) {
	m := singleHostRe.FindStringSubmatch(strings.TrimSpace(rule))
	if m == nil || strings.Contains(m[1], ".") || m[1] == "localhost" {
		return "", false
	}
	return m[1], true
}
