package tools

import "testing"

func TestRuleEvalHTTP(t *testing.T) {
	req := requestInfo{host: "app.example.com", path: "/api/v1/items", method: "GET"}
	for _, tc := range []struct {
		rule string
		want tri
	}{
		{"Host(`app.example.com`)", triYes},
		{"Host(`APP.example.com`)", triYes},
		{"Host(`other.example.com`)", triNo},
		{"Host(`a.example.com`, `app.example.com`)", triYes}, // v2 multi-arg
		{"Host(`app.example.com`) && PathPrefix(`/api`)", triYes},
		{"Host(`app.example.com`) && PathPrefix(`/admin`)", triNo},
		{"Host(`x.example.com`) || Host(`app.example.com`)", triYes},
		{"Host(`app.example.com`) && !PathPrefix(`/api`)", triNo},
		{"Host(`app.example.com`) && (Path(`/x`) || PathRegexp(`^/api/v[0-9]+/`))", triYes},
		{"HostRegexp(`^[a-z]+\\.example\\.com$`)", triYes},
		{"HostRegexp(`^[a-z]{2,3}\\.example\\.com$`)", triYes},
		{"HostRegexp(`{sub:[a-z]+}.example.com`)", triYes}, // v2 template
		{"HostRegexp(`{sub}.other.com`)", triNo},
		{"Path(`/api/{version}/items`)", triYes},
		{"Method(`POST`)", triNo},
		{"Method(`GET`, `POST`)", triYes},
		{"Host(`app.example.com`) && Header(`X-Debug`, `1`)", triUnknown},
		{"Host(`nope.example.com`) && Header(`X-Debug`, `1`)", triNo},
		{"Host(`app.example.com`) || ClientIP(`10.0.0.0/8`)", triYes},
		{"PathPrefix(`/`)", triYes},
	} {
		n, err := parseRule(tc.rule)
		if err != nil {
			t.Errorf("%s: parse: %v", tc.rule, err)
			continue
		}
		if got := n.evalHTTP(req); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.rule, got, tc.want)
		}
	}
}

func TestRuleEvalTCP(t *testing.T) {
	tlsReq := requestInfo{host: "mail.example.de", tls: true}
	plain := requestInfo{host: "mail.example.de"}
	for _, tc := range []struct {
		rule       string
		tls, plain tri
	}{
		{"HostSNI(`*`)", triYes, triYes},
		{"HostSNI(`mail.example.de`)", triYes, triNo},
		{"HostSNIRegexp(`^(mail|autodiscover)[.]example[.]de$`)", triYes, triNo},
		{"HostSNIRegexp(`{sub:[a-z]+}.example.de`)", triYes, triNo},
		{"HostSNI(`other.de`)", triNo, triNo},
		{"HostSNI(`*`) && ClientIP(`10.0.0.1`)", triUnknown, triUnknown},
	} {
		n, err := parseRule(tc.rule)
		if err != nil {
			t.Fatalf("%s: %v", tc.rule, err)
		}
		if got := n.evalTCP(tlsReq); got != tc.tls {
			t.Errorf("%s tls: got %s want %s", tc.rule, got, tc.tls)
		}
		if got := n.evalTCP(plain); got != tc.plain {
			t.Errorf("%s plain: got %s want %s", tc.rule, got, tc.plain)
		}
	}
}

func TestRuleParseErrors(t *testing.T) {
	for _, r := range []string{"", "Host(`a`", "Host(`a`) &&", "Host(a)", "Host(`a`) Path(`/`)", "Host(`unterminated)"} {
		if _, err := parseRule(r); err == nil {
			t.Errorf("%q: expected parse error", r)
		}
	}
	n, _ := parseRule("Host(`a`) && (Header(`X`, `1`) || Query(`q`, `1`))")
	if u := n.unknownMatchers(false); len(u) != 2 {
		t.Errorf("unknown matchers: %v", u)
	}
}

func TestGhostHost(t *testing.T) {
	for rule, want := range map[string]bool{
		"Host(`app-opennit`)":                    true,
		"Host(`app.example.com`)":                false,
		"Host(`localhost`)":                      false,
		"Host(`app-opennit`) && PathPrefix(`/`)": false,
	} {
		if _, got := ghostHost(rule); got != want {
			t.Errorf("%s: got %v", rule, got)
		}
	}
}
