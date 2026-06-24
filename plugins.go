// plugins.go: YAML-rule plugin engine.
//
// Plugins are YAML files under plugins/. Each rule binds to one driver
// output (ssh, smb, vnc, ...) and contains a boolean expression evaluated
// against the driver's report. Matching rules emit a Finding into the
// NDJSON stream. No Go rebuild needed to add or update a plugin.
//
// Expression engine: expr-lang/expr. Supports `==`, `!=`, `<`, `>`,
// `contains()`, `in`, `any`, `all`, `matches` (regex), etc.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"gopkg.in/yaml.v3"
)

// versionNumRe pulls the leading dotted-numeric portion of a version string,
// e.g. "5.0.51a-3ubuntu5" -> "5.0.51", "v1.2.3p1" -> "1.2.3".
var versionNumRe = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)*`)

func versionParts(s string) []int {
	m := versionNumRe.FindString(s)
	if m == "" {
		return nil
	}
	var out []int
	for _, p := range strings.Split(m, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

// compareVersions returns -1 if a<b, 0 if equal, 1 if a>b, comparing the
// dotted-numeric portions component by component. Missing trailing components
// count as 0 so "4.0" equals "4.0.0".
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va != vb {
			if va < vb {
				return -1
			}
			return 1
		}
	}
	return 0
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// versionExprOptions registers the version-comparison helpers usable inside a
// rule's when: expression. Each takes a captured version string and a target.
// An empty or unparseable captured version yields false (no false positive).
//   vlt(v,t)  v <  t        vle(v,t)  v <= t
//   vgt(v,t)  v >  t        vge(v,t)  v >= t
//   veq(v,t)  v == t        vbetween(v,minIncl,maxExcl)  minIncl <= v < maxExcl
func versionExprOptions() []expr.Option {
	has := func(v string) bool { return len(versionParts(v)) > 0 }
	cmp2 := func(name string, ok func(int) bool) expr.Option {
		return expr.Function(name, func(p ...any) (any, error) {
			v := toStr(p[0])
			if !has(v) {
				return false, nil
			}
			return ok(compareVersions(v, toStr(p[1]))), nil
		}, new(func(string, string) bool))
	}
	return []expr.Option{
		cmp2("vlt", func(c int) bool { return c < 0 }),
		cmp2("vle", func(c int) bool { return c <= 0 }),
		cmp2("vgt", func(c int) bool { return c > 0 }),
		cmp2("vge", func(c int) bool { return c >= 0 }),
		cmp2("veq", func(c int) bool { return c == 0 }),
		expr.Function("vbetween", func(p ...any) (any, error) {
			v := toStr(p[0])
			if !has(v) {
				return false, nil
			}
			return compareVersions(v, toStr(p[1])) >= 0 &&
				compareVersions(v, toStr(p[2])) < 0, nil
		}, new(func(string, string, string) bool)),
	}
}

// PluginRule is one YAML file describing a vulnerability rule.
type PluginRule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Severity    string   `yaml:"severity"`            // critical|high|medium|low|info
	Source      string   `yaml:"source"`              // driver name (ssh, smb, ...)
	When        string   `yaml:"when"`                // expr expression returning bool
	Evidence    string   `yaml:"evidence,omitempty"`  // Go-template, interpolated with report
	References  []string `yaml:"references,omitempty"`
	Remediation string   `yaml:"remediation,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`

	// internal: compiled expression program + parsed evidence template
	program  *vm.Program       `yaml:"-"`
	evidTpl  *template.Template `yaml:"-"`
	filePath string             `yaml:"-"`
}

// PluginFinding is the output of a fired plugin rule. Goes into the
// NDJSON stream as phase=finding, joining driver phase rows.
type PluginFinding struct {
	Phase       string   `json:"phase"`
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Source      string   `json:"source"`
	Host        string   `json:"host,omitempty"`
	Port        int      `json:"port,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	References  []string `json:"references,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Timestamp   string   `json:"ts"`
}

// PluginEngine holds compiled rules indexed by source.
type PluginEngine struct {
	bySource map[string][]*PluginRule
	rules    []*PluginRule
}

// LoadPlugins walks dir for *.yaml files, parses + compiles them.
func LoadPlugins(dir string) (*PluginEngine, error) {
	eng := &PluginEngine{bySource: map[string][]*PluginRule{}}
	if dir == "" {
		return eng, nil
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) == "versions.yaml" {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(path), ".yaml") &&
			!strings.HasSuffix(strings.ToLower(path), ".yml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var rule PluginRule
		if err := yaml.Unmarshal(raw, &rule); err != nil {
			return fmt.Errorf("%s: parse: %w", path, err)
		}
		rule.filePath = path
		if rule.ID == "" || rule.Source == "" || rule.When == "" {
			return fmt.Errorf("%s: rule must set id, source, when", path)
		}
		// Compile expression (with the version-comparison helpers registered)
		opts := versionExprOptions()
		opts = append(opts, expr.AsBool(), expr.AllowUndefinedVariables())
		prog, err := expr.Compile(rule.When, opts...)
		if err != nil {
			return fmt.Errorf("%s: when expr: %w", path, err)
		}
		rule.program = prog
		// Compile evidence template if present
		if rule.Evidence != "" {
			tpl, err := template.New(rule.ID).
				Option("missingkey=zero").Parse(rule.Evidence)
			if err != nil {
				return fmt.Errorf("%s: evidence template: %w", path, err)
			}
			rule.evidTpl = tpl
		}
		eng.bySource[rule.Source] = append(eng.bySource[rule.Source], &rule)
		eng.rules = append(eng.rules, &rule)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Auto-generate version-currency rules from versions.yaml
	if verr := eng.loadVersionRules(dir); verr != nil {
		fmt.Fprintf(os.Stderr, "[versions.yaml] %v\n", verr)
	}

	// Stable rule order for reproducible output
	for src := range eng.bySource {
		sort.Slice(eng.bySource[src], func(i, j int) bool {
			return eng.bySource[src][i].ID < eng.bySource[src][j].ID
		})
	}
	return eng, nil
}

// Evaluate runs every rule for source against the report struct.
// The report is JSON-marshaled then unmarshaled into a generic map so
// expressions can reference field names exactly as they appear in the
// JSON tags (e.g. "weak_algos", "smbv1_enabled").
func (e *PluginEngine) Evaluate(source string, report any) ([]PluginFinding, error) {
	rules := e.bySource[source]
	if len(rules) == 0 {
		return nil, nil
	}
	env, err := toMap(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	host, _ := env["host"].(string)
	portF, _ := env["port"].(float64)
	port := int(portF)

	var out []PluginFinding
	for _, r := range rules {
		v, err := expr.Run(r.program, env)
		if err != nil {
			// rule expression failed at runtime — log and move on
			fmt.Fprintf(os.Stderr, "plugin %s eval: %v\n", r.ID, err)
			continue
		}
		matched, _ := v.(bool)
		if !matched {
			continue
		}
		evid := ""
		if r.evidTpl != nil {
			var buf bytes.Buffer
			if err := r.evidTpl.Execute(&buf, env); err == nil {
				evid = strings.TrimSpace(buf.String())
			}
		}
		out = append(out, PluginFinding{
			Phase:       "finding",
			RuleID:      strings.TrimPrefix(r.ID, "nessus-"),
			Title:       r.Title,
			Severity:    r.Severity,
			Source:      r.Source,
			Host:        host,
			Port:        port,
			Evidence:    evid,
			References:  r.References,
			Remediation: strings.TrimSpace(r.Remediation),
			Tags:        r.Tags,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		})
	}
	return out, nil
}

// toMap marshals an arbitrary struct to JSON and back into a
// map[string]any. Cheaper than reflection, and the keys match the JSON
// tags on the driver structs, which is what the YAML expressions
// reference.
func toMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// RuleCount returns counts per source. Useful for startup log.
func (e *PluginEngine) RuleCount() map[string]int {
	out := map[string]int{}
	for src, rs := range e.bySource {
		out[src] = len(rs)
	}
	return out
}

// ── version-currency rules (auto-generated from plugins/versions.yaml) ──────

// sourceVersionCtx maps each source to [productField, versionField].
// An empty productField means the source always represents one product.
var sourceVersionCtx = map[string][2]string{
	// HTTP/HTTPS — server_product filled from Server: header, tech fingerprint,
	// or extra headers (X-Jenkins, X-Grafana-Version, X-Powered-By).
	"http": {"server_product", "server_version"},

	// Network protocol banners — product + product_version from greeting.
	"ssh":  {"product", "product_version"},
	"ftp":  {"product", "product_version"},
	"smtp": {"product", "product_version"},
	"imap": {"product", "product_version"},
	"pop3": {"product", "product_version"},

	// Relational databases — version from handshake.
	"mysql":      {"", "server_version"},
	"postgresql": {"", "server_version"},
	"mssql":      {"", "server_version"},
	"oracle":     {"", "server_version"},
	"db2":        {"", "server_version"},

	// NoSQL / caching.
	"mongodb":   {"", "version"},
	"redis":     {"", "version"},
	"memcached": {"", "version"},
	"couchdb":   {"", "version"},

	// Message queues — product field identifies the MQ, version is version.
	"amqp": {"product", "version"},

	// Search / analytics — standalone probe sources.
	"elasticsearch": {"", "version"},

	// DevOps / CI.
	"jenkins": {"", "version"},

	// NoSQL databases (additional).
	"cassandra": {"", "release_version"},

	// Message streaming.
	"kafka": {"", "version"},

	// SNMP-based network device version detection.
	"snmp": {"sys_product", "sys_version"},

	// Cloud orchestration / service mesh.
	"kubernetes": {"", "version"},
	"consul":     {"", "version"},
	"vault":      {"", "version"},

	// Monitoring.
	"prometheus": {"", "version"},

	// Graph databases.
	"neo4j": {"", "version"},

	// Message brokers (additional).
	"activemq": {"", "version"},
}

var advisoryURLs = map[string]string{
	"nginx":      "https://nginx.org/en/security_advisories.html",
	"apache":     "https://httpd.apache.org/security/vulnerabilities_24.html",
	"tomcat":     "https://tomcat.apache.org/security.html",
	"iis":        "https://msrc.microsoft.com/update-guide",
	"openssl":    "https://www.openssl.org/news/secadv/",
	"openssh":    "https://www.openssh.com/security.html",
	"proftpd":    "http://www.proftpd.org/docs/RELEASE_NOTES",
	"postfix":    "https://www.postfix.org/announcements.html",
	"mysql":      "https://dev.mysql.com/doc/relnotes/mysql/en/",
	"mariadb":    "https://mariadb.com/kb/en/security/",
	"postgresql": "https://www.postgresql.org/support/security/",
	"redis":      "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
	"mongodb":    "https://www.mongodb.com/docs/manual/release-notes/",
	"jenkins":    "https://www.jenkins.io/security/advisories/",
	"weblogic":   "https://www.oracle.com/security-alerts/",
}

func advisoryURL(product string) string {
	p := strings.ToLower(product)
	for k, u := range advisoryURLs {
		if strings.Contains(p, k) {
			return u
		}
	}
	return ""
}

// loadVersionRules reads plugins/versions.yaml and synthesises one PluginRule
// per entry that fires when the detected version is older than listed.
func (e *PluginEngine) loadVersionRules(dir string) error {
	versFile := filepath.Join(dir, "versions.yaml")
	raw, err := os.ReadFile(versFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%w", err)
	}
	var cfg map[string]map[string]string
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("versions.yaml parse: %w", err)
	}
	for source, products := range cfg {
		for product, currentVer := range products {
			rule, err := makeVersionRule(source, product, currentVer)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[versions.yaml] %s/%s: %v\n", source, product, err)
				continue
			}
			e.bySource[rule.Source] = append(e.bySource[rule.Source], rule)
			e.rules = append(e.rules, rule)
		}
	}
	return nil
}

func makeVersionRule(source, product, currentVer string) (*PluginRule, error) {
	var whenExpr, evidField string

	if source == "http" && strings.EqualFold(product, "openssl") {
		whenExpr = fmt.Sprintf(`openssl != "" && vlt(openssl, %q)`, currentVer)
		evidField = "{{ .openssl }}"
	} else if fields, ok := sourceVersionCtx[source]; ok {
		if fields[0] != "" {
			matchWord := regexp.QuoteMeta(strings.Fields(product)[0])
			whenExpr = fmt.Sprintf(`%s matches "(?i)%s" && %s != "" && vlt(%s, %q)`,
				fields[0], matchWord, fields[1], fields[1], currentVer)
			evidField = "{{ ." + fields[1] + " }}"
		} else {
			whenExpr = fmt.Sprintf(`%s != "" && vlt(%s, %q)`, fields[1], fields[1], currentVer)
			evidField = "{{ ." + fields[1] + " }}"
		}
	} else {
		matchWord := regexp.QuoteMeta(strings.Fields(product)[0])
		whenExpr = fmt.Sprintf(`product matches "(?i)%s" && product_version != "" && vlt(product_version, %q)`,
			matchWord, currentVer)
		evidField = "{{ .product_version }}"
	}

	opts := versionExprOptions()
	opts = append(opts, expr.AsBool(), expr.AllowUndefinedVariables())
	prog, err := expr.Compile(whenExpr, opts...)
	if err != nil {
		return nil, fmt.Errorf("compile when expr: %w", err)
	}

	firstWord := strings.Fields(product)[0]
	displayName := strings.ToUpper(firstWord[:1]) + firstWord[1:]
	ruleID := "version-outdated-" + strings.ReplaceAll(strings.ToLower(product), " ", "-")

	evidStr := fmt.Sprintf("Vulnerable Outdated %s Server — %s detected, current stable release is %s. "+
		"Upgrade to eliminate known CVE exposure. See vendor advisory for the full list of fixed vulnerabilities.",
		displayName, evidField, currentVer)

	tpl, err := template.New(ruleID).Option("missingkey=zero").Parse(evidStr)
	if err != nil {
		return nil, fmt.Errorf("evidence template: %w", err)
	}

	refs := []string{}
	if u := advisoryURL(product); u != "" {
		refs = append(refs, u)
	}

	return &PluginRule{
		ID:       ruleID,
		Title:    fmt.Sprintf("Vulnerable Outdated %s Server", displayName),
		Severity: "medium",
		Source:   source,
		When:     whenExpr,
		Evidence: evidStr,
		References:  refs,
		Remediation: fmt.Sprintf("Upgrade %s to %s or later. Review the vendor advisory for CVEs fixed since the detected version.", displayName, currentVer),
		Tags:        []string{"version-currency", "outdated", source, strings.ToLower(product)},
		program:     prog,
		evidTpl:     tpl,
	}, nil
}

