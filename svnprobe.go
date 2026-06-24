// svnprobe.go: phase 3 driver for SVN (3690, svnserve).
//
// The svn:// protocol greets the client immediately. The greeting is
// a parenthesised, whitespace-separated message of the form:
//
//   ( success ( <minver> <maxver> ( <mech> ... ) <realm-cstr> ( ... ) ) )
//
// We parse the version range, the capabilities list, and the realm.
// "ANONYMOUS" / "anonymous" / "EXTERNAL" appearing in the mech list
// indicates the server is willing to talk to unauthenticated clients.
package main

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type SVNReport struct {
	Host            string   `json:"host"`
	Port            int      `json:"port"`
	Reachable       bool     `json:"reachable"`
	ProtocolMinVer  string   `json:"protocol_min_version,omitempty"`
	ProtocolMaxVer  string   `json:"protocol_max_version,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Realm           string   `json:"realm,omitempty"`
	RepoUUID        string   `json:"repo_uuid,omitempty"`
	RepoRootURL     string   `json:"repo_root_url,omitempty"`
	RepoListing     []string `json:"repo_listing,omitempty"`
	ProbeErrors     []string `json:"probe_errors,omitempty"`
}

// svnMaxEntries caps how many top-level dirents we record.
const svnMaxEntries = 50

func ProbeSVN(host string, port int, timeout time.Duration) (*SVNReport, error) {
	rep := &SVNReport{Host: host, Port: port}
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return rep, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 4096)
	n, err := io.ReadAtLeast(conn, buf, 4)
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("read: %v", err))
		return rep, nil
	}
	greeting := string(buf[:n])
	if !strings.HasPrefix(strings.TrimSpace(greeting), "( success") &&
		!strings.HasPrefix(strings.TrimSpace(greeting), "(success") {
		rep.ProbeErrors = append(rep.ProbeErrors,
			fmt.Sprintf("non-svn greeting: %q", firstNBytes(greeting, 64)))
		return rep, nil
	}
	rep.Reachable = true
	rep.ProtocolMinVer, rep.ProtocolMaxVer, rep.Capabilities, rep.Realm = parseSVNGreeting(greeting)

	// Best-effort: complete the anonymous handshake and list the repo root.
	// The svn:// protocol on the target is svn://host:port (no path); the
	// server reports the real root URL and UUID during connect. The greeting
	// has been fully consumed; any bytes past it stay in buf[:n] but svnserve
	// does not send the auth-request until it sees our connect response, so
	// there is no leftover to carry over here.
	url := fmt.Sprintf("svn://%s:%d", host, port)
	svnListRepo(conn, url, rep)
	return rep, nil
}

// svnListRepo drives the rest of the svn:// connect sequence on an already
// greeted connection and fills RepoUUID/RepoRootURL/RepoListing. It is fully
// best-effort: any read/parse hiccup just leaves the fields empty.
//
// Sequence (svnserve protocol, edition 2):
//   server -> greeting (already read into buf[:n])
//   client -> ( 2 ( edit-pipeline svndiff1 ) 25:svn://host:port ( ) )
//   server -> ( success ( ( ANONYMOUS ... ) realm ) )   [auth-request]
//   client -> ( ANONYMOUS ( ) )
//   server -> ( success ( ) )                            [auth ok]
//   server -> ( success ( uuid url ( caps ) ) )          [repos-info]
//   client -> ( get-dir ( 0: ( ) false true ( kind ) ) ) [list root]
//   server -> ( success ( ) ) ( success ( ... dirents ... ) )
func svnListRepo(conn net.Conn, url string, rep *SVNReport) {
	r := &svnReader{conn: conn, buf: make([]byte, 4096)}

	// Client connect response: protocol version 2, a capability set, the
	// repository URL (counted string), the ra-client name (counted string),
	// and an empty optional list. svnserve closes the connection if the
	// ra-client field is omitted, so it must be present.
	const raClient = "fastscan"
	connectReq := fmt.Sprintf("( 2 ( edit-pipeline svndiff1 absent-entries depth ) %d:%s %d:%s ( ) ) ",
		len(url), url, len(raClient), raClient)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("connect write: %v", err))
		return
	}

	// auth-request: ( success ( ( <mechs> ) <realm> ) ).
	authReq, err := r.next()
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("auth-request: %v", err))
		return
	}
	if !strings.Contains(authReq, "ANONYMOUS") && !strings.Contains(authReq, "EXTERNAL") {
		rep.ProbeErrors = append(rep.ProbeErrors, "no anonymous mech offered")
		return
	}

	// Select ANONYMOUS with an empty response blob.
	if _, err := conn.Write([]byte("( ANONYMOUS ( ) ) ")); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("auth write: %v", err))
		return
	}
	// Server replies ( success ( ) ) [auth ok], then ( success ( <uuid>
	// <root-url> ( <caps> ) ) ) [repos-info]. They may share one segment.
	if _, err := r.next(); err != nil { // auth ok
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("auth-reply: %v", err))
		return
	}
	info, err := r.next()
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("repos-info: %v", err))
		return
	}
	if uuid, root := parseSVNReposInfo(info); uuid != "" {
		rep.RepoUUID = uuid
		rep.RepoRootURL = root
	}

	// get-dir on path "" wanting dirents only (no props, no contents). The
	// trailing ( kind ) is the dirent field list so each entry carries its
	// node-kind. svnserve answers with a command-ack then the dirent reply.
	if _, err := conn.Write([]byte("( get-dir ( 0: ( ) false true ( kind ) ) ) ")); err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("get-dir write: %v", err))
		return
	}
	if _, err := r.next(); err != nil { // command ack: ( success ( ... ) )
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("get-dir ack: %v", err))
		return
	}
	dir, err := r.next() // ( success ( rev props ( <dirents> ) ) )
	if err != nil {
		rep.ProbeErrors = append(rep.ProbeErrors, fmt.Sprintf("get-dir reply: %v", err))
		return
	}
	rep.RepoListing = parseSVNDirents(dir)
}

// svnReader pulls one balanced s-expression at a time off a connection while
// retaining any trailing bytes of the next expression. svnserve packs several
// responses into a single TCP segment, so leftover carry-over is required.
type svnReader struct {
	conn net.Conn
	buf  []byte
	rest string // bytes read past the last returned expression
}

// next returns the next top-level parenthesised s-expression. Counted strings
// of the form N:<bytes> are skipped wholesale so byte payloads never disturb
// the paren depth counter.
func (r *svnReader) next() (string, error) {
	data := r.rest
	for {
		if expr, leftover, ok := svnSplitExpr(data); ok {
			r.rest = leftover
			return strings.TrimSpace(expr), nil
		}
		m, err := r.conn.Read(r.buf)
		if m > 0 {
			data += string(r.buf[:m])
		}
		if err != nil {
			if expr, leftover, ok := svnSplitExpr(data); ok {
				r.rest = leftover
				return strings.TrimSpace(expr), nil
			}
			r.rest = ""
			return "", err
		}
	}
}

// svnSplitExpr returns the first balanced parenthesised expression in s, the
// remaining bytes, and ok=true if a complete expression was found.
func svnSplitExpr(s string) (expr, rest string, ok bool) {
	depth := 0
	started := false
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '(':
			depth++
			started = true
			i++
		case c == ')':
			depth--
			i++
			if started && depth <= 0 {
				return s[:i], s[i:], true
			}
		case c >= '0' && c <= '9':
			j := i
			num := 0
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				num = num*10 + int(s[j]-'0')
				j++
			}
			if j < len(s) && s[j] == ':' {
				skip := j + 1 + num
				if skip <= len(s) {
					i = skip
				} else {
					return "", s, false // counted bytes not all buffered
				}
			} else {
				i = j
			}
		default:
			i++
		}
	}
	return "", s, false
}

// parseSVNReposInfo pulls the UUID and root URL out of
// ( success ( <uuid> <root-url> ( <caps> ) ) ). Both are counted strings.
func parseSVNReposInfo(s string) (uuid, root string) {
	cs := svnCountedStrings(s)
	if len(cs) >= 1 {
		uuid = cs[0]
	}
	if len(cs) >= 2 {
		root = cs[1]
	}
	return
}

// parseSVNDirents walks the get-dir reply and pairs each entry name with its
// node-kind. The dirent list is a sequence of
//   ( name:cstring kind:word size:num has-props:bool created-rev:num ... )
// We extract the leading counted string (name) and the following word token
// (kind: "file"/"dir"/"none") from each inner list.
func parseSVNDirents(s string) []string {
	var out []string
	toks := svnTokenize(s)
	// Find the dirents list: the last "(" group at depth 3 inside the
	// command response. Simpler: scan for inner "( <N:name> <kind> ..." runs.
	for i := 0; i < len(toks); i++ {
		if toks[i] != "(" {
			continue
		}
		// Look for a counted-string name immediately after an open paren,
		// followed by a bare kind word.
		if i+2 < len(toks) {
			name, okName := svnCounted(toks[i+1])
			kind := toks[i+2]
			if okName && (kind == "file" || kind == "dir" || kind == "none") {
				label := kind
				if kind == "none" {
					label = "unknown"
				}
				out = append(out, fmt.Sprintf("%s (%s)", name, label))
				if len(out) >= svnMaxEntries {
					break
				}
			}
		}
	}
	return out
}

// svnTokenize splits an svn s-expression into "(", ")", and atom tokens.
// Counted strings N:<bytes> are kept as single tokens (the bytes may contain
// spaces), so the caller can decode them with svnCounted.
func svnTokenize(s string) []string {
	var toks []string
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '(' || c == ')':
			toks = append(toks, string(c))
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c >= '0' && c <= '9':
			// Counted string or plain number.
			j := i
			num := 0
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				num = num*10 + int(s[j]-'0')
				j++
			}
			if j < len(s) && s[j] == ':' {
				start := j + 1
				end := start + num
				if end > len(s) {
					end = len(s)
				}
				toks = append(toks, fmt.Sprintf("%d:%s", num, s[start:end]))
				i = end
			} else {
				toks = append(toks, s[i:j])
				i = j
			}
		default:
			j := i
			for j < len(s) && s[j] != '(' && s[j] != ')' &&
				s[j] != ' ' && s[j] != '\t' && s[j] != '\r' && s[j] != '\n' {
				j++
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks
}

// svnCounted decodes a single "N:<bytes>" token into its byte payload.
func svnCounted(tok string) (string, bool) {
	idx := strings.IndexByte(tok, ':')
	if idx <= 0 {
		return "", false
	}
	for _, c := range tok[:idx] {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return tok[idx+1:], true
}

// svnCountedStrings returns the decoded payloads of every counted string in s,
// in order of appearance.
func svnCountedStrings(s string) []string {
	var out []string
	for _, tok := range svnTokenize(s) {
		if v, ok := svnCounted(tok); ok {
			out = append(out, v)
		}
	}
	return out
}

// parseSVNGreeting extracts (min, max, caps, realm) from
// "( success ( <min> <max> ( <cap>... ) <realm> ( ... ) ) )".
// v0 is permissive: it tokenises by whitespace and pulls the realm
// cstring (svnserve uses N:<bytes> for counted strings).
func parseSVNGreeting(g string) (min, max string, caps []string, realm string) {
	// Drop everything up to first numeric (the min version).
	g = strings.TrimSpace(g)
	openParens := 0
	tokens := []string{}
	cur := strings.Builder{}
	for _, c := range g {
		switch c {
		case '(':
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			tokens = append(tokens, "(")
			openParens++
		case ')':
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			tokens = append(tokens, ")")
			openParens--
		case ' ', '\t', '\r', '\n':
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(c)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}

	// Locate first numeric token after the leading "( success (".
	i := 0
	for i < len(tokens) && !isSVNDigits(tokens[i]) {
		i++
	}
	if i >= len(tokens) {
		return
	}
	min = tokens[i]
	if i+1 < len(tokens) && isSVNDigits(tokens[i+1]) {
		max = tokens[i+1]
		i += 2
	} else {
		i++
	}
	// Next "(" starts the capabilities list.
	for i < len(tokens) && tokens[i] != "(" {
		i++
	}
	if i < len(tokens) && tokens[i] == "(" {
		i++
		for i < len(tokens) && tokens[i] != ")" {
			caps = append(caps, tokens[i])
			i++
		}
		if i < len(tokens) {
			i++ // skip ")"
		}
	}
	// Next token is the realm (counted-string "N:..." or bare word).
	if i < len(tokens) {
		tok := tokens[i]
		if idx := strings.IndexByte(tok, ':'); idx > 0 {
			realm = tok[idx+1:]
		} else {
			realm = tok
		}
	}
	return
}

func isSVNDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
