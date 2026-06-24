#!/usr/bin/env python3
"""
nasl_to_rules.py

Convert Nessus NASL version-CVE plugins into fastscan YAML detection rules.

Scope (deliberately conservative, per spec):
  * Three families of plugins are converted:
      (1) plugins whose target network service maps to a fastscan DB driver
          that captures a CLEAN dotted-numeric version field,
      (2) web-server plugins (Apache / nginx / IIS / lighttpd / OpenSSL),
          identified by their cpe + the "Web Servers" family, mapped to the
          parallel fastscan `http` source (server_product + server_version),
          and
      (3) remote network-service banner plugins (OpenSSH / vsftpd / ProFTPD /
          Exim / Postfix / Sendmail / Dovecot / ISC BIND), identified by their
          cpe (or script_name fallback), mapped to the parallel fastscan
          ssh / ftp / smtp / imap / pop3 / dns sources via the driver-emitted
          `product` + `product_version` fields (BIND uses `version_bind`).

STRICT UNAUTHENTICATED FILTER (applied to EVERY plugin, all three families):
  Only REMOTE, NO-CREDENTIAL checks are ever emitted. A plugin is eligible
  ONLY if every one of these holds:
    * script_set_attribute plugin_type == "remote"
      (DROP "local", "combined", "summary", "settings", or a missing value).
    * Its script_require_keys block references NO credential/local key:
      DROP on Host/local_checks_enabled, Host/uname, any SMB/*, any WMI/*,
      any Secret/*, Settings/PCI_DSS, or any Host/...installed inventory key.
      (Settings/ParanoidReport, installed_sw/* remote inventory, and
       service/version KB keys like bind/version are fine.)
    * Its script_family is NOT a local-security-check / OS-bulletin /
      policy-compliance / credentialed brute-force family
      (DROP "... Local Security Checks", "Windows : Microsoft Bulletins",
       "Windows", "Windows : User management", "Policy Compliance",
       "Default Unix Accounts", "Brute force attacks").
  Plugins dropped by this filter are counted separately as
  "authenticated/local".
  * Affected ranges are parsed from either:
      (a) the Nessus "vcf" framework literal constraints array
              var constraints = [ { 'min_version':'x', 'fixed_version':'y' } ];
      (b) the old-style version idioms (version_is_less / version_is_less_equal
          / version_in_range / version_in_range_exclusive / version_is_equal).
    Anything with freeform / regex version logic, or a partially-parseable
    idiom set, is SKIPPED and counted. This keeps the generated when:
    expressions provably correct and false-positive free (the engine's vXX()
    helpers return false on an empty or unparseable captured version).

  Out of scope (noted for a future batch): app-level web products such as
  WordPress / PHP / Drupal / Joomla / Tomcat. They need tech-field / path
  parsing rather than a Server: header version, so a web plugin that declares
  one of their cpes maps to nothing here.

The generated rules rely on version-comparison helpers already compiled into
the engine (plugins.go): vlt/vle/vgt/vge/veq/vbetween. The captured driver
version field feeds each helper, guarded by a presence check so a missing
version can never fire a rule.

Output: /root/fastscan/plugins/<source>/nessus-<scriptid>.yaml  (idempotent).
Existing hand-written rules are never touched (we only write nessus-*.yaml).

NOTE: this file and every YAML it emits must contain ZERO em-dash (U+2014) and
ZERO en-dash (U+2013) characters. Use ASCII hyphen, colon, or parentheses.
"""

import argparse
import os
import re
import sys

# --------------------------------------------------------------------------
# Service -> (fastscan source, version field). Only fields VERIFIED present in
# the driver report struct json tags are listed here. Each was grep-confirmed
# in /root/fastscan/<source>probe.go.
#
# The key is the Nessus "Services/<key>" token (the bit gated on by
# script_require_ports / script_require_keys). Several plugins use a
# *_server suffix, so both spellings map to the same fastscan source.
#
# has_reachable: whether the driver report struct exposes a "reachable" bool.
#   redis/mongodb/oracle/couchdb/memcached/amqp/db2 do; mysql/mssql do NOT,
#   so for those we must not put `reachable == true` in the guard (it would be
#   undefined/false for every scan and suppress all rules).
# --------------------------------------------------------------------------
SERVICE_MAP = {
    "redis":         {"source": "redis",     "field": "version",        "reachable": True},
    "redis_server":  {"source": "redis",     "field": "version",        "reachable": True},
    "mysql":         {"source": "mysql",     "field": "server_version", "reachable": False},
    "mssql":         {"source": "mssql",     "field": "version",        "reachable": False},
    "mongodb":       {"source": "mongodb",   "field": "version",        "reachable": True},
    "oracle":        {"source": "oracle",    "field": "version",        "reachable": True},
    "couchdb":       {"source": "couchdb",   "field": "version",        "reachable": True},
    "memcached":     {"source": "memcached", "field": "version",        "reachable": True},
    "amqp_server":   {"source": "amqp",      "field": "version",        "reachable": True},
    "amqp":          {"source": "amqp",      "field": "version",        "reachable": True},
    "db2das":        {"source": "db2",       "field": "server_version", "reachable": True},
    "db2":           {"source": "db2",       "field": "server_version", "reachable": True},
}

# --------------------------------------------------------------------------
# Part 1: STRICT UNAUTHENTICATED FILTER regexes.
#
# Applied to EVERY plugin before any conversion. We convert ONLY
# remote-unauthenticated checks. See the strict-filter docstring above.
# --------------------------------------------------------------------------
# The script_require_keys(...) call body (tokens listed inside).
RE_REQUIRE_KEYS = re.compile(r"script_require_keys\s*\((.*?)\)", re.S)

# script_family(english:"...") -> family name.
RE_FAMILY_NAME = re.compile(
    r'script_family\s*\(\s*english\s*:\s*"([^"]+)"'
)

# Credential / local-access KB keys. If a plugin's require_keys block
# references ANY of these, it needs credentials or local host access and is
# DROPPED. installed_sw/* (remote software inventory from a remote detect
# plugin) and Settings/ParanoidReport are deliberately NOT in this list, nor
# are service/version KB keys like bind/version or ftp/<port>/vsftpd/version.
RE_CRED_KEY = re.compile(
    r'["\'](?:'
    r'Host/local_checks_enabled'      # credentialed local checks gate
    r'|Host/uname'                    # credentialed uname
    r'|SMB/[^"\']*'                   # any SMB/* (credentialed Windows)
    r'|WMI/[^"\']*'                   # any WMI/* (credentialed Windows)
    r'|Secret/[^"\']*'                # any Secret/* (stored credentials)
    r'|Settings/PCI_DSS'             # credentialed PCI policy
    r'|Host/[^"\']*[Ii]nstalled[^"\']*'  # Host/...installed inventory
    r')["\']'
)

# Local-security-check / OS-bulletin / policy / credentialed-bruteforce
# families. A plugin in any of these is DROPPED even if plugin_type slipped
# through as "remote".
RE_LOCAL_FAMILY = re.compile(
    r'(?:'
    r'.*Local Security Checks'        # <Distro> Local Security Checks
    r'|Windows : Microsoft Bulletins'
    r'|Windows : User management'
    r'|Windows'                       # exact "Windows" family (SMB-credentialed)
    r'|Policy Compliance'
    r'|Default Unix Accounts'         # credentialed default-account checks
    r'|Brute force attacks'           # credential brute force
    r')$'
)

# --------------------------------------------------------------------------
# Part 2: remote network-service product map (banner / version based).
#
# Detect the product from the plugin's cpe attribute (preferred) or, for older
# plugins with no cpe, the script_name. Map it to the canonical product string
# the parallel driver emits (json field "product") plus the fastscan source
# and the version field the driver exposes (json field "product_version", or
# "version_bind" for ISC BIND).
#
# CONTRACT (driver json field names, supplied by the parallel driver work):
#   ssh / ftp / smtp / pop3 / imap : product + product_version
#   dns                            : version_bind  (already shipped)
#
# guard: the matches expression on the product field that gates the rule to
#   the right product. For BIND there is no product field on the dns driver,
#   so version_bind presence alone is the guard (only ISC BIND answers the
#   version.bind chaos query).
# --------------------------------------------------------------------------
NET_PRODUCTS = [
    {
        "key": "openssh",
        "source": "ssh",
        # cpe:/a:openbsd:openssh  or  cpe:/a:openssh:openssh
        "cpe": re.compile(r'cpe:/a:(?:openbsd|openssh):openssh\b'),
        "name": re.compile(r'(?i)\bopenssh\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)openssh"',
        "tag": "openssh",
    },
    {
        "key": "exim",
        "source": "smtp",
        "cpe": re.compile(r'cpe:/a:exim:exim\b'),
        "name": re.compile(r'(?i)\bexim\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)exim"',
        "tag": "exim",
    },
    {
        "key": "postfix",
        "source": "smtp",
        "cpe": re.compile(r'cpe:/a:(?:postfix:postfix|postfix)\b'),
        "name": re.compile(r'(?i)\bpostfix\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)postfix"',
        "tag": "postfix",
    },
    {
        "key": "sendmail",
        "source": "smtp",
        "cpe": re.compile(r'cpe:/a:(?:sendmail:sendmail|sendmail)\b'),
        "name": re.compile(r'(?i)\bsendmail\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)sendmail"',
        "tag": "sendmail",
    },
    {
        "key": "vsftpd",
        "source": "ftp",
        "cpe": re.compile(r'cpe:/a:(?:vsftpd|beasts:vsftpd|vsftpd:vsftpd)\b'),
        "name": re.compile(r'(?i)\bvsftpd\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)vsftpd"',
        "tag": "vsftpd",
    },
    {
        "key": "proftpd",
        "source": "ftp",
        "cpe": re.compile(r'cpe:/a:proftpd(?::proftpd)?\b'),
        "name": re.compile(r'(?i)\bproftpd\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)proftpd"',
        "tag": "proftpd",
    },
    {
        "key": "pureftpd",
        "source": "ftp",
        "cpe": re.compile(r'cpe:/a:(?:pureftpd|pure-ftpd)(?::[^\s"\']+)?\b'),
        "name": re.compile(r'(?i)\bpure-?ftpd\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)pure-?ftpd"',
        "tag": "pure-ftpd",
    },
    {
        "key": "dovecot-imap",
        "source": "imap",
        "cpe": re.compile(r'cpe:/a:dovecot(?::dovecot)?\b'),
        "name": re.compile(r'(?i)\bdovecot\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)dovecot"',
        "tag": "dovecot",
    },
    {
        "key": "dovecot-pop3",
        "source": "pop3",
        "cpe": re.compile(r'cpe:/a:dovecot(?::dovecot)?\b'),
        "name": re.compile(r'(?i)\bdovecot\b'),
        "vfield": "product_version",
        "guard": 'product matches "(?i)dovecot"',
        "tag": "dovecot",
    },
    {
        "key": "bind",
        "source": "dns",
        "cpe": re.compile(r'cpe:/a:isc:bind\b'),
        "name": re.compile(r'(?i)\bISC\s+BIND\b'),
        # ISC BIND version is the version.bind chaos record the dns driver
        # already exposes as version_bind. There is no product field on the
        # dns driver; version_bind presence alone is the guard (only BIND
        # answers version.bind).
        "vfield": "version_bind",
        "guard": None,
        "tag": "bind",
    },
]

# Dovecot speaks both IMAP and POP3, so a Dovecot plugin emits TWO rules
# (one per source). Every other product maps to a single source.
NET_KEYS = {p["key"] for p in NET_PRODUCTS}

# --------------------------------------------------------------------------
# NASL field extraction regexes.
# --------------------------------------------------------------------------
RE_SCRIPT_ID   = re.compile(r"script_id\s*\(\s*(\d+)\s*\)")
RE_SCRIPT_NAME = re.compile(r'script_name\s*\(\s*english\s*:\s*"((?:[^"\\]|\\.)*)"', re.S)
RE_CVE_BLOCK   = re.compile(r"script_cve_id\s*\((.*?)\)", re.S)
RE_CVE_ID      = re.compile(r'"(CVE-\d{4}-\d{3,7})"')
RE_RISK        = re.compile(
    r'script_set_attribute\s*\(\s*attribute\s*:\s*"risk_factor"\s*,\s*value\s*:\s*"([^"]+)"',
    re.S,
)
RE_CVSS3_BASE  = re.compile(
    r'script_set_cvss3_base_vector\s*\(\s*"[^"]*?/(?:CVSS:3\.[01]/)?.*?"\s*\)'
)
RE_CVSS3_SCORE = re.compile(
    r'script_set_attribute\s*\(\s*attribute\s*:\s*"cvss3_base_score"\s*,\s*value\s*:\s*"([\d.]+)"'
)
RE_CVSS_SCORE  = re.compile(
    r'script_set_attribute\s*\(\s*attribute\s*:\s*"cvss_base_score"\s*,\s*value\s*:\s*"([\d.]+)"'
)
# severity passed to vcf::check_version_and_report(..., severity:SECURITY_xxx)
RE_REPORT_SEV  = re.compile(r"severity\s*:\s*(SECURITY_HOLE|SECURITY_WARNING|SECURITY_NOTE)")

# Service gate tokens. Captures the <svc> in Services/<svc>.
RE_SERVICE     = re.compile(r'Services/([A-Za-z0-9_]+)')

# plugin_type attribute: we only want "remote" plugins. "local" plugins read
# their version from credentialed SMB hotfix enumeration (a different version
# namespace, e.g. SQL Server build "2019.150.4003.23") that does NOT match the
# version string our network probes capture over the wire, so converting them
# would compare apples to oranges and is unsafe.
RE_PLUGIN_TYPE = re.compile(
    r'script_set_attribute\s*\(\s*attribute\s*:\s*"plugin_type"\s*,\s*value\s*:\s*"([^"]+)"'
)
# vcf::microsoft::* helpers always operate on SMB build numbers, never on a
# remotely banner-grabbed version. Belt-and-suspenders exclusion.
RE_VCF_MICROSOFT = re.compile(r'vcf::microsoft::')

# The vcf constraints literal array. Captures the array body between [ and ].
# Handles both `var constraints = [...]` and `constraints = [...]`.
RE_CONSTRAINTS = re.compile(
    r'(?:var\s+)?constraints\s*=\s*\[(.*?)\]\s*;', re.S
)
# One constraint object's key/value pairs (single OR double quoted).
RE_KV = re.compile(
    r"""['"]([A-Za-z_]+)['"]\s*:\s*['"]([^'"]+)['"]"""
)

# --------------------------------------------------------------------------
# Part 1: old-style NASL version idioms.
#
# Beyond the vcf constraints array, some NASL plugins express their affected
# range with explicit comparison helpers. We parse these into when: terms on
# the mapped version field. Only the literal-string test_version arguments are
# usable; if the bound is a variable / non-literal we cannot convert it.
#
# A "named" capture for the literal version inside test_version:"X" style args.
# Each idiom is matched as a whole call so we can map argument positions.
# --------------------------------------------------------------------------
# version_is_less(version:ver, test_version:"X")          -> vlt(field, "X")
RE_IDIOM_LESS = re.compile(
    r'version_is_less\s*\(\s*'
    r'(?:version\s*:\s*[^,]+,\s*)?'
    r'test_version\s*:\s*["\']([^"\']+)["\']',
    re.S,
)
# version_is_less_equal(version:ver, test_version:"X")    -> vle(field, "X")
RE_IDIOM_LESS_EQ = re.compile(
    r'version_is_less_equal\s*\(\s*'
    r'(?:version\s*:\s*[^,]+,\s*)?'
    r'test_version\s*:\s*["\']([^"\']+)["\']',
    re.S,
)
# version_is_equal(version:ver, test_version:"X")         -> veq(field, "X")
RE_IDIOM_EQUAL = re.compile(
    r'version_is_equal\s*\(\s*'
    r'(?:version\s*:\s*[^,]+,\s*)?'
    r'test_version\s*:\s*["\']([^"\']+)["\']',
    re.S,
)
# version_in_range_exclusive(version:ver, low:"A", high:"B")  -> vbetween(A,B)
# (high treated as EXCLUSIVE, matching vbetween's minIncl/maxExcl semantics).
# Also accepts the test_version/test_version2 argument spelling.
RE_IDIOM_RANGE_EXCL = re.compile(
    r'version_in_range_exclusive\s*\(\s*'
    r'(?:version\s*:\s*[^,]+,\s*)?'
    r'(?:low\s*:\s*["\']([^"\']+)["\']\s*,\s*high\s*:\s*["\']([^"\']+)["\']'
    r'|test_version\s*:\s*["\']([^"\']+)["\']\s*,\s*'
    r'test_version2\s*:\s*["\']([^"\']+)["\'])',
    re.S,
)
# version_in_range(version:ver, test_version:"A", test_version2:"B")
#   -> vge(field,"A") and vle(field,"B")  (both bounds INCLUSIVE)
# Must be matched AFTER the exclusive variant so the longer name wins; we guard
# with a negative lookbehind on "_exclusive" by requiring the call boundary.
RE_IDIOM_RANGE = re.compile(
    r'(?<![A-Za-z_])version_in_range\s*\(\s*'
    r'(?:version\s*:\s*[^,]+,\s*)?'
    r'test_version\s*:\s*["\']([^"\']+)["\']\s*,\s*'
    r'test_version2\s*:\s*["\']([^"\']+)["\']',
    re.S,
)

# Any appearance of a version idiom (to detect plugins that use the idiom
# style at all, so we can skip-count those we cannot parse confidently).
RE_ANY_IDIOM = re.compile(
    r'(?<![A-Za-z_])version_(?:is_less(?:_equal)?|is_equal|in_range(?:_exclusive)?)\s*\('
)

# --------------------------------------------------------------------------
# ver_compare(...) idiom (dominant in older banner-based network plugins).
#
#   ver_compare(ver:version, fix:"X", ...) < 0      -> vlt(field, "X")
#   ver_compare(ver:version, fix:"X", ...) <= 0     -> vle(field, "X")
#   ver_compare(ver:version, fix:"X", ...) == -1    -> vlt(field, "X")
#
# We ONLY parse this when fix: is a literal string, OR a bareword that resolves
# to a `var fixed_version = 'literal'` declaration in the same file. Anything
# else (computed bound, no comparison operator we recognise) makes the whole
# plugin unparseable and it is skipped (conservative). The comparison operator
# is REQUIRED: a bare ver_compare result used as a boolean is ambiguous.
# --------------------------------------------------------------------------
# ver_compare(... fix:"LITERAL" ...) <op> <rhs>
RE_VER_COMPARE = re.compile(
    r'ver_compare\s*\(\s*'
    r'(?:ver\s*:\s*[^,)]+,\s*)?'
    r'fix\s*:\s*'
    r'(?:["\']([^"\']+)["\']|([A-Za-z_]\w*))'      # g1 literal | g2 bareword
    r'[^)]*\)'                                       # rest of the call args
    r'\s*(<=|<|==|!=|>=|>)\s*(-?\d+)',              # g3 op , g4 rhs int
    re.S,
)
# Detect ANY ver_compare call so a plugin that uses ver_compare but whose call
# we could not parse is skip-counted instead of silently emitting nothing.
RE_ANY_VER_COMPARE = re.compile(r'ver_compare\s*\(')
# `var fixed_version = '1.2.3'` (or fixed_level = / fix = ...), literal numeric
# only. Captures (varname, literal). Used to resolve a bareword fix: argument
# ONLY when there is a single unambiguous fixed-version assignment in the file.
RE_FIX_VARDEF = re.compile(
    r'\b(?:var\s+)?(\w*(?:fix|fixed)\w*)\s*=\s*["\']([0-9][0-9A-Za-z._\-]*)["\']'
)

# --------------------------------------------------------------------------
# Part 2: web-server product map. Product detection -> server_product guard.
# Keyed by an ordered list of (cpe-regex, product-key). server_version is the
# version field for the parallel http source (field-name contract).
#
# guard: the matches expression on server_product (or `server` for openssl,
#   whose version is embedded in the Server: header).
# tag:   the product tag appended to the rule's tags list.
# vfield: the json field carrying the dotted version.
# --------------------------------------------------------------------------
WEB_PRODUCTS = [
    {
        "key": "apache",
        # cpe:/a:apache:http_server  or  cpe:/a:apache:httpd
        "cpe": re.compile(r'cpe:/a:apache:(?:http_server|httpd)\b'),
        "guard": 'server_product matches "(?i)apache"',
        "tag": "apache",
        "vfield": "server_version",
    },
    {
        "key": "nginx",
        # cpe:/a:nginx:nginx  or  cpe:/a:igor_sysoev:nginx
        "cpe": re.compile(r'cpe:/a:(?:nginx:nginx|igor_sysoev:nginx)\b'),
        "guard": 'server_product matches "(?i)nginx"',
        "tag": "nginx",
        "vfield": "server_version",
    },
    {
        "key": "iis",
        # cpe:/a:microsoft:iis  or  cpe:/a:microsoft:internet_information_services
        "cpe": re.compile(
            r'cpe:/a:microsoft:(?:iis|internet_information_services)\b'),
        "guard": 'server_product matches "(?i)iis"',
        "tag": "iis",
        "vfield": "server_version",
    },
    {
        "key": "lighttpd",
        "cpe": re.compile(r'cpe:/a:lighttpd:lighttpd\b'),
        "guard": 'server_product matches "(?i)lighttpd"',
        "tag": "lighttpd",
        "vfield": "server_version",
    },
    # OpenSSL is intentionally NOT converted. The contract allows it only if the
    # version can be extracted cleanly from the Server: header, but in this
    # corpus ~80% of cpe:/a:openssl:openssl plugins are OS-local / credentialed
    # checks (AIX, Cisco, plugin_type:"local") that read the OpenSSL version from
    # a package manager, NOT from a web banner. A `server matches openssl` guard
    # would mis-fire on those and produce over-broad, false-positive rules, so
    # we skip the whole family (conservative, per spec).
]

# App-level web products that are OUT OF SCOPE for this batch (they need
# tech-field / path parsing, not a Server: header version). We detect their
# cpe so a web plugin that is really a WordPress/PHP/etc. check maps to
# nothing instead of being mis-attributed to the web server.
RE_WEB_APP_CPE = re.compile(
    r'cpe:/a:(?:wordpress|php|drupal|joomla|apache:tomcat|apache:coyote)\b'
)

SECURITY_TO_SEV = {
    "SECURITY_HOLE":    "high",
    "SECURITY_WARNING": "medium",
    "SECURITY_NOTE":    "low",
}
RISK_TO_SEV = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "none":     "info",
}

# Pull leading dotted-numeric prefix of a version, matching the engine's own
# versionParts() behaviour (so "3.6.0-rc0" -> "3.6.0"). If a target has no
# numeric part it is unusable as a comparison bound.
RE_VER_NUM = re.compile(r"\d+(?:\.\d+)*")


def clean_version(v):
    """Return the leading dotted-numeric part of a version target, or None."""
    m = RE_VER_NUM.match(v.strip())
    if not m:
        return None
    return m.group(0)


def yaml_squote(s):
    """Single-quote a scalar for YAML, escaping embedded single quotes."""
    return "'" + s.replace("'", "''") + "'"


EM_DASH = chr(0x2014)
EN_DASH = chr(0x2013)


def strip_dashes(s):
    """Defensive: replace any em/en dash that slipped in from a NASL title."""
    return s.replace(EM_DASH, " ").replace(EN_DASH, "-")


def parse_constraints(body):
    """
    Parse the body of a vcf constraints array into a list of dicts with any of
    min_version / fixed_version / max_version (cleaned to dotted-numeric).
    Returns (constraints, reason_if_unusable).
    """
    objs = re.findall(r"\{(.*?)\}", body, re.S)
    if not objs:
        return None, "no constraint objects"
    out = []
    for obj in objs:
        kv = dict(RE_KV.findall(obj))
        c = {}
        for key in ("min_version", "fixed_version", "max_version"):
            if key in kv:
                cv = clean_version(kv[key])
                if cv is None:
                    # a bound with no numeric part is unusable; drop this object
                    c = {}
                    break
                c[key] = cv
        # We require at least an upper or lower bound to form a term.
        if c and ("fixed_version" in c or "max_version" in c or "min_version" in c):
            out.append(c)
    if not out:
        return None, "no usable numeric bounds"
    return out, None


def build_term(field, c):
    """
    Build a single when: sub-term for one constraint object, per spec:
      min_version + fixed_version -> vbetween(field, min, fixed)
      fixed_version only          -> vlt(field, fixed)
      min_version + max_version   -> (vge(field, min) and vle(field, max))
      min_version only            -> vge(field, min)
      max_version only            -> vle(field, max)
    Returns the term string, or None if the object yields nothing.
    """
    mn = c.get("min_version")
    fx = c.get("fixed_version")
    mx = c.get("max_version")
    if mn and fx:
        return 'vbetween({f}, "{a}", "{b}")'.format(f=field, a=mn, b=fx)
    if fx:
        return 'vlt({f}, "{b}")'.format(f=field, b=fx)
    if mn and mx:
        return '(vge({f}, "{a}") and vle({f}, "{b}"))'.format(f=field, a=mn, b=mx)
    if mn:
        return 'vge({f}, "{a}")'.format(f=field, a=mn)
    if mx:
        return 'vle({f}, "{b}")'.format(f=field, b=mx)
    return None


def parse_idioms(field, text):
    """
    Part 1: parse old-style version idioms into when: terms on `field`.

    Returns (terms, reason_if_unusable):
      * terms is a list of when: sub-term strings (OR'd together by the caller),
        each built from a confidently-parsed idiom call.
      * If the plugin uses idiom calls but NONE could be parsed into a literal
        bound (e.g. all bounds are variables), returns (None, reason).
      * If the plugin uses no idiom calls at all, returns ([], None) so the
        caller can fall through to the vcf path.

    Conservative: a single unparseable idiom call in an otherwise-parseable
    plugin causes the whole plugin to be skipped, so we never emit a term that
    silently ignores part of the affected range.
    """
    if not RE_ANY_IDIOM.search(text):
        return [], None

    total_calls = len(RE_ANY_IDIOM.findall(text))
    terms = []

    for m in RE_IDIOM_LESS.finditer(text):
        v = clean_version(m.group(1))
        if v:
            terms.append('vlt({f}, "{b}")'.format(f=field, b=v))

    for m in RE_IDIOM_LESS_EQ.finditer(text):
        v = clean_version(m.group(1))
        if v:
            terms.append('vle({f}, "{b}")'.format(f=field, b=v))

    for m in RE_IDIOM_EQUAL.finditer(text):
        v = clean_version(m.group(1))
        if v:
            terms.append('veq({f}, "{b}")'.format(f=field, b=v))

    for m in RE_IDIOM_RANGE_EXCL.finditer(text):
        # low/high spelling -> groups 1,2 ; test_version spelling -> groups 3,4
        lo = m.group(1) or m.group(3)
        hi = m.group(2) or m.group(4)
        a = clean_version(lo) if lo else None
        b = clean_version(hi) if hi else None
        if a and b:
            # exclusive high boundary maps directly onto vbetween(min, maxExcl).
            terms.append('vbetween({f}, "{a}", "{b}")'.format(f=field, a=a, b=b))

    for m in RE_IDIOM_RANGE.finditer(text):
        a = clean_version(m.group(1))
        b = clean_version(m.group(2))
        if a and b:
            # inclusive range: vge(low) and vle(high).
            terms.append(
                '(vge({f}, "{a}") and vle({f}, "{b}"))'.format(f=field, a=a, b=b))

    if not terms:
        return None, "version idiom(s) present but no literal bounds parseable"
    # If we parsed fewer terms than the number of idiom calls, we likely missed
    # a non-literal call; be conservative and skip rather than emit a partial
    # (over-broad) range.
    if len(terms) < total_calls:
        return None, "version idiom(s) only partially parseable"
    return terms, None


def parse_ver_compare(field, text):
    """
    Parse ver_compare(ver:.., fix:X) <op> <int> idioms into when: terms.

    Returns (terms, reason_if_unusable), with the same contract as
    parse_idioms:
      * ([], None)          -> the plugin uses no ver_compare at all.
      * (terms, None)       -> every ver_compare call parsed confidently.
      * (None, reason)      -> ver_compare present but a call was unparseable
                               (be conservative and skip the whole plugin).

    Supported comparisons (vs. fixed version X):
      ... < 0   or  ... == -1   -> version < X    -> vlt(field, "X")
      ... <= 0                   -> version <= X   -> vle(field, "X")
    Any other operator/rhs (e.g. > 0, == 1, != 0) is NOT a "vulnerable below
    fixed" test and makes the plugin unparseable here (skip).
    """
    if not RE_ANY_VER_COMPARE.search(text):
        return [], None

    total_calls = len(RE_ANY_VER_COMPARE.findall(text))

    # Resolve a bareword fix: variable ONLY when the file has a single,
    # unambiguous fixed-version literal. Plugins that assign different fixed
    # versions in platform / branch conditionals (e.g. a Windows fix-pack level
    # vs a Linux one) are NOT safely convertible to one banner-version
    # comparison, so we refuse to resolve the variable and skip the plugin.
    fix_literals = {clean_version(v) for _, v in RE_FIX_VARDEF.findall(text)}
    fix_literals.discard(None)
    var_fix = next(iter(fix_literals)) if len(fix_literals) == 1 else None

    terms = []
    for m in RE_VER_COMPARE.finditer(text):
        lit, bareword, op, rhs = m.group(1), m.group(2), m.group(3), m.group(4)
        if lit:
            fixv = clean_version(lit)
        elif bareword:
            fixv = var_fix
        else:
            fixv = None
        if not fixv:
            continue
        try:
            rhs_i = int(rhs)
        except ValueError:
            continue
        # Map (operator, rhs) onto a "version below fixed" comparison.
        if (op == "<" and rhs_i == 0) or (op == "==" and rhs_i == -1):
            terms.append('vlt({f}, "{b}")'.format(f=field, b=fixv))
        elif op == "<=" and rhs_i == 0:
            terms.append('vle({f}, "{b}")'.format(f=field, b=fixv))
        # else: an operator we cannot map to "vulnerable below fixed"; leave it
        # unparsed so the count-guard below skips the plugin.

    if not terms:
        return None, "ver_compare present but no usable fix: bound parseable"
    # Conservative all-or-nothing: every recognised ver_compare call must have
    # produced a term, otherwise we may be ignoring part of the affected range.
    if len(terms) < total_calls:
        return None, "ver_compare only partially parseable"
    return terms, None


def severity_of(text):
    """Resolve severity from risk_factor, else CVSS score, else report sev."""
    m = RE_RISK.search(text)
    if m:
        rf = m.group(1).strip().lower()
        if rf in RISK_TO_SEV:
            return RISK_TO_SEV[rf]
    # CVSS3 base score, then CVSS2 base score.
    for rx in (RE_CVSS3_SCORE, RE_CVSS_SCORE):
        sm = rx.search(text)
        if sm:
            try:
                score = float(sm.group(1))
            except ValueError:
                score = None
            if score is not None:
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                if score > 0.0:
                    return "low"
                return "info"
    sm = RE_REPORT_SEV.search(text)
    if sm:
        return SECURITY_TO_SEV[sm.group(1)]
    return "medium"


def unauth_reject_reason(text):
    """
    Part 1: the STRICT global unauthenticated filter.

    Return a reason string if the plugin must be DROPPED as authenticated /
    local / credentialed, else None (the plugin is remote-unauthenticated and
    may proceed to conversion). Applied to EVERY plugin in every family.

    Conditions (any one DROPs):
      * plugin_type attribute is not exactly "remote"
        (covers "local", "combined", "summary", "settings", or missing).
      * script_require_keys references a credential / local-access KB key.
      * script_family is a local-security-check / OS-bulletin / policy /
        credentialed brute-force family.
    """
    pt = RE_PLUGIN_TYPE.search(text)
    ptv = pt.group(1).strip().lower() if pt else "(missing)"
    if ptv != "remote":
        return "plugin_type={} (not remote)".format(ptv)

    rk = RE_REQUIRE_KEYS.search(text)
    if rk and RE_CRED_KEY.search(rk.group(1)):
        return "credential/local require_key"

    fm = RE_FAMILY_NAME.search(text)
    if fm and RE_LOCAL_FAMILY.match(fm.group(1).strip()):
        return "local-security-check family ({})".format(fm.group(1).strip())

    return None


def detect_service(text):
    """Return the first Services/<svc> token that maps to a fastscan source."""
    for tok in RE_SERVICE.findall(text):
        if tok in SERVICE_MAP:
            return tok
    return None


RE_FAMILY_WEB = re.compile(
    r'script_family\s*\(\s*english\s*:\s*"Web Servers"', re.S
)


def detect_web_product(text):
    """
    Part 2: detect a web-SERVER product (apache/nginx/iis/lighttpd/openssl)
    from the plugin's cpe attribute(s).

    Returns the matching WEB_PRODUCTS entry, or None. Conservative rules:
      * The plugin must declare one of our server-product cpes.
      * If the plugin ALSO declares an app-level web cpe (WordPress/PHP/etc.)
        we bail out: it is an app check that merely runs on a web server, and
        a Server: header version would mis-attribute it. Out of scope here.
    """
    if RE_WEB_APP_CPE.search(text):
        return None
    for prod in WEB_PRODUCTS:
        if prod["cpe"].search(text):
            return prod
    return None


def short_name(name, limit=70):
    name = name.strip()
    if len(name) > limit:
        name = name[: limit - 3].rstrip() + "..."
    return name


def build_rule_yaml(source, field, has_reachable, sid, name, severity, cves,
                    terms):
    """Render the full YAML document for one plugin."""
    rule_id = "nessus-{src}-{sid}".format(src=source, sid=sid)
    title = strip_dashes(name)
    sname = strip_dashes(short_name(name))

    guard_parts = []
    if has_reachable:
        guard_parts.append("reachable == true")
    guard_parts.append("{f} != nil".format(f=field))
    guard_parts.append('{f} != ""'.format(f=field))
    guard = " and ".join(guard_parts)

    if len(terms) == 1:
        constraint_expr = terms[0]
    else:
        constraint_expr = " or ".join(terms)
    when = "{guard} and ( {c} )".format(guard=guard, c=constraint_expr)

    evidence = "{{{{ .{f} }}}} matches Nessus {sid}: {sn}".format(
        f=field, sid=sid, sn=sname
    )

    refs = ["https://nvd.nist.gov/vuln/detail/{cve}".format(cve=cve)
            for cve in cves]
    refs.append("https://www.tenable.com/plugins/nessus/{sid}".format(sid=sid))

    lines = []
    lines.append("id: {rid}".format(rid=rule_id))
    lines.append("title: {t}".format(t=title))
    lines.append("severity: {s}".format(s=severity))
    lines.append("source: {src}".format(src=source))
    lines.append("when: {w}".format(w=when))
    lines.append("evidence: {e}".format(e=yaml_squote(evidence)))
    lines.append("references:")
    for r in refs:
        lines.append("  - {r}".format(r=r))
    lines.append("remediation: |")
    if cves:
        cve_txt = ", ".join(cves)
        lines.append("  Affected version range flagged by Nessus plugin {sid}".format(sid=sid))
        lines.append("  ({cves}). Upgrade to a fixed release of {src} that".format(cves=cve_txt, src=source))
        lines.append("  is outside the affected version range, and apply current")
        lines.append("  vendor security updates.")
    else:
        lines.append("  Affected version range flagged by Nessus plugin {sid}.".format(sid=sid))
        lines.append("  Upgrade to a fixed release of {src} outside the affected".format(src=source))
        lines.append("  range and apply current vendor security updates.")
    lines.append("tags: [nessus, {src}, cve]".format(src=source))
    return rule_id, "\n".join(lines) + "\n"


def build_web_rule_yaml(prod, sid, name, severity, cves, terms):
    """
    Render the YAML document for one web-server (source http) plugin.

    Emits a product guard (server_product matches ...) plus a presence guard on
    the version field, then the OR of the parsed version terms. The version
    field (server_version) feeds the engine's vXX() helpers exactly like the DB
    path. The http source is wired in parallel; until it lands these rules
    compile under AllowUndefinedVariables and stay dormant (safe).
    """
    rule_id = "nessus-http-{sid}".format(sid=sid)
    title = strip_dashes(name)
    sname = strip_dashes(short_name(name))
    vfield = prod["vfield"]

    # Guard: product match + non-empty version. server_version is what the
    # vXX() helpers compare; an empty/unparseable version yields false, so a
    # missing version can never fire the rule.
    guard = '{g} and {f} != ""'.format(g=prod["guard"], f=vfield)

    if len(terms) == 1:
        constraint_expr = terms[0]
    else:
        constraint_expr = " or ".join(terms)
    when = "{guard} and ( {c} )".format(guard=guard, c=constraint_expr)

    # Evidence shows the raw Server: header so the finding is self-explanatory.
    evidence = "{{{{ .server }}}} matches Nessus {sid}: {sn}".format(
        sid=sid, sn=sname
    )

    refs = ["https://nvd.nist.gov/vuln/detail/{cve}".format(cve=cve)
            for cve in cves]
    refs.append("https://www.tenable.com/plugins/nessus/{sid}".format(sid=sid))

    lines = []
    lines.append("id: {rid}".format(rid=rule_id))
    lines.append("title: {t}".format(t=title))
    lines.append("severity: {s}".format(s=severity))
    lines.append("source: http")
    lines.append("when: {w}".format(w=when))
    lines.append("evidence: {e}".format(e=yaml_squote(evidence)))
    lines.append("references:")
    for r in refs:
        lines.append("  - {r}".format(r=r))
    lines.append("remediation: |")
    if cves:
        cve_txt = ", ".join(cves)
        lines.append("  Affected version range flagged by Nessus plugin {sid}".format(sid=sid))
        lines.append("  ({cves}). Upgrade the {p} web server to a fixed release".format(cves=cve_txt, p=prod["key"]))
        lines.append("  outside the affected version range, and apply current")
        lines.append("  vendor security updates.")
    else:
        lines.append("  Affected version range flagged by Nessus plugin {sid}.".format(sid=sid))
        lines.append("  Upgrade the {p} web server to a fixed release outside the".format(p=prod["key"]))
        lines.append("  affected range and apply current vendor security updates.")
    lines.append("tags: [nessus, http, cve, {p}]".format(p=prod["tag"]))
    return rule_id, "\n".join(lines) + "\n"


def detect_net_products(text):
    """
    Part 2: detect remote network-service products from the plugin's cpe
    attribute (preferred) or, as a fallback, the script_name.

    Returns a list of matching NET_PRODUCTS entries (Dovecot yields two: one
    for imap, one for pop3; every other product yields one). An empty list
    means no network-service product was recognised.

    Conservative: cpe is matched against the whole plugin text. The script_name
    fallback only fires when NO product cpe matched at all, and requires the
    product token to appear in the plugin's script_name (not just anywhere in
    the body), so a passing mention in a description cannot mis-attribute.
    """
    matched = []
    matched_keys = set()
    for prod in NET_PRODUCTS:
        if prod["cpe"].search(text):
            matched.append(prod)
            matched_keys.add(prod["key"])
    if matched:
        return matched

    # cpe fallback: match the product name strictly inside script_name only.
    nm = RE_SCRIPT_NAME.search(text)
    if not nm:
        return []
    sname = nm.group(1)
    for prod in NET_PRODUCTS:
        if prod["name"].search(sname):
            matched.append(prod)
    return matched


def build_net_rule_yaml(prod, sid, name, severity, cves, terms):
    """
    Render the YAML document for one remote network-service plugin.

    Emits a product guard (product matches ...; omitted for BIND, whose dns
    driver has no product field) plus a presence guard on the version field,
    then the OR of the parsed version terms. The version field feeds the
    engine's vXX() helpers, so an empty/unparseable version yields false and a
    missing version can never fire the rule.

    These rules reference the driver-contract fields product / product_version
    (version_bind for BIND). The ssh/ftp/smtp/imap/pop3 drivers do not yet emit
    product / product_version, so until that parallel work lands these rules
    compile under AllowUndefinedVariables and stay dormant (safe). version_bind
    already ships, so the BIND rules are live immediately.
    """
    source = prod["source"]
    rule_id = "nessus-{src}-{sid}".format(src=source, sid=sid)
    title = strip_dashes(name)
    sname = strip_dashes(short_name(name))
    vfield = prod["vfield"]

    # Presence guard: the version field must be a non-empty string.
    guard_parts = []
    if prod["guard"]:
        guard_parts.append(prod["guard"])
    guard_parts.append('{f} != ""'.format(f=vfield))
    guard = " and ".join(guard_parts)

    if len(terms) == 1:
        constraint_expr = terms[0]
    else:
        constraint_expr = " or ".join(terms)
    when = "{guard} and ( {c} )".format(guard=guard, c=constraint_expr)

    # Evidence: show product + version (BIND has no product field, so show the
    # version.bind string alone).
    if prod["guard"]:
        evidence = (
            "{{{{ .product }}}} {{{{ .{f} }}}} matches Nessus {sid}: {sn}"
            .format(f=vfield, sid=sid, sn=sname)
        )
    else:
        evidence = "{{{{ .{f} }}}} matches Nessus {sid}: {sn}".format(
            f=vfield, sid=sid, sn=sname
        )

    refs = ["https://nvd.nist.gov/vuln/detail/{cve}".format(cve=cve)
            for cve in cves]
    refs.append("https://www.tenable.com/plugins/nessus/{sid}".format(sid=sid))

    lines = []
    lines.append("id: {rid}".format(rid=rule_id))
    lines.append("title: {t}".format(t=title))
    lines.append("severity: {s}".format(s=severity))
    lines.append("source: {src}".format(src=source))
    lines.append("when: {w}".format(w=when))
    lines.append("evidence: {e}".format(e=yaml_squote(evidence)))
    lines.append("references:")
    for r in refs:
        lines.append("  - {r}".format(r=r))
    lines.append("remediation: |")
    if cves:
        cve_txt = ", ".join(cves)
        lines.append("  Affected version range flagged by Nessus plugin {sid}".format(sid=sid))
        lines.append("  ({cves}). Upgrade {p} to a fixed release outside the".format(cves=cve_txt, p=prod["tag"]))
        lines.append("  affected version range, and apply current vendor")
        lines.append("  security updates.")
    else:
        lines.append("  Affected version range flagged by Nessus plugin {sid}.".format(sid=sid))
        lines.append("  Upgrade {p} to a fixed release outside the affected".format(p=prod["tag"]))
        lines.append("  range and apply current vendor security updates.")
    lines.append("tags: [nessus, {src}, cve, {p}]".format(src=source, p=prod["tag"]))
    return rule_id, "\n".join(lines) + "\n"


def extract_meta(text):
    """
    Pull (sid, name, cves) common metadata from a NASL plugin body.
    Returns (sid, name, cves) or (None, None, None) if no script_id.
    """
    sm = RE_SCRIPT_ID.search(text)
    if sm is None:
        return None, None, None
    sid = sm.group(1)

    nm = RE_SCRIPT_NAME.search(text)
    name = nm.group(1) if nm else ""
    name = name.replace('\\"', '"').replace("\\n", " ").strip()

    cves = []
    cb = RE_CVE_BLOCK.search(text)
    if cb:
        cves = RE_CVE_ID.findall(cb.group(1))
    seen = set()
    cves = [c for c in cves if not (c in seen or seen.add(c))]
    return sid, name, cves


def dedup_terms(terms):
    """Drop duplicate when: sub-terms while preserving first-seen order."""
    seen = set()
    out = []
    for t in terms:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def collect_terms(field, text):
    """
    Build the OR-list of when: version terms for a plugin, trying, in order:
      Path A: the vcf constraints literal array (dominant modern style),
      Path B: the old-style version_is_*/version_in_range idioms,
      Path C: the ver_compare(ver:.., fix:X) <op> <int> idiom (older banner
              plugins, common in the network-service families).

    Returns (terms, reason_if_none):
      * terms: non-empty list on success (deduplicated, order preserved).
      * (None, reason): nothing parseable.
    """
    # Path A: vcf constraints array (the dominant modern style).
    cm = RE_CONSTRAINTS.search(text)
    if cm is not None:
        constraints, why = parse_constraints(cm.group(1))
        if constraints is not None:
            terms = []
            for c in constraints:
                t = build_term(field, c)
                if t:
                    terms.append(t)
            if terms:
                return dedup_terms(terms), None
            return None, "no usable version term (vcf)"
        # constraints array present but unparseable; fall through to idioms.

    # Path B: old-style version idioms.
    iterms, why = parse_idioms(field, text)
    if iterms is None:
        return None, why
    if iterms:
        return dedup_terms(iterms), None

    # Path C: ver_compare(..) idiom.
    vterms, why = parse_ver_compare(field, text)
    if vterms is None:
        return None, why
    if vterms:
        return dedup_terms(vterms), None

    return None, "no vcf constraints array and no version idiom"


# Sentinel reason used so main() can count strict-filter drops separately as
# "authenticated/local".
DROP_AUTH = "authenticated/local"


def convert_file(path):
    """
    Parse one NASL file.

    Returns (rules, skip_reason):
      * rules: a list of (rule_id, track_key, source, yaml_text) tuples
        (usually 0 or 1; Dovecot yields 2: one imap rule + one pop3 rule).
        A non-empty list means at least one rule was produced.
      * skip_reason: a string when rules is empty (why nothing was emitted),
        else None. The sentinel DROP_AUTH marks a plugin dropped by the strict
        unauthenticated filter (counted separately).

    track_key is the bucket used for per-category counting:
      * a web product key (apache/nginx/iis/lighttpd) for http rules,
      * a network product key (openssh/exim/bind/...) for net rules,
      * the DB source name (redis/mysql/...) for DB rules.
    source is the fastscan source the rule is written under.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return [], "read error: {}".format(exc)

    # ----------------------------------------------------------------------
    # Part 1: STRICT GLOBAL UNAUTHENTICATED FILTER (applies to EVERY plugin in
    # EVERY family: web, network service, and DB). Only remote, no-credential
    # checks survive. Anything else is dropped and counted as authenticated/
    # local.
    # ----------------------------------------------------------------------
    reason = unauth_reject_reason(text)
    if reason is not None:
        return [], DROP_AUTH

    # vcf::microsoft::* always operates on SMB build numbers (a different
    # version namespace than anything we capture over the wire). Never convert.
    # (Also credentialed in practice; belt-and-suspenders on top of Part 1.)
    if RE_VCF_MICROSOFT.search(text):
        return [], DROP_AUTH

    sid, name, cves = extract_meta(text)
    if sid is None:
        return [], "no script_id"
    if not cves and not name:
        return [], "no CVE and no title"
    severity = severity_of(text)

    # ----------------------------------------------------------------------
    # Part 2a: web-server family -> source http.
    # Checked FIRST: a web plugin gates on installed_sw/<product>, not on a
    # Services/<svc> token in SERVICE_MAP, so it would otherwise fall through.
    # ----------------------------------------------------------------------
    prod = detect_web_product(text)
    if prod is not None:
        terms, why = collect_terms(prod["vfield"], text)
        if terms is None:
            return [], "web product without parseable version ({})".format(why)
        rule_id, yaml_text = build_web_rule_yaml(
            prod, sid, name, severity, cves, terms,
        )
        return [(rule_id, prod["key"], "http", yaml_text)], None

    # ----------------------------------------------------------------------
    # Part 2b: remote network-service families (ssh/ftp/smtp/imap/pop3/dns).
    # A Dovecot plugin maps to BOTH imap and pop3, so this may emit 2 rules.
    # ----------------------------------------------------------------------
    netprods = detect_net_products(text)
    if netprods:
        out = []
        # Version terms are computed per product because BIND reads version_bind
        # while the rest read product_version.
        for np in netprods:
            terms, why = collect_terms(np["vfield"], text)
            if terms is None:
                continue
            rule_id, yaml_text = build_net_rule_yaml(
                np, sid, name, severity, cves, terms,
            )
            out.append((rule_id, np["key"], np["source"], yaml_text))
        if out:
            return out, None
        return [], "network product without parseable version"

    # ----------------------------------------------------------------------
    # Part 3: DB / service-mapped sources (vcf or idiom).
    # ----------------------------------------------------------------------
    svc = detect_service(text)
    if svc is None:
        return [], "service not mapped"
    info = SERVICE_MAP[svc]

    terms, why = collect_terms(info["field"], text)
    if terms is None:
        return [], "constraints unparseable ({})".format(why)

    rule_id, yaml_text = build_rule_yaml(
        info["source"], info["field"], info["reachable"],
        sid, name, severity, cves, terms,
    )
    return [(rule_id, info["source"], info["source"], yaml_text)], None


def clean_old_nessus_rules(out_dir):
    """
    Remove every previously generated nessus-*.yaml under out_dir so the new
    generation is the sole nessus-* set. HAND-WRITTEN rules (anything not named
    nessus-*) are NEVER touched.
    """
    removed = 0
    for root, _dirs, names in os.walk(out_dir):
        for n in names:
            if n.startswith("nessus-") and n.endswith(".yaml"):
                try:
                    os.remove(os.path.join(root, n))
                    removed += 1
                except OSError:
                    pass
    return removed


def main():
    ap = argparse.ArgumentParser(description="Convert Nessus NASL vcf plugins to fastscan YAML rules.")
    ap.add_argument("--nasl-dir", default="/opt/nessus/lib/nessus/plugins")
    ap.add_argument("--out-dir", default="/root/fastscan/plugins")
    ap.add_argument("--dry-run", action="store_true", help="parse + report, write nothing")
    ap.add_argument("--no-clean", action="store_true",
                    help="do NOT delete existing nessus-*.yaml before writing")
    args = ap.parse_args()

    files = []
    for root, _dirs, names in os.walk(args.nasl_dir):
        for n in names:
            if n.endswith(".nasl"):
                files.append(os.path.join(root, n))
    files.sort()

    removed = 0
    if not args.dry_run and not args.no_clean:
        removed = clean_old_nessus_rules(args.out_dir)

    written = {}            # track_key (product / web / DB source) -> count
    src_count = {}          # fastscan source -> rule count
    skip_reasons = {}       # reason -> count
    total_seen = 0
    rules_total = 0
    dropped_auth = 0
    em = en = 0

    for path in files:
        total_seen += 1
        rules, reason = convert_file(path)
        if not rules:
            if reason == DROP_AUTH:
                dropped_auth += 1
            else:
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
            continue
        for rule_id, track, source, yaml_text in rules:
            em += yaml_text.count(EM_DASH)
            en += yaml_text.count(EN_DASH)
            if not args.dry_run:
                d = os.path.join(args.out_dir, source)
                os.makedirs(d, exist_ok=True)
                out_path = os.path.join(d, rule_id + ".yaml")
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(yaml_text)
            written[track] = written.get(track, 0) + 1
            src_count[source] = src_count.get(source, 0) + 1
            rules_total += 1

    web_keys = {p["key"] for p in WEB_PRODUCTS}

    print("=== nasl_to_rules summary ===")
    print("scanned NASL files       : {}".format(total_seen))
    if not args.dry_run and not args.no_clean:
        print("stale nessus-* removed   : {}".format(removed))
    print("rules generated (total)  : {}".format(rules_total))
    print("dropped authenticated/local : {}".format(dropped_auth))
    print()
    print("--- rules per fastscan source ---")
    for src in sorted(src_count):
        print("  {:<10} {}".format(src, src_count[src]))
    print()
    print("--- rules per product/track ---")
    for k in sorted(written):
        kind = "web" if k in web_keys else ("net" if k in NET_KEYS else "db")
        print("  {:<14} {:<4} ({})".format(k, written[k], kind))
    print()
    print("skipped (not auth)       : {}".format(sum(skip_reasons.values())))
    for reason in sorted(skip_reasons, key=lambda r: -skip_reasons[r])[:12]:
        print("  {:>8}  {}".format(skip_reasons[reason], reason))
    print("em-dashes in output      : {}".format(em))
    print("en-dashes in output      : {}".format(en))
    if em or en:
        print("ERROR: dash characters present in generated YAML", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
