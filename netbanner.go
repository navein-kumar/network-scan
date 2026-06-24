// netbanner.go: shared banner -> (product, version) parser for the
// banner-based network drivers (SSH, FTP, SMTP, POP3, IMAP).
//
// Remote (unauthenticated) version-CVE rules match on the parsed product name
// and a dotted-numeric version. This file only does the parsing; the probes
// call parseProductVersion after they read their banner and set rep.Product /
// rep.ProductVersion. Best-effort: if nothing matches, both come back empty so
// no false product is reported. Never panics.
package main

import (
	"regexp"
	"strings"
)

// canonicalProduct maps a lower-cased detected token to the stable canonical
// product name the rules expect.
var canonicalProduct = map[string]string{
	"openssh":       "OpenSSH",
	"dropbear":      "Dropbear",
	"vsftpd":        "vsftpd",
	"proftpd":       "ProFTPD",
	"pure-ftpd":     "Pure-FTPd",
	"pureftpd":      "Pure-FTPd",
	"filezilla":     "FileZilla",
	"microsoft ftp": "Microsoft FTP",
	"exim":          "Exim",
	"postfix":       "Postfix",
	"sendmail":      "Sendmail",
	"dovecot":       "Dovecot",
	"courier":       "Courier",
	"cyrus":         "Cyrus",
}

// versionRe captures the leading dotted-numeric run of a token, e.g.
// "8.2p1" -> "8.2", "2.3.4" -> "2.3.4", "1.4.7_release" -> "1.4.7",
// "4.89" -> "4.89", "2019.78" -> "2019.78".
var versionRe = regexp.MustCompile(`(\d+(?:\.\d+)*)`)

// leadingVersion returns the leading dotted-numeric run of tok (suffix letters
// and other junk stripped). Empty if tok has no numeric run.
func leadingVersion(tok string) string {
	m := versionRe.FindString(tok)
	return m
}

// parseProductVersion inspects a service banner and returns a canonical product
// name and a dotted-numeric version. Either or both may be empty. Best-effort,
// case-insensitive, no panic.
func parseProductVersion(banner string) (product, version string) {
	if banner == "" {
		return "", ""
	}
	lower := strings.ToLower(banner)

	// ── SSH: identification string "SSH-2.0-<software>[ comment]" ──
	// e.g. "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "SSH-2.0-dropbear_2019.78".
	if strings.HasPrefix(strings.ToUpper(banner), "SSH-") {
		return parseSSHIdent(banner)
	}

	// ── Microsoft FTP: "Microsoft FTP Service" (no version exposed) ──
	if strings.Contains(lower, "microsoft ftp") {
		return "Microsoft FTP", ""
	}

	// ── Generic product+version match for the remaining services. ──
	// Walk the known products and, when one appears in the banner, take the
	// first dotted-numeric token that follows it as the version.
	fields := strings.Fields(banner)
	lowerFields := make([]string, len(fields))
	for i, f := range fields {
		lowerFields[i] = strings.ToLower(strings.Trim(f, "()[],"))
	}
	for i, lf := range lowerFields {
		canon, ok := canonicalProduct[lf]
		if !ok {
			continue
		}
		// Look ahead for the version token (often the very next field).
		for j := i + 1; j < len(fields) && j <= i+2; j++ {
			if v := leadingVersion(strings.Trim(fields[j], "()[],;")); v != "" {
				return canon, v
			}
		}
		return canon, ""
	}
	return "", ""
}

// parseSSHIdent parses an SSH identification string of the form
// "SSH-<proto>-<software>[ comment]" into a canonical product and version.
// The software part is "<name>_<version>" or "<name>-<version>".
func parseSSHIdent(banner string) (product, version string) {
	// Strip "SSH-2.0-" / "SSH-1.99-" prefix: software is the third '-' field.
	parts := strings.SplitN(banner, "-", 3)
	if len(parts) < 3 {
		return "", ""
	}
	software := parts[2]
	// Drop any trailing comment (space-separated), keep just the software tag.
	if sp := strings.IndexByte(software, ' '); sp >= 0 {
		software = software[:sp]
	}
	// software is like "OpenSSH_8.2p1" or "dropbear_2019.78".
	name := software
	verTok := ""
	if us := strings.IndexByte(software, '_'); us >= 0 {
		name = software[:us]
		verTok = software[us+1:]
	}
	canon, ok := canonicalProduct[strings.ToLower(name)]
	if !ok {
		return "", ""
	}
	return canon, leadingVersion(verTok)
}
