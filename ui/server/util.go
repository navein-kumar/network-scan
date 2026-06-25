package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
)

// writeErr emits a JSON error body {"error": msg} with the given status code.
func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeJSONResp encodes v as JSON with the given status code.
func writeJSONResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// streamFile copies a file to w, returning false if it cannot be opened.
func streamFile(w http.ResponseWriter, path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	_, _ = io.Copy(w, f)
	return true
}

// tail returns the last n bytes of a file as a string (best-effort).
func tail(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	size := fi.Size()
	start := int64(0)
	if size > n {
		start = size - n
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return ""
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	return string(b)
}

// pythonBin resolves an available python interpreter, preferring python3.
func pythonBin() string {
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return "python3"
}
