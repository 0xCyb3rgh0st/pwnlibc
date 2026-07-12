// Package jsonout provides the shared --json output envelope used by every
// pwnlibc subcommand so machine-readable output has one consistent shape.
package jsonout

import (
	"encoding/json"
	"io"
)

// Envelope is the top-level shape written to stdout when --json is set.
type Envelope struct {
	OK    bool        `json:"ok"`
	Data  interface{} `json:"data,omitempty"`
	Error *ErrorInfo  `json:"error,omitempty"`
}

// ErrorInfo carries a machine-readable error code alongside the message so
// scripts can branch on failure kind instead of parsing free text.
type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Emit writes a successful envelope wrapping data to w.
func Emit(w io.Writer, data interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Envelope{OK: true, Data: data})
}

// EmitError writes a failure envelope wrapping the given error code/message.
func EmitError(w io.Writer, code string, err error) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Envelope{OK: false, Error: &ErrorInfo{Code: code, Message: err.Error()}})
}

// CodeOf extracts a stable machine-readable code from a pwnlibc typed error,
// falling back to "internal" for anything unrecognized.
func CodeOf(err error) string {
	type coder interface{ Code() string }
	if c, ok := err.(coder); ok {
		return c.Code()
	}
	return "internal"
}
