// Package pwnerr defines the typed error taxonomy used across pwnlibc so
// both human and --json output can report actionable, stable error codes
// instead of ad-hoc wrapped strings.
package pwnerr

import "fmt"

// Code is a stable machine-readable error identifier.
type Code string

const (
	CodeMirrorUnreachable Code = "mirror_unreachable"
	CodeVersionNotFound   Code = "version_not_found"
	CodeChecksumMismatch  Code = "checksum_mismatch"
	CodeUnsafeArchive     Code = "unsafe_archive"
	CodeNotELF            Code = "not_elf"
	CodeDockerUnavailable Code = "docker_unavailable"
	CodeIndexCorrupt      Code = "index_corrupt"
	CodeInvalidInput      Code = "invalid_input"
	CodeIO                Code = "io_error"
)

// Error is a typed pwnlibc error carrying a stable Code plus a human message
// and optional wrapped cause.
type Error struct {
	code Code
	msg  string
	err  error
}

func New(code Code, msg string) *Error {
	return &Error{code: code, msg: msg}
}

func Wrap(code Code, msg string, err error) *Error {
	return &Error{code: code, msg: msg, err: err}
}

func (e *Error) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s: %v", e.msg, e.err)
	}
	return e.msg
}

func (e *Error) Unwrap() error { return e.err }

// Code returns the stable machine-readable code, satisfying jsonout.CodeOf's
// duck-typed `coder` interface.
func (e *Error) Code() string { return string(e.code) }
