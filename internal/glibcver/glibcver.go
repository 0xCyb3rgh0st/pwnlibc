// Package glibcver parses the "2.NN" major.minor component out of glibc
// version strings like "2.31-0ubuntu9.9" for ordering comparisons.
//
// This is deliberately NOT a float parse of "major.minor" (e.g. treating
// "2.5" as 2.5 and "2.19" as 2.19): as floats 2.5 > 2.19, which inverts the
// real ordering since glibc 2.5 (~2007) predates 2.19 (~2014). Major and
// minor are parsed as separate integers instead.
package glibcver

import (
	"strconv"
	"strings"
)

// Ordinal returns a value that sorts correctly by (major, minor) for glibc
// version strings such as "2.31-0ubuntu9.9", "2.5", or "glibc-2.19".
func Ordinal(version string) (int, bool) {
	v := strings.TrimPrefix(version, "glibc-")
	v = strings.SplitN(v, "-", 2)[0]
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return major*10000 + minor, true
}
