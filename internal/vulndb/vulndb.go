// Package vulndb ships a small curated list of well-known glibc CVEs and
// answers "which of these affect version X" queries for the `vuln`
// subcommand.
//
// This list is hand-curated from public CVE descriptions and is NOT a
// substitute for checking the NVD / your distro's security tracker before
// relying on it — version ranges for old CVEs are approximate.
package vulndb

import (
	_ "embed"
	"encoding/json"

	"pwnlibc/internal/glibcver"
)

//go:embed vulns.json
var vulnsJSON []byte

// Entry is one curated CVE record.
type Entry struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	AffectedFrom string `json:"affected_from"`
	AffectedTo   string `json:"affected_to"`
	Severity     string `json:"severity"`
	Description  string `json:"description"`
}

var all []Entry

func init() {
	if err := json.Unmarshal(vulnsJSON, &all); err != nil {
		panic("vulndb: embedded vulns.json is invalid: " + err.Error())
	}
}

// All returns every curated entry.
func All() []Entry { return all }

// AffectedBy returns every curated entry whose [affected_from, affected_to)
// range includes version.
func AffectedBy(version string) []Entry {
	target, ok := glibcver.Ordinal(version)
	if !ok {
		return nil
	}
	var out []Entry
	for _, e := range all {
		from, okFrom := glibcver.Ordinal(e.AffectedFrom)
		to, okTo := glibcver.Ordinal(e.AffectedTo)
		if !okFrom || !okTo {
			continue
		}
		if target >= from && target < to {
			out = append(out, e)
		}
	}
	return out
}
