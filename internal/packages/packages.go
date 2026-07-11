// Package packages parses apt pool directory listings into a unified,
// locally cached list of available libc6 / libc6-dbg package files across
// every configured mirror, so `search`/`download` never re-hit the network.
package packages

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

// Package is one .deb file found in a mirror's glibc pool directory.
type Package struct {
	Name     string   `json:"name"`     // libc6, libc6-dbg, libc6-dev, ...
	Version  string   `json:"version"`  // 2.31-0ubuntu9.9
	Arch     string   `json:"arch"`     // amd64, i386, arm64, ...
	Filename string   `json:"filename"` // libc6_2.31-0ubuntu9.9_amd64.deb
	Legacy   bool     `json:"legacy"`   // only present on old-releases (removed from active archive)
	Mirrors  []string `json:"mirrors"`  // mirror names where this exact filename was observed
}

// Key uniquely identifies a package file irrespective of which mirror it
// came from, so results from multiple mirrors merge into one entry.
func (p Package) Key() string { return p.Filename }

// VersionArch is the "<version>_<arch>" identifier used on the CLI, e.g.
// "2.31-0ubuntu9.9_amd64".
func (p Package) VersionArch() string { return p.Version + "_" + p.Arch }

// List is the full aggregated, cached package set.
type List struct {
	UpdatedAt string    `json:"updated_at"`
	Packages  []Package `json:"packages"`
}

// filenameRe matches hrefs like libc6_2.31-0ubuntu9.9_amd64.deb or
// libc6-dbg_2.35-0ubuntu3.8_i386.deb served from an Apache/nginx directory
// index (Ubuntu pool mirrors all use this style listing).
var filenameRe = regexp.MustCompile(`href="((?:libc6|glibc)[a-z0-9.+-]*_[0-9][^"_]*_[a-z0-9]+\.deb)"`)
var partsRe = regexp.MustCompile(`^([a-z0-9.+-]+)_([^_]+)_([a-z0-9]+)\.deb$`)

// ParsePoolListing extracts Package entries from a directory-index HTML page.
func ParsePoolListing(html []byte, mirrorName string, legacy bool) []Package {
	matches := filenameRe.FindAllSubmatch(html, -1)
	seen := map[string]bool{}
	var out []Package
	for _, m := range matches {
		filename := string(m[1])
		if seen[filename] {
			continue
		}
		seen[filename] = true
		parts := partsRe.FindStringSubmatch(filename)
		if parts == nil {
			continue
		}
		out = append(out, Package{
			Name:     parts[1],
			Version:  parts[2],
			Arch:     parts[3],
			Filename: filename,
			Legacy:   legacy,
			Mirrors:  []string{mirrorName},
		})
	}
	return out
}

// Merge combines package lists from multiple mirrors, unioning the Mirrors
// field for filenames observed on more than one.
func Merge(lists ...[]Package) []Package {
	byFile := map[string]*Package{}
	var order []string
	for _, list := range lists {
		for _, p := range list {
			if existing, ok := byFile[p.Key()]; ok {
				for _, mn := range p.Mirrors {
					if !contains(existing.Mirrors, mn) {
						existing.Mirrors = append(existing.Mirrors, mn)
					}
				}
				existing.Legacy = existing.Legacy && p.Legacy
				continue
			}
			cp := p
			byFile[p.Key()] = &cp
			order = append(order, p.Key())
		}
	}
	out := make([]Package, 0, len(order))
	for _, k := range order {
		out = append(out, *byFile[k])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Arch < out[j].Arch
	})
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Save writes the list as JSON to path.
func (l *List) Save(path string) error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadList reads a previously saved package list.
func LoadList(path string) (*List, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l List
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// FindVersionArch returns the libc6 (main) and, unless dbg is false, the
// matching libc6-dbg package for the given "<version>_<arch>" spec.
func (l *List) FindVersionArch(versionArch string, wantDbg bool) (main *Package, dbg *Package, err error) {
	for i := range l.Packages {
		p := &l.Packages[i]
		if p.Name != "libc6" {
			continue
		}
		if p.VersionArch() == versionArch {
			main = p
			break
		}
	}
	if main == nil {
		return nil, nil, fmt.Errorf("no libc6 package matches %q", versionArch)
	}
	if !wantDbg {
		return main, nil, nil
	}
	for i := range l.Packages {
		p := &l.Packages[i]
		if p.Name == "libc6-dbg" && p.VersionArch() == versionArch {
			dbg = p
			break
		}
	}
	return main, dbg, nil
}

// SearchByVersionPrefix returns all libc6 packages whose version starts with
// (or fuzzily contains) the given query string, for `search <query>`.
func (l *List) SearchByVersionPrefix(query string) []Package {
	var out []Package
	for _, p := range l.Packages {
		if p.Name != "libc6" {
			continue
		}
		if containsSubstr(p.Version, query) || containsSubstr(p.VersionArch(), query) {
			out = append(out, p)
		}
	}
	return out
}

func containsSubstr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}
