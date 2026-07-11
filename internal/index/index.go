// Package index maintains pwnlibc's local persistent index: a BuildID ->
// version map and a per-version symbol table cache, backed by bbolt (pure
// Go, no cgo) so lookups are O(1) instead of re-parsing ELF files on every
// search/identify/diff invocation.
package index

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"pwnlibc/internal/elfinfo"
)

var (
	bucketBuildID = []byte("buildid") // buildid(hex) -> versionArch
	bucketSymtab  = []byte("symtab")  // versionArch -> json []Symbol
	bucketMeta    = []byte("meta")    // versionArch -> json VersionMeta
)

// VersionMeta records what we know about an indexed version beyond its
// symbol table.
type VersionMeta struct {
	VersionArch string    `json:"version_arch"`
	BuildID     string    `json:"build_id,omitempty"`
	IndexedAt   time.Time `json:"indexed_at"`
}

// Index wraps the on-disk bbolt database.
type Index struct {
	db *bolt.DB
}

// Open opens (creating if needed) the index database at path.
func Open(path string) (*Index, error) {
	db, err := bolt.Open(path, 0o644, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("opening index db: %w", err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketBuildID, bucketSymtab, bucketMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Index{db: db}, nil
}

func (idx *Index) Close() error { return idx.db.Close() }

// IndexVersion records a version's symbol table and BuildID so future
// lookups don't need the original ELF file.
func (idx *Index) IndexVersion(versionArch, buildID string, symbols []elfinfo.Symbol) error {
	symData, err := json.Marshal(symbols)
	if err != nil {
		return err
	}
	meta := VersionMeta{VersionArch: versionArch, BuildID: buildID, IndexedAt: time.Now()}
	metaData, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return idx.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketSymtab).Put([]byte(versionArch), symData); err != nil {
			return err
		}
		if err := tx.Bucket(bucketMeta).Put([]byte(versionArch), metaData); err != nil {
			return err
		}
		if buildID != "" {
			if err := tx.Bucket(bucketBuildID).Put([]byte(buildID), []byte(versionArch)); err != nil {
				return err
			}
		}
		return nil
	})
}

// LookupBuildID returns the version_arch indexed under this BuildID, if any.
func (idx *Index) LookupBuildID(buildID string) (string, bool) {
	var versionArch string
	_ = idx.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketBuildID).Get([]byte(buildID))
		if v != nil {
			versionArch = string(v)
		}
		return nil
	})
	return versionArch, versionArch != ""
}

// Symbols returns the cached symbol table for a version_arch.
func (idx *Index) Symbols(versionArch string) ([]elfinfo.Symbol, error) {
	var symbols []elfinfo.Symbol
	err := idx.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSymtab).Get([]byte(versionArch))
		if v == nil {
			return fmt.Errorf("no indexed symbols for %q", versionArch)
		}
		return json.Unmarshal(v, &symbols)
	})
	return symbols, err
}

// AllVersions lists every version_arch currently indexed.
func (idx *Index) AllVersions() ([]VersionMeta, error) {
	var out []VersionMeta
	err := idx.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).ForEach(func(_, v []byte) error {
			var m VersionMeta
			if err := json.Unmarshal(v, &m); err != nil {
				return err
			}
			out = append(out, m)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].VersionArch < out[j].VersionArch })
	return out, err
}

// anchorSymbols is a fixed, stable set of widely-exported glibc functions
// used to fingerprint a version when BuildID matching fails (e.g. the
// build-id note was stripped). More anchors = fewer false positives.
var anchorSymbols = []string{
	"system", "printf", "puts", "execve", "malloc", "free", "read", "write",
	"strlen", "memcpy", "__libc_start_main", "setvbuf", "gets", "open",
}

// FingerprintScore describes how well a candidate version's anchor-symbol
// offsets matched the target file's.
type FingerprintScore struct {
	VersionArch string `json:"version_arch"`
	Matched     int    `json:"matched"`
	Compared    int    `json:"compared"`
}

// IdentifyByFingerprint compares target's anchor symbol offsets against
// every indexed version and returns candidates ranked by match count
// (descending), so the caller can report the best match plus confidence.
func (idx *Index) IdentifyByFingerprint(target []elfinfo.Symbol) ([]FingerprintScore, error) {
	targetOffsets := map[string]uint64{}
	for _, s := range target {
		targetOffsets[s.Name] = s.Value
	}

	versions, err := idx.AllVersions()
	if err != nil {
		return nil, err
	}
	var scores []FingerprintScore
	for _, v := range versions {
		syms, err := idx.Symbols(v.VersionArch)
		if err != nil {
			continue
		}
		candOffsets := map[string]uint64{}
		for _, s := range syms {
			candOffsets[s.Name] = s.Value
		}
		matched, compared := 0, 0
		for _, anchor := range anchorSymbols {
			tv, tok := targetOffsets[anchor]
			cv, cok := candOffsets[anchor]
			if !tok || !cok {
				continue
			}
			compared++
			if tv == cv {
				matched++
			}
		}
		if compared > 0 {
			scores = append(scores, FingerprintScore{VersionArch: v.VersionArch, Matched: matched, Compared: compared})
		}
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].Matched != scores[j].Matched {
			return scores[i].Matched > scores[j].Matched
		}
		return scores[i].Compared > scores[j].Compared
	})
	return scores, nil
}
