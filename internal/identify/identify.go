// Package identify determines which glibc version an unknown .so/binary is,
// trying (in order) BuildID exact match against the local index, BuildID
// lookup via libc.rip, and finally anchor-symbol fingerprint matching
// against every locally indexed version.
package identify

import (
	"context"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/elfinfo"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/index"
	"github.com/0xCyb3rgh0st/pwnlibc/internal/libcrip"
)

// Method records which technique produced the result.
type Method string

const (
	MethodBuildIDLocal  Method = "buildid_local"
	MethodBuildIDOnline Method = "buildid_online"
	MethodFingerprint   Method = "fingerprint"
	MethodNone          Method = "none"
)

// Result is the outcome of an identify attempt.
type Result struct {
	Method      Method                   `json:"method"`
	VersionArch string                   `json:"version_arch,omitempty"`
	BuildID     string                   `json:"build_id,omitempty"`
	Confidence  string                   `json:"confidence,omitempty"` // "exact", "high", "low"
	Candidates  []index.FingerprintScore `json:"candidates,omitempty"`
	OnlineMatch *libcrip.Match           `json:"online_match,omitempty"`
}

// Identify runs the full offline-first, online-fallback pipeline. Pass
// offline=true to skip the libc.rip network call entirely.
func Identify(ctx context.Context, idx *index.Index, ripClient *libcrip.Client, info *elfinfo.Info, symbols []elfinfo.Symbol, offline bool) (*Result, error) {
	if info.BuildID != "" {
		if versionArch, ok := idx.LookupBuildID(info.BuildID); ok {
			return &Result{Method: MethodBuildIDLocal, VersionArch: versionArch, BuildID: info.BuildID, Confidence: "exact"}, nil
		}
	}

	if info.BuildID != "" && !offline && ripClient != nil {
		matches, err := ripClient.FindByBuildID(ctx, info.BuildID)
		if err == nil && len(matches) > 0 {
			for _, m := range matches {
				for _, bid := range m.BuildID {
					if bid == info.BuildID {
						mm := m
						return &Result{Method: MethodBuildIDOnline, BuildID: info.BuildID, Confidence: "exact", OnlineMatch: &mm}, nil
					}
				}
			}
		}
	}

	scores, err := idx.IdentifyByFingerprint(symbols)
	if err != nil {
		return nil, err
	}
	if len(scores) == 0 {
		return &Result{Method: MethodNone, BuildID: info.BuildID}, nil
	}

	top := scores[0]
	confidence := "low"
	if top.Compared > 0 && top.Matched == top.Compared && top.Compared >= 6 {
		confidence = "high"
	}
	maxCandidates := 5
	if len(scores) < maxCandidates {
		maxCandidates = len(scores)
	}
	return &Result{
		Method:      MethodFingerprint,
		VersionArch: top.VersionArch,
		BuildID:     info.BuildID,
		Confidence:  confidence,
		Candidates:  scores[:maxCandidates],
	}, nil
}
