// Package mirrors defines the registry of apt mirrors pwnlibc downloads
// glibc packages from, and probes them concurrently for availability.
package mirrors

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/0xCyb3rgh0st/pwnlibc/internal/config"
)

// Mirror is a single apt-style mirror hosting the Ubuntu glibc pool.
type Mirror struct {
	Name     string
	BaseURL  string // e.g. https://mirrors.tuna.tsinghua.edu.cn/ubuntu
	Fallback bool
}

// PoolURL returns the glibc pool directory for this mirror, where all
// libc6*.deb files (across every Ubuntu release, current and historical)
// are listed.
func (m Mirror) PoolURL() string {
	return fmt.Sprintf("%s/pool/main/g/glibc/", m.BaseURL)
}

// builtins are tried in this order unless overridden by config.MirrorPriority.
var builtins = []Mirror{
	{Name: "tuna", BaseURL: "https://mirrors.tuna.tsinghua.edu.cn/ubuntu"},
	{Name: "ustc", BaseURL: "https://mirrors.ustc.edu.cn/ubuntu"},
	{Name: "ubuntu-archive", BaseURL: "http://archive.ubuntu.com/ubuntu"},
	{Name: "old-releases", BaseURL: "http://old-releases.ubuntu.com/ubuntu", Fallback: true},
}

// Registry resolves the effective mirror list: built-ins reordered by
// config priority, plus any user-defined custom mirrors.
type Registry struct {
	mirrors []Mirror
	health  *healthTracker
}

func NewRegistry(cfg *config.Config) *Registry {
	byName := map[string]Mirror{}
	for _, m := range builtins {
		byName[m.Name] = m
	}

	var ordered []Mirror
	seen := map[string]bool{}
	for _, name := range cfg.MirrorPriority {
		if m, ok := byName[name]; ok && !seen[name] {
			ordered = append(ordered, m)
			seen[name] = true
		}
	}
	// Append any built-ins not mentioned in priority (keeps new defaults visible).
	for _, m := range builtins {
		if !seen[m.Name] {
			ordered = append(ordered, m)
			seen[m.Name] = true
		}
	}
	for _, cm := range cfg.CustomMirrors {
		ordered = append(ordered, Mirror{Name: cm.Name, BaseURL: cm.BaseURL, Fallback: cm.Fallback})
	}

	// Non-fallback mirrors first, fallback ones last, each group stable-sorted.
	var primary, fallback []Mirror
	for _, m := range ordered {
		if m.Fallback {
			fallback = append(fallback, m)
		} else {
			primary = append(primary, m)
		}
	}

	return &Registry{mirrors: append(primary, fallback...), health: newHealthTracker()}
}

// All returns the effective, priority-ordered mirror list.
func (r *Registry) All() []Mirror { return r.mirrors }

// Ranked returns mirrors ordered by priority first, then by this session's
// observed health: a mirror that has failed repeatedly is deprioritized
// (circuit breaker) instead of being retried up front every time.
func (r *Registry) Ranked() []Mirror {
	out := make([]Mirror, len(r.mirrors))
	copy(out, r.mirrors)
	healthy, unhealthy := out[:0:0], []Mirror{}
	for _, m := range out {
		if r.health.isOpen(m.Name) {
			unhealthy = append(unhealthy, m)
		} else {
			healthy = append(healthy, m)
		}
	}
	return append(healthy, unhealthy...)
}

// RecordFailure marks a mirror failure; after enough consecutive failures
// the circuit opens and it sinks to the back of Ranked().
func (r *Registry) RecordFailure(name string) { r.health.recordFailure(name) }

// RecordSuccess resets a mirror's failure count.
func (r *Registry) RecordSuccess(name string) { r.health.recordSuccess(name) }

// healthTracker implements a simple per-session circuit breaker: no timers,
// no persistence — just "stop trying this mirror first after N failures".
type healthTracker struct {
	failures map[string]int
}

const circuitOpenThreshold = 3

func newHealthTracker() *healthTracker {
	return &healthTracker{failures: map[string]int{}}
}

func (h *healthTracker) recordFailure(name string) { h.failures[name]++ }
func (h *healthTracker) recordSuccess(name string) { h.failures[name] = 0 }
func (h *healthTracker) isOpen(name string) bool   { return h.failures[name] >= circuitOpenThreshold }

// Probe checks whether a mirror's pool directory is reachable within timeout.
func Probe(ctx context.Context, m Mirror, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, m.PoolURL(), nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s: HTTP %d", m.Name, resp.StatusCode)
	}
	return nil
}
