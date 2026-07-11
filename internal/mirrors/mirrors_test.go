package mirrors

import (
	"testing"

	"pwnlibc/internal/config"
)

func TestNewRegistryDefaultOrdering(t *testing.T) {
	cfg := config.Default()
	reg := NewRegistry(cfg)
	all := reg.All()
	if len(all) != 4 {
		t.Fatalf("got %d mirrors, want 4 built-ins", len(all))
	}
	if all[0].Name != "tuna" {
		t.Errorf("got first mirror %q, want tuna", all[0].Name)
	}
	if !all[len(all)-1].Fallback {
		t.Errorf("expected the last mirror (old-releases) to be marked Fallback")
	}
}

func TestNewRegistryRespectsCustomPriority(t *testing.T) {
	cfg := config.Default()
	cfg.MirrorPriority = []string{"ubuntu-archive", "tuna"}
	reg := NewRegistry(cfg)
	all := reg.All()
	if all[0].Name != "ubuntu-archive" || all[1].Name != "tuna" {
		t.Errorf("got order %v", names(all))
	}
}

func TestNewRegistryIncludesCustomMirrors(t *testing.T) {
	cfg := config.Default()
	cfg.CustomMirrors = []config.Mirror{{Name: "corp-mirror", BaseURL: "https://mirror.corp.internal/ubuntu"}}
	reg := NewRegistry(cfg)
	found := false
	for _, m := range reg.All() {
		if m.Name == "corp-mirror" {
			found = true
		}
	}
	if !found {
		t.Error("expected custom mirror to be present in the registry")
	}
}

func TestCircuitBreakerDeprioritizesFailingMirror(t *testing.T) {
	reg := NewRegistry(config.Default())
	total := len(reg.All())

	for i := 0; i < circuitOpenThreshold; i++ {
		reg.RecordFailure("tuna")
	}
	ranked := reg.Ranked()
	tunaIdx := -1
	for i, m := range ranked {
		if m.Name == "tuna" {
			tunaIdx = i
		}
	}
	if tunaIdx != total-1 {
		t.Errorf("expected tuna to sink to the last position after %d failures, got index %d of %d", circuitOpenThreshold, tunaIdx, total)
	}

	reg.RecordSuccess("tuna")
	ranked = reg.Ranked()
	if ranked[0].Name != "tuna" {
		t.Errorf("expected tuna to return to front after RecordSuccess, got order %v", names(ranked))
	}
}

func names(ms []Mirror) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Name
	}
	return out
}
