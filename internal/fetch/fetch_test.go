package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestGetWithRetrySucceedsAfterTransientFailure(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	resp, err := GetWithRetry(context.Background(), srv.URL, Options{Timeout: 2 * time.Second, MaxRetries: 5})
	if err != nil {
		t.Fatalf("GetWithRetry: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("got body %q", body)
	}
	if attempts != 3 {
		t.Errorf("got %d attempts, want 3", attempts)
	}
}

func TestGetWithRetryPermanentFailureNoRetry(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := GetWithRetry(context.Background(), srv.URL, Options{Timeout: 2 * time.Second, MaxRetries: 5})
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if attempts != 1 {
		t.Errorf("4xx should not be retried, got %d attempts", attempts)
	}
}

func TestDownloadFileRacingPicksWorkingMirror(t *testing.T) {
	const payload = "the-deb-contents"
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	dest := filepath.Join(t.TempDir(), "out.deb")
	result, err := DownloadFileRacing(context.Background(), []Candidate{
		{MirrorName: "bad", URL: bad.URL},
		{MirrorName: "good", URL: good.URL},
	}, dest, Options{Timeout: 2 * time.Second, MaxRetries: 0})
	if err != nil {
		t.Fatalf("DownloadFileRacing: %v", err)
	}
	if result.MirrorName != "good" {
		t.Errorf("got winning mirror %q, want %q", result.MirrorName, "good")
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != payload {
		t.Errorf("got file contents %q, want %q", data, payload)
	}
	sum := sha256.Sum256([]byte(payload))
	if result.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 mismatch: got %s", result.SHA256)
	}
}

func TestDownloadFileRacingAllFail(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()

	dest := filepath.Join(t.TempDir(), "out.deb")
	_, err := DownloadFileRacing(context.Background(), []Candidate{
		{MirrorName: "bad", URL: bad.URL},
	}, dest, Options{Timeout: 1 * time.Second, MaxRetries: 0})
	if err == nil {
		t.Fatal("expected error when every mirror fails")
	}
}
