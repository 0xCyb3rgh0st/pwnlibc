// Package fetch implements pwnlibc's HTTP retrieval strategy: bounded
// timeouts, exponential-backoff retries per mirror, and racing several
// mirrors concurrently so the fastest reachable one wins.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"
)

// Result describes a successfully downloaded file.
type Result struct {
	MirrorName string
	URL        string
	Path       string
	SHA256     string
	Size       int64
}

// Candidate is one mirror's URL for the same logical file.
type Candidate struct {
	MirrorName string
	URL        string
}

// Options controls retry/backoff/timeout behavior.
type Options struct {
	Timeout    time.Duration
	MaxRetries int
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	if o.MaxRetries <= 0 {
		o.MaxRetries = 3
	}
	return o
}

// GetWithRetry performs an HTTP GET against a single URL, retrying with
// exponential backoff + jitter on transient failures (network errors, 5xx).
// A 4xx response is treated as permanent and returned immediately.
func GetWithRetry(ctx context.Context, url string, opts Options) (*http.Response, error) {
	opts = opts.withDefaults()
	var lastErr error
	for attempt := 0; attempt <= opts.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 300 * time.Millisecond
			backoff += time.Duration(rand.Intn(200)) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 {
			_ = resp.Body.Close()
			cancel()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode >= 400 {
			cancel()
			return resp, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		// Response body must outlive this function; cancel() is deferred to
		// the caller closing resp.Body, so wrap it to cancel the context then.
		resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
		return resp, nil
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", opts.MaxRetries+1, lastErr)
}

type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// DownloadFileRacing races candidates for the *same file* and streams the
// first successful response straight to destPath, computing its SHA256 as
// it goes. Each candidate gets its own cancelable child context so that
// canceling the losers (once a winner is found) can never also tear down
// the winner's still-in-flight response body — they'd otherwise share one
// context and canceling it would kill every read, winner included.
func DownloadFileRacing(ctx context.Context, candidates []Candidate, destPath string, opts Options) (*Result, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no candidates")
	}

	type outcome struct {
		c      Candidate
		resp   *http.Response
		err    error
		cancel context.CancelFunc
	}
	results := make(chan outcome, len(candidates))
	for _, c := range candidates {
		c := c
		cctx, ccancel := context.WithCancel(ctx)
		go func() {
			resp, err := GetWithRetry(cctx, c.URL, opts)
			results <- outcome{c: c, resp: resp, err: err, cancel: ccancel}
		}()
	}

	var winner outcome
	found := false
	var errs []error
	for i := 0; i < len(candidates); i++ {
		r := <-results
		if r.err == nil && !found {
			winner = r
			found = true
			continue // keep winner's context alive; its body is read after this loop
		}
		if r.err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.c.MirrorName, r.err))
		} else if r.resp != nil {
			_ = r.resp.Body.Close()
		}
		r.cancel()
	}
	if !found {
		return nil, fmt.Errorf("all mirrors failed: %v", errs)
	}
	defer winner.cancel()
	defer func() { _ = winner.resp.Body.Close() }()

	out, err := os.Create(destPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = out.Close() }()

	h := sha256.New()
	n, err := io.Copy(out, io.TeeReader(winner.resp.Body, h))
	if err != nil {
		return nil, fmt.Errorf("downloading from %s: %w", winner.c.MirrorName, err)
	}

	return &Result{
		MirrorName: winner.c.MirrorName,
		URL:        winner.c.URL,
		Path:       destPath,
		SHA256:     hex.EncodeToString(h.Sum(nil)),
		Size:       n,
	}, nil
}
