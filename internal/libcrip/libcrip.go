// Package libcrip is a client for the libc.rip public reverse-symbol-lookup
// API, used by `search --symbol` and the online path of `identify`.
package libcrip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const baseURL = "https://libc.rip"

// Match is one candidate libc returned by a symbol query.
type Match struct {
	ID       string            `json:"id"`
	BuildID  []string          `json:"buildid"`
	MD5      string            `json:"md5"`
	SHA1     string            `json:"sha1"`
	SHA256   string            `json:"sha256"`
	Symbols  map[string]string `json:"symbols"`
	Download string            `json:"download_url"`
}

type Client struct {
	http *http.Client
}

func NewClient() *Client {
	return &Client{http: &http.Client{Timeout: 15 * time.Second}}
}

// Find performs a reverse lookup: given a set of symbol -> address (hex
// string, e.g. "0x4f440") pairs, returns every libc whose symbols match all
// of them exactly.
func (c *Client) Find(ctx context.Context, symbols map[string]string) ([]Match, error) {
	return c.find(ctx, map[string]interface{}{"symbols": symbols})
}

// FindByBuildID performs a reverse lookup by BuildID hex string instead of
// symbol offsets.
func (c *Client) FindByBuildID(ctx context.Context, buildID string) ([]Match, error) {
	return c.find(ctx, map[string]interface{}{"buildid": buildID})
}

func (c *Client) find(ctx context.Context, payload map[string]interface{}) ([]Match, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/find", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("libc.rip unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("libc.rip returned HTTP %d", resp.StatusCode)
	}

	var matches []Match
	if err := json.NewDecoder(resp.Body).Decode(&matches); err != nil {
		return nil, fmt.Errorf("decoding libc.rip response: %w", err)
	}
	return matches, nil
}

// Get fetches full metadata for a single libc by its libc.rip id.
func (c *Client) Get(ctx context.Context, id string) (*Match, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/libc/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("libc.rip unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("libc.rip returned HTTP %d for id %q", resp.StatusCode, id)
	}
	var m Match
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DownloadTo streams the libc.rip "download all files" bundle for id to w.
func (c *Client) DownloadTo(ctx context.Context, id string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/download/%s", baseURL, id), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("libc.rip unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("libc.rip returned HTTP %d for download %q", resp.StatusCode, id)
	}
	_, err = io.Copy(w, resp.Body)
	return err
}
