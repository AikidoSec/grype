// Package digestfeed clears vulnerability matches for prebuilt binaries that were patched in
// place. Such rebuilds keep the same version string and only the file bytes change, so version
// based matching still reports the CVE. Clearance is therefore keyed on (file sha256, CVE).
package digestfeed

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/grype/internal/log"
)

const (
	fetchTimeout = 10 * time.Second
	maxFeedBytes = 64 << 20
)

// Entry is a single feed record: the content hash of a file and the vulnerabilities that the
// content is known to be patched against.
type Entry struct {
	Sha256  string   `json:"sha256"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Arch    string   `json:"arch"`
	CveIDs  []string `json:"cve_ids"`
}

// Index maps a lowercase sha256 to the set of uppercase vulnerability IDs cleared for that content.
type Index map[string]map[string]struct{}

func NewIndex(entries []Entry) Index {
	index := make(Index, len(entries))
	for _, entry := range entries {
		sha := normalizeSha256(entry.Sha256)
		if sha == "" {
			continue
		}
		cleared, ok := index[sha]
		if !ok {
			cleared = make(map[string]struct{}, len(entry.CveIDs))
			index[sha] = cleared
		}
		for _, id := range entry.CveIDs {
			if id = strings.ToUpper(strings.TrimSpace(id)); id != "" {
				cleared[id] = struct{}{}
			}
		}
	}
	return index
}

func (i Index) Clears(sha256, vulnID string) bool {
	_, ok := i[normalizeSha256(sha256)][strings.ToUpper(strings.TrimSpace(vulnID))]
	return ok
}

// Load reads the feed from an http(s) URL or a local file path. URL responses are cached under
// cacheDir and reused while younger than ttl; if a fetch fails, a stale cache is preferred over
// losing clearance entirely.
func Load(source, cacheDir string, ttl time.Duration) (Index, error) {
	if !isURL(source) {
		return loadFile(source)
	}

	path := cachePath(cacheDir, source)
	if isFresh(path, ttl) {
		index, err := loadFile(path)
		if err == nil {
			return index, nil
		}
		log.WithFields("error", err, "path", path).Debug("unusable digest feed cache, refetching")
	}

	data, err := fetch(source)
	if err != nil {
		index, cacheErr := loadFile(path)
		if cacheErr != nil {
			return nil, err
		}
		log.WithFields("error", err).Warn("unable to fetch digest feed, falling back to stale cache")
		return index, nil
	}

	index, err := parse(data)
	if err != nil {
		return nil, err
	}

	writeCache(path, data)

	return index, nil
}

// cachePath keys the cache by source so that pointing at a different feed does not serve the
// previous feed's contents until the ttl lapses.
func cachePath(cacheDir, source string) string {
	sum := sha256.Sum256([]byte(source))
	return filepath.Join(cacheDir, fmt.Sprintf("digest-feed-%x.json", sum[:6]))
}

func fetch(url string) ([]byte, error) {
	client := &http.Client{Timeout: fetchTimeout}
	resp, err := client.Get(url) //nolint:noctx // the client timeout bounds this request
	if err != nil {
		return nil, fmt.Errorf("unable to fetch digest feed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status fetching digest feed: %s", resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, fmt.Errorf("unable to read digest feed: %w", err)
	}
	return data, nil
}

func loadFile(path string) (Index, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data)
}

func parse(data []byte) (Index, error) {
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("unable to parse digest feed: %w", err)
	}
	return NewIndex(entries), nil
}

// writeCache is best effort: a read-only or full cache dir must not fail the scan.
func writeCache(path string, data []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.WithFields("error", err, "path", path).Debug("unable to create digest feed cache dir")
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.WithFields("error", err, "path", tmp).Debug("unable to write digest feed cache")
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.WithFields("error", err, "path", path).Debug("unable to replace digest feed cache")
		_ = os.Remove(tmp)
	}
}

func isFresh(path string, ttl time.Duration) bool {
	if ttl <= 0 {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && time.Since(info.ModTime()) < ttl
}

func isURL(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

func normalizeSha256(value string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "sha256:"))
}
