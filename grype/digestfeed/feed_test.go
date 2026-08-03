package digestfeed

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const feedJSON = `[
  {"sha256":"64E8DDD0EB8848D9","name":"minio","version":"RELEASE.2025-09-07T16-13-09Z","arch":"amd64","cve_ids":["CVE-2025-62506"]},
  {"sha256":"sha256:33917deb0741b801","name":"minio","version":"RELEASE.2025-09-07T16-13-09Z","arch":"arm64","cve_ids":["cve-2025-62506","CVE-2024-1111"]}
]`

func TestIndexClearsIgnoresCasingAndPrefix(t *testing.T) {
	index, err := parse([]byte(feedJSON))
	require.NoError(t, err)
	require.Len(t, index, 2)

	assert.True(t, index.Clears("64e8ddd0eb8848d9", "CVE-2025-62506"))
	assert.True(t, index.Clears("sha256:64E8DDD0EB8848D9", "cve-2025-62506"), "sha prefix and casing should not matter")
	assert.True(t, index.Clears("33917deb0741b801", "CVE-2024-1111"))

	assert.False(t, index.Clears("64e8ddd0eb8848d9", "CVE-2024-1111"), "cleared CVEs are per hash")
	assert.False(t, index.Clears("deadbeef", "CVE-2025-62506"))
	assert.False(t, index.Clears("", ""))
}

func TestLoadFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.json")
	require.NoError(t, os.WriteFile(path, []byte(feedJSON), 0o600))

	index, err := Load(path, t.TempDir(), time.Hour)
	require.NoError(t, err)
	assert.True(t, index.Clears("64e8ddd0eb8848d9", "CVE-2025-62506"))
}

func TestLoadFromURLCachesAndReuses(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(feedJSON))
	}))
	defer server.Close()

	cacheDir := t.TempDir()

	index, err := Load(server.URL, cacheDir, time.Hour)
	require.NoError(t, err)
	assert.True(t, index.Clears("64e8ddd0eb8848d9", "CVE-2025-62506"))
	assert.FileExists(t, cachePath(cacheDir, server.URL))

	index, err = Load(server.URL, cacheDir, time.Hour)
	require.NoError(t, err)
	assert.True(t, index.Clears("64e8ddd0eb8848d9", "CVE-2025-62506"))
	assert.Equal(t, 1, hits, "a fresh cache should not be refetched")

	_, err = Load(server.URL, cacheDir, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, hits, "a zero ttl should always refetch")
}

func TestLoadFallsBackToStaleCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	require.NoError(t, os.WriteFile(cachePath(cacheDir, server.URL), []byte(feedJSON), 0o600))

	index, err := Load(server.URL, cacheDir, 0)
	require.NoError(t, err)
	assert.True(t, index.Clears("64e8ddd0eb8848d9", "CVE-2025-62506"))
}

func TestCachePathIsPerSource(t *testing.T) {
	cacheDir := t.TempDir()

	assert.NotEqual(t, cachePath(cacheDir, "https://a.example/feed"), cachePath(cacheDir, "https://b.example/feed"))
	assert.Equal(t, cachePath(cacheDir, "https://a.example/feed"), cachePath(cacheDir, "https://a.example/feed"))
}

func TestLoadFailsWithoutFeedOrCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := Load(server.URL, t.TempDir(), time.Hour)
	assert.Error(t, err)

	_, err = Load(filepath.Join(t.TempDir(), "missing.json"), t.TempDir(), time.Hour)
	assert.Error(t, err)
}
