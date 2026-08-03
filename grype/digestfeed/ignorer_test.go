package digestfeed

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const patchedSha = "64e8ddd0eb8848d9062ea66a5fca43f86a4c0125e20808c4284d21db9c125c46"

func testIgnorer() *Ignorer {
	return NewIgnorer(
		NewIndex([]Entry{{Sha256: patchedSha, CveIDs: []string{"CVE-2025-62506"}}}),
		map[string]string{"/usr/bin/minio": patchedSha},
	)
}

func testMatch(pkgType syftPkg.Type, path, vulnID string, related ...string) match.Match {
	var refs []vulnerability.Reference
	for _, id := range related {
		refs = append(refs, vulnerability.Reference{ID: id})
	}
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference:              vulnerability.Reference{ID: vulnID},
			RelatedVulnerabilities: refs,
		},
		Package: pkg.Package{
			ID:        pkg.ID(string(pkgType) + "-" + vulnID),
			Name:      "minio",
			Version:   "RELEASE.2025-09-07T16-13-09Z",
			Type:      pkgType,
			Locations: file.NewLocationSet(file.NewLocation(path)),
		},
	}
}

func TestApply(t *testing.T) {
	tests := []struct {
		name        string
		match       match.Match
		wantCleared bool
	}{
		{
			name:        "binary with a cleared content hash is ignored",
			match:       testMatch(syftPkg.BinaryPkg, "/usr/bin/minio", "CVE-2025-62506"),
			wantCleared: true,
		},
		{
			name:        "cleared hash reached through a related CVE",
			match:       testMatch(syftPkg.BinaryPkg, "/usr/bin/minio", "GHSA-xxxx-yyyy-zzzz", "CVE-2025-62506"),
			wantCleared: true,
		},
		{
			name:        "same hash but a different CVE stands",
			match:       testMatch(syftPkg.BinaryPkg, "/usr/bin/minio", "CVE-2024-1111"),
			wantCleared: false,
		},
		{
			name:        "unknown location stands",
			match:       testMatch(syftPkg.BinaryPkg, "/opt/other/minio", "CVE-2025-62506"),
			wantCleared: false,
		},
		{
			name:        "non binary package stands",
			match:       testMatch(syftPkg.GoModulePkg, "/usr/bin/minio", "CVE-2025-62506"),
			wantCleared: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := match.NewMatches(tt.match)

			remaining, ignored := testIgnorer().Apply(&matches, nil)

			if !tt.wantCleared {
				assert.Equal(t, 1, remaining.Count())
				assert.Empty(t, ignored)
				return
			}

			assert.Equal(t, 0, remaining.Count())
			require.Len(t, ignored, 1)
			require.Len(t, ignored[0].AppliedIgnoreRules, 1)
			assert.Equal(t, "CVE-2025-62506", ignored[0].AppliedIgnoreRules[0].Vulnerability)
			assert.Contains(t, ignored[0].AppliedIgnoreRules[0].Reason, patchedSha)
		})
	}
}

func TestApplyKeepsExistingIgnoredMatches(t *testing.T) {
	matches := match.NewMatches(testMatch(syftPkg.BinaryPkg, "/usr/bin/minio", "CVE-2025-62506"))
	existing := []match.IgnoredMatch{{Match: testMatch(syftPkg.GoModulePkg, "/app/main", "CVE-2020-0001")}}

	_, ignored := testIgnorer().Apply(&matches, existing)

	assert.Len(t, ignored, 2)
}

func TestApplyWithoutFeedOrDigestsIsANoop(t *testing.T) {
	matches := match.NewMatches(testMatch(syftPkg.BinaryPkg, "/usr/bin/minio", "CVE-2025-62506"))

	for name, ignorer := range map[string]*Ignorer{
		"nil ignorer": nil,
		"empty feed":  NewIgnorer(nil, map[string]string{"/usr/bin/minio": patchedSha}),
		"no digests":  NewIgnorer(NewIndex([]Entry{{Sha256: patchedSha, CveIDs: []string{"CVE-2025-62506"}}}), nil),
	} {
		t.Run(name, func(t *testing.T) {
			remaining, ignored := ignorer.Apply(&matches, nil)
			assert.Equal(t, 1, remaining.Count())
			assert.Empty(t, ignored)
		})
	}
}

func TestDigestsByPath(t *testing.T) {
	s := &sbom.SBOM{}
	s.Artifacts.FileDigests = map[file.Coordinates][]file.Digest{
		file.NewCoordinates("/usr/bin/minio", "layer-1"): {
			{Algorithm: "sha1", Value: "irrelevant"},
			{Algorithm: "sha256", Value: "sha256:" + patchedSha},
		},
		file.NewCoordinates("etc/hosts", ""):  {{Algorithm: "sha256", Value: "abc"}},
		file.NewCoordinates("/no/digest", ""): {{Algorithm: "md5", Value: "def"}},
		file.NewCoordinates("", ""):           {{Algorithm: "sha256", Value: "ghi"}},
	}

	byPath := DigestsByPath(s)

	assert.Equal(t, patchedSha, byPath["/usr/bin/minio"])
	assert.Equal(t, patchedSha, byPath["usr/bin/minio"], "paths are indexed with and without a leading slash")
	assert.Equal(t, "abc", byPath["/etc/hosts"])
	assert.NotContains(t, byPath, "/no/digest")
	assert.Nil(t, DigestsByPath(nil))
}
