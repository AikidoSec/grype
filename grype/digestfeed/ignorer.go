package digestfeed

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// Ignorer suppresses matches whose package content hash is cleared by the feed.
type Ignorer struct {
	index  Index
	byPath map[string]string
}

func NewIgnorer(index Index, digestsByPath map[string]string) *Ignorer {
	return &Ignorer{index: index, byPath: digestsByPath}
}

// DigestsByPath collects the sha256 of every file in the SBOM, keyed by path both with and
// without a leading slash since package locations are not consistently absolute.
func DigestsByPath(s *sbom.SBOM) map[string]string {
	if s == nil {
		return nil
	}
	byPath := make(map[string]string, len(s.Artifacts.FileDigests))
	for coords, digests := range s.Artifacts.FileDigests {
		sha := sha256Of(digests)
		if sha == "" || coords.RealPath == "" {
			continue
		}
		byPath[coords.RealPath] = sha
		byPath["/"+strings.TrimPrefix(coords.RealPath, "/")] = sha
		byPath[strings.TrimPrefix(coords.RealPath, "/")] = sha
	}
	return byPath
}

// Apply moves every cleared match out of matches and into the ignored set, annotated with the
// hash that cleared it.
func (ig *Ignorer) Apply(matches *match.Matches, ignored []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch) {
	if ig == nil || matches == nil || len(ig.index) == 0 || len(ig.byPath) == 0 {
		return matches, ignored
	}

	var kept []match.Match
	for _, m := range matches.Sorted() {
		sha, vulnID := ig.clearedBy(m)
		if sha == "" {
			kept = append(kept, m)
			continue
		}
		ignored = append(ignored, match.IgnoredMatch{
			Match: m,
			AppliedIgnoreRules: []match.IgnoreRule{{
				Vulnerability: vulnID,
				Reason:        fmt.Sprintf("patched binary content hash %s is cleared by the digest feed", sha),
			}},
		})
	}

	remaining := match.NewMatches(kept...)
	return &remaining, ignored
}

// clearedBy returns the content hash and the vulnerability ID that cleared the match, or empty
// strings when the match stands.
func (ig *Ignorer) clearedBy(m match.Match) (sha, vulnID string) {
	if m.Package.Type != syftPkg.BinaryPkg {
		return "", ""
	}

	sha = ig.sha256For(m.Package)
	if sha == "" {
		return "", ""
	}

	if ig.index.Clears(sha, m.Vulnerability.ID) {
		return sha, m.Vulnerability.ID
	}
	// the match may carry a non-CVE primary ID (e.g. GHSA) while the feed is keyed by CVE
	for _, related := range m.Vulnerability.RelatedVulnerabilities {
		if ig.index.Clears(sha, related.ID) {
			return sha, related.ID
		}
	}
	return "", ""
}

func (ig *Ignorer) sha256For(p pkg.Package) string {
	for _, location := range p.Locations.ToSlice() {
		if sha, ok := ig.byPath[location.RealPath]; ok {
			return sha
		}
	}
	return ""
}

func sha256Of(digests []file.Digest) string {
	for _, digest := range digests {
		switch strings.ToLower(digest.Algorithm) {
		case "sha256", "sha-256":
			return normalizeSha256(digest.Value)
		}
	}
	return ""
}
