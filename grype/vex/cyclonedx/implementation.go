package cyclonedx

import (
	"errors"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	vexStatus "github.com/anchore/grype/grype/vex/status"
)

type Processor struct{}

func New() *Processor {
	return &Processor{}
}

type Match struct {
	Vulnerability cdx.Vulnerability
}

type SearchedBy struct {
	Vulnerability string
	Package       string
}

func IsCycloneDX(document string) bool {
	bom, err := readBOM(document)
	return err == nil && bom.BOMFormat == cdx.BOMFormat
}

func HasVulnerabilityData(document string) bool {
	bom, err := readBOM(document)
	if err != nil || bom.BOMFormat != cdx.BOMFormat || bom.Vulnerabilities == nil {
		return false
	}
	return len(*bom.Vulnerabilities) > 0
}

func readBOM(document string) (*cdx.BOM, error) {
	f, err := os.Open(document)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, err
	}
	return bom, nil
}

func (p *Processor) ReadVexDocuments(docs []string) (any, error) {
	var boms []*cdx.BOM
	for _, doc := range docs {
		f, err := os.Open(doc)
		if err != nil {
			return nil, fmt.Errorf("opening CycloneDX VEX document %q: %w", doc, err)
		}

		bom := new(cdx.BOM)
		decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
		if err := decoder.Decode(bom); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("decoding CycloneDX VEX document %q: %w", doc, err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("closing CycloneDX VEX document %q: %w", doc, err)
		}
		boms = append(boms, bom)
	}
	return boms, nil
}

func (p *Processor) FilterMatches(
	docRaw any, ignoreRules []match.IgnoreRule, _ *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	boms, ok := docRaw.([]*cdx.BOM)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as CycloneDX BOMs")
	}

	remainingMatches := match.NewMatches()
	for _, m := range matches.Sorted() {
		vuln := findMatchingVulnerability(boms, m)
		if vuln == nil {
			remainingMatches.Add(m)
			continue
		}

		state := analysisState(vuln)
		if state != vexStatus.NotAffected && state != vexStatus.Fixed {
			remainingMatches.Add(m)
			continue
		}

		rule := matchingRule(ignoreRules, m, vuln, state, vexStatus.IgnoreList())
		if rule == nil {
			remainingMatches.Add(m)
			continue
		}

		ignoredMatches = append(ignoredMatches, match.IgnoredMatch{
			Match:              m,
			AppliedIgnoreRules: []match.IgnoreRule{*rule},
		})
	}

	return &remainingMatches, ignoredMatches, nil
}

func (p *Processor) AugmentMatches(
	docRaw any, ignoreRules []match.IgnoreRule, _ *pkg.Context, matches *match.Matches, ignoredMatches []match.IgnoredMatch,
) (*match.Matches, []match.IgnoredMatch, error) {
	boms, ok := docRaw.([]*cdx.BOM)
	if !ok {
		return nil, nil, errors.New("unable to cast vex document as CycloneDX BOMs")
	}

	remainingIgnoredMatches := []match.IgnoredMatch{}
	for _, ignored := range ignoredMatches {
		vuln := findMatchingVulnerability(boms, ignored.Match)
		if vuln == nil {
			remainingIgnoredMatches = append(remainingIgnoredMatches, ignored)
			continue
		}

		state := analysisState(vuln)
		if state != vexStatus.Affected && state != vexStatus.UnderInvestigation {
			remainingIgnoredMatches = append(remainingIgnoredMatches, ignored)
			continue
		}

		rule := matchingRule(ignoreRules, ignored.Match, vuln, state, vexStatus.AugmentList())
		if rule == nil {
			remainingIgnoredMatches = append(remainingIgnoredMatches, ignored)
			continue
		}

		newMatch := ignored.Match
		newMatch.Details = append(newMatch.Details, match.Detail{
			Type: match.ExactDirectMatch,
			SearchedBy: &SearchedBy{
				Vulnerability: ignored.Vulnerability.ID,
				Package:       ignored.Package.PURL,
			},
			Found:   Match{Vulnerability: *vuln},
			Matcher: match.CycloneDXVexMatcher,
		})
		matches.Add(newMatch)
	}

	return matches, remainingIgnoredMatches, nil
}
