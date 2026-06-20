package cyclonedx

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

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

func findMatchingVulnerability(boms []*cdx.BOM, m match.Match) *cdx.Vulnerability {
	for _, bom := range boms {
		if bom.Vulnerabilities == nil {
			continue
		}
		for i := range *bom.Vulnerabilities {
			vuln := &(*bom.Vulnerabilities)[i]
			if vuln.ID == m.Vulnerability.ID && (vulnerabilityAffectsPackage(bom, vuln, m.Package.PURL) || vulnerabilityAffectsSubcomponent(bom, vuln, m)) {
				return vuln
			}
		}
	}
	return nil
}

func vulnerabilityAffectsPackage(bom *cdx.BOM, vuln *cdx.Vulnerability, purl string) bool {
	if purl == "" || vuln.Affects == nil {
		return false
	}
	for _, affected := range *vuln.Affects {
		if affected.Ref == purl || componentPURLForRef(bom, affected.Ref) == purl {
			return true
		}
	}
	return false
}

func componentPURLForRef(bom *cdx.BOM, ref string) string {
	if bom.Components == nil {
		return ""
	}
	for _, component := range *bom.Components {
		if component.BOMRef == ref {
			return component.PackageURL
		}
	}
	return ""
}

func vulnerabilityAffectsSubcomponent(bom *cdx.BOM, vuln *cdx.Vulnerability, m match.Match) bool {
	if !isGoPackage(m.Package) || vuln.Affects == nil || len(*vuln.Affects) == 0 {
		return false
	}

	parentRefs := componentRefsForPURL(bom, m.Package.PURL)
	if len(parentRefs) == 0 {
		return false
	}

	for _, affected := range *vuln.Affects {
		if !componentIsSubcomponentOfPackage(bom, affected.Ref, m.Package.PURL) || !anyParentDependsOnRef(bom, parentRefs, affected.Ref) {
			return false
		}
	}
	return true
}

func isGoPackage(p pkg.Package) bool {
	return strings.HasPrefix(p.PURL, "pkg:golang/")
}

func componentRefsForPURL(bom *cdx.BOM, purl string) []string {
	if purl == "" {
		return nil
	}

	refs := []string{}
	if bom.Components != nil {
		for _, component := range *bom.Components {
			if component.PackageURL == purl {
				refs = append(refs, component.BOMRef)
			}
		}
	}
	if len(refs) == 0 {
		refs = append(refs, purl)
	}
	return refs
}

func componentIsSubcomponentOfPackage(bom *cdx.BOM, ref string, parentPURL string) bool {
	if ref == "" || parentPURL == "" {
		return false
	}
	for _, candidate := range []string{ref, componentPURLForRef(bom, ref)} {
		if candidate == "" || candidate == parentPURL {
			continue
		}
		if strings.HasPrefix(candidate, parentPURL+"#") {
			return true
		}
		parentName := strings.Split(parentPURL, "@")[0]
		if strings.HasPrefix(candidate, parentName+"/") {
			return true
		}
	}
	return false
}

func anyParentDependsOnRef(bom *cdx.BOM, parentRefs []string, childRef string) bool {
	for _, parentRef := range parentRefs {
		if dependsOnRef(bom, parentRef, childRef, map[string]bool{}) {
			return true
		}
	}
	return false
}

func dependsOnRef(bom *cdx.BOM, parentRef string, childRef string, visited map[string]bool) bool {
	if bom.Dependencies == nil || parentRef == "" || childRef == "" || visited[parentRef] {
		return false
	}
	visited[parentRef] = true

	for _, dependency := range *bom.Dependencies {
		if dependency.Ref != parentRef || dependency.Dependencies == nil {
			continue
		}
		for _, ref := range *dependency.Dependencies {
			if ref == childRef || dependsOnRef(bom, ref, childRef, visited) {
				return true
			}
		}
	}
	return false
}

func analysisState(vuln *cdx.Vulnerability) vexStatus.Status {
	if vuln.Analysis == nil {
		return ""
	}
	switch vuln.Analysis.State {
	case cdx.IASNotAffected:
		return vexStatus.NotAffected
	case cdx.IASResolved, cdx.IASResolvedWithPedigree:
		return vexStatus.Fixed
	case cdx.IASExploitable:
		return vexStatus.Affected
	case cdx.IASInTriage:
		return vexStatus.UnderInvestigation
	default:
		return ""
	}
}

func matchingRule(ignoreRules []match.IgnoreRule, m match.Match, vuln *cdx.Vulnerability, state vexStatus.Status, allowedStatuses []vexStatus.Status) *match.IgnoreRule {
	ms := match.NewMatches()
	ms.Add(m)

	if len(ignoreRules) == 0 && slices.Contains(allowedStatuses, state) {
		return &match.IgnoreRule{
			Namespace:        "vex",
			Vulnerability:    vuln.ID,
			VexJustification: vulnerabilityJustification(vuln),
			VexStatus:        string(state),
		}
	}

	for _, rule := range ignoreRules {
		if rule.HasConditions() {
			r := rule
			r.VexStatus = ""
			if _, ignored := match.ApplyIgnoreRules(ms, []match.IgnoreRule{r}); len(ignored) == 0 {
				continue
			}
		}

		if string(state) != rule.VexStatus {
			continue
		}

		if rule.VexStatus != "" && !slices.Contains(allowedStatuses, vexStatus.Status(rule.VexStatus)) {
			continue
		}

		if state == vexStatus.NotAffected && rule.VexJustification != "" && rule.VexJustification != vulnerabilityJustification(vuln) {
			continue
		}

		if rule.Vulnerability == "" || rule.Vulnerability == vuln.ID {
			return &rule
		}
	}

	return nil
}

func vulnerabilityJustification(vuln *cdx.Vulnerability) string {
	if vuln.Analysis == nil {
		return ""
	}
	return string(vuln.Analysis.Justification)
}
