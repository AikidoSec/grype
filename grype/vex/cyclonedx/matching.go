package cyclonedx

import (
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	vexStatus "github.com/anchore/grype/grype/vex/status"
)

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
