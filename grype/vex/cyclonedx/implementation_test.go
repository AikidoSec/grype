package cyclonedx

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

func TestFilterMatches_StdlibSubcomponentVEX(t *testing.T) {
	const (
		stdlibPURL = "pkg:golang/stdlib@go1.23.4"
		httpPURL   = "pkg:golang/stdlib/net/http@go1.23.4"
		vulnID     = "GO-2024-1234"
	)

	stdlibMatch := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: vulnID},
		},
		Package: pkg.Package{
			Name: "stdlib",
			PURL: stdlibPURL,
		},
	}

	tests := []struct {
		name        string
		bom         *cdx.BOM
		wantIgnored bool
	}{
		{
			name:        "suppresses stdlib parent when graph links affected subcomponent",
			bom:         stdlibSubcomponentBOM(stdlibPURL, httpPURL, vulnID, true),
			wantIgnored: true,
		},
		{
			name: "keeps stdlib parent when affected subcomponent is not linked from parent",
			bom:  stdlibSubcomponentBOM(stdlibPURL, httpPURL, vulnID, false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := New()
			matches := match.NewMatches(stdlibMatch)

			remaining, ignored, err := processor.FilterMatches([]*cdx.BOM{tt.bom}, nil, nil, &matches, nil)
			require.NoError(t, err)

			if tt.wantIgnored {
				require.Empty(t, remaining.Sorted())
				require.Len(t, ignored, 1)
				return
			}
			require.Len(t, remaining.Sorted(), 1)
			require.Empty(t, ignored)
		})
	}
}

func TestFilterMatches_GoModuleSubcomponentVEX(t *testing.T) {
	const (
		parentPURL = "pkg:golang/github.com/quic-go/quic-go@v0.39.0"
		childRef   = "pkg:golang/github.com/quic-go/quic-go@v0.39.0#github.com/quic-go/quic-go/http3"
		childPURL  = "pkg:golang/github.com/quic-go/quic-go/github.com/quic-go/quic-go/http3@v0.39.0"
		vulnID     = "GO-2025-4233"
	)

	moduleMatch := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: vulnID},
		},
		Package: pkg.Package{
			Name: "github.com/quic-go/quic-go",
			PURL: parentPURL,
		},
	}

	tests := []struct {
		name        string
		bom         *cdx.BOM
		wantIgnored bool
	}{
		{
			name:        "suppresses module parent when graph links affected package",
			bom:         goModuleSubcomponentBOM(parentPURL, childRef, childPURL, vulnID, true),
			wantIgnored: true,
		},
		{
			name: "keeps module parent when affected package is not linked from parent",
			bom:  goModuleSubcomponentBOM(parentPURL, childRef, childPURL, vulnID, false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := New()
			matches := match.NewMatches(moduleMatch)

			remaining, ignored, err := processor.FilterMatches([]*cdx.BOM{tt.bom}, nil, nil, &matches, nil)
			require.NoError(t, err)

			if tt.wantIgnored {
				require.Empty(t, remaining.Sorted())
				require.Len(t, ignored, 1)
				return
			}
			require.Len(t, remaining.Sorted(), 1)
			require.Empty(t, ignored)
		})
	}
}

func TestFilterMatches_AffectsComponentRefWithPackageURL(t *testing.T) {
	const (
		componentRef = "pkg:golang/golang.org/x/crypto@v0.49.0?package-id=abc"
		packagePURL  = "pkg:golang/golang.org/x/crypto@v0.49.0"
		vulnID       = "GO-2026-5005"
	)

	cryptoMatch := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: vulnID},
		},
		Package: pkg.Package{
			Name: "golang.org/x/crypto",
			PURL: packagePURL,
		},
	}

	matches := match.NewMatches(cryptoMatch)
	remaining, ignored, err := New().FilterMatches(
		[]*cdx.BOM{
			{
				BOMFormat: cdx.BOMFormat,
				Components: &[]cdx.Component{
					{
						BOMRef:     componentRef,
						Type:       cdx.ComponentTypeLibrary,
						Name:       "golang.org/x/crypto",
						Version:    "v0.49.0",
						PackageURL: packagePURL,
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{
					{
						ID: vulnID,
						Analysis: &cdx.VulnerabilityAnalysis{
							State:         cdx.IASNotAffected,
							Justification: cdx.IAJCodeNotReachable,
						},
						Affects: &[]cdx.Affects{{Ref: componentRef}},
					},
				},
			},
		},
		nil,
		nil,
		&matches,
		nil,
	)

	require.NoError(t, err)
	require.Empty(t, remaining.Sorted())
	require.Len(t, ignored, 1)
}

func stdlibSubcomponentBOM(stdlibPURL, subcomponentPURL, vulnID string, linkSubcomponent bool) *cdx.BOM {
	dependencies := []cdx.Dependency{{Ref: stdlibPURL}}
	if linkSubcomponent {
		dependencies[0].Dependencies = &[]string{subcomponentPURL}
	}

	return &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Components: &[]cdx.Component{
			{
				BOMRef:     stdlibPURL,
				Type:       cdx.ComponentTypeLibrary,
				Name:       "stdlib",
				Version:    "go1.23.4",
				PackageURL: stdlibPURL,
			},
			{
				BOMRef:     subcomponentPURL,
				Type:       cdx.ComponentTypeLibrary,
				Name:       "stdlib/net/http",
				Version:    "go1.23.4",
				PackageURL: subcomponentPURL,
			},
		},
		Dependencies: &dependencies,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: vulnID,
				Analysis: &cdx.VulnerabilityAnalysis{
					State:         cdx.IASNotAffected,
					Justification: cdx.IAJCodeNotReachable,
				},
				Affects: &[]cdx.Affects{{Ref: subcomponentPURL}},
			},
		},
	}
}

func goModuleSubcomponentBOM(parentPURL, childRef, childPURL, vulnID string, linkSubcomponent bool) *cdx.BOM {
	dependencies := []cdx.Dependency{{Ref: parentPURL}}
	if linkSubcomponent {
		dependencies[0].Dependencies = &[]string{childRef}
	}

	return &cdx.BOM{
		BOMFormat: cdx.BOMFormat,
		Components: &[]cdx.Component{
			{
				BOMRef:     parentPURL,
				Type:       cdx.ComponentTypeLibrary,
				Name:       "github.com/quic-go/quic-go",
				Version:    "v0.39.0",
				PackageURL: parentPURL,
			},
			{
				BOMRef:     childRef,
				Type:       cdx.ComponentTypeLibrary,
				Name:       "github.com/quic-go/quic-go/http3",
				Version:    "v0.39.0",
				PackageURL: childPURL,
			},
		},
		Dependencies: &dependencies,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: vulnID,
				Analysis: &cdx.VulnerabilityAnalysis{
					State:         cdx.IASNotAffected,
					Justification: cdx.IAJCodeNotReachable,
				},
				Affects: &[]cdx.Affects{{Ref: childRef}},
			},
		},
	}
}
