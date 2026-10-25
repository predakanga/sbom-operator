package processor

import (
	"slices"
	"testing"

	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/stretchr/testify/assert"
)

func TestInitTargets(t *testing.T) {
	internal.OperatorConfig = &internal.Config{
		Targets:       []string{"dtrack", "configmap"},
		DtrackBaseUrl: "http://localhost",
		DtrackApiKey:  "api",
	}

	targets := initTargets(nil)
	assert.Len(t, targets, 2)
}

func TestIsNamespaceAllowed(t *testing.T) {
	p := &Processor{
		allowedNamespaces: make(map[string]bool),
	}

	internal.OperatorConfig = &internal.Config{NamespaceLabelSelector: ""}
	assert.True(t, p.isNamespaceAllowed("default"))

	internal.OperatorConfig = &internal.Config{NamespaceLabelSelector: "scan=true"}
	assert.False(t, p.isNamespaceAllowed("default"))

	p.addAllowedNamespace("default")
	assert.True(t, p.isNamespaceAllowed("default"))

	p.removeAllowedNamespace("default")
	assert.False(t, p.isNamespaceAllowed("default"))
}

func TestNamespaceLabelMatches(t *testing.T) {
	p := &Processor{}
	selector := "scan=true"

	labels1 := map[string]string{"scan": "true"}
	assert.True(t, p.namespaceLabelMatches(labels1, selector))

	labels2 := map[string]string{"scan": "false"}
	assert.False(t, p.namespaceLabelMatches(labels2, selector))

	labels3 := map[string]string{"foo": "bar"}
	assert.False(t, p.namespaceLabelMatches(labels3, selector))
}

// fakeTarget records the SBOMs it receives and accepts every media type.
type fakeTarget struct {
	received []*target.TargetContext
}

func (f *fakeTarget) Initialize() error     { return nil }
func (f *fakeTarget) ValidateConfig() error { return nil }
func (f *fakeTarget) ProcessSbom(ctx *target.TargetContext) error {
	f.received = append(f.received, ctx)
	return nil
}
func (f *fakeTarget) LoadImages() ([]*liboci.RegistryImage, error) { return nil, nil }
func (f *fakeTarget) Remove(images []*liboci.RegistryImage) error  { return nil }

// filteringTarget implements target.MediaTypeFilter.
type filteringTarget struct {
	fakeTarget
	accepted []string
}

func (f *filteringTarget) AcceptsMediaType(mediaType string) bool {
	return mediaType == "" || slices.Contains(f.accepted, mediaType)
}

func TestSbomDispatch(t *testing.T) {
	cdx := target.NewContext("cdx", nil, nil).WithAttestation("", oci.CycloneDXJSONMediaType)
	spdx := target.NewContext("spdx", nil, nil).WithAttestation("", oci.SPDXJSONMediaType)
	scopedSpdx := target.NewContext("scoped-spdx", nil, nil).WithAttestation("app", oci.SPDXJSONMediaType)
	syftCtx := target.NewContext("syft", nil, nil)

	acceptAll := &fakeTarget{}
	cdxOnly := &filteringTarget{accepted: []string{oci.CycloneDXJSONMediaType}}

	tests := []struct {
		name          string
		targets       []target.Target
		attestations  []*target.TargetContext
		expectSyft    bool
		expectedSboms map[target.Target][]string
	}{
		{
			name:          "no attestations",
			targets:       []target.Target{acceptAll, cdxOnly},
			attestations:  nil,
			expectSyft:    true,
			expectedSboms: map[target.Target][]string{acceptAll: {"syft"}, cdxOnly: {"syft"}},
		},
		{
			name:          "default-scope CycloneDX accepted by all",
			targets:       []target.Target{acceptAll, cdxOnly},
			attestations:  []*target.TargetContext{cdx},
			expectSyft:    false,
			expectedSboms: map[target.Target][]string{acceptAll: {"cdx"}, cdxOnly: {"cdx"}},
		},
		{
			name:          "default-scope SPDX only usable by one target",
			targets:       []target.Target{acceptAll, cdxOnly},
			attestations:  []*target.TargetContext{spdx},
			expectSyft:    true,
			expectedSboms: map[target.Target][]string{acceptAll: {"spdx"}, cdxOnly: {"syft"}},
		},
		{
			name:          "default-scope SPDX with a filtering target only",
			targets:       []target.Target{cdxOnly},
			attestations:  []*target.TargetContext{spdx},
			expectSyft:    true,
			expectedSboms: map[target.Target][]string{cdxOnly: {"syft"}},
		},
		{
			name:          "scoped attestation doesn't replace the default SBOM",
			targets:       []target.Target{acceptAll},
			attestations:  []*target.TargetContext{scopedSpdx},
			expectSyft:    true,
			expectedSboms: map[target.Target][]string{acceptAll: {"scoped-spdx", "syft"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectSyft, needsSyftSbom(tt.targets, tt.attestations))

			var syft *target.TargetContext
			if tt.expectSyft {
				syft = syftCtx
			}

			for _, ta := range tt.targets {
				sboms := make([]string, 0)
				for _, ctx := range sbomsForTarget(ta, tt.attestations, syft) {
					sboms = append(sboms, ctx.Sbom)
				}
				assert.Equal(t, tt.expectedSboms[ta], sboms)
			}
		})
	}
}
