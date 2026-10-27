package processor

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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

// fakeTarget records the SBOMs it receives and accepts every media type. It
// fails for the image IDs in fail.
type fakeTarget struct {
	received []*target.TargetContext
	fail     map[string]bool
	images   []*liboci.RegistryImage
	loadErr  error
	removed  []string
}

func (f *fakeTarget) Initialize() error     { return nil }
func (f *fakeTarget) ValidateConfig() error { return nil }
func (f *fakeTarget) ProcessSbom(ctx *target.TargetContext) error {
	if f.fail[ctx.Image.ImageID] {
		return errors.New("target unavailable")
	}
	f.received = append(f.received, ctx)
	return nil
}
func (f *fakeTarget) LoadImages() ([]*liboci.RegistryImage, error) { return f.images, f.loadErr }
func (f *fakeTarget) Remove(images []*liboci.RegistryImage) error {
	for _, i := range images {
		f.removed = append(f.removed, i.ImageID)
	}
	return nil
}

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

func container(name, imageID string) *libk8s.ContainerInfo {
	return &libk8s.ContainerInfo{Name: name, Image: &liboci.RegistryImage{ImageID: imageID, Image: imageID}}
}

func images(ids ...string) []*liboci.RegistryImage {
	result := make([]*liboci.RegistryImage, 0, len(ids))
	for _, id := range ids {
		result = append(result, &liboci.RegistryImage{ImageID: id})
	}
	return result
}

func TestFindImagesToScan(t *testing.T) {
	mysqlPod := libk8s.PodInfo{
		PodName:      "mysql-0",
		PodNamespace: "db",
		Containers: []*libk8s.ContainerInfo{
			container("mysql", "mysql@sha256:1"),
			container("pmm-agent", "pmm-client@sha256:2"),
			container("init", "busybox@sha256:3"),
		},
	}
	annotatedPod := libk8s.PodInfo{
		PodName:      "web-0",
		PodNamespace: "web",
		Annotations:  map[string]string{"ckotzbauer.sbom-operator.io/nginx": "nginx@sha256:4"},
		Containers:   []*libk8s.ContainerInfo{container("nginx", "nginx@sha256:4")},
	}
	completePod := libk8s.PodInfo{
		PodName:      "redis-0",
		PodNamespace: "cache",
		Containers:   []*libk8s.ContainerInfo{container("redis", "redis@sha256:5")},
	}
	sharedImagePod := libk8s.PodInfo{
		PodName:      "mysql-1",
		PodNamespace: "db",
		Containers:   []*libk8s.ContainerInfo{container("pmm-agent", "pmm-client@sha256:2")},
	}

	tests := []struct {
		name            string
		pods            []libk8s.PodInfo
		targetImages    [][]*liboci.RegistryImage
		expectedMissing []string
		expectedImages  []string
	}{
		{
			name:            "later containers count as running when the first needs analysis",
			pods:            []libk8s.PodInfo{mysqlPod},
			targetImages:    [][]*liboci.RegistryImage{images("pmm-client@sha256:2", "busybox@sha256:3")},
			expectedMissing: []string{"mysql@sha256:1"},
			expectedImages:  []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
		},
		{
			name:            "an image missing from several targets is returned once",
			pods:            []libk8s.PodInfo{mysqlPod},
			targetImages:    [][]*liboci.RegistryImage{images(), images(), images()},
			expectedMissing: []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
			expectedImages:  []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
		},
		{
			name:            "an image missing from only one target is returned",
			pods:            []libk8s.PodInfo{completePod},
			targetImages:    [][]*liboci.RegistryImage{images("redis@sha256:5"), images()},
			expectedMissing: []string{"redis@sha256:5"},
			expectedImages:  []string{"redis@sha256:5"},
		},
		{
			name:            "images of annotated and complete pods aren't returned",
			pods:            []libk8s.PodInfo{annotatedPod, completePod},
			targetImages:    [][]*liboci.RegistryImage{images("redis@sha256:5")},
			expectedMissing: []string{},
			expectedImages:  []string{"nginx@sha256:4", "redis@sha256:5"},
		},
		{
			name:            "images shared between pods are listed once",
			pods:            []libk8s.PodInfo{mysqlPod, sharedImagePod},
			targetImages:    [][]*liboci.RegistryImage{images("mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3")},
			expectedMissing: []string{},
			expectedImages:  []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
		},
		{
			name:            "an image missing for several pods is returned once",
			pods:            []libk8s.PodInfo{mysqlPod, sharedImagePod},
			targetImages:    [][]*liboci.RegistryImage{images("mysql@sha256:1", "busybox@sha256:3")},
			expectedMissing: []string{"pmm-client@sha256:2"},
			expectedImages:  []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
		},
		{
			name:            "nothing is missing when no target could be loaded",
			pods:            []libk8s.PodInfo{mysqlPod},
			targetImages:    [][]*liboci.RegistryImage{},
			expectedMissing: []string{},
			expectedImages:  []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
		},
	}

	p := &Processor{K8s: &kubernetes.KubeClient{}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missing, all := p.findImagesToScan(tt.pods, tt.targetImages)
			assert.Equal(t, tt.expectedMissing, missing)

			imageIDs := make([]string, 0)
			for _, i := range all {
				imageIDs = append(imageIDs, i.ImageID)
			}
			assert.Equal(t, tt.expectedImages, imageIDs)
		})
	}
}

// fakeGenerator returns an SBOM named after the image, and fails for the image
// IDs in fail.
type fakeGenerator struct {
	scanned []string
	fail    map[string]bool
}

func (f *fakeGenerator) ExecuteSyft(img *liboci.RegistryImage) (string, error) {
	f.scanned = append(f.scanned, img.ImageID)
	if f.fail[img.ImageID] {
		return "", errors.New("TOOMANYREQUESTS")
	}
	return "sbom of " + img.ImageID, nil
}

func containerNames(containers []*libk8s.ContainerInfo) []string {
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		names = append(names, c.Name)
	}
	return names
}

func TestPendingImages(t *testing.T) {
	bare := "sha256:7c3a6a8f5c2e1d0b9a8f7e6d5c4b3a2918273645546372819a0b1c2d3e4f5a6b"
	pods := []libk8s.PodInfo{
		{
			PodName:      "mysql-0",
			PodNamespace: "db",
			Annotations:  map[string]string{"ckotzbauer.sbom-operator.io/done": "done@sha256:0"},
			Containers: []*libk8s.ContainerInfo{
				container("mysql", "mysql@sha256:1"),
				container("pmm-agent", "pmm-client@sha256:2"),
				container("pmm-init", "pmm-client@sha256:2"),
				container("done", "done@sha256:0"),
				container("imported", bare),
			},
		},
		{
			PodName:      "mysql-1",
			PodNamespace: "db",
			Containers:   []*libk8s.ContainerInfo{container("pmm-agent", "pmm-client@sha256:2")},
		},
	}

	p := &Processor{K8s: &kubernetes.KubeClient{}}
	type pending struct {
		pod        string
		containers []string
	}
	result := map[string][]pending{}
	order := make([]string, 0)
	for _, scan := range p.pendingImages(pods) {
		order = append(order, scan.imageID)
		for _, pc := range scan.pods {
			result[scan.imageID] = append(result[scan.imageID], pending{pod: pc.pod.PodName, containers: containerNames(pc.containers)})
		}
	}

	assert.Equal(t, []string{"mysql@sha256:1", "pmm-client@sha256:2"}, order, "annotated and bare-digest containers are left out")
	assert.Equal(t, map[string][]pending{
		"mysql@sha256:1":      {{pod: "mysql-0", containers: []string{"mysql"}}},
		"pmm-client@sha256:2": {{pod: "mysql-0", containers: []string{"pmm-agent", "pmm-init"}}, {pod: "mysql-1", containers: []string{"pmm-agent"}}},
	}, result)
	assert.Equal(t, map[string]bool{bare: true}, p.bareDigestsWarned)
}

// scanPending scans every pending image of the pods in p's store, and returns
// the IDs of those that failed.
func scanPending(p *Processor) []string {
	failed := make([]string, 0)
	for _, scan := range p.pendingImages(p.allowedPods()) {
		if err := p.scanImage(scan); err != nil {
			failed = append(failed, scan.imageID)
		}
	}
	return failed
}

func TestScanImage(t *testing.T) {
	internal.OperatorConfig = &internal.Config{}

	newMysqlPod := func() *corev1.Pod {
		pod := newPod("db", "mysql-0", "mysql", "mysql@sha256:1", "pmm-agent", "pmm-client@sha256:2", "pmm-init", "pmm-client@sha256:2", "done", "done@sha256:0")
		pod.Annotations = map[string]string{"ckotzbauer.sbom-operator.io/done": "done@sha256:0"}
		return pod
	}
	done := map[string]string{"ckotzbauer.sbom-operator.io/done": "done@sha256:0"}
	with := func(annotations map[string]string) map[string]string {
		maps.Copy(annotations, done)
		return annotations
	}

	t.Run("a Syft failure fails only that image", func(t *testing.T) {
		gen := &fakeGenerator{fail: map[string]bool{"mysql@sha256:1": true}}
		ta := &fakeTarget{}
		p, api, _ := newQueueProcessor(t, gen, []target.Target{ta}, newMysqlPod())

		assert.Equal(t, []string{"mysql@sha256:1"}, scanPending(p))
		assert.Equal(t, with(map[string]string{
			"ckotzbauer.sbom-operator.io/pmm-agent": "pmm-client@sha256:2",
			"ckotzbauer.sbom-operator.io/pmm-init":  "pmm-client@sha256:2",
		}), api.annotations("db/mysql-0"))
		assert.Equal(t, []string{"mysql@sha256:1", "pmm-client@sha256:2"}, gen.scanned, "each image is scanned once, annotated containers are skipped")
		assert.Equal(t, map[string]bool{"pmm-client@sha256:2": true}, p.imageMap)
		assert.Len(t, ta.received, 1)
	})

	t.Run("a target failure fails the image and is retried", func(t *testing.T) {
		gen := &fakeGenerator{}
		ok := &fakeTarget{}
		failing := &fakeTarget{fail: map[string]bool{"pmm-client@sha256:2": true}}
		p, api, store := newQueueProcessor(t, gen, []target.Target{ok, failing}, newMysqlPod())

		assert.Equal(t, []string{"pmm-client@sha256:2"}, scanPending(p))
		assert.Equal(t, with(map[string]string{"ckotzbauer.sbom-operator.io/mysql": "mysql@sha256:1"}), api.annotations("db/mysql-0"))
		assert.False(t, p.imageMap["pmm-client@sha256:2"])

		// once the target recovers, the image is sent again
		failing.fail = nil
		pod := newMysqlPod()
		pod.Annotations = api.annotations("db/mysql-0")
		require.NoError(t, store.Update(pod))
		assert.Empty(t, scanPending(p))
		assert.Equal(t, with(map[string]string{
			"ckotzbauer.sbom-operator.io/mysql":     "mysql@sha256:1",
			"ckotzbauer.sbom-operator.io/pmm-agent": "pmm-client@sha256:2",
			"ckotzbauer.sbom-operator.io/pmm-init":  "pmm-client@sha256:2",
		}), api.annotations("db/mysql-0"))
		assert.Equal(t, []string{"mysql@sha256:1", "pmm-client@sha256:2", "pmm-client@sha256:2"}, gen.scanned, "only the failed image is scanned again")
	})

	t.Run("images processed before aren't sent again", func(t *testing.T) {
		gen := &fakeGenerator{}
		ta := &fakeTarget{}
		p, api, _ := newQueueProcessor(t, gen, []target.Target{ta}, newMysqlPod())
		p.imageMap = map[string]bool{"mysql@sha256:1": true, "pmm-client@sha256:2": true}

		assert.Empty(t, scanPending(p))
		assert.Len(t, api.annotations("db/mysql-0"), 4)
		assert.Empty(t, gen.scanned)
		assert.Empty(t, ta.received)
	})
}

func TestIsBareDigest(t *testing.T) {
	digest := "sha256:7c3a6a8f5c2e1d0b9a8f7e6d5c4b3a2918273645546372819a0b1c2d3e4f5a6b"
	tests := []struct {
		imageID  string
		expected bool
	}{
		{imageID: digest, expected: true},
		{imageID: "registry.k8s.io/coredns/coredns@" + digest, expected: false},
		{imageID: "coredns@" + digest, expected: false},
		{imageID: "docker.io/library/alpine:3.20", expected: false},
		{imageID: "sha256:abc", expected: false},
		{imageID: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.imageID, func(t *testing.T) {
			assert.Equal(t, tt.expected, isBareDigest(tt.imageID))
		})
	}
}

func TestBareDigestImagesAreSkipped(t *testing.T) {
	internal.OperatorConfig = &internal.Config{}
	bare := "sha256:7c3a6a8f5c2e1d0b9a8f7e6d5c4b3a2918273645546372819a0b1c2d3e4f5a6b"

	coredns := newPod("kube-system", "coredns-0", "coredns", bare, "sidecar", "envoy@sha256:1")
	gen := &fakeGenerator{}
	p, api, _ := newQueueProcessor(t, gen, []target.Target{&fakeTarget{}}, coredns)

	assert.Empty(t, scanPending(p), "a bare digest isn't a failure, so it isn't retried")
	assert.Equal(t, map[string]string{"ckotzbauer.sbom-operator.io/sidecar": "envoy@sha256:1"}, api.annotations("kube-system/coredns-0"), "and isn't annotated")
	assert.Equal(t, []string{"envoy@sha256:1"}, gen.scanned)
	assert.Equal(t, map[string]bool{bare: true}, p.bareDigestsWarned)
}

func TestBareDigestWarningDuringInitialSync(t *testing.T) {
	internal.OperatorConfig = &internal.Config{}
	bare := "sha256:7c3a6a8f5c2e1d0b9a8f7e6d5c4b3a2918273645546372819a0b1c2d3e4f5a6b"
	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)

	// pods with only a bare-digest container are never queued, so the
	// initial sync has to warn about them itself
	pods := []libk8s.PodInfo{
		{PodName: "coredns-0", PodNamespace: "kube-system", Containers: []*libk8s.ContainerInfo{container("coredns", bare)}},
		{PodName: "coredns-1", PodNamespace: "kube-system", Containers: []*libk8s.ContainerInfo{container("coredns", bare)}},
	}
	p := &Processor{K8s: &kubernetes.KubeClient{}}
	missing, _ := p.findImagesToScan(pods, [][]*liboci.RegistryImage{images()})
	assert.Empty(t, missing, "a bare digest alone doesn't make an image need analysis")
	p.findImagesToScan(pods, [][]*liboci.RegistryImage{images()})

	warnings := 0
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.WarnLevel && strings.Contains(e.Message, bare) {
			warnings++
		}
	}
	assert.Equal(t, 1, warnings, "the warning is logged once per image")
}
