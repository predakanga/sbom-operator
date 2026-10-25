package processor

import (
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
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

func TestFindPodsToScan(t *testing.T) {
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
			expectedMissing: []string{"mysql-0"},
			expectedImages:  []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
		},
		{
			name:            "a pod missing from several targets is returned once",
			pods:            []libk8s.PodInfo{mysqlPod},
			targetImages:    [][]*liboci.RegistryImage{images(), images(), images()},
			expectedMissing: []string{"mysql-0"},
			expectedImages:  []string{"mysql@sha256:1", "pmm-client@sha256:2", "busybox@sha256:3"},
		},
		{
			name:            "a pod missing from only one target is returned",
			pods:            []libk8s.PodInfo{completePod},
			targetImages:    [][]*liboci.RegistryImage{images("redis@sha256:5"), images()},
			expectedMissing: []string{"redis-0"},
			expectedImages:  []string{"redis@sha256:5"},
		},
		{
			name:            "annotated and complete pods aren't returned",
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
			missing, all := p.findPodsToScan(tt.pods, tt.targetImages)

			missingNames := make([]string, 0)
			for _, pod := range missing {
				missingNames = append(missingNames, pod.PodName)
			}
			assert.Equal(t, tt.expectedMissing, missingNames)

			imageIDs := make([]string, 0)
			for _, i := range all {
				imageIDs = append(imageIDs, i.ImageID)
			}
			assert.Equal(t, tt.expectedImages, imageIDs)
		})
	}
}
