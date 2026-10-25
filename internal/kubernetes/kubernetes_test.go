package kubernetes

import (
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func containerInfo(name, imageID string) *libk8s.ContainerInfo {
	return &libk8s.ContainerInfo{Name: name, Image: &oci.RegistryImage{ImageID: imageID}}
}

func TestWithContainerAnnotations(t *testing.T) {
	existing := map[string]string{
		"other":                                "value",
		"ckotzbauer.sbom-operator.io/sidecar":  "envoy@sha256:1",
		"ckotzbauer.sbom-operator.io/app":      "app@sha256:old",
		"ckotzbauer.sbom-operator.io/not-mine": "x",
	}

	result := withContainerAnnotations(existing, []*libk8s.ContainerInfo{containerInfo("app", "app@sha256:new")})
	assert.Equal(t, map[string]string{
		"other":                                "value",
		"ckotzbauer.sbom-operator.io/sidecar":  "envoy@sha256:1",
		"ckotzbauer.sbom-operator.io/app":      "app@sha256:new",
		"ckotzbauer.sbom-operator.io/not-mine": "x",
	}, result)

	result = withContainerAnnotations(nil, []*libk8s.ContainerInfo{containerInfo("app", "app@sha256:1"), containerInfo("init", "busybox@sha256:2")})
	assert.Equal(t, map[string]string{
		"ckotzbauer.sbom-operator.io/app":  "app@sha256:1",
		"ckotzbauer.sbom-operator.io/init": "busybox@sha256:2",
	}, result)
}

func TestHasAnnotation(t *testing.T) {
	c := containerInfo("app", "docker.io/library/app@sha256:1")

	tests := []struct {
		name              string
		annotations       map[string]string
		ignoreAnnotations bool
		expected          bool
	}{
		{name: "no annotations", annotations: nil, expected: false},
		{name: "other container", annotations: map[string]string{"ckotzbauer.sbom-operator.io/sidecar": "docker.io/library/app@sha256:1"}, expected: false},
		{name: "matching image", annotations: map[string]string{"ckotzbauer.sbom-operator.io/app": "docker.io/library/app@sha256:1"}, expected: true},
		{name: "different image", annotations: map[string]string{"ckotzbauer.sbom-operator.io/app": "docker.io/library/app@sha256:2"}, expected: false},
		{name: "raw docker-pullable value from older versions", annotations: map[string]string{"ckotzbauer.sbom-operator.io/app": "docker-pullable://docker.io/library/app@sha256:1"}, expected: true},
		{name: "ignored annotations", annotations: map[string]string{"ckotzbauer.sbom-operator.io/app": "docker.io/library/app@sha256:1"}, ignoreAnnotations: true, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &KubeClient{ignoreAnnotations: tt.ignoreAnnotations}
			assert.Equal(t, tt.expected, client.HasAnnotation(tt.annotations, c))
		})
	}
}

// On Docker-runtime nodes the status image ID carries a docker-pullable://
// prefix. What gets written must match what ExtractPodInfos reads back.
func TestAnnotationRoundTripOnDockerRuntime(t *testing.T) {
	pod := corev1.Pod{
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", Image: "app:1", ImageID: "docker-pullable://docker.io/library/app@sha256:1"},
			},
		},
	}

	client := &KubeClient{Client: &libk8s.KubeClient{}}
	info := client.Client.ExtractPodInfos(pod)
	annotations := withContainerAnnotations(nil, info.Containers)
	assert.Equal(t, "docker.io/library/app@sha256:1", annotations["ckotzbauer.sbom-operator.io/app"])
	assert.True(t, client.HasAnnotation(annotations, info.Containers[0]))
}

func TestNormaliseImageID(t *testing.T) {
	assert.Equal(t, "app@sha256:1", normaliseImageID("docker-pullable://app@sha256:1"))
	assert.Equal(t, "app@sha256:1", normaliseImageID("app@sha256:1"))
	assert.Equal(t, "sha256:1", normaliseImageID("sha256:1"))
}
