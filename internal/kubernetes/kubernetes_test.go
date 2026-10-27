package kubernetes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

func TestLoadPullSecrets(t *testing.T) {
	// serves every requested secret as a (credential-less) docker config
	var gets atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/v1/namespaces/<ns>/secrets/<name>
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/"), "/")
		gets.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&corev1.Secret{
			ObjectMeta: meta.ObjectMeta{Namespace: parts[0], Name: parts[2]},
			Type:       corev1.SecretTypeDockerConfigJson,
			Data:       map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{}}`)},
		})
	}))
	t.Cleanup(ts.Close)
	cs, err := k8sclient.NewForConfig(&rest.Config{Host: ts.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json"}})
	require.NoError(t, err)
	fallback := &oci.KubeCreds{SecretName: "fallback"}
	client := &KubeClient{Client: &libk8s.KubeClient{Client: cs}, fallbackPullSecret: []*oci.KubeCreds{fallback}}

	pods := []libk8s.PodInfo{
		{PodNamespace: "a", PodName: "app-0", PullSecretNames: []corev1.LocalObjectReference{{Name: "regcred"}}},
		{PodNamespace: "a", PodName: "app-1", PullSecretNames: []corev1.LocalObjectReference{{Name: "regcred"}}},
		{PodNamespace: "b", PodName: "app-2", PullSecretNames: []corev1.LocalObjectReference{{Name: "regcred"}, {Name: "other"}}},
		{PodNamespace: "c", PodName: "app-3"},
	}

	names := make([]string, 0)
	for _, s := range client.LoadPullSecrets(pods) {
		names = append(names, s.SecretName)
	}
	assert.Equal(t, []string{"regcred", "regcred", "other", "fallback"}, names, "each pod's secrets, loaded once per namespace, then the fallback")

	assert.Equal(t, int32(3), gets.Load())
}

func TestExtractPodInfosTakesPinnedImagesFromSpec(t *testing.T) {
	pinned := "ghcr.io/predakanga/sbom-operator:0.47.0.3@sha256:ed3409b03659fa0dc7ce044bb8ebf3ecd06b05f2d42d2fda67e45fdfb50cf9a1"
	imageID := "ghcr.io/predakanga/sbom-operator@sha256:ed3409b03659fa0dc7ce044bb8ebf3ecd06b05f2d42d2fda67e45fdfb50cf9a1"
	configDigest := "sha256:8072cdef760d20705eee1aa637896df8bc3dc6976c7e69d9202d34087b33fec7"
	status := func(name, image, imageID string) corev1.ContainerStatus {
		return corev1.ContainerStatus{Name: name, Image: image, ImageID: imageID}
	}

	// as containerd reports a name:tag@digest pin, plus other cases
	pod := &corev1.Pod{
		ObjectMeta: meta.ObjectMeta{Namespace: "sbom", Name: "sbom-operator-0"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "operator", Image: pinned, Args: []string{"--targets=dtrack"}},
				{Name: "tagged", Image: "nginx:1.27"},
				{Name: "imported", Image: "registry.k8s.io/coredns/coredns:v1.11.1"},
			},
			InitContainers:      []corev1.Container{{Name: "init", Image: "busybox:1.37@" + configDigest}},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "alpine:3.22"}}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				status("operator", configDigest, imageID),
				status("tagged", "docker.io/library/nginx:1.27", "docker.io/library/nginx@sha256:1"),
				status("imported", configDigest, configDigest),
				status("gone", configDigest, "gone@sha256:2"),
			},
			InitContainerStatuses:      []corev1.ContainerStatus{status("init", configDigest, "docker.io/library/busybox@sha256:3")},
			EphemeralContainerStatuses: []corev1.ContainerStatus{status("debug", configDigest, "docker.io/library/alpine@sha256:4")},
		},
	}

	transformed, err := transformPod(pod)
	require.NoError(t, err)
	assert.Empty(t, transformed.(*corev1.Pod).Spec.Containers[0].Args, "the transform keeps only names and images")

	client := &KubeClient{Client: &libk8s.KubeClient{}}
	info := client.ExtractPodInfos(*transformed.(*corev1.Pod))

	images := map[string]string{}
	imageIDs := map[string]string{}
	for _, c := range info.Containers {
		images[c.Name] = c.Image.Image
		imageIDs[c.Name] = c.Image.ImageID
	}
	assert.Equal(t, map[string]string{
		"operator": pinned,
		"tagged":   "docker.io/library/nginx:1.27",
		"imported": "registry.k8s.io/coredns/coredns:v1.11.1",
		"gone":     configDigest,
		"init":     "busybox:1.37@" + configDigest,
		"debug":    "alpine:3.22",
	}, images, "a bare-digest status image is replaced by the spec's, if there is one")
	assert.Equal(t, imageID, imageIDs["operator"], "the image ID is unchanged")
}
