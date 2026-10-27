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
