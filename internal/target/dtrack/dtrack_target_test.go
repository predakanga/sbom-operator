package dtrack

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	libk8s_real "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRepoWithVersion(t *testing.T) {
	tests := []struct {
		name             string
		image            *liboci.RegistryImage
		useShortName     bool
		k8sClusterId     string
		k8sClusterIdMode string
		expectedName     string
		expectedVersion  string
		scope            string
	}{
		{
			name:             "Long name, tag mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     false,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			expectedName:     "docker.io/library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "Long name, prefix mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     false,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "prefix",
			expectedName:     "my-cluster-docker.io/library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "Short name, prefix mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "prefix",
			expectedName:     "my-cluster-library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "Short name, tag mode",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			expectedName:     "library/alpine",
			expectedVersion:  "3.14",
		},
		{
			name:             "SHA version",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300", Image: "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			expectedName:     "library/alpine",
			expectedVersion:  "sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300",
		},
		{
			name:             "SHA version",
			image:            &liboci.RegistryImage{ImageID: "docker.io/library/alpine:3.14", Image: "alpine:3.14"},
			useShortName:     true,
			k8sClusterId:     "my-cluster",
			k8sClusterIdMode: "tag",
			scope:            "testScope",
			expectedName:     "library/alpine-testScope",
			expectedVersion:  "3.14",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version := getRepoWithVersion(tt.image, tt.useShortName, tt.k8sClusterId, tt.k8sClusterIdMode, tt.scope)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestContainsTag(t *testing.T) {
	tags := []dtrack.Tag{
		{Name: "tag1"},
		{Name: "kubernetes-cluster=my-cluster"},
	}

	assert.True(t, containsTag(tags, "tag1"))
	assert.True(t, containsTag(tags, "kubernetes-cluster=my-cluster"))
	assert.True(t, containsTag(tags, "kubernetes-cluster="))
	assert.False(t, containsTag(tags, "tag2"))
}

func TestRemoveTag(t *testing.T) {
	tags := []dtrack.Tag{
		{Name: "tag1"},
		{Name: "tag2"},
	}

	newTags := removeTag(tags, "tag1")
	assert.Len(t, newTags, 1)
	assert.Equal(t, "tag2", newTags[0].Name)

	newTags = removeTag(tags, "tag3")
	assert.Len(t, newTags, 2)
}

func TestGetNameAndVersionFromString(t *testing.T) {
	n, v := getNameAndVersionFromString("name:version", ":")
	assert.Equal(t, "name", n)
	assert.Equal(t, "version", v)

	n, v = getNameAndVersionFromString("name", ":")
	assert.Equal(t, "name", n)
	assert.Equal(t, "latest", v)
}

func TestGetContainerNameFromAnnotationKey(t *testing.T) {
	c, s := getContainerNameAndScopeFromAnnotationKey("prefix/container", "/")
	assert.Equal(t, "container", c)
	assert.Equal(t, "", s)

	c, s = getContainerNameAndScopeFromAnnotationKey("container", "/")
	assert.Equal(t, "", c)
	assert.Equal(t, "", s)
}

func TestGetScopeFromAnnotationKey(t *testing.T) {
	c, s := getContainerNameAndScopeFromAnnotationKey("prefix/container/scope", "/")
	assert.Equal(t, "container", c)
	assert.Equal(t, "scope", s)
}

func TestNewDependencyTrackTarget(t *testing.T) {
	target := NewDependencyTrackTarget("url", "api", "matcher", "ca", "cert", "key", "cluster", "tag", "parent", "p-ann", "n-ann", true, true, "")
	assert.Equal(t, "url", target.baseUrl)
	assert.Equal(t, "api", target.apiKey)
	assert.Equal(t, "matcher", target.podLabelTagMatcher)
	assert.Equal(t, "ca", target.caCertFile)
	assert.Equal(t, "cert", target.clientCertFile)
	assert.Equal(t, "key", target.clientKeyFile)
	assert.Equal(t, "cluster", target.k8sClusterId)
	assert.Equal(t, "tag", target.k8sClusterIdMode)
	assert.Equal(t, "parent", target.defaultParentProject)
	assert.Equal(t, "p-ann", target.parentProjectAnnotationKey)
	assert.Equal(t, "n-ann", target.projectNameAnnotationKey)
	assert.True(t, target.useShortName)
	assert.True(t, target.manageProjectActiveStatus)
}

func TestInitialize(t *testing.T) {
	target := &DependencyTrackTarget{
		apiKey: "apikey",
	}
	err := target.Initialize()
	assert.NoError(t, err)
	assert.Len(t, target.clientOptions, 2)

	target.caCertFile = "ca.crt"
	err = target.Initialize()
	assert.NoError(t, err)
	assert.Len(t, target.clientOptions, 3)
}

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		value    string
		expected time.Duration
		wantErr  bool
	}{
		{value: "", expected: DefaultTimeout},
		{value: "  ", expected: DefaultTimeout},
		{value: "90s", expected: 90 * time.Second},
		{value: "2m30s", expected: 150 * time.Second},
		{value: "500ms", expected: 500 * time.Millisecond},
		{value: "45", expected: 45 * time.Second},
		{value: "0", wantErr: true},
		{value: "-5s", wantErr: true},
		{value: "soon", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			timeout, err := parseTimeout(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, timeout)
		})
	}
}

func TestTimeoutIsApplied(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer ts.Close()
	defer close(release)

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "200ms")
	require.NoError(t, g.ValidateConfig())
	require.NoError(t, g.Initialize())

	ctx := &target.TargetContext{
		Image:      &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:        &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers: []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Sbom:       "{}",
	}

	start := time.Now()
	err := g.ProcessSbom(ctx)
	assert.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		target  *DependencyTrackTarget
		wantErr bool
	}{
		{
			name: "Valid config",
			target: &DependencyTrackTarget{
				baseUrl: "http://localhost:8080",
				apiKey:  "apikey",
			},
			wantErr: false,
		},
		{
			name: "Missing baseUrl",
			target: &DependencyTrackTarget{
				apiKey: "apikey",
			},
			wantErr: true,
		},
		{
			name: "Missing apiKey",
			target: &DependencyTrackTarget{
				baseUrl: "http://localhost:8080",
			},
			wantErr: true,
		},
		{
			name: "Invalid UUID for parent project",
			target: &DependencyTrackTarget{
				baseUrl:              "http://localhost:8080",
				apiKey:               "apikey",
				defaultParentProject: "invalid-uuid",
			},
			wantErr: true,
		},
		{
			name: "Invalid timeout",
			target: &DependencyTrackTarget{
				baseUrl: "http://localhost:8080",
				apiKey:  "apikey",
				timeout: "soon",
			},
			wantErr: true,
		},
		{
			name: "Valid timeout",
			target: &DependencyTrackTarget{
				baseUrl: "http://localhost:8080",
				apiKey:  "apikey",
				timeout: "2m",
			},
			wantErr: false,
		},
		{
			name: "Missing client cert/key for mTLS",
			target: &DependencyTrackTarget{
				baseUrl:    "http://localhost:8080",
				apiKey:     "apikey",
				caCertFile: "ca.crt",
			},
			wantErr: true,
		},
		{
			name: "Manage active status without parent project",
			target: &DependencyTrackTarget{
				baseUrl:                   "http://localhost:8080",
				apiKey:                    "apikey",
				manageProjectActiveStatus: true,
			},
			wantErr: true,
		},
		{
			name: "Manage active status with default parent",
			target: &DependencyTrackTarget{
				baseUrl:                   "http://localhost:8080",
				apiKey:                    "apikey",
				defaultParentProject:      "8c940608-8e62-431a-ac5d-2092b7c41372",
				manageProjectActiveStatus: true,
			},
			wantErr: false,
		},
		{
			name: "Manage active status with parent annotation key",
			target: &DependencyTrackTarget{
				baseUrl:                    "http://localhost:8080",
				apiKey:                     "apikey",
				parentProjectAnnotationKey: "example.com/parent",
				manageProjectActiveStatus:  true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.target.ValidateConfig()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProcessSbomUnsupportedMediaType(t *testing.T) {
	ctx := &target.TargetContext{
		Image:      &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:        &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers: []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Sbom:       "{}",
		MediaType:  "unsupported",
	}
	g := NewDependencyTrackTarget("", "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.ProcessSbom(ctx)
	assert.NoError(t, err)
}

func TestAcceptsMediaType(t *testing.T) {
	tests := []struct {
		mediaType string
		expected  bool
	}{
		{mediaType: "", expected: true},
		{mediaType: oci.CycloneDXJSONMediaType, expected: true},
		{mediaType: oci.CycloneDXXMLMediaType, expected: true},
		{mediaType: oci.SPDXJSONMediaType, expected: false},
		{mediaType: oci.SPDXMediaType, expected: false},
		{mediaType: oci.SyftMediaType, expected: false},
	}

	g := &DependencyTrackTarget{}
	for _, tt := range tests {
		t.Run(tt.mediaType, func(t *testing.T) {
			assert.Equal(t, tt.expected, g.AcceptsMediaType(tt.mediaType))
		})
	}
}

func TestProcessSbomMinimal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" {
			if r.Method == "POST" {
				_, _ = w.Write([]byte("{}"))
			} else {
				_, _ = w.Write([]byte("[]"))
			}
			return
		}
		_, _ = w.Write([]byte("{\"version\": \"4.8.0\", \"token\": \"uuid-token\", \"name\": \"alpine\", \"version\": \"3.14\", \"uuid\": \"8c940608-8e62-431a-ac5d-2092b7c41372\", \"totalCount\": 0}"))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:      &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:        &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers: []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Sbom:       "{}",
	}

	_ = g.ProcessSbom(ctx)
}

func TestProcessSbomParentProject(t *testing.T) {
	parentUUID := "aaaaaaaa-1111-2222-3333-444444444444"

	tests := []struct {
		name            string
		annotationValue string
		parentProjects  string
		expectParentRef bool
	}{
		{
			name:            "parent project by name only (no version)",
			annotationValue: "MyParentProject",
			parentProjects:  `[{"name":"MyParentProject","version":"","uuid":"` + parentUUID + `"}]`,
			expectParentRef: true,
		},
		{
			name:            "parent project by name and version",
			annotationValue: "MyParentProject:1.0",
			parentProjects:  `[{"name":"MyParentProject","version":"1.0","uuid":"` + parentUUID + `"}]`,
			expectParentRef: true,
		},
		{
			name:            "explicit version does not match any returned project",
			annotationValue: "MyParentProject:2.0",
			parentProjects:  `[{"name":"MyParentProject","version":"1.0","uuid":"` + parentUUID + `"}]`,
			expectParentRef: false,
		},
		{
			name:            "no parent project found",
			annotationValue: "MyParentProject",
			parentProjects:  `[]`,
			expectParentRef: false,
		},
		{
			name:            "parent project with uuuid",
			annotationValue: "aaaaaaaa-1111-2222-3333-44444444444",
			parentProjects:  `[{"name":"MyParentProject","version":"","uuid":"` + parentUUID + `"}]`,
			expectParentRef: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updateBody := ""
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				switch {
				case r.URL.Path == "/api/v1/bom":
					_, _ = w.Write([]byte(`{"token": "uuid-token"}`))
				case r.URL.Path == "/api/v1/project/lookup":
					_, _ = w.Write([]byte(`{"name":"alpine","version":"3.14","uuid":"8c940608-8e62-431a-ac5d-2092b7c41372"}`))
				case r.URL.Path == "/api/v1/project" && r.Method == http.MethodGet:
					// GetProjectsForName for parent lookup
					_, _ = w.Write([]byte(tt.parentProjects))
				case r.URL.Path == "/api/v1/project" && r.Method == http.MethodPost:
					// Project.Update - capture the body to inspect ParentRef
					buf, _ := io.ReadAll(r.Body)
					updateBody = string(buf)
					logrus.Infof("%s", updateBody)
					_, _ = w.Write([]byte(`{}`))
				default:
					// any other output
					_, _ = w.Write([]byte(`{}`))
				}
			}))
			defer ts.Close()

			g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "my.parent.project", "", true, false, "")
			err := g.Initialize()
			assert.NoError(t, err)
			// Pre-populate so LoadImages is skipped during ProcessSbom.
			g.imageProjectMap = map[string]uuid.UUID{}

			ctx := &target.TargetContext{
				Image:      &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
				Pod:        &libk8s_real.PodInfo{PodNamespace: "default", Annotations: map[string]string{"my.parent.project/alpine": tt.annotationValue}},
				Containers: []*libk8s_real.ContainerInfo{{Name: "alpine"}},
				Sbom:       "{}",
			}

			err = g.ProcessSbom(ctx)
			assert.NoError(t, err)

			if tt.expectParentRef {
				assert.Contains(t, updateBody, parentUUID)
			} else {
				assert.NotContains(t, updateBody, parentUUID)
			}
		})
	}
}

func TestRemoveMinimal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte("{\"version\": \"4.8.0\", \"totalCount\": 0}"))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.Initialize()
	assert.NoError(t, err)

	images := []*liboci.RegistryImage{
		{ImageID: "alpine:3.14", Image: "alpine:3.14"},
	}

	_ = g.Remove(images)
}

func TestAddRawImageIdTag(t *testing.T) {
	t.Run("first digest is added", func(t *testing.T) {
		tags := addRawImageIdTag([]dtrack.Tag{{Name: sbomOperator}}, "alpine@sha256:aaa")
		assert.Equal(t, []dtrack.Tag{{Name: sbomOperator}, {Name: "raw-image-id=alpine@sha256:aaa"}}, tags)
	})

	t.Run("another digest is added next to the existing one", func(t *testing.T) {
		tags := addRawImageIdTag([]dtrack.Tag{
			{Name: sbomOperator},
			{Name: "raw-image-id=alpine@sha256:aaa"},
			{Name: "kubernetes-cluster=my-cluster"},
		}, "alpine@sha256:bbb")
		assert.Equal(t, []string{"alpine@sha256:aaa", "alpine@sha256:bbb"}, getRawImageIds(tags))
		assert.Len(t, tags, 4)
	})

	t.Run("a recorded digest isn't added twice", func(t *testing.T) {
		tags := addRawImageIdTag([]dtrack.Tag{{Name: "raw-image-id=alpine@sha256:aaa"}}, "alpine@sha256:aaa")
		assert.Equal(t, []string{"alpine@sha256:aaa"}, getRawImageIds(tags))
	})

	t.Run("a digest that is a prefix of a recorded one is added", func(t *testing.T) {
		tags := addRawImageIdTag([]dtrack.Tag{{Name: "raw-image-id=alpine@sha256:aaab"}}, "alpine@sha256:aaa")
		assert.Equal(t, []string{"alpine@sha256:aaab", "alpine@sha256:aaa"}, getRawImageIds(tags))
	})
}

func TestRemoveRawImageIdTags(t *testing.T) {
	tags := []dtrack.Tag{
		{Name: sbomOperator},
		{Name: "raw-image-id=alpine@sha256:aaa"},
		{Name: "raw-image-id=alpine@sha256:bbb"},
		{Name: "raw-image-id=alpine@sha256:ccc"},
	}
	result := removeRawImageIdTags(tags, []string{"alpine@sha256:aaa", "alpine@sha256:ccc"})
	assert.Equal(t, []dtrack.Tag{{Name: sbomOperator}, {Name: "raw-image-id=alpine@sha256:bbb"}}, result)
}

// TestLoadImagesResetsImageProjectMap ensures stale digest -> UUID entries do
// not survive across LoadImages calls. Without this, a re-pulled image would
// leave a stale entry pointing at a still-live project's UUID, and a subsequent
// Remove() on the stale digest would operate on the live project.
func TestLoadImagesResetsImageProjectMap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" && r.Method == "GET" {
			// One project tagged for our cluster, current raw-image-id=alpine@sha256:new
			_, _ = w.Write([]byte(`[{
				"name": "alpine", "version": "3.14",
				"uuid": "8c940608-8e62-431a-ac5d-2092b7c41372",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine@sha256:new"}
				]
			}]`))
			return
		}
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte(`{"version": "4.8.0"}`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount": 1}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.Initialize()
	assert.NoError(t, err)

	// Seed a stale entry from a previous reconcile cycle.
	g.imageProjectMap = map[string]uuid.UUID{
		"alpine@sha256:OLD": uuid.MustParse("8c940608-8e62-431a-ac5d-2092b7c41372"),
	}

	images, err := g.LoadImages()
	assert.NoError(t, err)

	// Returned set reflects the current DT state only.
	assert.Len(t, images, 1)
	assert.Equal(t, "alpine@sha256:new", images[0].ImageID)

	// The stale entry must be gone; only the current digest remains.
	_, staleStillPresent := g.imageProjectMap["alpine@sha256:OLD"]
	assert.False(t, staleStillPresent, "stale digest entry must be cleared on LoadImages")

	currentUUID, currentPresent := g.imageProjectMap["alpine@sha256:new"]
	assert.True(t, currentPresent)
	assert.Equal(t, "8c940608-8e62-431a-ac5d-2092b7c41372", currentUUID.String())
}

func TestLoadImagesTagMode(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" && r.Method == "GET" {
			_, _ = w.Write([]byte("[{\"name\": \"alpine\", \"version\": \"3.14\", \"tags\": [{\"name\": \"kubernetes-cluster=my-cluster\"}], \"uuid\": \"8c940608-8e62-431a-ac5d-2092b7c41372\"}]"))
			return
		}
		if r.Method == "PATCH" {
			_, _ = w.Write([]byte("{}"))
			return
		}
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte("{\"version\": \"4.8.0\"}"))
			return
		}
		_, _ = w.Write([]byte("{\"totalCount\": 1}"))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "")
	err := g.Initialize()
	assert.NoError(t, err)

	_, _ = g.LoadImages()
}

func TestGetRawImageIds(t *testing.T) {
	assert.Empty(t, getRawImageIds([]dtrack.Tag{{Name: "sbom-operator"}}))
	assert.Equal(t, []string{"alpine@sha256:aaa"}, getRawImageIds([]dtrack.Tag{{Name: "raw-image-id=alpine@sha256:aaa"}}))
	assert.Equal(t, []string{"alpine@sha256:bbb", "alpine@sha256:ccc"}, getRawImageIds([]dtrack.Tag{
		{Name: "raw-image-id=alpine@sha256:bbb"},
		{Name: "sbom-operator"},
		{Name: "raw-image-id=alpine@sha256:ccc"},
		{Name: "namespace=default"},
	}))
}

// TestProcessSbomReactivateWithoutUpload verifies the lookup-first optimization:
// when an inactive project already exists with a matching raw-image-id, the BOM is
// not re-uploaded and the project is reactivated instead.
func TestProcessSbomReactivateWithoutUpload(t *testing.T) {
	var postBomCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case "/api/v1/project/lookup":
			// existing inactive project with matching raw-image-id
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.13", "active": false,
				"uuid": "11111111-2222-3333-4444-555555555555",
				"parent": {"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
				"tags": [{"name": "sbom-operator"}, {"name": "raw-image-id=alpine:3.13"}]
			}`))
		case "/api/v1/bom":
			postBomCount++
			_, _ = w.Write([]byte(`{"token": "tok"}`))
		case "/api/v1/project":
			if r.Method == "POST" {
				_, _ = w.Write([]byte(`{}`))
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "8c940608-8e62-431a-ac5d-2092b7c41372", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:      &liboci.RegistryImage{ImageID: "alpine:3.13", Image: "alpine:3.13"},
		Pod:        &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers: []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Sbom:       "{}",
	}

	_ = g.ProcessSbom(ctx)
	assert.Equal(t, 0, postBomCount, "BOM must not be re-uploaded when reactivating an existing project")
}

// TestProcessSbomDeactivatesSiblings verifies that uploading a new version causes
// sibling versions under the same parent to be patched as inactive.
func TestProcessSbomDeactivatesSiblings(t *testing.T) {
	parentUUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	activeUUID := "11111111-2222-3333-4444-555555555555"
	siblingUUID := "66666666-7777-8888-9999-000000000000"
	untaggedSiblingUUID := "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
	inactiveSiblingUUID := "88888888-9999-aaaa-bbbb-cccccccccccc"

	var patchUUIDs []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case "/api/v1/project/lookup":
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.14", "active": true,
				"uuid": "` + activeUUID + `",
				"parent": {"uuid": "` + parentUUID + `"},
				"tags": [{"name": "sbom-operator"}]
			}`))
		case "/api/v1/bom":
			_, _ = w.Write([]byte(`{"token": "tok"}`))
		case "/api/v1/project":
			if r.Method == "POST" {
				_, _ = w.Write([]byte(`{}`))
			} else if r.URL.Query().Get("name") != "" {
				// GetProjectsForName returns the current version + a sibling version
				_, _ = w.Write([]byte(`[
					{"name": "library/alpine", "version": "3.14", "active": true,
					 "uuid": "` + activeUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": [{"name": "sbom-operator"}]},
					{"name": "library/alpine", "version": "3.13", "active": true,
					 "uuid": "` + siblingUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": [{"name": "sbom-operator"}]},
					{"name": "library/alpine", "version": "3.12", "active": true,
					 "uuid": "` + untaggedSiblingUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": []},
					{"name": "library/alpine", "version": "3.11", "active": false,
					 "uuid": "` + inactiveSiblingUUID + `", "parent": {"uuid": "` + parentUUID + `"},
					 "tags": [{"name": "sbom-operator"}]}
				]`))
			} else {
				_, _ = w.Write([]byte(`[]`))
			}
		default:
			if r.Method == "PATCH" {
				patchUUIDs = append(patchUUIDs, strings.TrimPrefix(r.URL.Path, "/api/v1/project/"))
				_, _ = w.Write([]byte(`{}`))
			} else {
				_, _ = w.Write([]byte(`{}`))
			}
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "8c940608-8e62-431a-ac5d-2092b7c41372", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	ctx := &target.TargetContext{
		Image:      &liboci.RegistryImage{ImageID: "alpine:3.14", Image: "alpine:3.14"},
		Pod:        &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers: []*libk8s_real.ContainerInfo{{Name: "alpine"}},
		Sbom:       "{}",
	}

	_ = g.ProcessSbom(ctx)
	// Only the active, sbom-operator-tagged sibling should be patched as inactive.
	// The current project, the untagged sibling, and the already-inactive sibling
	// must not be touched.
	assert.Equal(t, []string{siblingUUID}, patchUUIDs)
}

// TestDeactivate verifies that Deactivate patches projects as inactive instead of
// deleting them.
func TestDeactivate(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"
	inactiveUUID := "88888888-9999-aaaa-bbbb-cccccccccccc"
	var patchCount, deleteCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch {
		case r.URL.Path == "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case r.URL.Path == "/api/v1/project/"+projectUUID && r.Method == "GET":
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [{"name": "sbom-operator"}, {"name": "raw-image-id=alpine:3.13"}]
			}`))
		case r.URL.Path == "/api/v1/project/"+inactiveUUID && r.Method == "GET":
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.12", "active": false,
				"uuid": "` + inactiveUUID + `",
				"tags": [{"name": "sbom-operator"}, {"name": "raw-image-id=alpine:3.12"}]
			}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/") && r.Method == "PATCH":
			patchCount++
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/") && r.Method == "DELETE":
			deleteCount++
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	// Seed the map directly with one active and one already-inactive project.
	g.imageProjectMap = map[string]uuid.UUID{
		"alpine:3.13": uuid.MustParse(projectUUID),
		"alpine:3.12": uuid.MustParse(inactiveUUID),
	}

	images := []*liboci.RegistryImage{
		{ImageID: "alpine:3.13", Image: "alpine:3.13"},
		{ImageID: "alpine:3.12", Image: "alpine:3.12"},
	}
	_ = g.Deactivate(images)
	// Only the active project should be patched as inactive; the already-inactive
	// one must be skipped (no 304 PATCH).
	assert.Equal(t, 1, patchCount, "only the active project should be patched as inactive")
	assert.Equal(t, 0, deleteCount, "project must not be deleted")
	assert.True(t, g.ShouldDeactivateOrphans())
}

// TestDeactivateTagModeMultiCluster verifies that in tag mode, Deactivate removes
// the current cluster's tag but does NOT deactivate the project when another
// cluster is still using it.
func TestDeactivateTagModeMultiCluster(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"
	var patchCount int
	var updateBodies []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch {
		case r.URL.Path == "/api/v1/version":
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
		case r.URL.Path == "/api/v1/project" && r.Method == "GET":
			// LoadImages returns the project tagged for both my-cluster and other-cluster
			_, _ = w.Write([]byte(`[{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "kubernetes-cluster=other-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"}
				]
			}]`))
		case r.URL.Path == "/api/v1/project/"+projectUUID && r.Method == "GET":
			_, _ = w.Write([]byte(`{
				"name": "library/alpine", "version": "3.13", "active": true,
				"uuid": "` + projectUUID + `",
				"tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "kubernetes-cluster=other-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"}
				]
			}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/project/") && r.Method == "PATCH":
			patchCount++
			_, _ = w.Write([]byte(`{}`))
		case r.URL.Path == "/api/v1/project" && r.Method == "POST":
			body, _ := io.ReadAll(r.Body)
			updateBodies = append(updateBodies, string(body))
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	images := []*liboci.RegistryImage{{ImageID: "alpine:3.13", Image: "alpine:3.13"}}
	_ = g.Deactivate(images)

	// Project must NOT be patched as inactive because another cluster still uses it.
	assert.Equal(t, 0, patchCount, "project must not be deactivated while another cluster uses it")

	// The cluster tag for my-cluster must have been removed in the Update body.
	assert.Len(t, updateBodies, 1)
	assert.Contains(t, updateBodies[0], `"kubernetes-cluster=other-cluster"`)
	assert.NotContains(t, updateBodies[0], `"kubernetes-cluster=my-cluster"`)
}

// TestLoadImagesSkipsInactiveProjects verifies that inactive projects are not
// returned when active-status management is enabled, so they don't surface as
// orphans and rolled-back images get re-scanned.
func TestLoadImagesSkipsInactiveProjects(t *testing.T) {
	activeUUID := "11111111-2222-3333-4444-555555555555"
	inactiveUUID := "66666666-7777-8888-9999-000000000000"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.URL.Path == "/api/v1/project" && r.Method == "GET" {
			_, _ = w.Write([]byte(`[
				{"name": "library/alpine", "version": "3.14", "active": true,
				 "uuid": "` + activeUUID + `",
				 "tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.14"}
				 ]},
				{"name": "library/alpine", "version": "3.13", "active": false,
				 "uuid": "` + inactiveUUID + `",
				 "tags": [
					{"name": "kubernetes-cluster=my-cluster"},
					{"name": "sbom-operator"},
					{"name": "raw-image-id=alpine:3.13"}
				 ]}
			]`))
			return
		}
		if r.URL.Path == "/api/v1/version" {
			_, _ = w.Write([]byte(`{"version": "5.0.0"}`))
			return
		}
		_, _ = w.Write([]byte(`{"totalCount": 1}`))
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, true, "")
	err := g.Initialize()
	assert.NoError(t, err)

	images, err := g.LoadImages()
	assert.NoError(t, err)
	assert.Len(t, images, 1)
	assert.Equal(t, "alpine:3.14", images[0].ImageID)
	_, inactivePresent := g.imageProjectMap["alpine:3.13"]
	assert.False(t, inactivePresent, "inactive project must not populate imageProjectMap")
}

func TestDeactivateSiblingVersions_TagMode_MultiCluster(t *testing.T) {
	parentUUID := uuid.New()
	currentUUID := uuid.New()
	siblingOtherClusterOnlyUUID := uuid.New()
	siblingSharedClusterUUID := uuid.New()
	siblingOwnClusterOnlyUUID := uuid.New()

	var updatedProjects []dtrack.Project
	var patchedUUIDs []string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"4.11.0"}`))
	})
	mux.HandleFunc("/api/v1/project", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			siblings := []dtrack.Project{
				{
					UUID:      currentUUID,
					Name:      "order-service-container",
					Version:   "1.2.0",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=approval_eu"},
					},
				},
				{
					// Szenario 1: Läuft nur in live_eu -> darf von approval_eu NICHT angefasst werden
					UUID:      siblingOtherClusterOnlyUUID,
					Name:      "order-service-container",
					Version:   "1.0.0",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=live_eu"},
					},
				},
				{
					// Szenario 2: Läuft in approval_eu UND approval_nar -> Tag approval_eu entfernen (POST), bleibt Active: true
					UUID:      siblingSharedClusterUUID,
					Name:      "order-service-container",
					Version:   "1.1.0-rc1",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=approval_eu"},
						{Name: "kubernetes-cluster=approval_nar"},
					},
				},
				{
					// Szenario 3: Läuft NUR in approval_eu -> wird deaktiviert (PATCH)
					UUID:      siblingOwnClusterOnlyUUID,
					Name:      "order-service-container",
					Version:   "1.0.9",
					Active:    true,
					ParentRef: &dtrack.ParentRef{UUID: parentUUID},
					Tags: []dtrack.Tag{
						{Name: "sbom-operator"},
						{Name: "kubernetes-cluster=approval_eu"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(siblings)

		case http.MethodPost:
			var p dtrack.Project
			_ = json.NewDecoder(r.Body).Decode(&p)
			updatedProjects = append(updatedProjects, p)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(p)
		}
	})
	mux.HandleFunc("/api/v1/project/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch {
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/project/")
			patchedUUIDs = append(patchedUUIDs, id)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"active":false}`))
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := dtrack.NewClient(server.URL)
	require.NoError(t, err)

	target := &DependencyTrackTarget{
		k8sClusterId:              "approval_eu",
		k8sClusterIdMode:          "tag",
		manageProjectActiveStatus: true,
	}

	currentProject := dtrack.Project{
		UUID:      currentUUID,
		Name:      "order-service-container",
		Version:   "1.2.0",
		Active:    true,
		ParentRef: &dtrack.ParentRef{UUID: parentUUID},
	}

	target.deactivateSiblingVersions(client, currentProject)

	// Szenario 2 (siblingSharedClusterUUID): Nur Tag-Update per POST, bleibt aktiv
	require.Len(t, updatedProjects, 1)
	shared := updatedProjects[0]
	assert.Equal(t, siblingSharedClusterUUID, shared.UUID)
	assert.True(t, shared.Active)
	assert.False(t, containsTag(shared.Tags, "kubernetes-cluster=approval_eu"))
	assert.True(t, containsTag(shared.Tags, "kubernetes-cluster=approval_nar"))

	// Szenario 3 (siblingOwnClusterOnlyUUID): Deaktiviert per PATCH (und Szenario 1 wurde komplett ignoriert)
	assert.Equal(t, []string{siblingOwnClusterOnlyUUID.String()}, patchedUUIDs)
}

// When an upload times out, Dependency-Track usually imports the BOM anyway.
// The project must still get our tags (so LoadImages recognises it and it can
// be cleaned up), but the upload is reported as failed so it's retried.
func TestProcessSbomTagsProjectAfterUploadTimeout(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"

	tests := []struct {
		name          string
		bomStatus     int
		projectExists bool
		expectTimeout bool
		expectLookup  bool
		expectUpdate  bool
	}{
		{name: "project created despite timeout", projectExists: true, expectTimeout: true, expectLookup: true, expectUpdate: true},
		{name: "project not created (yet)", projectExists: false, expectTimeout: true, expectLookup: true, expectUpdate: false},
		{name: "other upload errors aren't treated as timeouts", bomStatus: http.StatusInternalServerError, projectExists: true, expectTimeout: false, expectLookup: false, expectUpdate: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := make(chan struct{})
			lookedUp := false
			var updatedTags []string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == "/api/v1/bom":
					if tt.bomStatus != 0 {
						w.WriteHeader(tt.bomStatus)
						return
					}
					<-release
				case r.URL.Path == "/api/v1/project/lookup":
					lookedUp = true
					if !tt.projectExists {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					_, _ = w.Write([]byte(`{"name": "library/alpine", "version": "3.14", "uuid": "` + projectUUID + `", "tags": []}`))
				case r.URL.Path == "/api/v1/project" && r.Method == http.MethodPost:
					var p dtrack.Project
					_ = json.NewDecoder(r.Body).Decode(&p)
					for _, tag := range p.Tags {
						updatedTags = append(updatedTags, tag.Name)
					}
					_, _ = w.Write([]byte(`{}`))
				default:
					_, _ = w.Write([]byte(`{"totalCount": 0}`))
				}
			}))
			defer ts.Close()
			defer close(release)

			g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", true, false, "300ms")
			require.NoError(t, g.ValidateConfig())
			require.NoError(t, g.Initialize())
			g.imageProjectMap = map[string]uuid.UUID{}

			ctx := &target.TargetContext{
				Image:      &liboci.RegistryImage{ImageID: "alpine@sha256:aaa", Image: "alpine:3.14"},
				Pod:        &libk8s_real.PodInfo{PodNamespace: "default"},
				Containers: []*libk8s_real.ContainerInfo{{Name: "alpine"}},
				Sbom:       "{}",
			}

			err := g.ProcessSbom(ctx)
			require.Error(t, err, "the upload is retried in every case")
			assert.Equal(t, tt.expectTimeout, isTimeout(err))
			assert.Equal(t, tt.expectLookup, lookedUp)
			if tt.expectUpdate {
				assert.ElementsMatch(t, []string{"kubernetes-cluster=my-cluster", "sbom-operator", "raw-image-id=alpine@sha256:aaa", "namespace=default"}, updatedTags)
				assert.Equal(t, projectUUID, g.imageProjectMap["alpine@sha256:aaa"].String())
			} else {
				assert.Empty(t, updatedTags)
			}
		})
	}
}

// fakeDependencyTrack keeps projects by UUID and records changes to them.
type fakeDependencyTrack struct {
	projects map[string]*dtrack.Project
	updated  []string
	deleted  []string
	patched  []string
}

func newFakeDependencyTrack(t *testing.T, projects ...dtrack.Project) (*fakeDependencyTrack, string) {
	f := &fakeDependencyTrack{projects: map[string]*dtrack.Project{}}
	for i := range projects {
		f.projects[projects[i].UUID.String()] = &projects[i]
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/project/")
		switch {
		case r.URL.Path == "/api/version":
			_, _ = w.Write([]byte(`{"version": "4.12.0"}`))
		case r.URL.Path == "/api/v1/project" && r.Method == http.MethodGet:
			all := make([]dtrack.Project, 0, len(f.projects))
			for _, p := range projects {
				all = append(all, *f.projects[p.UUID.String()])
			}
			w.Header().Set("X-Total-Count", fmt.Sprint(len(all)))
			_ = json.NewEncoder(w).Encode(all)
		case r.URL.Path == "/api/v1/project" && r.Method == http.MethodPost:
			var p dtrack.Project
			_ = json.NewDecoder(r.Body).Decode(&p)
			f.projects[p.UUID.String()] = &p
			f.updated = append(f.updated, p.UUID.String())
			_ = json.NewEncoder(w).Encode(p)
		case r.Method == http.MethodGet && f.projects[id] != nil:
			_ = json.NewEncoder(w).Encode(f.projects[id])
		case r.Method == http.MethodDelete:
			delete(f.projects, id)
			f.deleted = append(f.deleted, id)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPatch:
			f.patched = append(f.patched, id)
			f.projects[id].Active = false
			_ = json.NewEncoder(w).Encode(f.projects[id])
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return f, ts.URL
}

func multiDigestProject(id string, active bool, extraTags ...string) dtrack.Project {
	tags := []dtrack.Tag{
		{Name: sbomOperator},
		{Name: "kubernetes-cluster=my-cluster"},
		{Name: "raw-image-id=thelounge@sha256:aaa"},
		{Name: "raw-image-id=thelounge@sha256:bbb"},
	}
	for _, tag := range extraTags {
		tags = append(tags, dtrack.Tag{Name: tag})
	}
	return dtrack.Project{UUID: uuid.MustParse(id), Name: "ghcr.io/thelounge/thelounge", Version: "4.4.3", Active: active, Tags: tags}
}

func registryImages(ids ...string) []*liboci.RegistryImage {
	images := make([]*liboci.RegistryImage, 0, len(ids))
	for _, id := range ids {
		images = append(images, &liboci.RegistryImage{ImageID: id})
	}
	return images
}

// Two pods of a Deployment can run different digests of a re-pushed tag. Both
// must be recorded, or one always looks missing and is rescanned forever.
func TestLoadImagesReturnsEveryDigest(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"
	_, url := newFakeDependencyTrack(t, multiDigestProject(projectUUID, true))

	g := NewDependencyTrackTarget(url, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", false, false, "")
	require.NoError(t, g.Initialize())

	images, err := g.LoadImages()
	require.NoError(t, err)
	ids := make([]string, 0)
	for _, i := range images {
		ids = append(ids, i.ImageID)
	}
	assert.Equal(t, []string{"thelounge@sha256:aaa", "thelounge@sha256:bbb"}, ids)
	assert.Equal(t, projectUUID, g.imageProjectMap["thelounge@sha256:aaa"].String())
	assert.Equal(t, projectUUID, g.imageProjectMap["thelounge@sha256:bbb"].String())
}

func TestProcessSbomKeepsOtherDigests(t *testing.T) {
	var updatedTags []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/bom":
			_, _ = w.Write([]byte(`{"token": "tok"}`))
		case r.URL.Path == "/api/v1/project/lookup":
			_, _ = w.Write([]byte(`{"name": "ghcr.io/thelounge/thelounge", "version": "4.4.3", "uuid": "11111111-2222-3333-4444-555555555555",
				"tags": [{"name": "sbom-operator"}, {"name": "kubernetes-cluster=my-cluster"}, {"name": "raw-image-id=thelounge@sha256:aaa"}]}`))
		case r.URL.Path == "/api/v1/project" && r.Method == http.MethodPost:
			var p dtrack.Project
			_ = json.NewDecoder(r.Body).Decode(&p)
			for _, tag := range p.Tags {
				updatedTags = append(updatedTags, tag.Name)
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer ts.Close()

	g := NewDependencyTrackTarget(ts.URL, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", false, false, "")
	require.NoError(t, g.Initialize())
	g.imageProjectMap = map[string]uuid.UUID{}

	err := g.ProcessSbom(&target.TargetContext{
		Image:      &liboci.RegistryImage{ImageID: "thelounge@sha256:bbb", Image: "ghcr.io/thelounge/thelounge:4.4.3"},
		Pod:        &libk8s_real.PodInfo{PodNamespace: "default"},
		Containers: []*libk8s_real.ContainerInfo{{Name: "thelounge"}},
		Sbom:       "{}",
	})
	require.NoError(t, err)
	assert.Contains(t, updatedTags, "raw-image-id=thelounge@sha256:aaa")
	assert.Contains(t, updatedTags, "raw-image-id=thelounge@sha256:bbb")
}

func TestRemoveOnlyDropsOrphanedDigests(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"

	tests := []struct {
		name            string
		project         dtrack.Project
		orphans         []string
		expectDeleted   bool
		expectUpdated   bool
		expectedDigests []string
	}{
		{
			name:            "a digest still running keeps the project",
			project:         multiDigestProject(projectUUID, true),
			orphans:         []string{"thelounge@sha256:aaa"},
			expectUpdated:   true,
			expectedDigests: []string{"thelounge@sha256:bbb"},
		},
		{
			name:          "the project is removed with its last digest",
			project:       multiDigestProject(projectUUID, true),
			orphans:       []string{"thelounge@sha256:aaa", "thelounge@sha256:bbb"},
			expectDeleted: true,
		},
		{
			name:            "digests of a project used by other clusters are kept",
			project:         multiDigestProject(projectUUID, true, "kubernetes-cluster=other-cluster"),
			orphans:         []string{"thelounge@sha256:aaa"},
			expectedDigests: []string{"thelounge@sha256:aaa", "thelounge@sha256:bbb"},
		},
		{
			name:            "the cluster tag is removed with the last digest, if other clusters use the project",
			project:         multiDigestProject(projectUUID, true, "kubernetes-cluster=other-cluster"),
			orphans:         []string{"thelounge@sha256:aaa", "thelounge@sha256:bbb"},
			expectUpdated:   true,
			expectedDigests: []string{"thelounge@sha256:aaa", "thelounge@sha256:bbb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			internal.OperatorConfig = &internal.Config{}
			dt, url := newFakeDependencyTrack(t, tt.project)

			g := NewDependencyTrackTarget(url, "apikey", "", "", "", "", "my-cluster", "tag", "", "", "", false, false, "")
			require.NoError(t, g.Initialize())
			_, err := g.LoadImages()
			require.NoError(t, err)

			require.NoError(t, g.Remove(registryImages(tt.orphans...)))
			if tt.expectDeleted {
				assert.Equal(t, []string{projectUUID}, dt.deleted)
				return
			}
			assert.Empty(t, dt.deleted)
			if tt.expectUpdated {
				assert.Equal(t, []string{projectUUID}, dt.updated)
			} else {
				assert.Empty(t, dt.updated)
			}
			assert.Equal(t, tt.expectedDigests, getRawImageIds(dt.projects[projectUUID].Tags))
		})
	}
}

func TestDeactivateOnlyDropsOrphanedDigests(t *testing.T) {
	projectUUID := "11111111-2222-3333-4444-555555555555"

	t.Run("a digest still running keeps the project active", func(t *testing.T) {
		dt, url := newFakeDependencyTrack(t, multiDigestProject(projectUUID, true))
		g := NewDependencyTrackTarget(url, "apikey", "", "", "", "", "my-cluster", "tag", "8c940608-8e62-431a-ac5d-2092b7c41372", "", "", false, true, "")
		require.NoError(t, g.ValidateConfig())
		require.NoError(t, g.Initialize())
		_, err := g.LoadImages()
		require.NoError(t, err)

		require.NoError(t, g.Deactivate(registryImages("thelounge@sha256:aaa")))
		assert.Empty(t, dt.patched)
		assert.True(t, dt.projects[projectUUID].Active)
		assert.Equal(t, []string{"thelounge@sha256:bbb"}, getRawImageIds(dt.projects[projectUUID].Tags))
	})

	t.Run("the project is deactivated with its last digest", func(t *testing.T) {
		dt, url := newFakeDependencyTrack(t, multiDigestProject(projectUUID, true))
		g := NewDependencyTrackTarget(url, "apikey", "", "", "", "", "my-cluster", "tag", "8c940608-8e62-431a-ac5d-2092b7c41372", "", "", false, true, "")
		require.NoError(t, g.ValidateConfig())
		require.NoError(t, g.Initialize())
		_, err := g.LoadImages()
		require.NoError(t, err)

		require.NoError(t, g.Deactivate(registryImages("thelounge@sha256:aaa", "thelounge@sha256:bbb")))
		assert.Equal(t, []string{projectUUID}, dt.patched)
		assert.Equal(t, []string{"thelounge@sha256:aaa", "thelounge@sha256:bbb"}, getRawImageIds(dt.projects[projectUUID].Tags), "digests are kept for reactivation")
	})
}
