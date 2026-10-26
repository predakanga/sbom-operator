package trivy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestFormat(t *testing.T) {
	tests := []struct {
		format  string
		want    string
		wantErr bool
	}{
		{format: "cyclonedxjson", want: "cyclonedx"},
		{format: "spdxjson", want: "spdx-json"},
		{format: "spdx", want: "spdx"},
		{format: "spdxtagvalue", want: "spdx"},
		{format: "cyclonedx", wantErr: true},
		{format: "json", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got, err := Format(tt.format)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// fakeRun records trivy's args and the Docker config it was given.
type fakeRun struct {
	args         []string
	env          []string
	dockerConfig map[string]map[string]authn.AuthConfig
	stdout       string
	stderr       string
	err          error
}

func (f *fakeRun) run(_ context.Context, args []string, env []string) ([]byte, []byte, error) {
	f.args = args
	f.env = env
	for _, kv := range env {
		if dir, ok := strings.CutPrefix(kv, "DOCKER_CONFIG="); ok {
			b, err := os.ReadFile(filepath.Join(dir, "config.json")) /* #nosec */
			if err != nil {
				return nil, nil, err
			}
			if err := json.Unmarshal(b, &f.dockerConfig); err != nil {
				return nil, nil, err
			}
		}
	}
	return []byte(f.stdout), []byte(f.stderr), f.err
}

func pullSecret(registry, username, password string) *oci.KubeCreds {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	data := `{"auths":{"` + registry + `":{"auth":"` + auth + `"}}}`
	return &oci.KubeCreds{SecretName: "pull", SecretCredsData: []byte(data)}
}

func TestExecuteSyft(t *testing.T) {
	fake := &fakeRun{stdout: `{"bomFormat":"CycloneDX"}`, stderr: "INFO\tDetected OS\n"}
	tr, err := New("cyclonedxjson", "/cache", nil)
	require.NoError(t, err)
	tr.run = fake.run

	img := &oci.RegistryImage{
		ImageID:     "registry.example.com/app@" + digest,
		Image:       "registry.example.com/app:1.0",
		PullSecrets: []*oci.KubeCreds{pullSecret("registry.example.com", "user", "pass")},
	}
	sbom, err := tr.ExecuteSyft(img)
	require.NoError(t, err)

	assert.Equal(t, `{"bomFormat":"CycloneDX"}`, sbom)
	assert.Equal(t, "registry.example.com/app@"+digest, fake.args[len(fake.args)-1])
	assert.Subset(t, fake.args, []string{"--format", "cyclonedx", "--cache-dir", "/cache", "--image-src", "remote", "--skip-version-check", "--disable-telemetry"})
	assert.Equal(t, authn.AuthConfig{Username: "user", Password: "pass"}, withoutAuth(fake.dockerConfig["auths"]["registry.example.com"]))
}

func TestExecuteSyftProxyRegistry(t *testing.T) {
	fake := &fakeRun{}
	tr, err := New("cyclonedxjson", "/cache", map[string]string{"registry.example.com": "proxy.example.com"})
	require.NoError(t, err)
	tr.run = fake.run

	img := &oci.RegistryImage{ImageID: "registry.example.com/app@" + digest, Image: "registry.example.com/app:1.0"}
	_, err = tr.ExecuteSyft(img)
	require.NoError(t, err)

	assert.Equal(t, "proxy.example.com/app@"+digest, fake.args[len(fake.args)-1])
	// The original names are kept for the targets
	assert.Equal(t, "registry.example.com/app@"+digest, img.ImageID)
	assert.Equal(t, "registry.example.com/app:1.0", img.Image)
}

func TestExecuteSyftFailure(t *testing.T) {
	fake := &fakeRun{
		stderr: "INFO\tDownloading\nFATAL\tFatal error\trun error: image scan error: unauthorized\n",
		err:    errors.New("exit status 1"),
	}
	tr, err := New("cyclonedxjson", "/cache", nil)
	require.NoError(t, err)
	tr.run = fake.run

	_, err = tr.ExecuteSyft(&oci.RegistryImage{ImageID: "registry.example.com/app@" + digest})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit status 1")
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestWriteDockerConfig(t *testing.T) {
	dir := t.TempDir()
	err := writeDockerConfig(dir, []image.RegistryCredentials{
		{Authority: "docker.io", Username: "hub", Password: "first"},
		{Authority: "https://index.docker.io/v1/", Username: "hub", Password: "second"},
		{Authority: "ghcr.io", Token: "bearer"},
		{Authority: "registry.example.com:5000", Authenticator: authn.FromConfig(authn.AuthConfig{Username: "u", Password: "p"})},
		{Authority: "empty.example.com"},
		{Authority: ""},
	})
	require.NoError(t, err)

	b, err := os.ReadFile(filepath.Join(dir, "config.json")) /* #nosec */
	require.NoError(t, err)
	var cfg map[string]map[string]authn.AuthConfig
	require.NoError(t, json.Unmarshal(b, &cfg))

	auths := cfg["auths"]
	assert.Len(t, auths, 3)
	assert.Equal(t, authn.AuthConfig{Username: "hub", Password: "first"}, withoutAuth(auths[authn.DefaultAuthKey]))
	assert.Equal(t, authn.AuthConfig{RegistryToken: "bearer"}, withoutAuth(auths["ghcr.io"]))
	assert.Equal(t, authn.AuthConfig{Username: "u", Password: "p"}, withoutAuth(auths["registry.example.com:5000"]))
}

func TestAuthKey(t *testing.T) {
	tests := map[string]string{
		"docker.io":                   authn.DefaultAuthKey,
		"index.docker.io":             authn.DefaultAuthKey,
		"https://index.docker.io/v1/": authn.DefaultAuthKey,
		"https://ghcr.io":             "ghcr.io",
		"registry.example.com:5000":   "registry.example.com:5000",
		"":                            "",
	}

	for authority, want := range tests {
		assert.Equal(t, want, authKey(authority), authority)
	}
}

func TestTrivyEnv(t *testing.T) {
	t.Setenv("PATH", "/usr/local/bin")
	t.Setenv("TRIVY_JAVA_DB_REPOSITORY", "mirror.example.com/trivy-java-db:1")
	t.Setenv("SBOM_DTRACK_API_KEY", "secret")

	env := trivyEnv("/tmp/config")

	assert.Contains(t, env, "DOCKER_CONFIG=/tmp/config")
	assert.Contains(t, env, "PATH=/usr/local/bin")
	assert.Contains(t, env, "TRIVY_JAVA_DB_REPOSITORY=mirror.example.com/trivy-java-db:1")
	assert.NotContains(t, env, "SBOM_DTRACK_API_KEY=secret")
}

// withoutAuth drops the encoded "auth" field that AuthConfig's JSON adds for
// username and password, to compare the rest.
func withoutAuth(cfg authn.AuthConfig) authn.AuthConfig {
	cfg.Auth = ""
	return cfg
}
