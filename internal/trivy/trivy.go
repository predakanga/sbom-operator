package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	internaloci "github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sirupsen/logrus"
)

// Binary is the trivy CLI, looked up in PATH.
const Binary = "trivy"

// Trivy creates SBOMs by running the trivy CLI. Its SBOMs name distros and
// record source packages the way Trivy's vulnerability matching expects, so
// Dependency-Track's Trivy analyzer can match their OS packages.
type Trivy struct {
	format           string
	cacheDir         string
	proxyRegistryMap map[string]string
	run              runFunc
}

// runFunc runs trivy with args and env, returning its stdout and stderr.
type runFunc func(ctx context.Context, args []string, env []string) ([]byte, []byte, error)

// Format maps an operator SBOM format to Trivy's name for it. Trivy can't
// write the other formats, and always uses its own spec version.
func Format(sbomFormat string) (string, error) {
	switch sbomFormat {
	case "cyclonedxjson":
		return "cyclonedx", nil
	case "spdxjson":
		return "spdx-json", nil
	case "spdx", "spdxtv", "spdxtagvalue":
		return "spdx", nil
	default:
		return "", fmt.Errorf("format %q isn't supported by the trivy generator, use cyclonedxjson, spdxjson or spdx", sbomFormat)
	}
}

// ErrUnsupportedFormatVersion is returned when a format version is set, as
// Trivy always writes its own spec version.
var ErrUnsupportedFormatVersion = errors.New("--format-version isn't supported by the trivy generator, which always writes its own spec version")

func New(sbomFormat string, cacheDir string, proxyRegistryMap map[string]string) (*Trivy, error) {
	format, err := Format(sbomFormat)
	if err != nil {
		return nil, err
	}

	return &Trivy{
		format:           format,
		cacheDir:         cacheDir,
		proxyRegistryMap: proxyRegistryMap,
		run:              runTrivy,
	}, nil
}

// ExecuteSyft creates an SBOM for img with Trivy. It keeps the generator
// interface's name, which predates the Trivy generator.
func (t *Trivy) ExecuteSyft(img *oci.RegistryImage) (string, error) {
	logrus.Infof("Processing image %s", img.ImageID)

	oriImage := img.Image
	oriImageID := img.ImageID

	err := kubernetes.ApplyProxyRegistry(img, true, t.proxyRegistryMap)
	if err != nil {
		return "", err
	}
	ref := img.ImageID
	credentials := internaloci.ResolveCredentials(img, t.proxyRegistryMap)

	// revert image info to the original value - we want to register with original names
	img.Image = oriImage
	img.ImageID = oriImageID

	// Trivy reads registry credentials from a Docker config, so write one per
	// scan and remove it straight after
	configDir, err := os.MkdirTemp("", "sbom-operator-trivy-")
	if err != nil {
		return "", fmt.Errorf("could not create Docker config dir: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(configDir); err != nil {
			logrus.WithError(err).Warnf("Could not remove %s", configDir)
		}
	}()

	if err := writeDockerConfig(configDir, credentials); err != nil {
		return "", err
	}

	args := []string{
		"image",
		"--image-src", "remote",
		"--platform", "linux/" + runtime.GOARCH,
		"--format", t.format,
		"--cache-dir", t.cacheDir,
		"--no-progress",
		// Both are needed to stop the update check on every run
		"--skip-version-check",
		"--disable-telemetry",
		// Large images (GitLab's are ~3GB) outlast the default 5m
		"--timeout", "30m",
		ref,
	}

	stdout, stderr, err := t.run(context.Background(), args, trivyEnv(configDir))
	for _, line := range strings.Split(strings.TrimSpace(string(stderr)), "\n") {
		if line != "" {
			logrus.Debugf("trivy: %s", line)
		}
	}
	if err != nil {
		logrus.WithError(err).Error("SBOM-Creation failed")
		return "", fmt.Errorf("trivy failed for %s: %w: %s", ref, err, lastLine(stderr))
	}

	return string(stdout), nil
}

func runTrivy(ctx context.Context, args []string, env []string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, Binary, args...) /* #nosec */
	cmd.Env = env
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// trivyEnv passes on what Trivy needs from the operator's environment, but
// not its other settings (such as the Dependency-Track API key). TRIVY_*
// variables are passed on, so Trivy can be tuned without a new flag.
func trivyEnv(dockerConfigDir string) []string {
	env := []string{"DOCKER_CONFIG=" + dockerConfigDir}
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		switch strings.ToUpper(key) {
		case "PATH", "HOME", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR":
			env = append(env, kv)
		default:
			if strings.HasPrefix(key, "TRIVY_") {
				env = append(env, kv)
			}
		}
	}

	return env
}

// writeDockerConfig writes credentials to dir/config.json. A registry with
// several credentials gets the first usable one, as a Docker config only
// holds one per registry.
func writeDockerConfig(dir string, credentials []image.RegistryCredentials) error {
	auths := map[string]authn.AuthConfig{}
	for _, c := range credentials {
		key := authKey(c.Authority)
		if key == "" {
			continue
		}
		if _, ok := auths[key]; ok {
			continue
		}

		cfg := authn.AuthConfig{Username: c.Username, Password: c.Password, RegistryToken: c.Token}
		if c.Authenticator != nil {
			resolved, err := c.Authenticator.Authorization()
			if err != nil {
				logrus.WithError(err).Warnf("Could not get credentials for %s", c.Authority)
				continue
			}
			cfg = *resolved
		}
		if cfg == (authn.AuthConfig{}) {
			continue
		}

		auths[key] = cfg
	}

	b, err := json.Marshal(map[string]any{"auths": auths})
	if err != nil {
		return fmt.Errorf("could not encode Docker config: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0600); err != nil {
		return fmt.Errorf("could not write Docker config: %w", err)
	}

	return nil
}

// authKey returns the Docker config key that go-containerregistry looks up
// for a registry, e.g. Docker Hub's legacy URL for "docker.io".
func authKey(authority string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(authority, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	if host == "" {
		return ""
	}

	reg, err := name.NewRegistry(host)
	if err != nil {
		logrus.WithError(err).Debugf("Ignoring credentials for invalid registry %q", authority)
		return ""
	}
	if reg.RegistryStr() == name.DefaultRegistry {
		return authn.DefaultAuthKey
	}

	return reg.RegistryStr()
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}
