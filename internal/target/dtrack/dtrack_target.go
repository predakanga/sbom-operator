package dtrack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	parser "github.com/novln/docker-parser"
	"github.com/sirupsen/logrus"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/target"
)

type DependencyTrackTarget struct {
	clientOptions []dtrack.ClientOption

	baseUrl                    string
	apiKey                     string
	podLabelTagMatcher         string
	defaultParentProject       string
	parentProjectAnnotationKey string
	projectNameAnnotationKey   string
	caCertFile                 string
	clientCertFile             string
	clientKeyFile              string
	k8sClusterId               string
	k8sClusterIdMode           string
	useShortName               bool
	manageProjectActiveStatus  bool
	timeout                    string
	imageProjectMap            map[string]uuid.UUID

	defaultParentProjectParsed *uuid.UUID
	timeoutParsed              time.Duration
}

const (
	kubernetesCluster  = "kubernetes-cluster"
	sbomOperator       = "sbom-operator"
	rawImageId         = "raw-image-id"
	podNamespaceTagKey = "namespace"

	// DefaultTimeout is used when no timeout is configured. Dependency-Track
	// processes a BOM before replying to the upload, which takes well over the
	// client's own 10s default for images with tens of thousands of components.
	DefaultTimeout = 60 * time.Second
)

func NewDependencyTrackTarget(baseUrl, apiKey, podLabelTagMatcher, caCertFile, clientCertFile, clientKeyFile, k8sClusterId string, k8sClusterIdMode string, defaultParentProject string, parentProjectAnnotationKey string, projectNameAnnotationKey string, useShortName bool, manageProjectActiveStatus bool, timeout string) *DependencyTrackTarget {
	return &DependencyTrackTarget{
		baseUrl:                    baseUrl,
		apiKey:                     apiKey,
		podLabelTagMatcher:         podLabelTagMatcher,
		caCertFile:                 caCertFile,
		clientCertFile:             clientCertFile,
		clientKeyFile:              clientKeyFile,
		k8sClusterId:               k8sClusterId,
		k8sClusterIdMode:           k8sClusterIdMode,
		defaultParentProject:       defaultParentProject,
		parentProjectAnnotationKey: parentProjectAnnotationKey,
		projectNameAnnotationKey:   projectNameAnnotationKey,
		useShortName:               useShortName,
		manageProjectActiveStatus:  manageProjectActiveStatus,
		timeout:                    timeout,
	}
}

func (g *DependencyTrackTarget) ValidateConfig() error {
	if g.baseUrl == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencyTrackBaseUrl)
	}
	if g.apiKey == "" {
		return fmt.Errorf("%s is empty", internal.ConfigKeyDependencyTrackApiKey)
	}
	if g.caCertFile != "" {
		if g.clientCertFile == "" {
			return fmt.Errorf(
				"%s provided but %s is empty",
				internal.ConfigKeyDependencyTrackCaCertFile,
				internal.ConfigKeyDependencyTrackClientCertFile,
			)
		}

		if g.clientKeyFile == "" {
			return fmt.Errorf(
				"%s provided but %s is empty",
				internal.ConfigKeyDependencyTrackCaCertFile,
				internal.ConfigKeyDependencyTrackClientKeyFile,
			)
		}
	}
	if g.defaultParentProject != "" {
		uuid, err := uuid.Parse(g.defaultParentProject)
		if err != nil {
			return fmt.Errorf(
				"default parent project is not a valid UUID",
			)
		}
		g.defaultParentProjectParsed = &uuid
	} else {
		g.defaultParentProjectParsed = nil
	}

	timeout, err := parseTimeout(g.timeout)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", internal.ConfigKeyDependencyTrackTimeout, err)
	}
	g.timeoutParsed = timeout

	if g.manageProjectActiveStatus && g.parentProjectAnnotationKey == "" && g.defaultParentProjectParsed == nil {
		return fmt.Errorf(
			"%s is enabled but no parent project is configured (set %s or %s)",
			internal.ConfigKeyDependencyTrackManageProjectActiveStatus,
			internal.ConfigKeyDependencyTrackDtrackParentProjectAnnotationKey,
			internal.ConfigKeyDefaultParentProject,
		)
	}

	return nil
}

func (g *DependencyTrackTarget) Initialize() error {
	g.clientOptions = []dtrack.ClientOption{}

	g.clientOptions = append(g.clientOptions, dtrack.WithAPIKey(g.apiKey))

	if len(g.caCertFile) > 0 {
		g.clientOptions = append(g.clientOptions, dtrack.WithMTLS(g.caCertFile, g.clientCertFile, g.clientKeyFile))
	}

	timeout := g.timeoutParsed
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	g.clientOptions = append(g.clientOptions, dtrack.WithTimeout(timeout))

	return nil
}

// parseTimeout parses a Go duration ("90s", "2m"). A bare number is taken as
// seconds. An empty value selects DefaultTimeout.
func parseTimeout(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return DefaultTimeout, nil
	}

	timeout, err := time.ParseDuration(value)
	if err != nil {
		seconds, numErr := strconv.ParseInt(value, 10, 64)
		if numErr != nil {
			return 0, err
		}
		timeout = time.Duration(seconds) * time.Second
	}

	if timeout <= 0 {
		return 0, fmt.Errorf("timeout must be positive, got %q", value)
	}

	return timeout, nil
}

func (g *DependencyTrackTarget) identifyProjectNameAndVersion(ctx *target.TargetContext) (string, string) {
	projectName := ""
	version := ""
	// Set custom project name by kubernetes annotation?
	if g.projectNameAnnotationKey != "" {
		logrus.Debugf(`Try to set project name by configured annotationkey "%s"`, g.projectNameAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			var err error
			projectName, version, err = g.getContainerNameAndVersion(podAnnotationKey, podAnnotationValue, g.projectNameAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong project name configuration. Skip setting custom project name for image '%s'", ctx.Image.Image)
				continue
			}
			if projectName != "" {
				break
			}
		}
	}

	// If projectNameAnnotationKey is not set or could not be parsed correctly, use image instead
	if projectName == "" || version == "" {
		projectName, version = getRepoWithVersion(ctx.Image, g.useShortName, g.k8sClusterId, g.k8sClusterIdMode, ctx.Scope)
	}
	return projectName, version
}

func (g *DependencyTrackTarget) identifiyParentProjectUuid(ctx *target.TargetContext, client *dtrack.Client) *uuid.UUID {
	if g.parentProjectAnnotationKey != "" {
		logrus.Debugf("Try to set parent project by configured annotationkey %s", g.parentProjectAnnotationKey)
		for podAnnotationKey, podAnnotationValue := range ctx.Pod.Annotations {
			logrus.Debugf("AnnotationKey %s starts with %s?", podAnnotationKey, g.parentProjectAnnotationKey)

			parentProjectName, parentProjectVersion, err := g.getContainerNameAndVersion(podAnnotationKey, podAnnotationValue, g.parentProjectAnnotationKey, ctx)
			if err != nil {
				logrus.WithError(err).Errorf("Wrong parent project configuration. Skipping parent for image '%s'", ctx.Image.Image)
				continue
			}
			if parentProjectName == "" {
				continue
			}
			parentProjectUuid, err := uuid.Parse(parentProjectName)
			if err == nil {
				return &parentProjectUuid
			}
			hasExplicitVersion := strings.Contains(podAnnotationValue, ":")
			logrus.Debugf("Try to find parent project by name from annotation \"%s\", for image %s, parentProjectName \"%s\" and parentProjectVersion \"%s\"", podAnnotationKey, ctx.Image.Image, parentProjectName, parentProjectVersion)
			parentProjects, err := client.Project.GetProjectsForName(context.Background(), parentProjectName, false, true)
			if err != nil {
				logrus.WithError(err).Errorf(`Could not find parent project "%s"`, parentProjectName)
			} else if len(parentProjects) == 0 {
				logrus.Errorf(`No parent project found with name "%s"`, parentProjectName)
			} else {
				var parentProject dtrack.Project
				found := false
				if hasExplicitVersion {
					for _, p := range parentProjects {
						if p.Version == parentProjectVersion {
							parentProject = p
							found = true
							break
						}
					}
					if !found {
						logrus.Errorf(`No parent project found with name "%s" and version "%s"`, parentProjectName, parentProjectVersion)
					}
				} else {
					if len(parentProjects) > 1 {
						logrus.Warnf(`Multiple root projects found with name "%s", using the first one`, parentProjectName)
					}
					parentProject = parentProjects[0]
					found = true
				}
				if found {
					logrus.Infof(`Found parent project with name "%s" and UUID "%s" for image "%s"`, parentProjectName, parentProject.UUID, ctx.Image.Image)
					return &parentProject.UUID
				}
			}
			break

		}
	}
	return g.defaultParentProjectParsed
}

func (g *DependencyTrackTarget) ProcessSbom(ctx *target.TargetContext) error {
	if ctx.MediaType != "" && ctx.MediaType != oci.CycloneDXJSONMediaType && ctx.MediaType != oci.CycloneDXXMLMediaType {
		logrus.Warnf("Skipping attestation SBOM (scope=%s) with unsupported mediaType %s for Dependency-Track", ctx.Scope, ctx.MediaType)
		return nil
	}

	logrus.Debugf("%v", g)
	projectName, version := g.identifyProjectNameAndVersion(ctx)

	if ctx.Sbom == "" {
		logrus.Infof("Empty SBOM - skip image (image=%s)", ctx.Image.ImageID)
		return nil
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}
	// When active-status management is enabled, try to reactivate an existing
	// inactive project without re-uploading the SBOM (e.g. a rollback to a
	// previously deployed image with a matching digest).
	project, skipUpload := dtrack.Project{}, false
	if g.manageProjectActiveStatus {
		existing, lookupErr := client.Project.Lookup(context.Background(), projectName, version)
		if lookupErr == nil && !existing.Active && slices.Contains(getRawImageIds(existing.Tags), ctx.Image.ImageID) {
			project = existing
			skipUpload = true
			logrus.Infof("Reactivating existing project %s:%s without re-uploading SBOM", projectName, version)
		}
	}

	parentUuid := g.identifiyParentProjectUuid(ctx, client)
	// set when the upload timed out: the project is still tagged, but the
	// upload is reported as failed so that it's retried
	var uploadErr error
	if !skipUpload {
		logrus.Infof("Sending SBOM to Dependency Track (project=%s, version=%s)", projectName, version)
		uploadToken, err := client.BOM.PostBom(
			context.Background(),
			dtrack.BOMUploadRequest{ProjectName: projectName, ProjectVersion: version, ParentUUID: parentUuid, AutoCreate: true, BOM: ctx.Sbom},
		)
		if err != nil {
			if !isTimeout(err) {
				logrus.Errorf("Could not upload BOM: %v", err)
				return err
			}

			// Dependency-Track only replies once it has processed the BOM, and
			// usually goes on to import it after we gave up. Without our tags the
			// project would neither be recognised by LoadImages nor cleaned up.
			logrus.Warnf("Upload of SBOM for %s:%s timed out, consider raising --%s. Tagging the project in case Dependency-Track created it anyway", projectName, version, internal.ConfigKeyDependencyTrackTimeout)
			uploadErr = fmt.Errorf("BOM upload timed out: %w", err)
		} else {
			logrus.Infof("Uploaded SBOM (upload-token=%s)", uploadToken)
		}
	}

	if !skipUpload {
		project, err = client.Project.Lookup(context.Background(), projectName, version)
		if err != nil {
			if uploadErr != nil {
				logrus.Warnf("Project %s:%s doesn't exist (yet) after the timed out upload", projectName, version)
				return uploadErr
			}
			logrus.Errorf("Could not find project: %v", err)
			return err
		}
	}

	if parentUuid != nil {
		project.ParentRef = &dtrack.ParentRef{UUID: *parentUuid}
	}
	kubernetesClusterTag := kubernetesCluster + "=" + g.k8sClusterId
	if g.k8sClusterIdMode == "tag" {
		if !containsTag(project.Tags, kubernetesClusterTag) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: kubernetesClusterTag})
		}
	} else {
		if containsTag(project.Tags, kubernetesClusterTag) {
			project.Tags = removeTag(project.Tags, kubernetesClusterTag)
		}
	}

	if !containsTag(project.Tags, sbomOperator) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: sbomOperator})
	}

	// Record the container's digest. The same (projectName, version) can be backed
	// by several digests at once (mutable `:latest`, a re-pushed tag pulled at
	// different times by different pods), so the project keeps one raw-image-id
	// tag per digest. Remove()/Deactivate() drop a digest's tag once no pod runs
	// it, and only touch the project itself when no digest is left.
	project.Tags = addRawImageIdTag(project.Tags, ctx.Image.ImageID)
	podNamespaceTag := podNamespaceTagKey + "=" + ctx.Pod.PodNamespace
	if !containsTag(project.Tags, podNamespaceTag) {
		project.Tags = append(project.Tags, dtrack.Tag{Name: podNamespaceTag})
	}

	var reg *regexp.Regexp
	if g.podLabelTagMatcher != "" {
		reg, err = regexp.Compile(g.podLabelTagMatcher)
		if err != nil {
			logrus.Errorf("Could not parse regex: %v", err)
			return err
		}
	}

	for podLabelKey, podLabelValue := range ctx.Pod.Labels {
		podLabel := fmt.Sprintf("%s=%s", podLabelKey, podLabelValue)
		if !containsTag(project.Tags, podLabel) && (reg == nil || reg.MatchString(podLabelKey)) {
			project.Tags = append(project.Tags, dtrack.Tag{Name: podLabel})
		}
	}

	if g.manageProjectActiveStatus {
		project.Active = true
		project.IsLatest = dtrack.OptionalBoolOf(true)
	}

	_, err = client.Project.Update(context.Background(), project)
	if err != nil {
		logrus.WithError(err).Errorf("Could not update project")
	}

	if g.manageProjectActiveStatus {
		g.deactivateSiblingVersions(client, project)
	}

	if g.imageProjectMap == nil {
		// prepropulate imageProjectMap
		_, err := g.LoadImages()
		if err != nil {
			return err
		}
	}

	g.imageProjectMap[ctx.Image.ImageID] = project.UUID
	return uploadErr
}

// isTimeout reports whether err is a client-side timeout.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (g *DependencyTrackTarget) getContainerNameAndVersion(podAnnotationKey string, podAnnotationValue string, expectedAnnotationKey string, ctx *target.TargetContext) (string, string, error) {
	if strings.HasPrefix(podAnnotationKey, expectedAnnotationKey) {
		// determine container name and scope from annotation key
		containerName, scope := getContainerNameAndScopeFromAnnotationKey(podAnnotationKey, "/")
		if podAnnotationValue != "" {
			// correct container found?
			for _, c := range ctx.Containers {
				if (containerName == "" || containerName == c.Name) && scope == ctx.Scope {
					name, version := getNameAndVersionFromString(podAnnotationValue, ":")
					logrus.Infof(`Custom '%s' found at annotation '%s' for container '%s' and scope '%s': '%s:%s'`, expectedAnnotationKey, podAnnotationKey, containerName, scope, name, version)
					return name, version, nil
				} else {
					logrus.Debugf("skipping container '%s' as not configured for annotation key '%s'", c.Name, expectedAnnotationKey)
				}
			}
		} else {
			return "", "", fmt.Errorf(`empty value for annotation '%s' in image '%s'`, podAnnotationKey, ctx.Image.Image)
		}
	}
	return "", "", nil
}

func (g *DependencyTrackTarget) LoadImages() ([]*libk8s.RegistryImage, error) {
	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return nil, err
	}

	// Always rebuild the imageProjectMap from DT state. Previously the map was
	// only initialised when nil, so entries accumulated across reconcile cycles.
	// After a pod/image update, stale `digest -> UUID` entries kept pointing at
	// UUIDs of still-live projects (because rotation of raw-image-id was broken,
	// see ProcessSbom). That caused `Remove()` to operate on live projects.
	// Resetting here guarantees the map mirrors the current DT state.
	g.imageProjectMap = make(map[string]uuid.UUID)

	var (
		pageNumber = 1
		pageSize   = 50
	)

	images := make([]*libk8s.RegistryImage, 0)
	for {
		projectsPage, err := client.Project.GetAll(context.Background(), dtrack.PageOptions{
			PageNumber: pageNumber,
			PageSize:   pageSize,
		})
		if err != nil {
			logrus.Errorf("Could not load projects: %v", err)
			return nil, err
		}

		for _, project := range projectsPage.Items {
			sbomOperatorPropFound := false
			imageRelatesToCluster := false

			//extend lookup logic to support `prefix` mode to resolve image association
			if g.k8sClusterIdMode == "prefix" {
				imageRelatesToCluster = strings.HasPrefix(project.Name, g.k8sClusterId+"-")
			}

			for _, tag := range project.Tags {
				if g.k8sClusterIdMode == "tag" && strings.Index(tag.Name, kubernetesCluster) == 0 {
					clusterId := string(tag.Name[len(kubernetesCluster)+1:])
					if clusterId == g.k8sClusterId {
						imageRelatesToCluster = true
					}
				}
				if tag.Name == sbomOperator {
					sbomOperatorPropFound = true
				}
			}

			// When active-status management is enabled, inactive projects are not
			// returned so they neither appear as orphans on every cycle nor block
			// re-scanning of a rolled-back image.
			if g.manageProjectActiveStatus && !project.Active {
				continue
			}

			if imageRelatesToCluster && sbomOperatorPropFound {
				for _, imageId := range getRawImageIds(project.Tags) {
					images = append(images, &libk8s.RegistryImage{ImageID: imageId})
					g.imageProjectMap[imageId] = project.UUID
				}
			}
		}

		if pageNumber*pageSize >= projectsPage.TotalCount {
			break
		}

		pageNumber++
	}

	return images, nil
}

func (g *DependencyTrackTarget) Remove(images []*libk8s.RegistryImage) error {
	if g.imageProjectMap == nil {
		// prepropulate imageProjectMap
		_, err := g.LoadImages()
		if err != nil {
			return err
		}
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}

	for _, orphans := range g.groupByProject(images) {
		project, err := client.Project.Get(context.Background(), orphans.uuid)
		if err != nil {
			logrus.Errorf("Could not load project: %v", err)
			continue
		}

		currentImageName := fmt.Sprintf("%v:%v", project.Name, project.Version)
		otherClusterIds := []string{}
		sbomOperatorPropFound := false

		for _, tag := range project.Tags {
			if tag.Name == sbomOperator {
				sbomOperatorPropFound = true
			}
		}

		if !sbomOperatorPropFound {
			continue
		}

		if g.removeOrphanedDigests(client, &project, orphans.imageIDs) {
			continue
		}

		if g.k8sClusterIdMode != "tag" {
			// Prefix mode: dt-projects are cluster-specific by name. These are safe to be deleted.
			logrus.Infof("Image not running in any cluster - removing %v", currentImageName)
			err := client.Project.Delete(context.Background(), project.UUID)
			g.forgetImages(orphans.imageIDs)
			if err != nil {
				logrus.WithError(err).Warnf("Project %s could not be deleted", project.UUID.String())
			}
			continue
		}

		// Tag mode: check all tags, remove the current cluster and aggregate a list of other clusters
		for _, tag := range project.Tags {
			if strings.Index(tag.Name, kubernetesCluster) == 0 {
				clusterId := string(tag.Name[len(kubernetesCluster)+1:])
				if clusterId == g.k8sClusterId {
					logrus.Infof("Removing %v=%v tag from project %v", kubernetesCluster, g.k8sClusterId, currentImageName)
					project.Tags = removeTag(project.Tags, kubernetesCluster+"="+g.k8sClusterId)
					_, err := client.Project.Update(context.Background(), project)
					g.forgetImages(orphans.imageIDs)
					if err != nil {
						logrus.WithError(err).Warnf("Project %s could not be updated", project.UUID.String())
					}
				} else {
					otherClusterIds = append(otherClusterIds, clusterId)
				}
			}
		}

		// if not in other cluster delete the project
		if len(otherClusterIds) == 0 {
			logrus.Infof("Image not running in any cluster - removing %v", currentImageName)
			err := client.Project.Delete(context.Background(), project.UUID)
			g.forgetImages(orphans.imageIDs)
			if err != nil {
				logrus.WithError(err).Warnf("Project %s could not be deleted", project.UUID.String())
			}
		}
	}

	return nil
}

// projectOrphans are the orphaned digests recorded by one project.
type projectOrphans struct {
	uuid     uuid.UUID
	imageIDs []string
}

// groupByProject groups images by the project that records them, in order.
// Images without a known project are skipped.
func (g *DependencyTrackTarget) groupByProject(images []*libk8s.RegistryImage) []*projectOrphans {
	groups := make([]*projectOrphans, 0, len(images))
	byUUID := make(map[uuid.UUID]*projectOrphans)
	for _, img := range images {
		projectUUID, ok := g.imageProjectMap[img.ImageID]
		if !ok || projectUUID == uuid.Nil {
			logrus.Warnf("No project found for imageID: %s", img.ImageID)
			continue
		}

		group, ok := byUUID[projectUUID]
		if !ok {
			group = &projectOrphans{uuid: projectUUID}
			byUUID[projectUUID] = group
			groups = append(groups, group)
		}
		group.imageIDs = append(group.imageIDs, img.ImageID)
	}

	return groups
}

func (g *DependencyTrackTarget) forgetImages(imageIDs []string) {
	for _, id := range imageIDs {
		delete(g.imageProjectMap, id)
	}
}

// removeOrphanedDigests handles a project that records digests besides the
// orphaned ones, i.e. one that is still in use: only the orphaned digests'
// raw-image-id tags are removed, the project is kept. It reports whether it
// handled the project; if not, no recorded digest is in use anymore.
//
// In tag mode, a project that other clusters use keeps all its digest tags:
// the digests that aren't running here may be running there.
func (g *DependencyTrackTarget) removeOrphanedDigests(client *dtrack.Client, project *dtrack.Project, orphanedIDs []string) bool {
	remaining := slices.DeleteFunc(getRawImageIds(project.Tags), func(id string) bool {
		return slices.Contains(orphanedIDs, id)
	})
	if len(remaining) == 0 {
		return false
	}

	g.forgetImages(orphanedIDs)
	if g.k8sClusterIdMode == "tag" && len(g.otherClusterIds(project.Tags)) > 0 {
		logrus.Debugf("Project '%s:%s' is used by other clusters, keeping the tags of digests %v", project.Name, project.Version, orphanedIDs)
		return true
	}

	logrus.Infof("Digests %v of project '%s:%s' aren't running anymore, removing their %s tags", orphanedIDs, project.Name, project.Version, rawImageId)
	project.Tags = removeRawImageIdTags(project.Tags, orphanedIDs)
	if _, err := client.Project.Update(context.Background(), *project); err != nil {
		logrus.WithError(err).Warnf("Project tags could not be updated for project '%s:%s'", project.Name, project.Version)
	}

	return true
}

// otherClusterIds returns the IDs of the clusters other than this one that
// tag the project.
func (g *DependencyTrackTarget) otherClusterIds(tags []dtrack.Tag) []string {
	ids := make([]string, 0)
	for _, tag := range tags {
		if strings.HasPrefix(tag.Name, kubernetesCluster+"=") {
			if clusterId := strings.TrimPrefix(tag.Name, kubernetesCluster+"="); clusterId != g.k8sClusterId {
				ids = append(ids, clusterId)
			}
		}
	}
	return ids
}

// Deactivate sets the given projects as inactive (and not latest) instead of
// deleting them, preserving them for version history. Only invoked when
// ShouldDeactivateOrphans returns true. All tags are kept.
func (g *DependencyTrackTarget) Deactivate(images []*libk8s.RegistryImage) error {
	if g.imageProjectMap == nil {
		_, err := g.LoadImages()
		if err != nil {
			return err
		}
	}

	client, err := dtrack.NewClient(g.baseUrl, g.clientOptions...)
	if err != nil {
		logrus.WithError(err).Errorf("failed to init dtrack client")
		return err
	}

	for _, orphans := range g.groupByProject(images) {
		project, err := client.Project.Get(context.Background(), orphans.uuid)
		if err != nil {
			logrus.Errorf("Could not load project: %v", err)
			continue
		}

		if !project.Active || !slices.ContainsFunc(project.Tags, func(t dtrack.Tag) bool { return t.Name == sbomOperator }) {
			continue
		}

		if g.removeOrphanedDigests(client, &project, orphans.imageIDs) {
			continue
		}

		_ = g.handleProjectDeactivation(client, &project)
	}

	return nil
}

func (g *DependencyTrackTarget) ShouldDeactivateOrphans() bool {
	return g.manageProjectActiveStatus
}

// deactivateSiblingVersions sets all other versions of the same project name
// under the same parent as inactive (and not latest), so that only the currently
// running version stays active.
func (g *DependencyTrackTarget) deactivateSiblingVersions(client *dtrack.Client, project dtrack.Project) {
	if project.ParentRef == nil {
		return
	}

	siblings, err := client.Project.GetProjectsForName(context.Background(), project.Name, false, false)
	if err != nil {
		logrus.WithError(err).Errorf("Could not load sibling projects for name %s", project.Name)
		return
	}

	for _, sibling := range siblings {
		if sibling.UUID == project.UUID {
			continue
		}
		if sibling.ParentRef == nil || sibling.ParentRef.UUID != project.ParentRef.UUID {
			continue
		}
		if sibling.Version == project.Version {
			continue
		}
		_ = g.handleProjectDeactivation(client, &sibling)
	}
}

func getNameAndVersionFromString(input string, delimiter string) (string, string) {
	parts := strings.Split(input, delimiter)
	name := parts[0]
	version := "latest"
	if len(parts) == 2 {
		version = parts[1]
	}
	return name, version
}

func getContainerNameAndScopeFromAnnotationKey(annotationKey string, delimiter string) (string, string) {
	parts := strings.Split(annotationKey, delimiter)
	containerName := ""
	scope := ""
	if len(parts) >= 2 {
		containerName = parts[1]
	}
	if len(parts) == 3 {
		scope = parts[2]
	}
	return containerName, scope
}

func containsTag(tags []dtrack.Tag, tagString string) bool {
	for _, tag := range tags {
		if tag.Name == tagString || strings.Index(tag.Name, tagString) == 0 {
			return true
		}
	}
	return false
}

func removeTag(tags []dtrack.Tag, tagString string) []dtrack.Tag {
	newTags := []dtrack.Tag{}
	for _, tag := range tags {
		if tag.Name != tagString {
			newTags = append(newTags, tag)
		}
	}
	return newTags
}

// getRawImageIds returns the values of all `raw-image-id=<id>` tags.
func getRawImageIds(tags []dtrack.Tag) []string {
	prefix := rawImageId + "="
	ids := make([]string, 0, 1)
	for _, tag := range tags {
		if strings.HasPrefix(tag.Name, prefix) {
			ids = append(ids, strings.TrimPrefix(tag.Name, prefix))
		}
	}
	return ids
}

// addRawImageIdTag appends a `raw-image-id=<digest>` tag, unless the project
// already records that digest. See ProcessSbom for the rationale.
func addRawImageIdTag(tags []dtrack.Tag, imageID string) []dtrack.Tag {
	name := rawImageId + "=" + imageID
	for _, tag := range tags {
		if tag.Name == name {
			return tags
		}
	}
	return append(tags, dtrack.Tag{Name: name})
}

// removeRawImageIdTags drops the `raw-image-id=<digest>` tags of the given
// digests.
func removeRawImageIdTags(tags []dtrack.Tag, imageIDs []string) []dtrack.Tag {
	out := make([]dtrack.Tag, 0, len(tags))
	for _, tag := range tags {
		if !strings.HasPrefix(tag.Name, rawImageId+"=") || !slices.Contains(imageIDs, strings.TrimPrefix(tag.Name, rawImageId+"=")) {
			out = append(out, tag)
		}
	}
	return out
}

func getRepoWithVersion(image *libk8s.RegistryImage, useShortName bool, k8sClusterId string, k8sClusterIdMode string, scope string) (string, string) {
	imageRef, err := parser.Parse(image.ImageID)
	if err != nil {
		logrus.WithError(err).Errorf("Could not parse image %s", image.ImageID)
		return "", ""
	}

	var projectName string
	//add Cluster prefix to projectName if prefix mode is set
	if k8sClusterIdMode == "prefix" {
		projectName = k8sClusterId + "-"
	}
	if useShortName {
		projectName += imageRef.ShortName()
	} else {
		projectName += imageRef.Repository()
	}
	if scope != "" {
		projectName += "-" + scope
	}

	if strings.Index(image.Image, "sha256") != 0 {
		imageRef, err = parser.Parse(image.Image)
		if err != nil {
			logrus.WithError(err).Errorf("Could not parse image %s", image.Image)
			return "", ""
		}
	}

	version := imageRef.Tag()
	return projectName, version
}

// handleProjectDeactivation removes the current cluster tag in "tag" mode
// and persists the updated tags. If no other clusters are referencing the
// project anymore, it patches the project to be inactive (and not latest).
func (g *DependencyTrackTarget) handleProjectDeactivation(client *dtrack.Client, project *dtrack.Project) error {
	if !project.Active {
		return nil
	}
	sbomOperatorPropFound := false
	for _, tag := range project.Tags {
		if tag.Name == sbomOperator {
			sbomOperatorPropFound = true
			break
		}
	}
	if !sbomOperatorPropFound {
		return nil
	}

	if g.k8sClusterIdMode == "tag" {
		ownClusterTagFound := false
		otherClusterIds := []string{}

		for _, tag := range project.Tags {
			if strings.Index(tag.Name, kubernetesCluster) == 0 {
				clusterId := string(tag.Name[len(kubernetesCluster)+1:])
				if clusterId == g.k8sClusterId {
					ownClusterTagFound = true
					logrus.Infof("Removing %s=%s tag from project '%s:%s'", kubernetesCluster, g.k8sClusterId, project.Name, project.Version)
					project.Tags = removeTag(project.Tags, kubernetesCluster+"="+g.k8sClusterId)
				} else {
					otherClusterIds = append(otherClusterIds, clusterId)
				}
			}
		}

		if len(otherClusterIds) > 0 {
			if ownClusterTagFound {
				_, err := client.Project.Update(context.Background(), *project)
				if err != nil {
					logrus.WithError(err).Warnf("Project tags could not be updated for project '%s:%s'", project.Name, project.Version)
					return err
				}
			}
			return nil
		}
	}

	// No other clusters are using it (or tag mode is disabled) -> deactivate
	logrus.Infof("Deactivating project '%s:%s' as it is not used by any other clusters", project.Name, project.Version)
	_, err := client.Project.Patch(context.Background(), project.UUID, dtrack.Project{
		Active:   false,
		IsLatest: dtrack.OptionalBoolOf(false),
	})
	if err != nil {
		logrus.WithError(err).Warnf("Project '%s:%s' could not be deactivated", project.Name, project.Version)
		return err
	}

	return nil
}
