package processor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/libstandard"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/job"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/oci"
	"github.com/ckotzbauer/sbom-operator/internal/syft"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/ckotzbauer/sbom-operator/internal/target/configmap"
	"github.com/ckotzbauer/sbom-operator/internal/target/dtrack"
	"github.com/ckotzbauer/sbom-operator/internal/target/git"
	targetoci "github.com/ckotzbauer/sbom-operator/internal/target/oci"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// sbomGenerator creates an SBOM for an image (implemented by syft.Syft).
type sbomGenerator interface {
	ExecuteSyft(img *liboci.RegistryImage) (string, error)
}

type Processor struct {
	K8s               *kubernetes.KubeClient
	sy                sbomGenerator
	Targets           []target.Target
	imageMap          map[string]bool
	allowedNamespaces map[string]bool
	namespaceMutex    sync.RWMutex
}

func New(k8s *kubernetes.KubeClient, sy *syft.Syft) *Processor {
	targets := make([]target.Target, 0)
	if !HasJobImage() {
		logrus.Debugf("Targets set to: %v", internal.OperatorConfig.Targets)
		targets = initTargets(k8s)
	}

	return &Processor{K8s: k8s, sy: sy, Targets: targets, imageMap: make(map[string]bool), allowedNamespaces: make(map[string]bool)}
}

func (p *Processor) ListenForPods() {
	// Load allowed namespaces based on namespace-label-selector
	namespaceSelector := internal.OperatorConfig.NamespaceLabelSelector
	if namespaceSelector != "" {
		// Initial load of namespaces
		namespaces, err := p.K8s.Client.ListNamespaces(namespaceSelector)
		if err != nil {
			logrus.WithError(err).Fatalf("Failed to list namespaces with selector: %s", namespaceSelector)
			return
		}

		logrus.Debugf("Discovered %v namespaces matching selector '%s'", len(namespaces), namespaceSelector)
		for _, ns := range namespaces {
			p.allowedNamespaces[ns.Name] = true
			logrus.Tracef("Allowing namespace: %s", ns.Name)
		}

		// Start namespace informer to watch for namespace changes
		// We use an unfiltered informer and check labels manually to properly handle
		// the case where a namespace's labels are updated to no longer match the selector
		namespaceInformer, err := p.K8s.StartNamespaceInformer("", cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				ns := obj.(*corev1.Namespace)
				// Check if namespace matches the selector
				if p.namespaceLabelMatches(ns.Labels, namespaceSelector) {
					p.addAllowedNamespace(ns.Name)
				}
			},
			UpdateFunc: func(old, new interface{}) {
				newNs := new.(*corev1.Namespace)
				wasAllowed := p.isNamespaceAllowed(newNs.Name)
				shouldBeAllowed := p.namespaceLabelMatches(newNs.Labels, namespaceSelector)

				if shouldBeAllowed && !wasAllowed {
					p.addAllowedNamespace(newNs.Name)
				} else if !shouldBeAllowed && wasAllowed {
					p.removeAllowedNamespace(newNs.Name)
				}
			},
			DeleteFunc: func(obj interface{}) {
				ns := obj.(*corev1.Namespace)
				// Only remove if it was in the allowed list
				if p.isNamespaceAllowed(ns.Name) {
					p.removeAllowedNamespace(ns.Name)
				}
			},
		})

		if err != nil {
			logrus.WithError(err).Fatal("Can't create namespace informer")
			return
		}

		// Start the namespace informer asynchronously
		go func() {
			logrus.Info("Starting namespace informer")
			namespaceInformer.Run(make(chan struct{}))
		}()
	} else {
		logrus.Debug("No namespace-label-selector configured, all namespaces will be processed")
	}

	var informer cache.SharedIndexInformer
	informer, err := p.K8s.StartPodInformer(internal.OperatorConfig.PodLabelSelector, cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(old, new interface{}) {
			oldPod := old.(*corev1.Pod)
			newPod := new.(*corev1.Pod)

			// Filter by namespace if selector is configured
			if !p.isNamespaceAllowed(newPod.Namespace) {
				logrus.Tracef("Skipping pod %s/%s - namespace not in allowed list", newPod.Namespace, newPod.Name)
				return
			}

			oldInfo := p.K8s.Client.ExtractPodInfos(*oldPod)
			newInfo := p.K8s.Client.ExtractPodInfos(*newPod)
			logrus.Tracef("Pod %s/%s was updated.", newInfo.PodNamespace, newInfo.PodName)

			var removedContainers []*libk8s.ContainerInfo
			newInfo.Containers, removedContainers = getChangedContainers(oldInfo, newInfo)
			_ = p.scanPod(newInfo) // errors are logged
			p.cleanupImagesIfNeeded(removedContainers, informer.GetStore().List())
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)

			// Filter by namespace if selector is configured
			if !p.isNamespaceAllowed(pod.Namespace) {
				logrus.Tracef("Skipping pod %s/%s - namespace not in allowed list", pod.Namespace, pod.Name)
				return
			}

			info := p.K8s.Client.ExtractPodInfos(*pod)
			logrus.Tracef("Pod %s/%s was removed.", info.PodNamespace, info.PodName)
			p.cleanupImagesIfNeeded(info.Containers, informer.GetStore().List())
		},
	})

	if err != nil {
		logrus.WithError(err).Fatal("Can't listen for pod-changes.")
		return
	}

	p.runInformerAsync(informer)
}

func (p *Processor) isNamespaceAllowed(namespace string) bool {
	// If no namespace selector is configured, allow all namespaces
	if internal.OperatorConfig.NamespaceLabelSelector == "" {
		return true
	}

	// Check if namespace is in the allowed list (thread-safe read)
	p.namespaceMutex.RLock()
	defer p.namespaceMutex.RUnlock()
	return p.allowedNamespaces[namespace]
}

func (p *Processor) addAllowedNamespace(namespace string) {
	p.namespaceMutex.Lock()
	defer p.namespaceMutex.Unlock()
	p.allowedNamespaces[namespace] = true
	logrus.Infof("Namespace %s is now allowed for scanning", namespace)
}

func (p *Processor) removeAllowedNamespace(namespace string) {
	p.namespaceMutex.Lock()
	defer p.namespaceMutex.Unlock()
	delete(p.allowedNamespaces, namespace)
	logrus.Infof("Namespace %s is no longer allowed for scanning", namespace)
}

func (p *Processor) namespaceLabelMatches(nsLabels map[string]string, selector string) bool {
	// Parse the label selector
	labelSelector, err := labels.Parse(selector)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to parse namespace label selector: %s", selector)
		return false
	}

	// Check if the namespace labels match the selector
	return labelSelector.Matches(labels.Set(nsLabels))
}

func (p *Processor) ProcessAllPods(pods []libk8s.PodInfo, allImages []*liboci.RegistryImage) {
	if !HasJobImage() {
		p.executeSyftScans(pods, allImages)
	} else {
		p.executeJobImage(pods)
	}
}

// scanPod processes the pod's containers which aren't annotated as processed
// yet, and annotates those that succeeded. It returns an error if any failed.
func (p *Processor) scanPod(pod libk8s.PodInfo) error {
	processed, err := p.processPod(pod)
	p.K8s.UpdatePodAnnotation(pod, processed)
	return err
}

// processPod sends SBOMs for the images of the pod's unannotated containers to
// all targets. It returns the containers whose image succeeded, and an error
// if any image failed.
func (p *Processor) processPod(pod libk8s.PodInfo) ([]*libk8s.ContainerInfo, error) {
	p.K8s.InjectPullSecrets(pod)
	imageIDs := make([]string, 0)
	containersByImage := make(map[string][]*libk8s.ContainerInfo)
	for _, container := range pod.Containers {
		if p.K8s.HasAnnotation(pod.Annotations, container) {
			logrus.Debugf("Skip image %s", container.Image.ImageID)
			continue
		}
		if _, ok := containersByImage[container.Image.ImageID]; !ok {
			imageIDs = append(imageIDs, container.Image.ImageID)
		}
		containersByImage[container.Image.ImageID] = append(containersByImage[container.Image.ImageID], container)
	}

	processed := make([]*libk8s.ContainerInfo, 0)
	var errs []error
	for _, imageID := range imageIDs {
		containers := containersByImage[imageID]
		if err := p.processImage(&pod, imageID, containers); err != nil {
			logrus.WithError(err).Errorf("Failed to process image %s of pod %s/%s", imageID, pod.PodNamespace, pod.PodName)
			errs = append(errs, err)
			continue
		}
		processed = append(processed, containers...)
	}

	return processed, errors.Join(errs...)
}

// processImage sends the SBOMs for an image to all targets, unless that
// already succeeded for another pod. The image is only recorded as processed
// once every target accepted its SBOMs, so failures are retried.
func (p *Processor) processImage(pod *libk8s.PodInfo, imageID string, containers []*libk8s.ContainerInfo) error {
	if p.imageMap[imageID] {
		logrus.Debugf("Image %s was already processed", imageID)
		return nil
	}

	image := containers[0].Image
	var attContexts []*target.TargetContext
	if internal.OperatorConfig.FetchOciAttestations {
		attSboms, attErr := oci.FetchSbomAttestations(context.Background(), image, libstandard.ToMap(internal.OperatorConfig.RegistryProxies))
		if attErr != nil {
			logrus.WithError(attErr).Warnf("Could not fetch OCI attestations for image %s", imageID)
		} else {
			for _, att := range attSboms {
				attContexts = append(attContexts, target.NewContext(att.Sbom, image, pod).
					WithAttestation(att.Scope, string(att.MediaType)))
			}
		}
	}

	var syftContext *target.TargetContext
	if needsSyftSbom(p.Targets, attContexts) {
		// Execute syft only if some target can't use any of the default-scope SBOMs attached in OCI
		sbom, err := p.sy.ExecuteSyft(image)
		if err != nil {
			return fmt.Errorf("syft failed: %w", err)
		}
		syftContext = target.NewContext(sbom, image, pod)
	}

	var errs []error
	for _, t := range p.Targets {
		for _, ctx := range sbomsForTarget(t, attContexts, syftContext) {
			if err := t.ProcessSbom(ctx.WithContainers(containers)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("target failed: %w", errors.Join(errs...))
	}

	p.imageMap[imageID] = true
	return nil
}

// hasDefaultScopeSbom reports whether one of the attestation SBOMs is a
// default-scope SBOM that t accepts.
func hasDefaultScopeSbom(t target.Target, attContexts []*target.TargetContext) bool {
	for _, ctx := range attContexts {
		if ctx.Scope == "" && target.AcceptsMediaType(t, ctx.MediaType) {
			return true
		}
	}

	return false
}

// needsSyftSbom reports whether any target lacks a usable default-scope
// attestation SBOM, and so needs one generated by Syft.
func needsSyftSbom(targets []target.Target, attContexts []*target.TargetContext) bool {
	for _, t := range targets {
		if !hasDefaultScopeSbom(t, attContexts) {
			return true
		}
	}

	return false
}

// sbomsForTarget returns the SBOMs to send to t: every attestation SBOM it
// accepts, plus the Syft SBOM (if any) when no accepted attestation covers the
// default scope.
func sbomsForTarget(t target.Target, attContexts []*target.TargetContext, syftContext *target.TargetContext) []*target.TargetContext {
	contexts := make([]*target.TargetContext, 0, len(attContexts)+1)
	for _, ctx := range attContexts {
		if target.AcceptsMediaType(t, ctx.MediaType) {
			contexts = append(contexts, ctx)
		}
	}

	if syftContext != nil && !hasDefaultScopeSbom(t, attContexts) {
		contexts = append(contexts, syftContext)
	}

	return contexts
}

func initTargets(k8s *kubernetes.KubeClient) []target.Target {
	targets := make([]target.Target, 0)

	for _, ta := range internal.OperatorConfig.Targets {
		var err error

		// nolint QF1003
		if ta == "git" {
			workingTree := internal.OperatorConfig.GitWorkingTree
			workPath := internal.OperatorConfig.GitPath
			repository := internal.OperatorConfig.GitRepository
			branch := internal.OperatorConfig.GitBranch
			format := internal.OperatorConfig.Format
			token := internal.OperatorConfig.GitAccessToken
			userName := internal.OperatorConfig.GitUserName
			password := internal.OperatorConfig.GitPassword
			name := internal.OperatorConfig.GitAuthorName
			email := internal.OperatorConfig.GitAuthorEmail
			githubAppId := internal.OperatorConfig.GitHubAppId
			githubAppInstallationId := internal.OperatorConfig.GitHubAppInstallationId
			githubAppPrivateKey := internal.OperatorConfig.GitHubPrivateKey
			t := git.NewGitTarget(workingTree, workPath, repository, branch, name, email, token, userName, password, githubAppId, githubAppInstallationId, githubAppPrivateKey, format)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "dtrack" {
			baseUrl := internal.OperatorConfig.DtrackBaseUrl
			apiKey := internal.OperatorConfig.DtrackApiKey
			podLabelTagMatcher := internal.OperatorConfig.DtrackLabelTagMatcher
			parentProjectAnnotationKey := internal.OperatorConfig.DtrackParentProjectAnnotationKey
			projectNameAnnotationKey := internal.OperatorConfig.DtrackProjectNameAnnotationKey
			caCertFile := internal.OperatorConfig.DtrackCaCertFile
			clientCertFile := internal.OperatorConfig.DtrackClientCertFile
			clientKeyFile := internal.OperatorConfig.DtrackClientKeyFile
			k8sClusterId := internal.OperatorConfig.KubernetesClusterId
			k8sClusterIdMode := internal.OperatorConfig.DtrackKubernetesClusterIdMode
			defaultParentProject := internal.OperatorConfig.DtrackDefaultParentProject
			useShortName := internal.OperatorConfig.DtrackUseShortName
			manageProjectActiveStatus := internal.OperatorConfig.DtrackManageProjectActiveStatus
			t := dtrack.NewDependencyTrackTarget(baseUrl, apiKey, podLabelTagMatcher, caCertFile, clientCertFile, clientKeyFile, k8sClusterId, k8sClusterIdMode, defaultParentProject, parentProjectAnnotationKey, projectNameAnnotationKey, useShortName, manageProjectActiveStatus)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "oci" {
			registry := internal.OperatorConfig.OciRegistry
			username := internal.OperatorConfig.OciUser
			token := internal.OperatorConfig.OciToken
			format := internal.OperatorConfig.Format
			t := targetoci.NewOciTarget(registry, username, token, format)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else if ta == "configmap" {
			t := configmap.NewConfigMapTarget(k8s)
			err = t.ValidateConfig()
			targets = append(targets, t)
		} else {
			logrus.Fatalf("Unknown target %s", ta)
		}

		if err != nil {
			logrus.WithError(err).Fatal("Config-Validation failed!")
		}
	}

	if len(targets) == 0 {
		logrus.Fatalf("Please specify at least one target.")
	}

	return targets
}

func HasJobImage() bool {
	return internal.OperatorConfig.JobImage != ""
}

func (p *Processor) executeSyftScans(pods []libk8s.PodInfo, allImages []*liboci.RegistryImage) {
	for _, pod := range pods {
		_ = p.scanPod(pod) // errors are logged, failed images are retried on the next run
	}

	for _, t := range p.Targets {
		targetImages, err := t.LoadImages()
		if err != nil {
			logrus.WithError(err).Error("Failed to load images from target")
			continue
		}

		removableImages := make([]*liboci.RegistryImage, 0)
		for _, t := range targetImages {
			if !containsImage(allImages, t.ImageID) {
				removableImages = append(removableImages, t)
				delete(p.imageMap, t.ImageID)
				logrus.Debugf("Image %s marked for removal", t.ImageID)
			}
		}

		if len(removableImages) > 0 {
			p.handleOrphanImages(t, removableImages)
		}
	}
}

// findPodsToScan returns the pods that have at least one container whose image
// is missing from any of the targets (one image list per target) and isn't
// annotated as processed. It also returns every image running in pods,
// deduplicated, which is what orphan detection compares the targets against.
func (p *Processor) findPodsToScan(pods []libk8s.PodInfo, targetImages [][]*liboci.RegistryImage) ([]libk8s.PodInfo, []*liboci.RegistryImage) {
	targetImageSets := make([]map[string]bool, 0, len(targetImages))
	for _, images := range targetImages {
		set := make(map[string]bool, len(images))
		for _, i := range images {
			set[i.ImageID] = true
		}
		targetImageSets = append(targetImageSets, set)
	}

	missingPods := make([]libk8s.PodInfo, 0)
	allImages := make([]*liboci.RegistryImage, 0)
	seenImages := make(map[string]bool)

	for _, info := range pods {
		needsAnalysis := false
		for _, c := range info.Containers {
			// every container counts as running, also those after the first one needing analysis
			if !seenImages[c.Image.ImageID] {
				seenImages[c.Image.ImageID] = true
				allImages = append(allImages, c.Image)
			}

			if needsAnalysis || p.K8s.HasAnnotation(info.Annotations, c) {
				continue
			}

			for _, set := range targetImageSets {
				if !set[c.Image.ImageID] {
					needsAnalysis = true
					break
				}
			}
		}

		if needsAnalysis {
			missingPods = append(missingPods, info)
			logrus.Debugf("Pod %s/%s needs to be analyzed", info.PodNamespace, info.PodName)
		}
	}

	return missingPods, allImages
}

func (p *Processor) executeJobImage(pods []libk8s.PodInfo) {
	jobClient := job.New(
		p.K8s,
		internal.OperatorConfig.JobImage,
		internal.OperatorConfig.JobImagePullSecret,
		internal.OperatorConfig.KubernetesClusterId,
		internal.OperatorConfig.JobTimeout)

	filteredPods := make([]libk8s.PodInfo, 0)
	for _, pod := range pods {
		filteredContainers := make([]*libk8s.ContainerInfo, 0)
		for _, container := range pod.Containers {
			if p.K8s.HasAnnotation(pod.Annotations, container) {
				logrus.Debugf("Skip image %s", container.Image.ImageID)
				continue
			}

			filteredContainers = append(filteredContainers, container)
		}

		if len(filteredContainers) > 0 {
			filteredPods = append(filteredPods, pod)
		}
	}

	j, err := jobClient.StartJob(filteredPods)
	if err != nil {
		// Already handled from job-module
		return
	}

	if jobClient.WaitForJob(j) {
		for _, pod := range filteredPods {
			p.K8s.UpdatePodAnnotation(pod, pod.Containers)
		}
	}
}

func getChangedContainers(oldPod, newPod libk8s.PodInfo) ([]*libk8s.ContainerInfo, []*libk8s.ContainerInfo) {
	addedContainers := make([]*libk8s.ContainerInfo, 0)
	removedContainers := make([]*libk8s.ContainerInfo, 0)
	for _, c := range newPod.Containers {
		if !containsContainerImage(oldPod.Containers, c.Image.ImageID) {
			addedContainers = append(addedContainers, c)
		}
	}

	for _, c := range oldPod.Containers {
		if !containsContainerImage(newPod.Containers, c.Image.ImageID) {
			removedContainers = append(removedContainers, c)
		}
	}

	return addedContainers, removedContainers
}

func containsImage(images []*liboci.RegistryImage, image string) bool {
	for _, i := range images {
		if i.ImageID == image {
			return true
		}
	}

	return false
}

func containsContainerImage(containers []*libk8s.ContainerInfo, image string) bool {
	for _, c := range containers {
		if c.Image.ImageID == image {
			return true
		}
	}

	return false
}

func (p *Processor) cleanupImagesIfNeeded(removedContainers []*libk8s.ContainerInfo, allPods []interface{}) {
	images := make([]*liboci.RegistryImage, 0)

	for _, c := range removedContainers {
		found := false
		for _, po := range allPods {
			pod := po.(*corev1.Pod)
			info := p.K8s.Client.ExtractPodInfos(*pod)
			found = found || containsContainerImage(info.Containers, c.Image.ImageID)
		}

		if !found {
			images = append(images, c.Image)
			delete(p.imageMap, c.Image.ImageID)
			logrus.Debugf("Image %s marked for removal", c.Image.ImageID)
		}
	}

	if len(images) > 0 {
		for _, t := range p.Targets {
			p.handleOrphanImages(t, images)
		}
	}
}

// handleOrphanImages dispatches orphan cleanup for a single target. Targets that
// implement DeactivateTarget and opt in via ShouldDeactivateOrphans have their
// orphans deactivated (rather than deleted) regardless of the global
// delete-orphan-images flag. All other targets follow delete-orphan-images.
func (p *Processor) handleOrphanImages(t target.Target, images []*liboci.RegistryImage) {
	if dt, ok := t.(target.DeactivateTarget); ok && dt.ShouldDeactivateOrphans() {
		if err := dt.Deactivate(images); err != nil {
			logrus.WithError(err).Error("Failed to deactivate images in target")
		}
		return
	}

	if internal.OperatorConfig.DeleteOrphanImages {
		if err := t.Remove(images); err != nil {
			logrus.WithError(err).Error("Failed to remove images from target")
		}
	}
}

func (p *Processor) runInformerAsync(informer cache.SharedIndexInformer) {
	stop := make(chan struct{})
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		run := true
		for run {
			sig := <-sigs
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				logrus.Infof("Received signal %s", sig)
				close(stop)
				run = false
			}
		}
	}()

	go func() {
		if !HasJobImage() {
			for _, t := range p.Targets {
				err := t.Initialize()
				if err != nil {
					logrus.WithError(err).Fatal("Target could not be initialized,")
				}
			}
		}

		logrus.Info("Start pod-informer")
		informer.Run(stop)
		logrus.Info("Pod-informer has stopped")
		os.Exit(0)
	}()

	go func() {
		if !HasJobImage() {
			logrus.Info("Wait for cache to be synced")
			if !cache.WaitForCacheSync(stop, informer.HasSynced) {
				logrus.Fatal("Timed out waiting for the cache to sync")
			}

			logrus.Info("Finished cache sync")
			pods := make([]libk8s.PodInfo, 0)
			for _, po := range informer.GetStore().List() {
				pod := po.(*corev1.Pod)

				// Filter by namespace if selector is configured
				if !p.isNamespaceAllowed(pod.Namespace) {
					logrus.Tracef("Skipping pod %s/%s during initial sync - namespace not in allowed list", pod.Namespace, pod.Name)
					continue
				}

				pods = append(pods, p.K8s.Client.ExtractPodInfos(*pod))
			}

			targetImages := make([][]*liboci.RegistryImage, 0, len(p.Targets))
			for _, t := range p.Targets {
				images, err := t.LoadImages()
				if err != nil {
					logrus.WithError(err).Error("Failed to load images from target")
					continue
				}
				targetImages = append(targetImages, images)
			}

			missingPods, allImages := p.findPodsToScan(pods, targetImages)
			if len(missingPods) > 0 {
				p.executeSyftScans(missingPods, allImages)
			}
		}
	}()
}
