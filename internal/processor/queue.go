package processor

import (
	"errors"
	"fmt"
	"time"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

// All scans, uploads and orphan removals in informer mode run as work items on
// a single worker. That keeps scans from overlapping (they share stereoscope's
// temp dirs) and keeps imageMap and the targets' state to one goroutine.
// Failed items are retried with exponential backoff.

type workKind int

const (
	// scan the unannotated containers of the pod with the given key
	workScanPod workKind = iota
	// remove the image from the targets if no pod runs it anymore
	workCleanupImage
	// compare the targets with the cluster after the informer's cache synced
	workInitialSync
)

type workItem struct {
	kind workKind
	// pod key (namespace/name) or image ID
	key string
	// image reference, for workCleanupImage
	image string
}

var (
	retryBaseDelay = 30 * time.Second
	retryMaxDelay  = time.Hour
)

func newWorkQueue() workqueue.TypedRateLimitingInterface[workItem] {
	return workqueue.NewTypedRateLimitingQueue(
		workqueue.NewTypedItemExponentialFailureRateLimiter[workItem](retryBaseDelay, retryMaxDelay))
}

func scanPodItem(namespace, name string) workItem {
	return workItem{kind: workScanPod, key: cache.NewObjectName(namespace, name).String()}
}

func cleanupImageItem(image *liboci.RegistryImage) workItem {
	return workItem{kind: workCleanupImage, key: image.ImageID, image: image.Image}
}

func (i workItem) String() string {
	switch i.kind {
	case workScanPod:
		return "scan of pod " + i.key
	case workCleanupImage:
		return "cleanup of image " + i.key
	case workInitialSync:
		return "initial sync"
	default:
		return fmt.Sprintf("work item %d/%s", i.kind, i.key)
	}
}

func (p *Processor) runWorker() {
	for p.processNextWorkItem() {
	}
}

func (p *Processor) processNextWorkItem() bool {
	item, shutdown := p.queue.Get()
	if shutdown {
		return false
	}
	defer p.queue.Done(item)

	err := p.handleWorkItem(item)
	if err == nil {
		p.queue.Forget(item)
		return true
	}

	attempt := p.queue.NumRequeues(item) + 1
	logrus.WithError(err).Warnf("The %s failed (attempt %d), will retry", item, attempt)
	p.queue.AddRateLimited(item)
	return true
}

func (p *Processor) handleWorkItem(item workItem) error {
	switch item.kind {
	case workScanPod:
		return p.scanPodByKey(item.key)
	case workCleanupImage:
		p.cleanupImageIfUnused(&liboci.RegistryImage{ImageID: item.key, Image: item.image})
		return nil
	case workInitialSync:
		return p.initialSync()
	default:
		return fmt.Errorf("unknown work item kind %d", item.kind)
	}
}

// scanPodByKey scans the current state of the pod in the informer's store. A
// pod that is gone, or now in a namespace that isn't allowed, is skipped.
func (p *Processor) scanPodByKey(key string) error {
	obj, exists, err := p.podStore.GetByKey(key)
	if err != nil {
		return err
	}
	if !exists {
		logrus.Debugf("Pod %s is gone, skip scan", key)
		return nil
	}

	pod := obj.(*corev1.Pod)
	if !p.isNamespaceAllowed(pod.Namespace) {
		logrus.Tracef("Skipping pod %s - namespace not in allowed list", key)
		return nil
	}

	return p.scanPod(p.K8s.Client.ExtractPodInfos(*pod))
}

// allowedPods returns the pods in the informer's store, without those in
// namespaces that aren't allowed.
func (p *Processor) allowedPods() []libk8s.PodInfo {
	pods := make([]libk8s.PodInfo, 0)
	for _, po := range p.podStore.List() {
		pod := po.(*corev1.Pod)

		// Filter by namespace if selector is configured
		if !p.isNamespaceAllowed(pod.Namespace) {
			logrus.Tracef("Skipping pod %s/%s during initial sync - namespace not in allowed list", pod.Namespace, pod.Name)
			continue
		}

		pods = append(pods, p.K8s.Client.ExtractPodInfos(*pod))
	}

	return pods
}

// initialSync queues every pod with an image missing from a target, and
// removes the targets' images that no pod runs anymore. It fails (and is
// retried) if a target's images couldn't be loaded; the other targets are
// still synced.
func (p *Processor) initialSync() error {
	pods := p.allowedPods()

	var loadErrs []error
	loadedTargets := make([]int, 0, len(p.Targets))
	targetImages := make([][]*liboci.RegistryImage, 0, len(p.Targets))
	for i, t := range p.Targets {
		images, err := t.LoadImages()
		if err != nil {
			logrus.WithError(err).Error("Failed to load images from target")
			loadErrs = append(loadErrs, err)
			continue
		}
		loadedTargets = append(loadedTargets, i)
		targetImages = append(targetImages, images)
	}

	missingPods, allImages := p.findPodsToScan(pods, targetImages)
	for _, pod := range missingPods {
		p.queue.Add(scanPodItem(pod.PodNamespace, pod.PodName))
	}

	for i, t := range loadedTargets {
		p.removeOrphans(p.Targets[t], targetImages[i], allImages)
	}

	if len(loadErrs) > 0 {
		return fmt.Errorf("could not load images of %d target(s): %w", len(loadErrs), errors.Join(loadErrs...))
	}

	return nil
}

// cleanupImageIfUnused removes image from all targets, unless a pod in the
// informer's store still runs it.
func (p *Processor) cleanupImageIfUnused(image *liboci.RegistryImage) {
	for _, po := range p.podStore.List() {
		info := p.K8s.Client.ExtractPodInfos(*po.(*corev1.Pod))
		if containsContainerImage(info.Containers, image.ImageID) {
			return
		}
	}

	delete(p.imageMap, image.ImageID)
	logrus.Debugf("Image %s marked for removal", image.ImageID)
	for _, t := range p.Targets {
		p.handleOrphanImages(t, []*liboci.RegistryImage{image})
	}
}
