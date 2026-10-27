package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	"github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/libk8soci/pkg/util"
)

type KubeClient struct {
	Client             *libk8s.KubeClient
	ignoreAnnotations  bool
	fallbackPullSecret []*oci.KubeCreds
}

var (
	AnnotationTemplate = "ckotzbauer.sbom-operator.io/%s"
	/* #nosec */
	jobSecretName       = "sbom-operator-job-config"
	JobName             = "sbom-operator-job"
	updatePodMaxRetries = 3
)

func NewClient(ignoreAnnotations bool, fallbackPullSecretName string) *KubeClient {
	client := libk8s.NewClient()

	sbomOperatorNamespace := os.Getenv("POD_NAMESPACE")
	fallbackPullSecret := loadFallbackPullSecret(client, sbomOperatorNamespace, fallbackPullSecretName)
	return &KubeClient{Client: client, ignoreAnnotations: ignoreAnnotations, fallbackPullSecret: fallbackPullSecret}
}

func (client *KubeClient) StartPodInformer(podLabelSelector string, handler cache.ResourceEventHandlerFuncs) (cache.SharedIndexInformer, error) {
	informer := client.Client.CreatePodInformer(podLabelSelector)
	_, err := informer.AddEventHandler(handler)
	if err != nil {
		return nil, err
	}

	err = informer.SetTransform(transformPod)
	return informer, err
}

// transformPod strips the pod down to what the operator uses. Of the spec,
// that's the pull secrets and each container's name and image (see
// ExtractPodInfos).
func transformPod(x interface{}) (interface{}, error) {
	pod := x.(*corev1.Pod).DeepCopy()
	logrus.Tracef("Transform %s/%s", pod.Namespace, pod.Name)

	spec := corev1.PodSpec{ImagePullSecrets: pod.Spec.ImagePullSecrets}
	for _, c := range pod.Spec.Containers {
		spec.Containers = append(spec.Containers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range pod.Spec.InitContainers {
		spec.InitContainers = append(spec.InitContainers, corev1.Container{Name: c.Name, Image: c.Image})
	}
	for _, c := range pod.Spec.EphemeralContainers {
		spec.EphemeralContainers = append(spec.EphemeralContainers, corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: c.Name, Image: c.Image},
		})
	}

	return &corev1.Pod{
			ObjectMeta: meta.ObjectMeta{
				Name:        pod.Name,
				Namespace:   pod.Namespace,
				Annotations: pod.Annotations,
				Labels:      pod.Labels,
			},
			Status: corev1.PodStatus{
				InitContainerStatuses:      pod.Status.InitContainerStatuses,
				EphemeralContainerStatuses: pod.Status.EphemeralContainerStatuses,
				ContainerStatuses:          pod.Status.ContainerStatuses,
			},
			Spec: spec,
		},
		nil
}

// ExtractPodInfos wraps libk8soci's ExtractPodInfos, which takes each
// container's image from its status. For an image pinned as name:tag@digest,
// containerd reports the status image as the bare config digest, so the tag
// (used e.g. as the Dependency-Track project version) is lost. In that case
// the image is taken from the pod spec instead. Images are always pulled by
// the image ID, so that's unaffected.
func (client *KubeClient) ExtractPodInfos(pod corev1.Pod) libk8s.PodInfo {
	info := client.Client.ExtractPodInfos(pod)

	specImages := make(map[string]string)
	for _, c := range pod.Spec.Containers {
		specImages[c.Name] = c.Image
	}
	for _, c := range pod.Spec.InitContainers {
		specImages[c.Name] = c.Image
	}
	for _, c := range pod.Spec.EphemeralContainers {
		specImages[c.Name] = c.Image
	}

	for _, c := range info.Containers {
		if _, err := v1.NewHash(c.Image.Image); err != nil {
			continue
		}
		if specImage := specImages[c.Name]; specImage != "" {
			c.Image.Image = specImage
		}
	}

	return info
}

func (client *KubeClient) StartNamespaceInformer(namespaceLabelSelector string, handler cache.ResourceEventHandlerFuncs) (cache.SharedIndexInformer, error) {
	// Create a namespace informer manually using the client-go library
	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options meta.ListOptions) (runtime.Object, error) {
				options.LabelSelector = namespaceLabelSelector
				return client.Client.Client.CoreV1().Namespaces().List(context.Background(), options)
			},
			WatchFunc: func(options meta.ListOptions) (watch.Interface, error) {
				options.LabelSelector = namespaceLabelSelector
				return client.Client.Client.CoreV1().Namespaces().Watch(context.Background(), options)
			},
		},
		&corev1.Namespace{},
		0, // No resync period
		cache.Indexers{},
	)

	_, err := informer.AddEventHandler(handler)
	if err != nil {
		return nil, err
	}

	err = informer.SetTransform(func(x interface{}) (interface{}, error) {
		ns := x.(*corev1.Namespace).DeepCopy()
		logrus.Tracef("Transform namespace %s", ns.Name)

		return &corev1.Namespace{
				ObjectMeta: meta.ObjectMeta{
					Name:   ns.Name,
					Labels: ns.Labels,
				},
			},
			nil
	})

	return informer, err
}

func loadFallbackPullSecret(client *libk8s.KubeClient, namespace, name string) []*oci.KubeCreds {
	var fallbackPullSecret []*oci.KubeCreds

	if name != "" {
		if namespace == "" {
			logrus.Debugf("please specify the environment variable 'POD_NAMESPACE' in order to use the fallbackPullSecret")
		} else {
			fallbackPullSecret = client.LoadSecrets(namespace, []corev1.LocalObjectReference{{Name: name}})
		}
	}

	return fallbackPullSecret
}

// LoadPullSecrets returns the pull secrets of all given pods, loading each
// secret once, followed by the fallback pull secret.
func (client *KubeClient) LoadPullSecrets(pods []libk8s.PodInfo) []*oci.KubeCreds {
	secrets := make([]*oci.KubeCreds, 0)
	loaded := make(map[string]bool)
	for _, pod := range pods {
		for _, ref := range pod.PullSecretNames {
			key := pod.PodNamespace + "/" + ref.Name
			if loaded[key] {
				continue
			}
			loaded[key] = true
			secrets = append(secrets, client.Client.LoadSecrets(pod.PodNamespace, []corev1.LocalObjectReference{ref})...)
		}
	}

	return append(secrets, client.fallbackPullSecret...)
}

// loadPodInfos is libk8soci's LoadPodInfos, with ExtractPodInfos from above.
func (client *KubeClient) loadPodInfos(namespaces []corev1.Namespace, podLabelSelector string) []libk8s.PodInfo {
	podInfos := []libk8s.PodInfo{}
	options := meta.ListOptions{LabelSelector: util.Unescape(podLabelSelector)}
	for _, ns := range namespaces {
		pods, err := client.Client.Client.CoreV1().Pods(ns.Name).List(context.Background(), options)
		if err != nil {
			logrus.WithError(err).Errorf("failed to list pods for namespace: %s", ns.Name)
			continue
		}

		for _, pod := range pods.Items {
			podInfos = append(podInfos, client.ExtractPodInfos(pod))
		}
	}

	return podInfos
}

func (client *KubeClient) LoadImageInfos(namespaces []corev1.Namespace, podLabelSelector string) ([]libk8s.PodInfo, []*oci.RegistryImage) {
	podInfos := client.loadPodInfos(namespaces, podLabelSelector)
	allImages := make([]*oci.RegistryImage, 0)

	for _, pod := range podInfos {
		for _, container := range pod.Containers {
			allImages = append(allImages, container.Image)
		}
	}

	return podInfos, allImages
}

// UpdatePodAnnotation records the given containers of pod as processed, each
// with the image ID it was processed with. Other containers keep their
// annotations, if any.
func (client *KubeClient) UpdatePodAnnotation(pod libk8s.PodInfo, containers []*libk8s.ContainerInfo) {
	if len(containers) == 0 {
		return
	}

	for i := 0; i < updatePodMaxRetries; i++ {
		err := client.updatePodAnnotation(pod, containers)
		if err == nil {
			break
		}

		logrus.WithError(err).Warnf("Failed to update annotation for pod %s/%s!", pod.PodNamespace, pod.PodName)
	}
}

func (client *KubeClient) updatePodAnnotation(pod libk8s.PodInfo, containers []*libk8s.ContainerInfo) error {
	newPod, err := client.Client.Client.CoreV1().Pods(pod.PodNamespace).Get(context.Background(), pod.PodName, meta.GetOptions{})
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("pod could not be fetched: %w", err)
		}

		return nil
	}

	newPod.Annotations = withContainerAnnotations(newPod.Annotations, containers)

	_, err = client.Client.Client.CoreV1().Pods(newPod.Namespace).Update(context.Background(), newPod, meta.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("pod could not be updated: %w", err)
	}

	return nil
}

// withContainerAnnotations returns annotations with an entry per container,
// set to the container's (normalised) image ID.
func withContainerAnnotations(annotations map[string]string, containers []*libk8s.ContainerInfo) map[string]string {
	if annotations == nil {
		annotations = make(map[string]string)
	}

	for _, c := range containers {
		annotations[fmt.Sprintf(AnnotationTemplate, c.Name)] = c.Image.ImageID
	}

	return annotations
}

func (client *KubeClient) HasAnnotation(annotations map[string]string, container *libk8s.ContainerInfo) bool {
	if annotations == nil || client.ignoreAnnotations {
		return false
	}

	if val, ok := annotations[fmt.Sprintf(AnnotationTemplate, container.Name)]; ok {
		return normaliseImageID(val) == container.Image.ImageID
	}

	return false
}

// normaliseImageID strips the runtime prefix (e.g. "docker-pullable://") from
// an image ID, as libk8soci's ExtractPodInfos does. Older versions annotated
// pods with the raw status value.
func normaliseImageID(imageID string) string {
	parts := strings.Split(imageID, "://")
	return parts[len(parts)-1]
}

func (client *KubeClient) CreateJobSecret(namespace, suffix string, data []byte) error {
	m := make(map[string][]byte)
	m["image-config.json"] = data
	vTrue := true
	vFalse := false

	s := &corev1.Secret{
		ObjectMeta: meta.ObjectMeta{
			Namespace: namespace,
			Name:      fmt.Sprintf("%s-%s", jobSecretName, suffix),
			OwnerReferences: []meta.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               os.Getenv("POD_NAME"),
					UID:                types.UID(os.Getenv("POD_UID")),
					BlockOwnerDeletion: &vTrue,
					Controller:         &vFalse,
				},
			},
		},
		Data: m,
	}

	_, err := client.Client.Client.CoreV1().Secrets(namespace).Create(context.Background(), s, meta.CreateOptions{})
	return err
}

func (client *KubeClient) CreateJob(namespace, suffix, image, pullSecrets string, timeout int64, envs map[string]string) (*batchv1.Job, error) {
	backoffLimit := int32(0)
	vTrue := true
	vFalse := false

	j := &batchv1.Job{
		ObjectMeta: meta.ObjectMeta{
			Namespace: namespace,
			Name:      fmt.Sprintf("%s-%s", JobName, suffix),
			OwnerReferences: []meta.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               os.Getenv("POD_NAME"),
					UID:                types.UID(os.Getenv("POD_UID")),
					BlockOwnerDeletion: &vTrue,
					Controller:         &vFalse,
				},
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:          &backoffLimit,
			ActiveDeadlineSeconds: &timeout,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: meta.ObjectMeta{
					Name: JobName,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "sbom",
							Image: image,
							Env:   mapToEnvVars(envs),
							SecurityContext: &corev1.SecurityContext{
								Privileged: &vTrue,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config",
									MountPath: "/sbom",
								},
							},
						},
					},
					RestartPolicy:    corev1.RestartPolicyNever,
					ImagePullSecrets: createPullSecrets(pullSecrets),
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: fmt.Sprintf("%s-%s", jobSecretName, suffix),
								},
							},
						},
					},
				},
			},
		},
	}

	return client.Client.Client.BatchV1().Jobs(namespace).Create(context.Background(), j, meta.CreateOptions{})
}

func createPullSecrets(name string) []corev1.LocalObjectReference {
	refs := make([]corev1.LocalObjectReference, 0)

	if name != "" {
		refs = append(refs, corev1.LocalObjectReference{Name: name})
	}

	return refs
}

func mapToEnvVars(m map[string]string) []corev1.EnvVar {
	vars := make([]corev1.EnvVar, 0)
	for k, v := range m {
		vars = append(vars, corev1.EnvVar{Name: k, Value: v})
	}

	return vars
}

func (client *KubeClient) CreateConfigMap(namespace, name, imageId string, data []byte) error {
	cm := corev1.ConfigMap{
		ObjectMeta: meta.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"ckotzbauer.sbom-operator.io": "true",
			},
			Annotations: map[string]string{
				fmt.Sprintf(AnnotationTemplate, "image-id"): imageId,
			},
		},
		BinaryData: map[string][]byte{"sbom": data},
	}

	_, err := client.Client.Client.CoreV1().ConfigMaps(namespace).Create(context.Background(), &cm, meta.CreateOptions{})
	return err
}

func (client *KubeClient) ListConfigMaps() ([]corev1.ConfigMap, error) {
	list, err := client.Client.Client.CoreV1().ConfigMaps("").List(context.Background(), meta.ListOptions{LabelSelector: "ckotzbauer.sbom-operator.io=true"})
	return list.Items, err
}

func (client *KubeClient) DeleteConfigMap(cm corev1.ConfigMap) error {
	return client.Client.Client.CoreV1().ConfigMaps(cm.Namespace).Delete(context.Background(), cm.Name, meta.DeleteOptions{})
}
