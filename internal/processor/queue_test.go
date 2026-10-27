package processor

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	libk8s "github.com/ckotzbauer/libk8soci/pkg/kubernetes"
	liboci "github.com/ckotzbauer/libk8soci/pkg/oci"
	"github.com/ckotzbauer/sbom-operator/internal"
	"github.com/ckotzbauer/sbom-operator/internal/kubernetes"
	"github.com/ckotzbauer/sbom-operator/internal/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// fakeAPIServer serves GET and PUT for pods, which is all UpdatePodAnnotation
// needs.
type fakeAPIServer struct {
	mu   sync.Mutex
	pods map[string]*corev1.Pod
}

func (f *fakeAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /api/v1/namespaces/<ns>/pods/<name>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/"), "/")
	if len(parts) != 3 || parts[1] != "pods" {
		http.NotFound(w, r)
		return
	}
	key := parts[0] + "/" + parts[2]

	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method {
	case http.MethodGet:
		pod, ok := f.pods[key]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(meta.Status{Status: meta.StatusFailure, Reason: meta.StatusReasonNotFound, Code: http.StatusNotFound})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pod)
	case http.MethodPut:
		pod := &corev1.Pod{}
		if err := json.NewDecoder(r.Body).Decode(pod); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.pods[key] = pod
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pod)
	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func (f *fakeAPIServer) annotations(key string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pods[key].Annotations
}

// newPod returns a pod with a container per name/image ID pair.
func newPod(namespace, name string, containerImages ...string) *corev1.Pod {
	pod := &corev1.Pod{ObjectMeta: meta.ObjectMeta{Namespace: namespace, Name: name}}
	for i := 0; i+1 < len(containerImages); i += 2 {
		pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses, corev1.ContainerStatus{Name: containerImages[i], Image: containerImages[i+1], ImageID: containerImages[i+1]})
	}
	return pod
}

// newQueueProcessor returns a processor in informer mode, backed by a fake API
// server and an informer store with the given pods.
func newQueueProcessor(t *testing.T, gen SbomGenerator, targets []target.Target, pods ...*corev1.Pod) (*Processor, *fakeAPIServer, cache.Store) {
	t.Helper()

	retryBaseDelay, retryMaxDelay = 20*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { retryBaseDelay, retryMaxDelay = 30*time.Second, time.Hour })

	api := &fakeAPIServer{pods: map[string]*corev1.Pod{}}
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, pod := range pods {
		api.pods[pod.Namespace+"/"+pod.Name] = pod.DeepCopy()
		require.NoError(t, store.Add(pod))
	}

	ts := httptest.NewServer(api)
	t.Cleanup(ts.Close)
	cs, err := k8sclient.NewForConfig(&rest.Config{Host: ts.URL, ContentConfig: rest.ContentConfig{ContentType: "application/json"}})
	require.NoError(t, err)

	p := &Processor{
		K8s:               &kubernetes.KubeClient{Client: &libk8s.KubeClient{Client: cs}},
		sy:                gen,
		Targets:           targets,
		imageMap:          map[string]bool{},
		allowedNamespaces: map[string]bool{},
		queue:             newWorkQueue(),
		podStore:          store,
	}
	t.Cleanup(p.queue.ShutDown)
	return p, api, store
}

// processQueued processes items until the queue is empty. Rate-limited
// retries aren't waited for.
func processQueued(t *testing.T, p *Processor) {
	t.Helper()
	for p.queue.Len() > 0 {
		p.processNextWorkItem()
	}
}

func waitForRetry(t *testing.T, p *Processor) {
	t.Helper()
	require.Eventually(t, func() bool { return p.queue.Len() > 0 }, time.Second, time.Millisecond, "expected a retry to be queued")
}

func TestInitialSyncScansMissingImagesAndRemovesOrphans(t *testing.T) {
	internal.OperatorConfig = &internal.Config{DeleteOrphanImages: true}

	mysql := newPod("db", "mysql-0", "mysql", "mysql@sha256:1", "pmm-agent", "pmm-client@sha256:2")
	gen := &fakeGenerator{fail: map[string]bool{"mysql@sha256:1": true}}
	ta := &fakeTarget{images: images("pmm-client@sha256:2", "old@sha256:9")}
	p, api, _ := newQueueProcessor(t, gen, []target.Target{ta}, mysql)

	p.queue.Add(workItem{kind: workInitialSync})
	p.processNextWorkItem()

	// the sidecar's image is running, only the stale image is an orphan
	assert.Equal(t, []string{"old@sha256:9"}, ta.removed)
	require.Equal(t, 1, p.queue.Len(), "only the image missing from the target is queued")

	// the mysql scan fails (e.g. rate limited)
	processQueued(t, p)
	assert.Empty(t, api.annotations("db/mysql-0"))
	assert.Equal(t, 1, p.queue.NumRequeues(scanImageItem("mysql@sha256:1")))

	// the retry succeeds once the registry recovers
	gen.fail = nil
	waitForRetry(t, p)
	processQueued(t, p)
	assert.Equal(t, map[string]string{"ckotzbauer.sbom-operator.io/mysql": "mysql@sha256:1"}, api.annotations("db/mysql-0"))
	assert.Equal(t, 0, p.queue.NumRequeues(scanImageItem("mysql@sha256:1")))
	assert.Equal(t, []string{"mysql@sha256:1", "mysql@sha256:1"}, gen.scanned)
}

func TestFailingImageIsRetriedOnceForAllPods(t *testing.T) {
	internal.OperatorConfig = &internal.Config{}

	pods := []*corev1.Pod{
		newPod("redpanda", "redpanda-0", "redpanda", "redpanda@sha256:1", "sidecar", "sidecar@sha256:2"),
		newPod("redpanda", "redpanda-1", "redpanda", "redpanda@sha256:1"),
		newPod("redpanda", "redpanda-2", "redpanda", "redpanda@sha256:1"),
	}
	gen := &fakeGenerator{fail: map[string]bool{"redpanda@sha256:1": true}}
	ta := &fakeTarget{}
	p, api, _ := newQueueProcessor(t, gen, []target.Target{ta}, pods...)

	p.queue.Add(workItem{kind: workInitialSync})
	p.processNextWorkItem()
	require.Equal(t, 2, p.queue.Len(), "one item per image, not per pod")

	processQueued(t, p)
	assert.Equal(t, []string{"redpanda@sha256:1", "sidecar@sha256:2"}, gen.scanned, "the failing image is fetched once, not once per pod")
	assert.Equal(t, 1, p.queue.NumRequeues(scanImageItem("redpanda@sha256:1")))
	assert.Equal(t, map[string]string{"ckotzbauer.sbom-operator.io/sidecar": "sidecar@sha256:2"}, api.annotations("redpanda/redpanda-0"))

	// a new pod with the image doesn't bypass the backoff
	p.queueScan("redpanda@sha256:1")
	assert.Equal(t, 0, p.queue.Len())

	gen.fail = nil
	waitForRetry(t, p)
	processQueued(t, p)
	assert.Equal(t, []string{"redpanda@sha256:1", "sidecar@sha256:2", "redpanda@sha256:1"}, gen.scanned)
	assert.Len(t, ta.received, 2, "the SBOM is uploaded once")
	for _, name := range []string{"redpanda-0", "redpanda-1", "redpanda-2"} {
		assert.Equal(t, "redpanda@sha256:1", api.annotations("redpanda/" + name)["ckotzbauer.sbom-operator.io/redpanda"], "every pod waiting for the image is annotated")
	}
}

func TestTargetFailureIsRetried(t *testing.T) {
	internal.OperatorConfig = &internal.Config{}

	pod := newPod("default", "app", "app", "app@sha256:1")
	ta := &fakeTarget{fail: map[string]bool{"app@sha256:1": true}}
	p, api, _ := newQueueProcessor(t, &fakeGenerator{}, []target.Target{ta}, pod)

	p.queue.Add(scanImageItem("app@sha256:1"))
	processQueued(t, p)
	assert.Empty(t, api.annotations("default/app"))
	assert.False(t, p.imageMap["app@sha256:1"])

	ta.fail = nil
	waitForRetry(t, p)
	processQueued(t, p)
	assert.Equal(t, map[string]string{"ckotzbauer.sbom-operator.io/app": "app@sha256:1"}, api.annotations("default/app"))
	assert.Len(t, ta.received, 1)
}

func TestInitialSyncIsRetriedWhenATargetCantLoad(t *testing.T) {
	internal.OperatorConfig = &internal.Config{DeleteOrphanImages: true}

	pod := newPod("default", "app", "app", "app@sha256:1")
	ok := &fakeTarget{images: images("app@sha256:1", "old@sha256:9")}
	down := &fakeTarget{loadErr: errors.New("connection refused")}
	p, _, _ := newQueueProcessor(t, &fakeGenerator{}, []target.Target{ok, down}, pod)

	p.queue.Add(workItem{kind: workInitialSync})
	p.processNextWorkItem()
	assert.Equal(t, []string{"old@sha256:9"}, ok.removed, "the reachable target is still synced")
	assert.Equal(t, 0, p.queue.Len(), "nothing is missing from the reachable target")
	assert.Equal(t, 1, p.queue.NumRequeues(workItem{kind: workInitialSync}))

	down.loadErr = nil
	waitForRetry(t, p)
	p.processNextWorkItem()
	require.Equal(t, 1, p.queue.Len(), "the image is missing from the recovered target")
	processQueued(t, p)
	assert.Len(t, down.received, 1)
}

func TestScanOfDeletedPodIsSkipped(t *testing.T) {
	internal.OperatorConfig = &internal.Config{}

	pod := newPod("default", "app", "app", "app@sha256:1")
	gen := &fakeGenerator{}
	p, _, store := newQueueProcessor(t, gen, []target.Target{&fakeTarget{}}, pod)

	p.queue.Add(scanImageItem("app@sha256:1"))
	require.NoError(t, store.Delete(pod))
	processQueued(t, p)
	assert.Empty(t, gen.scanned)
	assert.Equal(t, 0, p.queue.NumRequeues(scanImageItem("app@sha256:1")))
}

func TestCleanupImageIfUnused(t *testing.T) {
	internal.OperatorConfig = &internal.Config{DeleteOrphanImages: true}

	stillRunning := newPod("default", "other", "app", "app@sha256:1")
	ta := &fakeTarget{}
	p, _, store := newQueueProcessor(t, &fakeGenerator{}, []target.Target{ta}, stillRunning)
	p.imageMap["app@sha256:1"] = true
	p.imageMap["gone@sha256:2"] = true

	p.queue.Add(cleanupImageItem(&liboci.RegistryImage{ImageID: "app@sha256:1"}))
	p.queue.Add(cleanupImageItem(&liboci.RegistryImage{ImageID: "gone@sha256:2"}))
	processQueued(t, p)
	assert.Equal(t, []string{"gone@sha256:2"}, ta.removed)
	assert.Equal(t, map[string]bool{"app@sha256:1": true}, p.imageMap)

	require.NoError(t, store.Delete(stillRunning))
	p.queue.Add(cleanupImageItem(&liboci.RegistryImage{ImageID: "app@sha256:1"}))
	processQueued(t, p)
	assert.Equal(t, []string{"gone@sha256:2", "app@sha256:1"}, ta.removed)
}

func TestOrphanImages(t *testing.T) {
	orphans := orphanImages(images("a", "b", "c"), images("b", "d"))
	ids := make([]string, 0)
	for _, i := range orphans {
		ids = append(ids, i.ImageID)
	}
	assert.Equal(t, []string{"a", "c"}, ids)
}
