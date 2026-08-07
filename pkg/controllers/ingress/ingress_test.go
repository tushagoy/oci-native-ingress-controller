package ingress

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/events"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/oracle/oci-go-sdk/v65/common"
	ociloadbalancer "github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-native-ingress-controller/pkg/certificate"
	"github.com/oracle/oci-native-ingress-controller/pkg/client"
	lb "github.com/oracle/oci-native-ingress-controller/pkg/loadbalancer"
	ociclient "github.com/oracle/oci-native-ingress-controller/pkg/oci/client"
	"github.com/oracle/oci-native-ingress-controller/pkg/state"
	"github.com/oracle/oci-native-ingress-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/informers"
	networkinginformers "k8s.io/client-go/informers/networking/v1"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	corelisters "k8s.io/client-go/listers/core/v1"

	"k8s.io/client-go/tools/cache"
)

const (
	ingressPath              = "ingressPath.yaml"
	ingressPathWithFinalizer = "ingressPathWithFinalizer.yaml"
	ingressPathWithTlsSecret = "ingressPathWithTlsSecret.yaml"
	multiCertificateWarning  = "OCI Load Balancer multi-certificate listeners may not be supported in this tenancy or region; verify enablement or use one certificate"
)

func setUp(ctx context.Context, ingressClassList *networkingv1.IngressClassList, ingressList *networkingv1.IngressList, testService *v1.ServiceList) (networkinginformers.IngressClassInformer, networkinginformers.IngressInformer, coreinformers.ServiceAccountInformer, corelisters.ServiceLister, coreinformers.SecretInformer, *fakeclientset.Clientset) {
	fakeClient := fakeclientset.NewSimpleClientset()
	action := "list"

	util.UpdateFakeClientCall(fakeClient, action, "ingressclasses", ingressClassList)
	util.UpdateFakeClientCall(fakeClient, action, "ingresses", ingressList)
	util.UpdateFakeClientCall(fakeClient, "get", "ingresses", &ingressList.Items[0])
	util.UpdateFakeClientCall(fakeClient, "update", "ingresses", &ingressList.Items[0])
	util.UpdateFakeClientCall(fakeClient, "patch", "ingresses", &ingressList.Items[0])
	util.UpdateFakeClientCall(fakeClient, action, "services", testService)

	informerFactory := informers.NewSharedInformerFactory(fakeClient, 0)
	ingressClassInformer := informerFactory.Networking().V1().IngressClasses()
	ingressClassInformer.Lister()

	ingressInformer := informerFactory.Networking().V1().Ingresses()
	ingressInformer.Lister()

	serviceInformer := informerFactory.Core().V1().Services()
	serviceLister := serviceInformer.Lister()

	secretInformer := informerFactory.Core().V1().Secrets()
	secretInformer.Lister()

	saInformer := informerFactory.Core().V1().ServiceAccounts()

	informerFactory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), ingressClassInformer.Informer().HasSynced)
	cache.WaitForCacheSync(ctx.Done(), ingressInformer.Informer().HasSynced)
	cache.WaitForCacheSync(ctx.Done(), secretInformer.Informer().HasSynced)
	return ingressClassInformer, ingressInformer, saInformer, serviceLister, secretInformer, fakeClient
}

func inits(ctx context.Context, ingressClassList *networkingv1.IngressClassList, ingressList *networkingv1.IngressList) *Controller {

	testService := util.GetServiceListResource(namespace, "testecho1", 80)
	lbClient := GetLoadBalancerClient()
	certClient := GetCertClient()
	certManageClient := GetCertManageClient()

	loadBalancerClient := &lb.LoadBalancerClient{
		LbClient: lbClient,
		Mu:       sync.Mutex{},
		Cache:    map[string]*lb.LbCacheObj{},
	}

	certificatesClient := &certificate.CertificatesClient{
		ManagementClient:   certManageClient,
		CertificatesClient: certClient,
		CertCache:          map[string]*ociclient.CertCacheObj{},
		CaBundleCache:      map[string]*ociclient.CaBundleCacheObj{},
	}

	ingressClassInformer, ingressInformer, saInformer, serviceLister, secretInformer, k8client := setUp(ctx, ingressClassList, ingressList, testService)
	wrapperClient := client.NewWrapperClient(k8client, nil, loadBalancerClient, certificatesClient, nil)
	fakeClient := &client.ClientProvider{
		K8sClient:           k8client,
		DefaultConfigGetter: &MockConfigGetter{},
		Cache:               NewMockCacheStore(wrapperClient),
	}
	fakeRecorder := events.NewFakeRecorder(10)
	c := NewController("oci.oraclecloud.com/native-ingress-controller", "", ingressClassInformer,
		ingressInformer, saInformer, serviceLister, secretInformer, fakeClient, nil, nil, false, fakeRecorder)
	return c
}

// Helper to build controller with a custom LB client to simulate edge cases
func initsWithCustomLB(ctx context.Context, ingressClassList *networkingv1.IngressClassList, ingressList *networkingv1.IngressList, lbIface ociclient.LoadBalancerInterface) *Controller {
	testService := util.GetServiceListResource(namespace, "testecho1", 80)
	certClient := GetCertClient()
	certManageClient := GetCertManageClient()

	loadBalancerClient := &lb.LoadBalancerClient{
		LbClient: lbIface,
		Mu:       sync.Mutex{},
		Cache:    map[string]*lb.LbCacheObj{},
	}

	certificatesClient := &certificate.CertificatesClient{
		ManagementClient:   certManageClient,
		CertificatesClient: certClient,
		CertCache:          map[string]*ociclient.CertCacheObj{},
		CaBundleCache:      map[string]*ociclient.CaBundleCacheObj{},
	}

	ingressClassInformer, ingressInformer, saInformer, serviceLister, secretInformer, k8client := setUp(ctx, ingressClassList, ingressList, testService)
	wrapperClient := client.NewWrapperClient(k8client, nil, loadBalancerClient, certificatesClient, nil)
	fakeClient := &client.ClientProvider{
		K8sClient:           k8client,
		DefaultConfigGetter: &MockConfigGetter{},
		Cache:               NewMockCacheStore(wrapperClient),
	}
	fakeRecorder := events.NewFakeRecorder(10)
	return NewController("oci.oraclecloud.com/native-ingress-controller", "", ingressClassInformer,
		ingressInformer, saInformer, serviceLister, secretInformer, fakeClient, nil, nil, false, fakeRecorder)
}

func drainControllerQueue(c *Controller) {
	for c.queue.Len() > 0 {
		item, shutdown := c.queue.Get()
		if shutdown {
			return
		}
		c.queue.Done(item)
	}
}

// Mock that returns a listener with nil Protocol
type MockLoadBalancerClientNilProtocol struct{ MockLoadBalancerClient }

func (m MockLoadBalancerClientNilProtocol) GetLoadBalancer(ctx context.Context, request ociloadbalancer.GetLoadBalancerRequest) (ociloadbalancer.GetLoadBalancerResponse, error) {
	res := util.SampleLoadBalancerResponse()
	for k, l := range res.LoadBalancer.Listeners {
		lCopy := l
		lCopy.Protocol = nil
		res.LoadBalancer.Listeners[k] = lCopy
		break
	}
	return res, nil
}

// Mock that returns a listener with nil DefaultBackendSetName
type MockLoadBalancerClientNilDefaultBS struct{ MockLoadBalancerClient }

func (m MockLoadBalancerClientNilDefaultBS) GetLoadBalancer(ctx context.Context, request ociloadbalancer.GetLoadBalancerRequest) (ociloadbalancer.GetLoadBalancerResponse, error) {
	res := util.SampleLoadBalancerResponse()
	for k, l := range res.LoadBalancer.Listeners {
		lCopy := l
		lCopy.DefaultBackendSetName = nil
		res.LoadBalancer.Listeners[k] = lCopy
		break
	}
	return res, nil
}

func TestEnsureIngress_NilListenerProtocol_DoesNotPanic(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPath)

	c := initsWithCustomLB(ctx, ingressClassList, ingressList, MockLoadBalancerClientNilProtocol{})
	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
}

func TestEnsureIngress_NilDefaultBackendSet_DoesNotPanic(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPath)

	c := initsWithCustomLB(ctx, ingressClassList, ingressList, MockLoadBalancerClientNilDefaultBS{})
	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
}

func TestSync(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPath)
	c := inits(ctx, ingressClassList, ingressList)
	err := c.sync("default/ingress-readiness")

	Expect(err == nil).Should(Equal(false))
	Expect(err.Error()).Should(Equal("ingress class not ready"))
}

func TestEnsureIngressSuccess(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPath)
	c := inits(ctx, ingressClassList, ingressList)
	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err == nil).Should(Equal(true))
}

func TestEnsureIngress_CreateListenerWithMultipleCertificateIds(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("certA,certB")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort: 443,
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
	Expect(len(capturingLB.CreateListenerRequests)).Should(Equal(1))
	Expect(capturingLB.CreateListenerRequests[0].CreateListenerDetails.SslConfiguration.CertificateIds).Should(Equal([]string{"certA", "certB"}))
}

func TestEnsureIngress_UpdateListenerSingleToMultiCertificateIds(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("certA,certB")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort:           80,
		ExistingCertificateIDs: []string{"certA"},
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
	Expect(len(capturingLB.UpdateListenerRequests)).Should(Equal(1))
	Expect(capturingLB.UpdateListenerRequests[0].UpdateListenerDetails.SslConfiguration.CertificateIds).Should(Equal([]string{"certA", "certB"}))
}

func TestEnsureIngress_UpdateListenerMultiToSingleCertificateIds(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("certA")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort:           80,
		ExistingCertificateIDs: []string{"certA", "certB"},
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
	Expect(len(capturingLB.UpdateListenerRequests)).Should(Equal(1))
	Expect(capturingLB.UpdateListenerRequests[0].UpdateListenerDetails.SslConfiguration.CertificateIds).Should(Equal([]string{"certA"}))
}

func TestEnsureIngress_UpdateListenerNoopWhenCertificateIdsMatch(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("certA,certB")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort:           80,
		ExistingCertificateIDs: []string{"certA", "certB"},
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
	Expect(len(capturingLB.UpdateListenerRequests)).Should(Equal(0))
}

func TestEnsureIngress_UpdateListenerClearsCertificateIdsWhenDesiredSslConfigAbsent(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort:           80,
		ExistingCertificateIDs: []string{"certA", "certB"},
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
	Expect(len(capturingLB.UpdateListenerRequests)).Should(Equal(1))
	Expect(capturingLB.UpdateListenerRequests[0].UpdateListenerDetails.SslConfiguration).NotTo(BeNil())
	Expect(capturingLB.UpdateListenerRequests[0].UpdateListenerDetails.SslConfiguration.CertificateIds).Should(Equal([]string{}))
}

func TestEnsureIngress_UpdateListenerNoopWhenExistingSslConfigAlreadyCleared(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort:           80,
		ExistingCertificateIDs: []string{},
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).NotTo(HaveOccurred())
	Expect(len(capturingLB.UpdateListenerRequests)).Should(Equal(0))
}

func TestEnsureIngress_CreateListenerUnsupportedMultiCertErrorIsActionable(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("certA,certB")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort:      443,
		CreateListenerErr: unsupportedCapabilityServiceError{},
		UpdateListenerErr: nil,
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(Equal(multiCertificateWarning))
}

func TestEnsureIngress_UpdateListenerUnsupportedMultiCertErrorPublishesActionableEvent(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := getIngressListWithDirectCertificates("certA,certB")
	capturingLB := &CapturingLoadBalancerClient{
		ListenerPort:      80,
		UpdateListenerErr: unsupportedCapabilityServiceError{},
	}
	c := initsWithCustomLB(ctx, ingressClassList, ingressList, capturingLB)

	err := c.ensureIngress(getContextWithClient(c, ctx), &ingressList.Items[0], &ingressClassList.Items[0])
	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(Equal(multiCertificateWarning))

	fakeRecorder, ok := c.eventRecorder.(*events.FakeRecorder)
	Expect(ok).To(BeTrue())
	c.handleErr(err, fmt.Sprintf("%s/%s", namespace, ingressList.Items[0].Name))

	select {
	case event := <-fakeRecorder.Events:
		Expect(event).To(ContainSubstring("IngressReconcileFailed"))
		Expect(event).To(ContainSubstring(multiCertificateWarning))
	case <-time.After(2 * time.Second):
		t.Fatalf("expected warning event for unsupported multi-cert capability failure")
	}
}

func getContextWithClient(c *Controller, ctx context.Context) context.Context {
	wc, err := c.client.GetClient(&MockConfigGetter{})
	Expect(err).To(BeNil())
	ctx = context.WithValue(ctx, util.WrapperClient, wc)
	return ctx
}

func TestSyncListenerClearsStaleSSLConfigWhenTLSNotDesired(t *testing.T) {
	RegisterTestingT(t)
	port := 10901
	lbId := "id"
	listenerName := util.GenerateListenerName(int32(port))
	defaultBackendSet := util.GenerateBackendSetName(namespace, "testecho1", int32(port))
	mockClient := &staleSSLLoadBalancerClient{
		listenerName:      listenerName,
		port:              port,
		defaultBackendSet: defaultBackendSet,
		protocol:          util.ProtocolTCP,
		certificateIds:    []string{"certificate-id"},
	}
	loadBalancerClient := &lb.LoadBalancerClient{
		LbClient: mockClient,
		Mu:       sync.Mutex{},
		Cache:    map[string]*lb.LbCacheObj{},
	}
	wrapperClient := client.NewWrapperClient(nil, nil, loadBalancerClient, nil, nil)
	ctx := context.WithValue(context.Background(), util.WrapperClient, wrapperClient)
	stateStore := &state.StateStore{
		IngressGroupState: state.IngressClassState{
			ListenerProtocolMap: map[int32]string{
				int32(port): util.ProtocolTCP,
			},
			ListenerDefaultBsMap: map[int32]string{
				int32(port): defaultBackendSet,
			},
			ListenerTLSConfigMap: map[int32]state.TlsConfig{},
		},
	}

	err := syncListener(ctx, namespace, stateStore, &lbId, listenerName, "", &Controller{})

	Expect(err).To(BeNil())
	Expect(mockClient.updateListenerRequest).ToNot(BeNil())
	Expect(mockClient.updateListenerRequest.UpdateListenerDetails.SslConfiguration).To(BeNil())
}

func TestEnsureLoadBalancerIP(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPath)
	c := inits(ctx, ingressClassList, ingressList)
	err := c.ensureLoadBalancerIP(getContextWithClient(c, ctx), "ip", &ingressList.Items[0])
	Expect(err == nil).Should(Equal(true))
}

func TestEnsureFinalizer(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPathWithFinalizer)
	c := inits(ctx, ingressClassList, ingressList)
	err := c.ensureFinalizer(getContextWithClient(c, ctx), &ingressList.Items[0])
	Expect(err == nil).Should(Equal(true))
	err = c.ensureFinalizer(getContextWithClient(c, ctx), &ingressList.Items[1])
	Expect(err == nil).Should(Equal(true))
}

func TestDeleteIngress(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPathWithFinalizer)
	c := inits(ctx, ingressClassList, ingressList)
	err := c.deleteIngress(&ingressList.Items[0])
	Expect(err == nil).Should(Equal(true))
	err = c.deleteIngress(&ingressList.Items[1])
	Expect(err == nil).Should(Equal(true))
}

func TestIngressAdd(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPath)
	c := inits(ctx, ingressClassList, ingressList)
	drainControllerQueue(c)
	queueSize := c.queue.Len()
	c.ingressAdd(&ingressList.Items[0])
	Expect(c.queue.Len()).Should(Equal(queueSize + 1))
}

func TestIngressUpdate(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPathWithFinalizer)
	c := inits(ctx, ingressClassList, ingressList)
	drainControllerQueue(c)
	queueSize := c.queue.Len()
	c.ingressUpdate(&ingressList.Items[0], &ingressList.Items[1])
	Expect(c.queue.Len()).Should(Equal(queueSize))

	oldIngress := ingressList.Items[0].DeepCopy()
	newIngress := ingressList.Items[1].DeepCopy()
	oldIngress.ResourceVersion = "1"
	newIngress.ResourceVersion = "2"

	c.ingressUpdate(oldIngress, newIngress)
	Expect(c.queue.Len()).Should(Equal(queueSize + 1))
}
func TestIngressDelete(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPathWithFinalizer)
	c := inits(ctx, ingressClassList, ingressList)
	drainControllerQueue(c)
	queueSize := c.queue.Len()
	c.ingressDelete(&ingressList.Items[0])
	Expect(c.queue.Len()).Should(Equal(queueSize + 1))
}

func TestSecretAdd(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPathWithTlsSecret)
	c := inits(ctx, ingressClassList, ingressList)
	drainControllerQueue(c)
	queueSize := c.queue.Len()
	c.secretAdd(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: namespace}}, false)
	Expect(c.queue.Len()).Should(Equal(queueSize + 1))
}

func TestSecretAdd_IsInInitialList(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPathWithTlsSecret)
	c := inits(ctx, ingressClassList, ingressList)
	drainControllerQueue(c)
	queueSize := c.queue.Len()
	c.secretAdd(&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: namespace}}, true)
	Expect(c.queue.Len()).Should(Equal(queueSize))
}

func TestSecretUpdate(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassList()
	ingressList := util.ReadResourceAsIngressList(ingressPathWithTlsSecret)
	c := inits(ctx, ingressClassList, ingressList)
	drainControllerQueue(c)
	queueSize := c.queue.Len()
	c.secretUpdate(nil, &v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: namespace}})
	Expect(c.queue.Len()).Should(Equal(queueSize + 1))
}

func TestProcessNextItem(t *testing.T) {
	RegisterTestingT(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ingressClassList := util.GetIngressClassListWithLBSet("id")
	ingressList := util.ReadResourceAsIngressList(ingressPathWithFinalizer)
	c := inits(ctx, ingressClassList, ingressList)

	drainControllerQueue(c)
	c.queue.Add("default-ingress-class")
	res := c.processNextItem()
	Expect(res).Should(BeTrue())
}

func GetLoadBalancerClient() ociclient.LoadBalancerInterface {
	return &MockLoadBalancerClient{}
}

type MockLoadBalancerClient struct {
}

func (m MockLoadBalancerClient) GetLoadBalancer(ctx context.Context, request ociloadbalancer.GetLoadBalancerRequest) (ociloadbalancer.GetLoadBalancerResponse, error) {
	res := util.SampleLoadBalancerResponse()
	return res, nil
}

func (m MockLoadBalancerClient) UpdateLoadBalancer(ctx context.Context, request ociloadbalancer.UpdateLoadBalancerRequest) (response ociloadbalancer.UpdateLoadBalancerResponse, err error) {
	return ociloadbalancer.UpdateLoadBalancerResponse{}, nil
}

func (m MockLoadBalancerClient) UpdateLoadBalancerShape(ctx context.Context, request ociloadbalancer.UpdateLoadBalancerShapeRequest) (response ociloadbalancer.UpdateLoadBalancerShapeResponse, err error) {
	return ociloadbalancer.UpdateLoadBalancerShapeResponse{}, nil
}

func (m MockLoadBalancerClient) UpdateNetworkSecurityGroups(ctx context.Context, request ociloadbalancer.UpdateNetworkSecurityGroupsRequest) (ociloadbalancer.UpdateNetworkSecurityGroupsResponse, error) {
	return ociloadbalancer.UpdateNetworkSecurityGroupsResponse{}, nil
}

func (m MockLoadBalancerClient) CreateLoadBalancer(ctx context.Context, request ociloadbalancer.CreateLoadBalancerRequest) (ociloadbalancer.CreateLoadBalancerResponse, error) {
	return ociloadbalancer.CreateLoadBalancerResponse{}, nil
}

func (m MockLoadBalancerClient) DeleteLoadBalancer(ctx context.Context, request ociloadbalancer.DeleteLoadBalancerRequest) (ociloadbalancer.DeleteLoadBalancerResponse, error) {
	return ociloadbalancer.DeleteLoadBalancerResponse{
		OpcRequestId:     common.String("OpcRequestId"),
		OpcWorkRequestId: common.String("OpcWorkRequestId"),
	}, nil
}

func (m MockLoadBalancerClient) GetWorkRequest(ctx context.Context, request ociloadbalancer.GetWorkRequestRequest) (ociloadbalancer.GetWorkRequestResponse, error) {
	id := "id"
	requestId := "opcrequestid"
	return ociloadbalancer.GetWorkRequestResponse{
		RawResponse: nil,
		WorkRequest: ociloadbalancer.WorkRequest{
			Id:             &id,
			LoadBalancerId: &id,
			Type:           nil,
			LifecycleState: ociloadbalancer.WorkRequestLifecycleStateSucceeded,
		},
		OpcRequestId: &requestId,
	}, nil
}

func (m MockLoadBalancerClient) CreateBackendSet(ctx context.Context, request ociloadbalancer.CreateBackendSetRequest) (ociloadbalancer.CreateBackendSetResponse, error) {
	reqId := "opcrequestid"
	return ociloadbalancer.CreateBackendSetResponse{
		RawResponse:      nil,
		OpcWorkRequestId: &reqId,
		OpcRequestId:     &reqId,
	}, nil
}

func (m MockLoadBalancerClient) UpdateBackendSet(ctx context.Context, request ociloadbalancer.UpdateBackendSetRequest) (ociloadbalancer.UpdateBackendSetResponse, error) {
	reqId := "opcrequestid"
	res := ociloadbalancer.UpdateBackendSetResponse{
		RawResponse:      nil,
		OpcWorkRequestId: &reqId,
		OpcRequestId:     &reqId,
	}
	return res, nil
}

func (m MockLoadBalancerClient) DeleteBackendSet(ctx context.Context, request ociloadbalancer.DeleteBackendSetRequest) (ociloadbalancer.DeleteBackendSetResponse, error) {
	return ociloadbalancer.DeleteBackendSetResponse{
		OpcRequestId:     common.String("OpcRequestId"),
		OpcWorkRequestId: common.String("OpcWorkRequestId"),
	}, nil
}

func (m MockLoadBalancerClient) GetBackendSetHealth(ctx context.Context, request ociloadbalancer.GetBackendSetHealthRequest) (ociloadbalancer.GetBackendSetHealthResponse, error) {
	return ociloadbalancer.GetBackendSetHealthResponse{}, nil
}

func (m MockLoadBalancerClient) CreateRoutingPolicy(ctx context.Context, request ociloadbalancer.CreateRoutingPolicyRequest) (ociloadbalancer.CreateRoutingPolicyResponse, error) {
	return ociloadbalancer.CreateRoutingPolicyResponse{}, nil
}

func (m MockLoadBalancerClient) UpdateRoutingPolicy(ctx context.Context, request ociloadbalancer.UpdateRoutingPolicyRequest) (ociloadbalancer.UpdateRoutingPolicyResponse, error) {
	return ociloadbalancer.UpdateRoutingPolicyResponse{}, nil
}

func (m MockLoadBalancerClient) DeleteRoutingPolicy(ctx context.Context, request ociloadbalancer.DeleteRoutingPolicyRequest) (ociloadbalancer.DeleteRoutingPolicyResponse, error) {
	return ociloadbalancer.DeleteRoutingPolicyResponse{}, nil
}

func (m MockLoadBalancerClient) CreateListener(ctx context.Context, request ociloadbalancer.CreateListenerRequest) (ociloadbalancer.CreateListenerResponse, error) {
	reqId := "opcrequestid"
	res := ociloadbalancer.CreateListenerResponse{
		RawResponse:      nil,
		OpcWorkRequestId: &reqId,
		OpcRequestId:     &reqId,
	}
	return res, nil
}

func (m MockLoadBalancerClient) UpdateListener(ctx context.Context, request ociloadbalancer.UpdateListenerRequest) (ociloadbalancer.UpdateListenerResponse, error) {
	return ociloadbalancer.UpdateListenerResponse{}, nil
}

type staleSSLLoadBalancerClient struct {
	MockLoadBalancerClient
	listenerName          string
	port                  int
	defaultBackendSet     string
	protocol              string
	certificateIds        []string
	updateListenerRequest *ociloadbalancer.UpdateListenerRequest
}

func (m *staleSSLLoadBalancerClient) GetLoadBalancer(ctx context.Context, request ociloadbalancer.GetLoadBalancerRequest) (ociloadbalancer.GetLoadBalancerResponse, error) {
	lbId := "id"
	etag := "etag"
	listener := ociloadbalancer.Listener{
		Name:                  common.String(m.listenerName),
		Port:                  common.Int(m.port),
		Protocol:              common.String(m.protocol),
		DefaultBackendSetName: common.String(m.defaultBackendSet),
		SslConfiguration: &ociloadbalancer.SslConfiguration{
			CertificateIds: m.certificateIds,
		},
	}
	return ociloadbalancer.GetLoadBalancerResponse{
		LoadBalancer: ociloadbalancer.LoadBalancer{
			Id: common.String(lbId),
			Listeners: map[string]ociloadbalancer.Listener{
				m.listenerName: listener,
			},
		},
		ETag: common.String(etag),
	}, nil
}

func (m *staleSSLLoadBalancerClient) UpdateListener(ctx context.Context, request ociloadbalancer.UpdateListenerRequest) (ociloadbalancer.UpdateListenerResponse, error) {
	m.updateListenerRequest = &request
	id := "id"
	return ociloadbalancer.UpdateListenerResponse{
		RawResponse:      nil,
		OpcWorkRequestId: &id,
		OpcRequestId:     &id,
	}, nil
}

func (m MockLoadBalancerClient) DeleteListener(ctx context.Context, request ociloadbalancer.DeleteListenerRequest) (ociloadbalancer.DeleteListenerResponse, error) {
	return ociloadbalancer.DeleteListenerResponse{}, nil
}

type CapturingLoadBalancerClient struct {
	MockLoadBalancerClient
	ListenerPort           int
	ExistingCertificateIDs []string
	CreateListenerErr      error
	UpdateListenerErr      error
	CreateListenerRequests []ociloadbalancer.CreateListenerRequest
	UpdateListenerRequests []ociloadbalancer.UpdateListenerRequest
}

func (m *CapturingLoadBalancerClient) GetLoadBalancer(ctx context.Context, request ociloadbalancer.GetLoadBalancerRequest) (ociloadbalancer.GetLoadBalancerResponse, error) {
	res := util.SampleLoadBalancerResponse()
	if m.ListenerPort <= 0 {
		return res, nil
	}

	listenerName := util.GenerateListenerName(int32(m.ListenerPort))
	listenerPort := m.ListenerPort
	protocol := util.ProtocolHTTP
	defaultBackendSet := util.DefaultBackendSetName
	sslConfig := &ociloadbalancer.SslConfiguration{
		CertificateIds: append([]string(nil), m.ExistingCertificateIDs...),
	}
	res.LoadBalancer.Listeners = map[string]ociloadbalancer.Listener{
		listenerName: {
			Name:                  common.String(listenerName),
			DefaultBackendSetName: common.String(defaultBackendSet),
			Port:                  common.Int(listenerPort),
			Protocol:              common.String(protocol),
			SslConfiguration:      sslConfig,
			RoutingPolicyName:     common.String(listenerName),
		},
	}
	return res, nil
}

func (m *CapturingLoadBalancerClient) CreateListener(ctx context.Context, request ociloadbalancer.CreateListenerRequest) (ociloadbalancer.CreateListenerResponse, error) {
	m.CreateListenerRequests = append(m.CreateListenerRequests, request)
	reqID := "opcrequestid"
	if m.CreateListenerErr != nil {
		return ociloadbalancer.CreateListenerResponse{
			RawResponse:      nil,
			OpcWorkRequestId: &reqID,
			OpcRequestId:     &reqID,
		}, m.CreateListenerErr
	}
	return ociloadbalancer.CreateListenerResponse{
		RawResponse:      nil,
		OpcWorkRequestId: &reqID,
		OpcRequestId:     &reqID,
	}, nil
}

func (m *CapturingLoadBalancerClient) UpdateListener(ctx context.Context, request ociloadbalancer.UpdateListenerRequest) (ociloadbalancer.UpdateListenerResponse, error) {
	m.UpdateListenerRequests = append(m.UpdateListenerRequests, request)
	reqID := "opcrequestid"
	if m.UpdateListenerErr != nil {
		return ociloadbalancer.UpdateListenerResponse{
			RawResponse:      nil,
			OpcWorkRequestId: &reqID,
			OpcRequestId:     &reqID,
		}, m.UpdateListenerErr
	}
	return ociloadbalancer.UpdateListenerResponse{
		RawResponse:      nil,
		OpcWorkRequestId: &reqID,
		OpcRequestId:     &reqID,
	}, nil
}

func (m *CapturingLoadBalancerClient) DeleteListener(ctx context.Context, request ociloadbalancer.DeleteListenerRequest) (ociloadbalancer.DeleteListenerResponse, error) {
	reqID := "opcrequestid"
	return ociloadbalancer.DeleteListenerResponse{
		RawResponse:      nil,
		OpcWorkRequestId: &reqID,
		OpcRequestId:     &reqID,
	}, nil
}

func getIngressListWithDirectCertificates(certificateList string) *networkingv1.IngressList {
	pathType := networkingv1.PathTypeExact
	return &networkingv1.IngressList{
		Items: []networkingv1.Ingress{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress-multi-cert",
					Namespace: namespace,
					Annotations: map[string]string{
						util.IngressListenerTlsCertificateAnnotation: certificateList,
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{
							Host: "foo.bar.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											PathType: &pathType,
											Path:     "/testecho1",
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "testecho1",
													Port: networkingv1.ServiceBackendPort{Number: 80},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

type unsupportedCapabilityServiceError struct{}

func (e unsupportedCapabilityServiceError) Error() string {
	return "BadRequest"
}

func (e unsupportedCapabilityServiceError) GetHTTPStatusCode() int {
	return 400
}

func (e unsupportedCapabilityServiceError) GetMessage() string {
	return "BadRequest"
}

func (e unsupportedCapabilityServiceError) GetCode() string {
	return "InvalidParameter"
}

func (e unsupportedCapabilityServiceError) GetOpcRequestID() string {
	return "fake-opc-request-id"
}

// MockConfigGetter is a mock implementation of the ConfigGetter interface for testing purposes.
type MockConfigGetter struct {
	ConfigurationProvider common.ConfigurationProvider
	Key                   string
	Error                 error
}

// NewMockConfigGetter creates a new instance of MockConfigGetter.
func NewMockConfigGetter(configurationProvider common.ConfigurationProvider, key string, err error) *MockConfigGetter {
	return &MockConfigGetter{
		ConfigurationProvider: configurationProvider,
		Key:                   key,
		Error:                 err,
	}
}
func (m *MockConfigGetter) GetConfigurationProvider() (common.ConfigurationProvider, error) {
	return m.ConfigurationProvider, m.Error
}
func (m *MockConfigGetter) GetKey() string {
	return m.Key
}

type MockCacheStore struct {
	client *client.WrapperClient
}

func (m *MockCacheStore) Add(obj interface{}) error {
	return nil
}

func (m *MockCacheStore) Update(obj interface{}) error {
	return nil
}

func (m *MockCacheStore) Delete(obj interface{}) error {
	return nil
}

func (m *MockCacheStore) List() []interface{} {
	return nil
}

func (m *MockCacheStore) ListKeys() []string {
	return nil
}

func (m *MockCacheStore) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, true, nil
}

func (m *MockCacheStore) Replace(i []interface{}, s string) error {
	return nil
}

func (m *MockCacheStore) Resync() error {
	return nil
}

func NewMockCacheStore(client *client.WrapperClient) *MockCacheStore {
	return &MockCacheStore{
		client: client,
	}
}

func (m *MockCacheStore) GetByKey(key string) (item interface{}, exists bool, err error) {
	return m.client, true, nil
}
