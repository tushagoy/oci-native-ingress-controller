/*
 *
 * * OCI Native Ingress Controller
 * *
 * * Copyright (c) 2023 Oracle America, Inc. and its affiliates.
 * * Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 *
 */

package state

import (
	"fmt"
	"reflect"
	"sort"

	ociloadbalancer "github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-native-ingress-controller/pkg/metric"
	"github.com/oracle/oci-native-ingress-controller/pkg/util"
	"github.com/pkg/errors"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/klog/v2"
)

const (
	ArtifactTypeSecret      = "secret"
	ArtifactTypeCertificate = "certificate"

	PortConflictMessage               = "validation failure: service port %d has multiple certificate or secret configs across ingresses in the ingress class"
	HealthCheckerConflictMessage      = "validation failure: incompatible health checker config across ingresses sharing backend set %s in the ingress class"
	PolicyConflictMessage             = "validation failure: incompatible policy config across ingresses sharing backend set %s in the ingress class"
	ProtocolConflictMessage           = "validation failure: incompatible protocol config across ingresses sharing listener %d in the ingress class"
	DefaultBackendSetConflictMessage  = "validation failure: incompatible default backend set across TCP ingresses sharing listener %d in the ingress class"
	SessionPersistenceEmptyMessage    = "validation failure: empty session persistence configuration for backend set %s"
	BackendTlsEnabledConflictMessage  = "validation failure: incompatible backend-tls-enabled config across ingresses sharing backend set %s in the ingress class"
	BackendTlsArtifactConflictMessage = "validation failure: incompatible backend TLS certificate or secret across ingresses sharing backend set %s in the ingress class"
)

type TlsConfig struct {
	Artifact  string
	Type      string
	Namespace string
}

type ListenerTLSConfig struct {
	TlsConfigs []TlsConfig
}

// listenerTLSCandidate is a pre-normalized listener TLS config discovered before deterministic sort and de-dupe.
type listenerTLSCandidate struct {
	IngressKey     string
	DiscoveryOrder int
	Config         TlsConfig
}

type backendTLSStatus struct {
	Enabled             bool
	HasTLSArtifactInput bool
	Config              TlsConfig
}

type StateStore struct {
	IngressClassLister networkinglisters.IngressClassLister
	IngressLister      networkinglisters.IngressLister
	ServiceLister      corelisters.ServiceLister
	IngressGroupState  IngressClassState
	IngressState       map[string]IngressState
	metricsCollector   *metric.IngressCollector
}

type IngressClassState struct {
	BackendSets                     sets.String
	BackendSetHealthCheckerMap      map[string]*ociloadbalancer.HealthCheckerDetails
	BackendSetPolicyMap             map[string]string
	BackendSetTLSConfigMap          map[string]TlsConfig
	BackendSetSessionPersistenceMap map[string]SessionPersistence
	Listeners                       sets.Int32
	ListenerProtocolMap             map[int32]string
	ListenerTLSConfigMap            map[int32]ListenerTLSConfig
	ListenerDefaultBsMap            map[int32]string
}

type IngressState struct {
	BackendSets sets.String
	Ports       sets.Int32
	ClassName   string
}

// SessionPersistence holds desired session persistence config for a backend set.
// Exactly one of the pointers should be non-nil. If both are nil and the session
// persistence annotation is present on the ingress, this is treated as a validation error.
// If no annotation is present, both may be nil (persistence disabled).
type SessionPersistence struct {
	AppCookie *ociloadbalancer.SessionPersistenceConfigurationDetails
	LbCookie  *ociloadbalancer.LbCookieSessionPersistenceConfigurationDetails
}

func NewStateStore(ingressClassLister networkinglisters.IngressClassLister,
	ingressLister networkinglisters.IngressLister,
	serviceLister corelisters.ServiceLister, collector *metric.IngressCollector) *StateStore {
	return &StateStore{
		IngressClassLister: ingressClassLister,
		IngressLister:      ingressLister,
		ServiceLister:      serviceLister,
		IngressGroupState:  IngressClassState{},
		IngressState:       map[string]IngressState{},
		metricsCollector:   collector,
	}
}

func (s *StateStore) BuildState(ingressClass *networkingv1.IngressClass) error {

	startBuildTime := util.GetCurrentTimeInUnixMillis()
	klog.Infof("Starting to build state for ingress class %s", ingressClass.Name)
	ingressList, err := s.IngressLister.List(labels.Everything())
	if err != nil {
		return errors.Wrap(err, "error listing ingress")
	}

	var ingressGroup []*networkingv1.Ingress
	for _, ing := range ingressList {
		if ((ing.Spec.IngressClassName == nil && ingressClass.Annotations[util.IngressClassIsDefault] == "true") ||
			(ing.Spec.IngressClassName != nil && ingressClass.Name == *ing.Spec.IngressClassName)) &&
			!util.IsIngressDeleting(ing) {
			ingressGroup = append(ingressGroup, ing)
		}
	}

	klog.Infof("Found %d ingress resources related to ingress class %s", len(ingressGroup), ingressClass.Name)
	bsTLSConfigMap := make(map[string]TlsConfig)
	backendTLSStatusMap := make(map[string]backendTLSStatus)
	listenerProtocolMap := make(map[int32]string)
	listenerTLSCandidateMap := make(map[int32][]listenerTLSCandidate)
	listenerDefaultBsMap := make(map[int32]string)
	bsHealthCheckerMap := make(map[string]*ociloadbalancer.HealthCheckerDetails)
	bsPolicyMap := make(map[string]string)
	bsSessionPersistenceMap := make(map[string]SessionPersistence)
	allBackendSets := sets.NewString(util.DefaultBackendSetName)
	allListeners := sets.NewInt32()

	bsHealthCheckerMap[util.DefaultBackendSetName] = util.GetDefaultHeathChecker()
	bsPolicyMap[util.DefaultBackendSetName] = util.DefaultBackendSetRoutingPolicy

	for _, ing := range ingressGroup {
		nextListenerTLSDiscoveryOrder := 0
		hostSecretMap := make(map[string]string)
		tlsConfiguredHosts := sets.NewString()
		desiredPorts := sets.NewInt32()
		// we always expect the default_ingress backendset
		desiredBackendSets := sets.NewString(util.DefaultBackendSetName)

		// For now, TLS spec is only applied to HTTP-family ingresses.
		if util.IsIngressProtocolHTTPBased(ing) {
			for ingressItem := range ing.Spec.TLS {
				ingressTls := ing.Spec.TLS[ingressItem]
				for j := range ingressTls.Hosts {
					host := ingressTls.Hosts[j]
					tlsConfiguredHosts.Insert(host)
					hostSecretMap[host] = ingressTls.SecretName
				}
			}
		}

		for _, rule := range ing.Spec.Rules {
			host := rule.Host
			if !util.HasHTTPPaths(rule) {
				klog.V(4).InfoS("skipping ingress rule without HTTP paths while building state", "ingress", klog.KObj(ing), "host", host)
				continue
			}

			for _, path := range rule.HTTP.Paths {
				if !util.HasServiceBackend(path) {
					util.LogAndPublishIngressBackendValidationWarning(nil, ing, host, path, " while building state")
					continue
				}
				serviceName, servicePort, err := util.PathToServiceAndPort(ing.Namespace, path, s.ServiceLister)
				if err != nil {
					return errors.Wrap(err, "error finding service and port")
				}

				listenerPort, err := util.DetermineListenerPort(ing, &tlsConfiguredHosts, host, servicePort)
				if err != nil {
					return errors.Wrap(err, "error determining listener port")
				}

				desiredPorts.Insert(listenerPort)
				allListeners.Insert(listenerPort)

				bsName := util.GenerateBackendSetName(ing.Namespace, serviceName, servicePort)
				desiredBackendSets.Insert(bsName)
				allBackendSets.Insert(bsName)

				err = validateListenerProtocol(ing, listenerProtocolMap, listenerPort)
				if err != nil {
					return err
				}

				err = validateListenerDefaultBackendSet(ing, listenerDefaultBsMap, listenerPort, bsName)
				if err != nil {
					return err
				}

				err = validateBackendSetHealthChecker(ing, bsHealthCheckerMap, bsName)
				if err != nil {
					return err
				}

				err = validateBackendSetPolicy(ing, bsPolicyMap, bsName)
				if err != nil {
					return err
				}

				err = validateBackendSetSessionPersistence(ing, bsSessionPersistenceMap, bsName)
				if err != nil {
					return err
				}

				err = validateTlsConfig(
					ing,
					listenerPort,
					bsName,
					host,
					listenerTLSCandidateMap,
					bsTLSConfigMap,
					backendTLSStatusMap,
					hostSecretMap,
					&nextListenerTLSDiscoveryOrder,
				)
				if err != nil {
					return err
				}
			}
		}

		s.IngressState[getIngressStateKey(ing.Namespace, ing.Name)] = IngressState{
			Ports:       desiredPorts,
			BackendSets: desiredBackendSets,
			ClassName:   ingressClass.Name,
		}
	}
	listenerTLSConfigMap := buildListenerTLSConfigMap(listenerTLSCandidateMap)
	s.IngressGroupState = IngressClassState{
		BackendSets:                     allBackendSets,
		BackendSetHealthCheckerMap:      bsHealthCheckerMap,
		BackendSetPolicyMap:             bsPolicyMap,
		BackendSetTLSConfigMap:          bsTLSConfigMap,
		BackendSetSessionPersistenceMap: bsSessionPersistenceMap,
		Listeners:                       allListeners,
		ListenerProtocolMap:             listenerProtocolMap,
		ListenerTLSConfigMap:            listenerTLSConfigMap,
		ListenerDefaultBsMap:            listenerDefaultBsMap,
	}

	klog.Infof("Ingress Group state %s, Ingress state %s", util.PrettyPrint(s.IngressGroupState), util.PrettyPrint(s.IngressState))
	klog.Infof("State build complete..")

	endBuildTime := util.GetCurrentTimeInUnixMillis()
	if s.metricsCollector != nil {
		s.metricsCollector.AddStateBuildTime(util.GetTimeDifferenceInSeconds(startBuildTime, endBuildTime))
	}
	return nil
}

func validateTlsConfig(ingress *networkingv1.Ingress, listenerPort int32, bsName string, host string, listenerTLSCandidateMap map[int32][]listenerTLSCandidate,
	bsTLSConfigMap map[string]TlsConfig, bsTLSStatusMap map[string]backendTLSStatus, hostSecretMap map[string]string, discoveryOrder *int) error {
	bsTLSEnabled := util.GetBackendTlsEnabled(ingress)
	certificateIds := util.GetListenerTlsCertificateOcids(ingress)
	ingressKey := getIngressStateKey(ingress.Namespace, ingress.Name)
	backendTLSConfig := TlsConfig{}
	hasTLSArtifactInput := false

	if len(certificateIds) > 0 && util.IsIngressProtocolHTTPBased(ingress) {
		for _, certificateId := range certificateIds {
			config := TlsConfig{
				Type:      ArtifactTypeCertificate,
				Artifact:  certificateId,
				Namespace: ingress.Namespace,
			}
			appendListenerTLSCandidate(listenerTLSCandidateMap, listenerPort, ingressKey, discoveryOrder, config)
		}

		hasTLSArtifactInput = true
		backendTLSConfig = TlsConfig{
			Type:      ArtifactTypeCertificate,
			Artifact:  certificateIds[0],
			Namespace: ingress.Namespace,
		}
	}

	if host != "" {
		secretName, ok := hostSecretMap[host]

		if ok && secretName != "" {
			hasTLSArtifactInput = true
			config := TlsConfig{
				Type:      ArtifactTypeSecret,
				Artifact:  secretName,
				Namespace: ingress.Namespace,
			}
			appendListenerTLSCandidate(listenerTLSCandidateMap, listenerPort, ingressKey, discoveryOrder, config)
			backendTLSConfig = config
		}
	}

	return updateBackendTlsStatus(bsTLSEnabled, hasTLSArtifactInput, bsTLSStatusMap, bsTLSConfigMap, bsName, backendTLSConfig)
}

func updateBackendTlsStatus(bsTLSEnabled bool, hasTLSArtifactInput bool, bsTLSStatusMap map[string]backendTLSStatus,
	bsTLSConfigMap map[string]TlsConfig, bsName string, config TlsConfig) error {
	current, ok := bsTLSStatusMap[bsName]
	if ok {
		if current.Enabled != bsTLSEnabled {
			return fmt.Errorf(BackendTlsEnabledConflictMessage, bsName)
		}
		if bsTLSEnabled && current.HasTLSArtifactInput && hasTLSArtifactInput && current.Config != config {
			return fmt.Errorf(BackendTlsArtifactConflictMessage, bsName)
		}
		if hasTLSArtifactInput && !current.HasTLSArtifactInput {
			current.HasTLSArtifactInput = true
			current.Config = config
			bsTLSStatusMap[bsName] = current
		}
	} else {
		bsTLSStatusMap[bsName] = backendTLSStatus{
			Enabled:             bsTLSEnabled,
			HasTLSArtifactInput: hasTLSArtifactInput,
			Config:              config,
		}
	}

	if hasTLSArtifactInput {
		if bsTLSEnabled {
			bsTLSConfigMap[bsName] = config
		} else {
			bsTLSConfigMap[bsName] = TlsConfig{}
		}
	}
	return nil
}

func validateBackendSetHealthChecker(ingressResource *networkingv1.Ingress,
	bsHealthCheckerMap map[string]*ociloadbalancer.HealthCheckerDetails, bsName string) error {
	defaultHealthChecker := util.GetDefaultHeathChecker()
	healthChecker, err := util.GetHealthChecker(ingressResource)
	if err != nil {
		return err
	}
	healthCheckerCurrent, ok := bsHealthCheckerMap[bsName]
	if ok && !reflect.DeepEqual(healthChecker, defaultHealthChecker) && !reflect.DeepEqual(healthChecker, healthCheckerCurrent) {
		return fmt.Errorf(HealthCheckerConflictMessage, bsName)
	}
	bsHealthCheckerMap[bsName] = healthChecker
	return nil
}

func validateBackendSetPolicy(ingressResource *networkingv1.Ingress, bsPolicyMap map[string]string, bsName string) error {
	policy := util.GetIngressPolicy(ingressResource)

	policyCurrent, ok := bsPolicyMap[bsName]
	if ok && policyCurrent != policy {
		return fmt.Errorf(PolicyConflictMessage, bsName)
	}
	bsPolicyMap[bsName] = policy
	return nil
}

func validateBackendSetSessionPersistence(ingressResource *networkingv1.Ingress,
	bsPersistenceMap map[string]SessionPersistence, bsName string) error {
	appCookie, lbCookie, err := util.GetSessionPersistenceConfigs(ingressResource)
	if err != nil {
		return fmt.Errorf("invalid session persistence configuration on ingress %s/%s: %w", ingressResource.Namespace, ingressResource.Name, err)
	}

	// Ensure mutual exclusivity (only one or none)
	if appCookie != nil && lbCookie != nil {
		// Prefer LB cookie if both provided; log and continue
		return fmt.Errorf("Provide only one of LB cookie or App cookie config for %s.", bsName)
	}

	// If annotation is present but both configs are nil, treat as validation error
	if util.HasSessionPersistenceAnnotation(ingressResource) && appCookie == nil && lbCookie == nil {
		return fmt.Errorf(SessionPersistenceEmptyMessage, bsName)
	}

	incoming := SessionPersistence{AppCookie: appCookie, LbCookie: lbCookie}

	current, ok := bsPersistenceMap[bsName]
	if ok {
		// Reconcile conflicts instead of erroring out
		if !reflect.DeepEqual(current, incoming) {
			// If either side has lbCookie, prefer lbCookie (LB-managed persistence)
			if current.LbCookie != nil || incoming.LbCookie != nil {
				// If current already lbCookie, keep it; else adopt incoming lbCookie
				if current.LbCookie != nil {
					klog.Warningf("session persistence conflict for %s; keeping existing lbCookie configuration", bsName)
					// keep current as-is
				} else {
					klog.Warningf("session persistence conflict for %s; adopting lbCookie configuration from ingress %s", bsName, ingressResource.Name)
					current = SessionPersistence{LbCookie: incoming.LbCookie}
				}
			} else if current.AppCookie != nil || incoming.AppCookie != nil {
				// Both sides appCookie but may differ on cookieName; keep existing to avoid churn
				if current.AppCookie != nil {
					klog.Warningf("session persistence conflict (appCookie) for %s; keeping existing configuration", bsName)
					// keep current
				} else {
					klog.Warningf("session persistence conflict (appCookie) for %s; adopting configuration from ingress %s", bsName, ingressResource.Name)
					current = SessionPersistence{AppCookie: incoming.AppCookie}
				}
			} else {
				// Both nil or one nil and other nil: end up nil
				current = SessionPersistence{}
			}
			bsPersistenceMap[bsName] = current
			return nil
		}
		// No change; keep current
		bsPersistenceMap[bsName] = current
		return nil
	}

	// First writer wins
	bsPersistenceMap[bsName] = incoming
	return nil
}

func validateListenerProtocol(ingressResource *networkingv1.Ingress, listenerProtocolMap map[int32]string, listenerPort int32) error {
	protocol := util.GetIngressProtocol(ingressResource)

	protocolCurrent, ok := listenerProtocolMap[listenerPort]
	if ok && protocolCurrent != protocol {
		return fmt.Errorf(ProtocolConflictMessage, listenerPort)
	}
	listenerProtocolMap[listenerPort] = protocol
	return nil
}

// backendSetName is ignored if ingress protocol is not TCP, uses default_ingress in that scenario
func validateListenerDefaultBackendSet(ingressResource *networkingv1.Ingress,
	listenerDefaultBsMap map[int32]string, listenerPort int32, backendSetName string) error {
	if !util.IsIngressProtocolTCP(ingressResource) {
		backendSetName = util.DefaultBackendSetName
	}

	defaultBackendSetCurrent, ok := listenerDefaultBsMap[listenerPort]
	if ok && defaultBackendSetCurrent != backendSetName {
		return fmt.Errorf(DefaultBackendSetConflictMessage, listenerPort)
	}
	listenerDefaultBsMap[listenerPort] = backendSetName
	return nil
}

func (s *StateStore) GetBackendSetHealthChecker(bsName string) *ociloadbalancer.HealthCheckerDetails {
	return s.IngressGroupState.BackendSetHealthCheckerMap[bsName]
}

func (s *StateStore) GetBackendSetPolicy(bsName string) string {
	return s.IngressGroupState.BackendSetPolicyMap[bsName]
}

func (s *StateStore) GetIngressBackendSets(namespace string, ingressName string) sets.String {
	ingress, ok := s.IngressState[getIngressStateKey(namespace, ingressName)]
	if ok {
		return ingress.BackendSets
	}
	return nil
}

func (s *StateStore) GetIngressPorts(namespace string, ingressName string) sets.Int32 {
	ingress, ok := s.IngressState[getIngressStateKey(namespace, ingressName)]
	if ok {
		return ingress.Ports
	}
	return nil
}

func (s *StateStore) GetListenerProtocol(listenerPort int32) string {
	return s.IngressGroupState.ListenerProtocolMap[listenerPort]
}

func (s *StateStore) GetListenerDefaultBackendSet(listenerPort int32) string {
	return s.IngressGroupState.ListenerDefaultBsMap[listenerPort]
}

func (s *StateStore) GetTLSConfigForListener(port int32) []TlsConfig {
	portTLSConfig, ok := s.IngressGroupState.ListenerTLSConfigMap[port]
	if ok {
		// Return a copy so callers cannot mutate state-store internals.
		tlsConfigs := make([]TlsConfig, len(portTLSConfig.TlsConfigs))
		copy(tlsConfigs, portTLSConfig.TlsConfigs)
		return tlsConfigs
	}
	return nil
}

func (s *StateStore) GetTLSConfigForBackendSet(bsName string) (string, string) {
	bsTLSConfig, ok := s.IngressGroupState.BackendSetTLSConfigMap[bsName]
	if ok {
		return bsTLSConfig.Artifact, bsTLSConfig.Type
	}
	return "", ""
}

func (s *StateStore) GetBackendSetSessionPersistence(bsName string) (*ociloadbalancer.SessionPersistenceConfigurationDetails, *ociloadbalancer.LbCookieSessionPersistenceConfigurationDetails) {
	p, ok := s.IngressGroupState.BackendSetSessionPersistenceMap[bsName]
	if ok {
		return p.AppCookie, p.LbCookie
	}
	return nil, nil
}

func (s *StateStore) GetAllBackendSetForIngressClass() sets.String {
	return s.IngressGroupState.BackendSets
}

func (s *StateStore) GetAllListenersForIngressClass() sets.Int32 {
	return s.IngressGroupState.Listeners
}

func appendListenerTLSCandidate(listenerTLSCandidateMap map[int32][]listenerTLSCandidate, listenerPort int32,
	ingressKey string, discoveryOrder *int, config TlsConfig) {
	listenerTLSCandidateMap[listenerPort] = append(listenerTLSCandidateMap[listenerPort], listenerTLSCandidate{
		IngressKey:     ingressKey,
		DiscoveryOrder: *discoveryOrder,
		Config:         config,
	})
	*discoveryOrder++
}

// buildListenerTLSConfigMap orders listener TLS configs deterministically by ingress key,
// discovery order, and config value. The order is for stable state across reconciles, not certificate priority.
func buildListenerTLSConfigMap(listenerTLSCandidateMap map[int32][]listenerTLSCandidate) map[int32]ListenerTLSConfig {
	listenerTLSConfigMap := make(map[int32]ListenerTLSConfig, len(listenerTLSCandidateMap))
	for port, candidates := range listenerTLSCandidateMap {
		sortedCandidates := make([]listenerTLSCandidate, len(candidates))
		copy(sortedCandidates, candidates)

		sort.SliceStable(sortedCandidates, func(i, j int) bool {
			leftCandidate := sortedCandidates[i]
			rightCandidate := sortedCandidates[j]
			if leftCandidate.IngressKey != rightCandidate.IngressKey {
				return leftCandidate.IngressKey < rightCandidate.IngressKey
			}
			if leftCandidate.DiscoveryOrder != rightCandidate.DiscoveryOrder {
				return leftCandidate.DiscoveryOrder < rightCandidate.DiscoveryOrder
			}
			if leftCandidate.Config.Artifact != rightCandidate.Config.Artifact {
				return leftCandidate.Config.Artifact < rightCandidate.Config.Artifact
			}
			if leftCandidate.Config.Type != rightCandidate.Config.Type {
				return leftCandidate.Config.Type < rightCandidate.Config.Type
			}
			return leftCandidate.Config.Namespace < rightCandidate.Config.Namespace
		})

		tlsConfigs := dedupeListenerTLSConfigs(sortedCandidates)
		if len(tlsConfigs) > 0 {
			listenerTLSConfigMap[port] = ListenerTLSConfig{TlsConfigs: tlsConfigs}
		}
	}
	return listenerTLSConfigMap
}

func dedupeListenerTLSConfigs(candidates []listenerTLSCandidate) []TlsConfig {
	tlsConfigs := make([]TlsConfig, 0, len(candidates))
	seen := make(map[TlsConfig]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, ok := seen[candidate.Config]; ok {
			continue
		}
		seen[candidate.Config] = struct{}{}
		tlsConfigs = append(tlsConfigs, candidate.Config)
	}
	return tlsConfigs
}

func getIngressStateKey(namespace string, ingressName string) string {
	return fmt.Sprintf("%s/%s", namespace, ingressName)
}
