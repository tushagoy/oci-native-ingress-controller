/*
 *
 * * OCI Native Ingress Controller
 * *
 * * Copyright (c) 2023 Oracle America, Inc. and its affiliates.
 * * Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 *
 */

package ingress

import (
	"fmt"
	"reflect"
	"sort"

	"bitbucket.oci.oraclecorp.com/oke/oci-native-ingress-controller/pkg/util"
	"github.com/oracle/oci-go-sdk/v65/common"
	ociloadbalancer "github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"k8s.io/apimachinery/pkg/util/sets"
)

const ociCustomizedCipherSuiteName = "oci-customized-ssl-cipher-suite"

type TLSPolicy struct {
	CipherSuiteName string
	Protocols       []string
}

type MultiCertTLSPolicyDefaults struct {
	Listener   TLSPolicy
	BackendSet TLSPolicy
}

var DefaultMultiCertTLSPolicy = MultiCertTLSPolicyDefaults{
	Listener: TLSPolicy{
		CipherSuiteName: "oci-tls-12-13-ssl-cipher-suite-v3",
		Protocols:       []string{"TLSv1.2", "TLSv1.3"},
	},
	BackendSet: TLSPolicy{
		CipherSuiteName: "oci-default-ssl-cipher-suite-v1",
		Protocols:       []string{"TLSv1.2"},
	},
}

func selectListenerMultiCertTLSPolicy(protocol string, sslConfig *ociloadbalancer.SslConfigurationDetails) (*TLSPolicy, error) {
	if sslConfig == nil || len(sslConfig.CertificateIds) <= 1 {
		return nil, nil
	}
	if protocol == util.ProtocolTCP {
		return nil, nil
	}
	return copyTLSPolicy(DefaultMultiCertTLSPolicy.Listener), nil
}

func listenerHasManagedMultiCertTLSPolicy(listener *ociloadbalancer.Listener) bool {
	if listener == nil || listener.SslConfiguration == nil || listener.SslConfiguration.CipherSuiteName == nil {
		return false
	}
	return *listener.SslConfiguration.CipherSuiteName == DefaultMultiCertTLSPolicy.Listener.CipherSuiteName &&
		tlsProtocolsEqual(listener.SslConfiguration.Protocols, DefaultMultiCertTLSPolicy.Listener.Protocols)
}

func selectBackendSetMultiCertTLSPolicy(backendSetName string, backendSetSslConfig *ociloadbalancer.SslConfigurationDetails,
	managedMultiCertBackendSets sets.String) *TLSPolicy {
	if backendSetSslConfig == nil || !managedMultiCertBackendSets.Has(backendSetName) {
		return nil
	}
	return copyTLSPolicy(DefaultMultiCertTLSPolicy.BackendSet)
}

func applyTLSPolicyToSSLConfig(sslConfig *ociloadbalancer.SslConfigurationDetails, policy *TLSPolicy) {
	if sslConfig == nil || policy == nil {
		return
	}
	sslConfig.CipherSuiteName = common.String(policy.CipherSuiteName)
	sslConfig.Protocols = append([]string(nil), policy.Protocols...)
}

func preserveListenerTLSPolicy(dst *ociloadbalancer.SslConfigurationDetails, current *ociloadbalancer.SslConfiguration) error {
	return preserveTLSPolicyFields("listener", dst, current)
}

func preserveBackendSetTLSPolicy(dst *ociloadbalancer.SslConfigurationDetails, current *ociloadbalancer.SslConfiguration) error {
	return preserveTLSPolicyFields("backend set", dst, current)
}

func preserveTLSPolicyFields(resourceKind string, dst *ociloadbalancer.SslConfigurationDetails, current *ociloadbalancer.SslConfiguration) error {
	if dst == nil || current == nil {
		return nil
	}
	if dst.CipherSuiteName == nil && current.CipherSuiteName != nil {
		if *current.CipherSuiteName == ociCustomizedCipherSuiteName {
			return fmt.Errorf("TLSPolicyPreserveFailed: cannot preserve non-requestable %s cipherSuiteName %q", resourceKind, *current.CipherSuiteName)
		}
		dst.CipherSuiteName = common.String(*current.CipherSuiteName)
	}
	if len(dst.Protocols) == 0 {
		dst.Protocols = append([]string(nil), current.Protocols...)
	}
	return nil
}

func listenerSslConfigNeedsUpdate(calculatedConfig *ociloadbalancer.SslConfigurationDetails,
	currentListener *ociloadbalancer.Listener, comparePolicy bool) bool {
	if currentListener == nil {
		return calculatedConfig != nil
	}

	currentConfig := currentListener.SslConfiguration
	if calculatedConfig == nil {
		return listenerHasSSLArtifacts(currentConfig)
	}
	if currentConfig == nil {
		return true
	}
	if !reflect.DeepEqual(currentConfig.CertificateIds, calculatedConfig.CertificateIds) {
		return true
	}
	if comparePolicy && (!reflect.DeepEqual(currentConfig.CipherSuiteName, calculatedConfig.CipherSuiteName) ||
		!tlsProtocolsEqual(currentConfig.Protocols, calculatedConfig.Protocols)) {
		return true
	}
	return false
}

func listenerHasSSLArtifacts(currentConfig *ociloadbalancer.SslConfiguration) bool {
	return currentConfig != nil && (len(currentConfig.CertificateIds) > 0 || currentConfig.CertificateName != nil)
}

func tlsProtocolsEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := append([]string(nil), a...)
	bCopy := append([]string(nil), b...)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {
			return false
		}
	}
	return true
}

func copyTLSPolicy(policy TLSPolicy) *TLSPolicy {
	return &TLSPolicy{
		CipherSuiteName: policy.CipherSuiteName,
		Protocols:       append([]string(nil), policy.Protocols...),
	}
}
