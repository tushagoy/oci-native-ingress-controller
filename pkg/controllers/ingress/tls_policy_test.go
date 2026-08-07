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
	"testing"

	"bitbucket.oci.oraclecorp.com/oke/oci-native-ingress-controller/pkg/util"
	. "github.com/onsi/gomega"
	"github.com/oracle/oci-go-sdk/v65/common"
	ociloadbalancer "github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestSelectListenerMultiCertTLSPolicy(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a", "cert-b"}}
	policy, err := selectListenerMultiCertTLSPolicy(util.ProtocolHTTP, sslConfig)
	Expect(err).NotTo(HaveOccurred())
	Expect(policy).NotTo(BeNil())
	Expect(policy.CipherSuiteName).To(Equal("oci-tls-12-13-ssl-cipher-suite-v3"))
	Expect(policy.Protocols).To(Equal([]string{"TLSv1.2", "TLSv1.3"}))
}

func TestSelectListenerMultiCertTLSPolicyNoopForSingleCertAndTCP(t *testing.T) {
	RegisterTestingT(t)

	singleCertConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a"}}
	policy, err := selectListenerMultiCertTLSPolicy(util.ProtocolHTTP, singleCertConfig)
	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(BeNil())

	policy, err = selectListenerMultiCertTLSPolicy(util.ProtocolHTTP2, singleCertConfig)
	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(BeNil())

	tcpConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a", "cert-b"}}
	policy, err = selectListenerMultiCertTLSPolicy(util.ProtocolTCP, tcpConfig)
	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(BeNil())
}

func TestSelectListenerMultiCertTLSPolicySupportsHTTP2(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a", "cert-b"}}
	policy, err := selectListenerMultiCertTLSPolicy(util.ProtocolHTTP2, sslConfig)
	Expect(err).NotTo(HaveOccurred())
	Expect(policy).NotTo(BeNil())
	Expect(policy.CipherSuiteName).To(Equal("oci-tls-12-13-ssl-cipher-suite-v3"))
	Expect(policy.Protocols).To(Equal([]string{"TLSv1.2", "TLSv1.3"}))
}

func TestSelectBackendSetMultiCertTLSPolicy(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{TrustedCertificateAuthorityIds: []string{"ca-a"}}
	managedBackendSets := sets.NewString("bs-managed")

	policy := selectBackendSetMultiCertTLSPolicy("bs-managed", sslConfig, managedBackendSets)
	Expect(policy).NotTo(BeNil())
	Expect(policy.CipherSuiteName).To(Equal("oci-default-ssl-cipher-suite-v1"))
	Expect(policy.Protocols).To(Equal([]string{"TLSv1.2"}))

	Expect(selectBackendSetMultiCertTLSPolicy("bs-managed", nil, managedBackendSets)).To(BeNil())
	Expect(selectBackendSetMultiCertTLSPolicy("bs-unrelated", sslConfig, managedBackendSets)).To(BeNil())
}

func TestApplyTLSPolicyToSSLConfigCopiesProtocols(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{}
	policy := &TLSPolicy{CipherSuiteName: "cipher", Protocols: []string{"TLSv1.2"}}
	applyTLSPolicyToSSLConfig(sslConfig, policy)

	policy.Protocols[0] = "changed"
	Expect(*sslConfig.CipherSuiteName).To(Equal("cipher"))
	Expect(sslConfig.Protocols).To(Equal([]string{"TLSv1.2"}))
}

func TestPreserveTLSPolicyUsesExplicitAllowlist(t *testing.T) {
	RegisterTestingT(t)

	current := &ociloadbalancer.SslConfiguration{
		TrustedCertificateAuthorityIds: []string{"current-ca"},
		CertificateIds:                 []string{"current-cert"},
		CertificateName:                common.String("legacy-cert-name"),
		CipherSuiteName:                common.String("existing-cipher"),
		Protocols:                      []string{"TLSv1.3", "TLSv1.2"},
		ServerOrderPreference:          ociloadbalancer.SslConfigurationServerOrderPreferenceEnabled,
	}
	listenerDetails := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"desired-cert-a", "desired-cert-b"}}

	err := preserveListenerTLSPolicy(listenerDetails, current)

	Expect(err).NotTo(HaveOccurred())
	Expect(listenerDetails.CertificateIds).To(Equal([]string{"desired-cert-a", "desired-cert-b"}))
	Expect(listenerDetails.CertificateName).To(BeNil())
	Expect(listenerDetails.TrustedCertificateAuthorityIds).To(BeNil())
	Expect(*listenerDetails.CipherSuiteName).To(Equal("existing-cipher"))
	Expect(listenerDetails.Protocols).To(Equal([]string{"TLSv1.3", "TLSv1.2"}))
	Expect(listenerDetails.ServerOrderPreference).To(Equal(ociloadbalancer.SslConfigurationDetailsServerOrderPreferenceEnum("")))
}

func TestPreserveTLSPolicyRejectsNonRequestableCipherSuite(t *testing.T) {
	RegisterTestingT(t)

	current := &ociloadbalancer.SslConfiguration{
		CipherSuiteName: common.String(ociCustomizedCipherSuiteName),
		Protocols:       []string{"TLSv1.2"},
	}
	details := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a"}}

	err := preserveListenerTLSPolicy(details, current)

	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("TLSPolicyPreserveFailed"))
	Expect(details.CipherSuiteName).To(BeNil())
}

func TestListenerSslConfigNeedsUpdate(t *testing.T) {
	RegisterTestingT(t)

	current := &ociloadbalancer.Listener{
		SslConfiguration: &ociloadbalancer.SslConfiguration{
			CertificateIds:  []string{"cert-a", "cert-b"},
			CipherSuiteName: common.String(DefaultMultiCertTLSPolicy.Listener.CipherSuiteName),
			Protocols:       []string{"TLSv1.3", "TLSv1.2"},
		},
	}
	desired := &ociloadbalancer.SslConfigurationDetails{
		CertificateIds:  []string{"cert-a", "cert-b"},
		CipherSuiteName: common.String(DefaultMultiCertTLSPolicy.Listener.CipherSuiteName),
		Protocols:       []string{"TLSv1.2", "TLSv1.3"},
	}

	Expect(listenerSslConfigNeedsUpdate(desired, current, true)).To(BeFalse())

	desiredMissingPolicy := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a", "cert-b"}}
	Expect(listenerSslConfigNeedsUpdate(desiredMissingPolicy, current, true)).To(BeTrue())
	Expect(listenerSslConfigNeedsUpdate(desiredMissingPolicy, current, false)).To(BeFalse())

	reorderedCertificates := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-b", "cert-a"}}
	Expect(listenerSslConfigNeedsUpdate(reorderedCertificates, current, false)).To(BeTrue())
}
