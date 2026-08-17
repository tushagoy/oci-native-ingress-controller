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

	. "github.com/onsi/gomega"
	"github.com/oracle/oci-go-sdk/v65/common"
	ociloadbalancer "github.com/oracle/oci-go-sdk/v65/loadbalancer"
	"github.com/oracle/oci-native-ingress-controller/pkg/util"
)

func TestParseExplicitTLSPolicyAnnotationAbsentAndConstants(t *testing.T) {
	RegisterTestingT(t)

	Expect(util.IngressListenerSslConfigAnnotation).To(Equal("oci-native-ingress.oraclecloud.com/listener-ssl-config"))
	Expect(util.IngressBackendSetSslConfigAnnotation).To(Equal("oci-native-ingress.oraclecloud.com/backendset-ssl-config"))

	policy, err := ParseExplicitTLSPolicyAnnotation(nil, util.IngressListenerSslConfigAnnotation)
	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(BeNil())

	policy, err = ParseExplicitTLSPolicyAnnotation(map[string]string{}, util.IngressListenerSslConfigAnnotation)
	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(BeNil())
}

func TestParseExplicitTLSPolicyAnnotationValidValues(t *testing.T) {
	tests := []struct {
		name            string
		value           string
		hasCipher       bool
		cipherSuiteName string
		hasProtocols    bool
		protocols       []string
	}{
		{
			name:            "lower camel full annotation",
			value:           `{"cipherSuiteName":"oci-tls-12-13-ssl-cipher-suite-v3","protocols":["TLSv1.3","TLSv1.2","TLSv1.3"]}`,
			hasCipher:       true,
			cipherSuiteName: "oci-tls-12-13-ssl-cipher-suite-v3",
			hasProtocols:    true,
			protocols:       []string{"TLSv1.2", "TLSv1.3"},
		},
		{
			name:            "exported full annotation",
			value:           `{"CipherSuiteName":"oci-tls-12-13-ssl-cipher-suite-v3","Protocols":["TLSv1.2"]}`,
			hasCipher:       true,
			cipherSuiteName: "oci-tls-12-13-ssl-cipher-suite-v3",
			hasProtocols:    true,
			protocols:       []string{"TLSv1.2"},
		},
		{
			name:            "cipher only annotation",
			value:           `{"cipherSuiteName":"oci-tls-12-13-ssl-cipher-suite-v3"}`,
			hasCipher:       true,
			cipherSuiteName: "oci-tls-12-13-ssl-cipher-suite-v3",
		},
		{
			name:         "protocols only annotation",
			value:        `{"protocols":["TLSv1.3","TLSv1.2"]}`,
			hasProtocols: true,
			protocols:    []string{"TLSv1.2", "TLSv1.3"},
		},
		{
			name:            "duplicate aliases with equivalent values",
			value:           `{"cipherSuiteName":"oci-tls-12-13-ssl-cipher-suite-v3","CipherSuiteName":"oci-tls-12-13-ssl-cipher-suite-v3","protocols":["TLSv1.3","TLSv1.2"],"Protocols":["TLSv1.2","TLSv1.3","TLSv1.2"]}`,
			hasCipher:       true,
			cipherSuiteName: "oci-tls-12-13-ssl-cipher-suite-v3",
			hasProtocols:    true,
			protocols:       []string{"TLSv1.2", "TLSv1.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			policy, err := ParseExplicitTLSPolicyAnnotationValue(util.IngressListenerSslConfigAnnotation, tt.value)

			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(policy).NotTo(BeNil())
			g.Expect(policy.HasCipherSuiteName).To(Equal(tt.hasCipher))
			g.Expect(policy.CipherSuiteName).To(Equal(tt.cipherSuiteName))
			g.Expect(policy.HasProtocols).To(Equal(tt.hasProtocols))
			g.Expect(policy.Protocols).To(Equal(tt.protocols))
		})
	}
}

func TestParseExplicitTLSPolicyAnnotationRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		substring string
	}{
		{
			name:      "malformed JSON",
			value:     `{"cipherSuiteName":`,
			substring: util.IngressListenerSslConfigAnnotation,
		},
		{
			name:      "non-object JSON",
			value:     `[]`,
			substring: "must be a JSON object",
		},
		{
			name:      "empty object",
			value:     `{}`,
			substring: "must set cipherSuiteName or protocols",
		},
		{
			name:      "unknown field",
			value:     `{"cipherSuite":"oci-tls-12-13-ssl-cipher-suite-v3"}`,
			substring: ".cipherSuite: unknown field",
		},
		{
			name:      "conflicting cipher alias",
			value:     `{"cipherSuiteName":"oci-tls-12-13-ssl-cipher-suite-v3","CipherSuiteName":"oci-default-http2-tls-12-13-ssl-cipher-suite-v1"}`,
			substring: "conflicts with duplicate cipherSuiteName field",
		},
		{
			name:      "conflicting protocol alias",
			value:     `{"protocols":["TLSv1.2"],"Protocols":["TLSv1.3"]}`,
			substring: "conflicts with duplicate protocols field",
		},
		{
			name:      "null cipher suite",
			value:     `{"cipherSuiteName":null}`,
			substring: ".cipherSuiteName: must not be null",
		},
		{
			name:      "empty cipher suite",
			value:     `{"cipherSuiteName":""}`,
			substring: ".cipherSuiteName: must not be empty",
		},
		{
			name:      "null protocols",
			value:     `{"protocols":null}`,
			substring: ".protocols: must not be null",
		},
		{
			name:      "empty protocols",
			value:     `{"protocols":[]}`,
			substring: ".protocols: must not be empty",
		},
		{
			name:      "empty protocol value",
			value:     `{"protocols":[""]}`,
			substring: ".protocols: protocol must not be empty",
		},
		{
			name:      "deprecated TLSv1",
			value:     `{"protocols":["TLSv1"]}`,
			substring: `deprecated protocol "TLSv1"`,
		},
		{
			name:      "deprecated TLSv1.0",
			value:     `{"protocols":["TLSv1.0"]}`,
			substring: `deprecated protocol "TLSv1.0"`,
		},
		{
			name:      "deprecated TLSv1.1",
			value:     `{"protocols":["TLSv1.1"]}`,
			substring: `deprecated protocol "TLSv1.1"`,
		},
		{
			name:      "unsupported protocol",
			value:     `{"protocols":["TLSv1.4"]}`,
			substring: `unsupported protocol "TLSv1.4"`,
		},
		{
			name:      "custom cipher suite",
			value:     `{"cipherSuiteName":"oci-customized-ssl-cipher-suite"}`,
			substring: `"oci-customized-ssl-cipher-suite" is not supported`,
		},
		{
			name:      "unsafe compatible suite",
			value:     `{"cipherSuiteName":"oci-compatible-ssl-cipher-suite-v1"}`,
			substring: `unsafe preconfigured cipher suite "oci-compatible-ssl-cipher-suite-v1"`,
		},
		{
			name:      "unsafe wider suite",
			value:     `{"cipherSuiteName":"oci-wider-compatible-ssl-cipher-suite-v1"}`,
			substring: `unsafe preconfigured cipher suite "oci-wider-compatible-ssl-cipher-suite-v1"`,
		},
		{
			name:      "unsafe tls 11 wider suite",
			value:     `{"cipherSuiteName":"oci-tls-11-12-13-wider-ssl-cipher-suite-v1"}`,
			substring: `unsafe preconfigured cipher suite "oci-tls-11-12-13-wider-ssl-cipher-suite-v1"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			policy, err := ParseExplicitTLSPolicyAnnotationValue(util.IngressListenerSslConfigAnnotation, tt.value)

			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(util.IngressListenerSslConfigAnnotation))
			g.Expect(err.Error()).To(ContainSubstring(tt.substring))
			g.Expect(policy).To(BeNil())
		})
	}
}

func TestResolveTLSPolicyNoopsWhenDesiredSSLConfigIsNil(t *testing.T) {
	RegisterTestingT(t)

	explicitPolicy := &ExplicitTLSPolicy{
		HasCipherSuiteName: true,
		CipherSuiteName:    "would-not-be-read",
		HasProtocols:       true,
		Protocols:          []string{"TLSv1.2"},
	}
	current := &ociloadbalancer.SslConfiguration{
		CipherSuiteName: common.String("existing-cipher"),
		Protocols:       []string{"TLSv1.2"},
	}

	policy, err := resolveTLSPolicy(tlsPolicyResourceListener, util.ProtocolHTTP, nil, explicitPolicy, true, current)

	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(BeNil())
}

func TestResolveTLSPolicyAppliesListenerCreateDefault(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a"}}

	policy, err := resolveTLSPolicy(tlsPolicyResourceListener, util.ProtocolHTTP, sslConfig, nil, true, nil)

	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(Equal(&LockedDefaultTLSPolicy.Listener))
	Expect(*sslConfig.CipherSuiteName).To(Equal(LockedDefaultTLSPolicy.Listener.CipherSuiteName))
	Expect(sslConfig.Protocols).To(Equal(LockedDefaultTLSPolicy.Listener.Protocols))
	Expect(sslConfig.CertificateIds).To(Equal([]string{"cert-a"}))
}

func TestResolveTLSPolicyAppliesHTTP2ListenerCreateDefault(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a"}}

	policy, err := resolveTLSPolicy(tlsPolicyResourceListener, util.ProtocolHTTP2, sslConfig, nil, true, nil)

	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(Equal(&LockedDefaultTLSPolicy.HTTP2Listener))
	Expect(*sslConfig.CipherSuiteName).To(Equal(util.ProtocolHTTP2DefaultCipherSuite))
	Expect(sslConfig.Protocols).To(Equal([]string{"TLSv1.2", "TLSv1.3"}))
}

func TestResolveTLSPolicyAppliesGRPCListenerCreateDefault(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a"}}

	policy, err := resolveTLSPolicy(tlsPolicyResourceListener, util.ProtocolGRPC, sslConfig, nil, true, nil)

	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(Equal(&LockedDefaultTLSPolicy.HTTP2Listener))
	Expect(*sslConfig.CipherSuiteName).To(Equal(util.ProtocolHTTP2DefaultCipherSuite))
	Expect(sslConfig.Protocols).To(Equal([]string{"TLSv1.2", "TLSv1.3"}))
}

func TestResolveTLSPolicyAppliesBackendSetCreateDefault(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{TrustedCertificateAuthorityIds: []string{"ca-a"}}

	policy, err := resolveTLSPolicy(tlsPolicyResourceBackendSet, "", sslConfig, nil, true, nil)

	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(Equal(&LockedDefaultTLSPolicy.BackendSet))
	Expect(*sslConfig.CipherSuiteName).To(Equal(util.ProtocolHTTP2DefaultCipherSuite))
	Expect(sslConfig.Protocols).To(Equal([]string{"TLSv1.2", "TLSv1.3"}))
	Expect(sslConfig.TrustedCertificateAuthorityIds).To(Equal([]string{"ca-a"}))
}

func TestResolveTLSPolicyOverlaysExplicitPolicy(t *testing.T) {
	tests := []struct {
		name             string
		resourceType     tlsPolicyResourceType
		listenerProtocol string
		explicitPolicy   *ExplicitTLSPolicy
		expectedCipher   string
		expectedProto    []string
	}{
		{
			name:             "normal listener protocols only TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.3"},
			},
			expectedCipher: listenerTLS13CipherSuite,
			expectedProto:  []string{"TLSv1.3"},
		},
		{
			name:             "normal listener protocols only TLS 1.2",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.2"},
			},
			expectedCipher: listenerTLS12CipherSuite,
			expectedProto:  []string{"TLSv1.2"},
		},
		{
			name:             "normal listener protocols only TLS 1.2 and TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.2", "TLSv1.3"},
			},
			expectedCipher: LockedDefaultTLSPolicy.Listener.CipherSuiteName,
			expectedProto:  []string{"TLSv1.2", "TLSv1.3"},
		},
		{
			name:             "HTTP2 listener protocols only TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP2,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.3"},
			},
			expectedCipher: http2ListenerTLS13CipherSuite,
			expectedProto:  []string{"TLSv1.3"},
		},
		{
			name:             "HTTP2 listener protocols only TLS 1.2",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP2,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.2"},
			},
			expectedCipher: http2ListenerTLS12CipherSuite,
			expectedProto:  []string{"TLSv1.2"},
		},
		{
			name:             "HTTP2 listener protocols only TLS 1.2 and TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP2,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.2", "TLSv1.3"},
			},
			expectedCipher: LockedDefaultTLSPolicy.HTTP2Listener.CipherSuiteName,
			expectedProto:  []string{"TLSv1.2", "TLSv1.3"},
		},
		{
			name:             "GRPC listener protocols only TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolGRPC,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.3"},
			},
			expectedCipher: http2ListenerTLS13CipherSuite,
			expectedProto:  []string{"TLSv1.3"},
		},
		{
			name:             "GRPC listener protocols only TLS 1.2",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolGRPC,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.2"},
			},
			expectedCipher: http2ListenerTLS12CipherSuite,
			expectedProto:  []string{"TLSv1.2"},
		},
		{
			name:             "GRPC listener protocols only TLS 1.2 and TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolGRPC,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.3", "TLSv1.2"},
			},
			expectedCipher: LockedDefaultTLSPolicy.HTTP2Listener.CipherSuiteName,
			expectedProto:  []string{"TLSv1.3", "TLSv1.2"},
		},
		{
			name:         "backend set protocols only TLS 1.2 and TLS 1.3",
			resourceType: tlsPolicyResourceBackendSet,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.2", "TLSv1.3"},
			},
			expectedCipher: LockedDefaultTLSPolicy.BackendSet.CipherSuiteName,
			expectedProto:  []string{"TLSv1.2", "TLSv1.3"},
		},
		{
			name:         "backend set protocols only TLS 1.3",
			resourceType: tlsPolicyResourceBackendSet,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.3"},
			},
			expectedCipher: http2ListenerTLS13CipherSuite,
			expectedProto:  []string{"TLSv1.3"},
		},
		{
			name:         "backend set protocols only TLS 1.2",
			resourceType: tlsPolicyResourceBackendSet,
			explicitPolicy: &ExplicitTLSPolicy{
				HasProtocols: true,
				Protocols:    []string{"TLSv1.2"},
			},
			expectedCipher: http2ListenerTLS12CipherSuite,
			expectedProto:  []string{"TLSv1.2"},
		},
		{
			name:             "cipher only preserves explicit cipher",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			explicitPolicy: &ExplicitTLSPolicy{
				HasCipherSuiteName: true,
				CipherSuiteName:    "explicit-cipher",
			},
			expectedCipher: "explicit-cipher",
			expectedProto:  LockedDefaultTLSPolicy.Listener.Protocols,
		},
		{
			name:             "both fields preserves explicit cipher and protocols",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP2,
			explicitPolicy: &ExplicitTLSPolicy{
				HasCipherSuiteName: true,
				CipherSuiteName:    "explicit-cipher",
				HasProtocols:       true,
				Protocols:          []string{"TLSv1.2"},
			},
			expectedCipher: "explicit-cipher",
			expectedProto:  []string{"TLSv1.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			sslConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a"}}

			policy, err := resolveTLSPolicy(tt.resourceType, tt.listenerProtocol, sslConfig, tt.explicitPolicy, false, &ociloadbalancer.SslConfiguration{})

			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(policy.CipherSuiteName).To(Equal(tt.expectedCipher))
			g.Expect(policy.Protocols).To(Equal(tt.expectedProto))
			g.Expect(*sslConfig.CipherSuiteName).To(Equal(tt.expectedCipher))
			g.Expect(sslConfig.Protocols).To(Equal(tt.expectedProto))
		})
	}
}

func TestProtocolCompatibleDefaultCipherSuite(t *testing.T) {
	tests := []struct {
		name             string
		resourceType     tlsPolicyResourceType
		listenerProtocol string
		protocols        []string
		expectedCipher   string
		expectedError    string
	}{
		{
			name:             "normal listener TLS 1.2",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			protocols:        []string{"TLSv1.2"},
			expectedCipher:   listenerTLS12CipherSuite,
		},
		{
			name:             "normal listener TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			protocols:        []string{"TLSv1.3"},
			expectedCipher:   listenerTLS13CipherSuite,
		},
		{
			name:             "normal listener TLS 1.2 and TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			protocols:        []string{"TLSv1.2", "TLSv1.3"},
			expectedCipher:   LockedDefaultTLSPolicy.Listener.CipherSuiteName,
		},
		{
			name:             "HTTP2 listener TLS 1.2",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP2,
			protocols:        []string{"TLSv1.2"},
			expectedCipher:   http2ListenerTLS12CipherSuite,
		},
		{
			name:             "HTTP2 listener TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP2,
			protocols:        []string{"TLSv1.3"},
			expectedCipher:   http2ListenerTLS13CipherSuite,
		},
		{
			name:             "HTTP2 listener TLS 1.2 and TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP2,
			protocols:        []string{"TLSv1.2", "TLSv1.3"},
			expectedCipher:   LockedDefaultTLSPolicy.HTTP2Listener.CipherSuiteName,
		},
		{
			name:             "GRPC listener TLS 1.2",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolGRPC,
			protocols:        []string{"TLSv1.2"},
			expectedCipher:   http2ListenerTLS12CipherSuite,
		},
		{
			name:             "GRPC listener TLS 1.3",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolGRPC,
			protocols:        []string{"TLSv1.3"},
			expectedCipher:   http2ListenerTLS13CipherSuite,
		},
		{
			name:             "GRPC listener TLS 1.3 and TLS 1.2 reordered",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolGRPC,
			protocols:        []string{"TLSv1.3", "TLSv1.2"},
			expectedCipher:   LockedDefaultTLSPolicy.HTTP2Listener.CipherSuiteName,
		},
		{
			name:           "backend set TLS 1.2",
			resourceType:   tlsPolicyResourceBackendSet,
			protocols:      []string{"TLSv1.2"},
			expectedCipher: http2ListenerTLS12CipherSuite,
		},
		{
			name:           "backend set TLS 1.3",
			resourceType:   tlsPolicyResourceBackendSet,
			protocols:      []string{"TLSv1.3"},
			expectedCipher: http2ListenerTLS13CipherSuite,
		},
		{
			name:           "backend set TLS 1.2 and TLS 1.3",
			resourceType:   tlsPolicyResourceBackendSet,
			protocols:      []string{"TLSv1.2", "TLSv1.3"},
			expectedCipher: LockedDefaultTLSPolicy.BackendSet.CipherSuiteName,
		},
		{
			name:             "listener unsupported protocols",
			resourceType:     tlsPolicyResourceListener,
			listenerProtocol: util.ProtocolHTTP,
			protocols:        []string{"TLSv1.4"},
			expectedError:    "has no confirmed safe default cipher suite",
		},
		{
			name:          "unknown resource type",
			resourceType:  tlsPolicyResourceType("unknown"),
			protocols:     []string{"TLSv1.2"},
			expectedError: `unknown TLS policy resource type "unknown"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cipherSuite, err := protocolCompatibleDefaultCipherSuite(tt.resourceType, tt.listenerProtocol, tt.protocols)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
				g.Expect(cipherSuite).To(BeEmpty())
				return
			}
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cipherSuite).To(Equal(tt.expectedCipher))
		})
	}
}

func TestResolveTLSPolicyPreservesExistingPolicyWithoutAnnotation(t *testing.T) {
	RegisterTestingT(t)

	sslConfig := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"desired-cert"}}
	current := &ociloadbalancer.SslConfiguration{
		CertificateIds:                 []string{"current-cert"},
		TrustedCertificateAuthorityIds: []string{"current-ca"},
		CertificateName:                common.String("legacy-cert-name"),
		CipherSuiteName:                common.String(LockedDefaultTLSPolicy.Listener.CipherSuiteName),
		Protocols:                      []string{"TLSv1.1"},
	}

	policy, err := resolveTLSPolicy(tlsPolicyResourceListener, util.ProtocolHTTP, sslConfig, nil, false, current)

	Expect(err).NotTo(HaveOccurred())
	Expect(policy).To(BeNil())
	Expect(sslConfig.CertificateIds).To(Equal([]string{"desired-cert"}))
	Expect(sslConfig.CertificateName).To(BeNil())
	Expect(sslConfig.TrustedCertificateAuthorityIds).To(BeNil())
	Expect(*sslConfig.CipherSuiteName).To(Equal(LockedDefaultTLSPolicy.Listener.CipherSuiteName))
	Expect(sslConfig.Protocols).To(Equal([]string{"TLSv1.1"}))
}

func TestResolveTLSPolicyRejectsCustomizedReadbackCipherSuiteWhenPreservingWithoutAnnotation(t *testing.T) {
	tests := []struct {
		name         string
		resourceType tlsPolicyResourceType
	}{
		{
			name:         "listener",
			resourceType: tlsPolicyResourceListener,
		},
		{
			name:         "backend set",
			resourceType: tlsPolicyResourceBackendSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			sslConfig := &ociloadbalancer.SslConfigurationDetails{}
			current := &ociloadbalancer.SslConfiguration{
				CipherSuiteName: common.String("oci-customized-ssl-cipher-suite"),
				Protocols:       []string{"TLSv1.2"},
			}

			policy, err := resolveTLSPolicy(tt.resourceType, util.ProtocolHTTP, sslConfig, nil, false, current)

			g.Expect(policy).To(BeNil())
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("TLSPolicyPreserveFailed"))
			g.Expect(sslConfig.CipherSuiteName).To(BeNil())
		})
	}
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

func TestPreserveTLSPolicyCopiesOnlyPolicyFields(t *testing.T) {
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

func TestListenerSslConfigNeedsUpdate(t *testing.T) {
	RegisterTestingT(t)

	current := &ociloadbalancer.Listener{
		SslConfiguration: &ociloadbalancer.SslConfiguration{
			CertificateIds:  []string{"cert-a", "cert-b"},
			CipherSuiteName: common.String(LockedDefaultTLSPolicy.Listener.CipherSuiteName),
			Protocols:       []string{"TLSv1.3", "TLSv1.2"},
		},
	}
	desired := &ociloadbalancer.SslConfigurationDetails{
		CertificateIds:  []string{"cert-a", "cert-b"},
		CipherSuiteName: common.String(LockedDefaultTLSPolicy.Listener.CipherSuiteName),
		Protocols:       []string{"TLSv1.2", "TLSv1.3"},
	}

	Expect(listenerSslConfigNeedsUpdate(desired, current, true)).To(BeFalse())

	desiredMissingPolicy := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-a", "cert-b"}}
	Expect(listenerSslConfigNeedsUpdate(desiredMissingPolicy, current, true)).To(BeTrue())
	Expect(listenerSslConfigNeedsUpdate(desiredMissingPolicy, current, false)).To(BeFalse())

	reorderedCertificates := &ociloadbalancer.SslConfigurationDetails{CertificateIds: []string{"cert-b", "cert-a"}}
	Expect(listenerSslConfigNeedsUpdate(reorderedCertificates, current, false)).To(BeTrue())
}
