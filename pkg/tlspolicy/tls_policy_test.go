/*
 *
 * * OCI Native Ingress Controller
 * *
 * * Copyright (c) 2026 Oracle America, Inc. and its affiliates.
 * * Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 *
 */

package tlspolicy

import (
	"errors"
	"testing"

	. "github.com/onsi/gomega"
)

func TestClassifyWarningEventReasonForTLSPolicyErrors(t *testing.T) {
	RegisterTestingT(t)

	fallback := "IngressReconcileFailed"
	invalidAnnotationErr := errors.New("TLSPolicyInvalidAnnotation: listener 443 ingress default/ing: oci-native-ingress.oraclecloud.com/listener-ssl-config.protocols: deprecated protocol \"TLSv1.1\" is not supported")
	conflictErr := errors.New("TLSPolicyConflict: backend set bs annotation oci-native-ingress.oraclecloud.com/backendset-ssl-config field protocols conflicts between ingress default/a value \"[TLSv1.2]\" and ingress default/b value \"[TLSv1.3]\"")
	ociErr := errors.New("Service error: InvalidParameter cipher suite was rejected by OCI")

	Expect(ClassifyWarningEventReason(nil, fallback)).To(Equal(fallback))
	Expect(ClassifyWarningEventReason(invalidAnnotationErr, fallback)).To(Equal(InvalidAnnotationReason))
	Expect(ClassifyWarningEventReason(conflictErr, fallback)).To(Equal(ConflictReason))
	Expect(ClassifyWarningEventReason(ociErr, fallback)).To(Equal(fallback))
}

func TestEnsureRequestableCipherSuiteRejectsCustomizedReadbackCipherSuite(t *testing.T) {
	RegisterTestingT(t)

	cipherSuiteName := "oci-customized-ssl-cipher-suite"

	err := EnsureRequestableCipherSuite("listener", &cipherSuiteName)

	Expect(err).To(HaveOccurred())
	Expect(err.Error()).To(ContainSubstring("TLSPolicyPreserveFailed"))
}

func TestEnsureRequestableCipherSuiteAllowsRequestableCipherSuite(t *testing.T) {
	RegisterTestingT(t)

	cipherSuiteName := "oci-tls-12-13-ssl-cipher-suite-v3"

	err := EnsureRequestableCipherSuite("listener", &cipherSuiteName)

	Expect(err).NotTo(HaveOccurred())
	Expect(EnsureRequestableCipherSuite("listener", nil)).To(Succeed())
}
