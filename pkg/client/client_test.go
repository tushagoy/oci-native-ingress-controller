/*
 *
 * * OCI Native Ingress Controller
 * *
 * * Copyright (c) 2026 Oracle America, Inc. and its affiliates.
 * * Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 *
 */
package client

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/certificates"
	"github.com/oracle/oci-go-sdk/v65/certificatesmanagement"
	"github.com/oracle/oci-go-sdk/v65/common"
)

type throttlingServiceError struct{}

func (e throttlingServiceError) Error() string {
	return "TooManyRequests"
}

func (e throttlingServiceError) GetHTTPStatusCode() int {
	return 429
}

func (e throttlingServiceError) GetMessage() string {
	return "TooManyRequests"
}

func (e throttlingServiceError) GetCode() string {
	return "TooManyRequests"
}

func (e throttlingServiceError) GetOpcRequestID() string {
	return "fakeopcrequestid"
}

func TestConfigureCertificatesClientsRetryPolicy(t *testing.T) {
	certBundleClient := certificates.CertificatesClient{}
	certMgmtClient := certificatesmanagement.CertificatesManagementClient{}

	configureCertificatesClientsRetryPolicy(&certBundleClient, &certMgmtClient)

	if certBundleClient.RetryPolicy() == nil {
		t.Fatalf("expected retry policy to be set for certificates bundle client")
	}
	if certMgmtClient.RetryPolicy() == nil {
		t.Fatalf("expected retry policy to be set for certificates management client")
	}
}

func TestCertificatesRetryPolicyRetriesOnThrottling(t *testing.T) {
	retryPolicy := getCertificatesRetryPolicy()
	if retryPolicy == nil {
		t.Fatalf("expected non-nil retry policy")
	}

	throttled := common.NewOCIOperationResponse(nil, throttlingServiceError{}, 1)
	if !retryPolicy.ShouldRetryOperation(throttled) {
		t.Fatalf("expected throttling response (429 TooManyRequests) to be retryable")
	}
}
