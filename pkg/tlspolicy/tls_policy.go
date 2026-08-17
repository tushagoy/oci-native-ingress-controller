/*
 *
 * * OCI Native Ingress Controller
 * *
 * * Copyright (c) 2023 Oracle America, Inc. and its affiliates.
 * * Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 *
 */

package tlspolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

const ociCustomizedCipherSuiteName = "oci-customized-ssl-cipher-suite"

const (
	// InvalidAnnotationReason is the warning event reason for invalid TLS policy annotations.
	InvalidAnnotationReason = "TLSPolicyInvalidAnnotation"
	// ConflictReason is the warning event reason for conflicting TLS policy annotations.
	ConflictReason = "TLSPolicyConflict"
)

const (
	explicitTLSPolicyFieldCipherSuiteName     = "cipherSuiteName"
	explicitTLSPolicyFieldProtocols           = "protocols"
	explicitTLSPolicyExportedFieldCipherSuite = "CipherSuiteName"
	explicitTLSPolicyExportedFieldProtocols   = "Protocols"
	tlsProtocolVersion12                      = "TLSv1.2"
	tlsProtocolVersion13                      = "TLSv1.3"
)

var unsafePreconfiguredCipherSuiteNames = map[string]struct{}{
	"oci-compatible-ssl-cipher-suite-v1":         {},
	"oci-wider-compatible-ssl-cipher-suite-v1":   {},
	"oci-tls-11-12-13-wider-ssl-cipher-suite-v1": {},
}

// ExplicitTLSPolicy is the validated TLS policy parsed from a NIC SSL policy
// annotation. The Has* fields distinguish omitted annotation fields from
// explicitly supplied zero values so the resolver can fill only omitted fields
// from NIC defaults.
type ExplicitTLSPolicy struct {
	HasCipherSuiteName bool
	CipherSuiteName    string
	HasProtocols       bool
	Protocols          []string
}

// ParseExplicitTLSPolicyAnnotation parses annotationName from annotations into
// an ExplicitTLSPolicy. It returns nil when annotations is nil or annotationName
// is absent. When present, the annotation value must be a JSON object containing
// cipherSuiteName, protocols, or both. Go-style exported field names
// CipherSuiteName and Protocols are also accepted for compatibility with copied
// examples.
func ParseExplicitTLSPolicyAnnotation(annotations map[string]string, annotationName string) (*ExplicitTLSPolicy, error) {
	if annotations == nil {
		return nil, nil
	}
	value, ok := annotations[annotationName]
	if !ok {
		return nil, nil
	}
	return ParseExplicitTLSPolicyAnnotationValue(annotationName, value)
}

// ParseExplicitTLSPolicyAnnotationValue parses one explicit TLS policy
// annotation value. It validates the JSON shape, rejects unknown or conflicting
// duplicate fields, rejects unsafe or unsupported cipher suite names, and
// accepts only TLSv1.2 and TLSv1.3 protocol values.
func ParseExplicitTLSPolicyAnnotationValue(annotationName string, value string) (*ExplicitTLSPolicy, error) {
	decoder := json.NewDecoder(strings.NewReader(value))

	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: malformed JSON: %w", annotationName, err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("%s: value must be a JSON object", annotationName)
	}

	policy := &ExplicitTLSPolicy{}
	fieldCount := 0
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: malformed JSON: %w", annotationName, err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, fmt.Errorf("%s: object field name must be a string", annotationName)
		}

		fieldCount++
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%s.%s: malformed JSON value: %w", annotationName, key, err)
		}

		switch key {
		case explicitTLSPolicyFieldCipherSuiteName, explicitTLSPolicyExportedFieldCipherSuite:
			cipherSuiteName, err := parseExplicitCipherSuiteName(annotationName, key, raw)
			if err != nil {
				return nil, err
			}
			if policy.HasCipherSuiteName && policy.CipherSuiteName != cipherSuiteName {
				return nil, fmt.Errorf("%s.%s: conflicts with duplicate cipherSuiteName field", annotationName, key)
			}
			policy.HasCipherSuiteName = true
			policy.CipherSuiteName = cipherSuiteName
		case explicitTLSPolicyFieldProtocols, explicitTLSPolicyExportedFieldProtocols:
			protocols, err := parseExplicitProtocols(annotationName, key, raw)
			if err != nil {
				return nil, err
			}
			if policy.HasProtocols && !reflect.DeepEqual(policy.Protocols, protocols) {
				return nil, fmt.Errorf("%s.%s: conflicts with duplicate protocols field", annotationName, key)
			}
			policy.HasProtocols = true
			policy.Protocols = protocols
		default:
			return nil, fmt.Errorf("%s.%s: unknown field", annotationName, key)
		}
	}

	endToken, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: malformed JSON: %w", annotationName, err)
	}
	endDelim, ok := endToken.(json.Delim)
	if !ok || endDelim != '}' {
		return nil, fmt.Errorf("%s: malformed JSON object", annotationName)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("%s: malformed JSON: %w", annotationName, err)
		}
		return nil, fmt.Errorf("%s: unexpected trailing JSON token %v", annotationName, token)
	}
	if fieldCount == 0 {
		return nil, fmt.Errorf("%s: value must set cipherSuiteName or protocols", annotationName)
	}
	if !policy.HasCipherSuiteName && !policy.HasProtocols {
		return nil, fmt.Errorf("%s: value must set cipherSuiteName or protocols", annotationName)
	}

	return policy, nil
}

// ClassifyWarningEventReason maps TLS policy reconcile errors to stable event reasons.
func ClassifyWarningEventReason(inputErr error, fallbackReason string) string {
	if inputErr == nil {
		return fallbackReason
	}
	message := inputErr.Error()
	if strings.Contains(message, InvalidAnnotationReason+":") {
		return InvalidAnnotationReason
	}
	if strings.Contains(message, ConflictReason+":") {
		return ConflictReason
	}
	return fallbackReason
}

// EnsureRequestableCipherSuite rejects OCI readback-only cipher suite names before request construction.
func EnsureRequestableCipherSuite(resourceKind string, cipherSuiteName *string) error {
	if cipherSuiteName != nil && *cipherSuiteName == ociCustomizedCipherSuiteName {
		return fmt.Errorf("TLSPolicyPreserveFailed: cannot preserve non-requestable %s cipherSuiteName %q", resourceKind, *cipherSuiteName)
	}
	return nil
}

func parseExplicitCipherSuiteName(annotationName string, fieldName string, raw json.RawMessage) (string, error) {
	if bytes.Equal(raw, []byte("null")) {
		return "", fmt.Errorf("%s.%s: must not be null", annotationName, fieldName)
	}

	var cipherSuiteName string
	if err := json.Unmarshal(raw, &cipherSuiteName); err != nil {
		return "", fmt.Errorf("%s.%s: must be a string", annotationName, fieldName)
	}
	if strings.TrimSpace(cipherSuiteName) == "" {
		return "", fmt.Errorf("%s.%s: must not be empty", annotationName, fieldName)
	}
	if cipherSuiteName == ociCustomizedCipherSuiteName {
		return "", fmt.Errorf("%s.%s: %q is not supported", annotationName, fieldName, cipherSuiteName)
	}
	if _, unsafe := unsafePreconfiguredCipherSuiteNames[cipherSuiteName]; unsafe {
		return "", fmt.Errorf("%s.%s: unsafe preconfigured cipher suite %q is not supported", annotationName, fieldName, cipherSuiteName)
	}

	return cipherSuiteName, nil
}

func parseExplicitProtocols(annotationName string, fieldName string, raw json.RawMessage) ([]string, error) {
	if bytes.Equal(raw, []byte("null")) {
		return nil, fmt.Errorf("%s.%s: must not be null", annotationName, fieldName)
	}

	var protocols []string
	if err := json.Unmarshal(raw, &protocols); err != nil {
		return nil, fmt.Errorf("%s.%s: must be an array of strings", annotationName, fieldName)
	}
	return normalizeExplicitTLSProtocols(annotationName, fieldName, protocols)
}

func normalizeExplicitTLSProtocols(annotationName string, fieldName string, protocols []string) ([]string, error) {
	if len(protocols) == 0 {
		return nil, fmt.Errorf("%s.%s: must not be empty", annotationName, fieldName)
	}

	seen := map[string]struct{}{}
	for _, protocol := range protocols {
		if strings.TrimSpace(protocol) == "" {
			return nil, fmt.Errorf("%s.%s: protocol must not be empty", annotationName, fieldName)
		}
		switch protocol {
		case tlsProtocolVersion12, tlsProtocolVersion13:
			seen[protocol] = struct{}{}
		case "TLSv1", "TLSv1.0", "TLSv1.1":
			return nil, fmt.Errorf("%s.%s: deprecated protocol %q is not supported", annotationName, fieldName, protocol)
		default:
			return nil, fmt.Errorf("%s.%s: unsupported protocol %q", annotationName, fieldName, protocol)
		}
	}

	normalized := make([]string, 0, len(seen))
	for _, protocol := range []string{tlsProtocolVersion12, tlsProtocolVersion13} {
		if _, ok := seen[protocol]; ok {
			normalized = append(normalized, protocol)
		}
	}
	return normalized, nil
}
