/*
 *
 * * OCI Native Ingress Controller
 * *
 * * Copyright (c) 2023 Oracle America, Inc. and its affiliates.
 * * Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
 *
 */
package client

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	PrivateIPLifetimeReserved = core.PrivateIpLifetimeReserved
)

type PrivateIp = core.PrivateIp
type GetPrivateIpRequest = core.GetPrivateIpRequest
type GetPrivateIpResponse = core.GetPrivateIpResponse

type PrivateIpInterface interface {
	GetPrivateIp(ctx context.Context, request GetPrivateIpRequest) (GetPrivateIpResponse, error)
}

type PrivateIpClient struct {
	privateIpClient *core.VirtualNetworkClient
}

func NewPrivateIpClient(configProvider common.ConfigurationProvider) (*PrivateIpClient, error) {
	privateIpClient, err := core.NewVirtualNetworkClientWithConfigurationProvider(configProvider)
	if err != nil {
		return nil, err
	}

	return &PrivateIpClient{
		privateIpClient: &privateIpClient,
	}, nil
}

func (c *PrivateIpClient) GetPrivateIp(ctx context.Context, request GetPrivateIpRequest) (GetPrivateIpResponse, error) {
	return c.privateIpClient.GetPrivateIp(ctx, request)
}
