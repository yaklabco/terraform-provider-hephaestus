// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import "time"

// Kubernetes API server constants.
const (
	// KubernetesAPIPort is the standard Kubernetes API server port.
	KubernetesAPIPort = 6443

	// DefaultPodCIDR is the default pod network CIDR.
	DefaultPodCIDR = "10.244.0.0/16"

	// DefaultServiceCIDR is the default service network CIDR.
	DefaultServiceCIDR = "10.96.0.0/12"
)

// Default timeout constants.
const (
	// DefaultSSHWaitInterval is the interval between SSH availability checks.
	DefaultSSHWaitInterval = 2 * time.Second

	// DefaultVIPWaitTimeout is the timeout for VIP to become ready.
	DefaultVIPWaitTimeout = 60 * time.Second

	// DefaultCheckInterval is the default interval for polling operations.
	DefaultCheckInterval = 2 * time.Second

	// DefaultAPIWaitTimeout is the timeout for API server to become ready.
	DefaultAPIWaitTimeout = 5 * time.Minute

	// DefaultAPIWaitPollInterval is the interval between API readiness checks.
	DefaultAPIWaitPollInterval = 10 * time.Second
)

// Kubernetes version constants.
const (
	// DefaultKubernetesVersion is the default Kubernetes version to install.
	DefaultKubernetesVersion = "1.31.3"
)

// Network interface constants.
const (
	// DefaultNetworkInterface is the default network interface for kube-vip.
	DefaultNetworkInterface = "eth0"
)

// Token expiry constants.
const (
	// TokenExpiryHours is the number of hours until a kubeadm token expires.
	TokenExpiryHours = 24
)
