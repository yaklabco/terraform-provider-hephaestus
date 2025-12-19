// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import "fmt"

// KubeVIPConfig holds configuration for generating kube-vip manifests.
type KubeVIPConfig struct {
	Interface string
	VIP       string
	Version   string
}

// DefaultKubeVIPVersion is the default version of kube-vip to deploy.
const DefaultKubeVIPVersion = "v0.8.0"

// GenerateKubeVIPManifest creates a kube-vip static pod manifest.
// This manifest is deployed to /etc/kubernetes/manifests/ on control plane nodes
// to provide virtual IP failover for high availability.
func GenerateKubeVIPManifest(cfg KubeVIPConfig) string {
	version := cfg.Version
	if version == "" {
		version = DefaultKubeVIPVersion
	}

	return fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: kube-vip
  namespace: kube-system
spec:
  containers:
  - args:
    - manager
    env:
    - name: KUBECONFIG
      value: /etc/kubernetes/admin.conf
    - name: vip_arp
      value: "true"
    - name: port
      value: "6443"
    - name: vip_interface
      value: "%s"
    - name: vip_cidr
      value: "32"
    - name: cp_enable
      value: "true"
    - name: vip_ddns
      value: "false"
    - name: svc_enable
      value: "false"
    - name: cp_namespace
      value: kube-system
    - name: vip_leaderelection
      value: "true"
    - name: vip_leasename
      value: plndr-cp-lock
    - name: vip_leaseduration
      value: "5"
    - name: vip_renewdeadline
      value: "3"
    - name: vip_retryperiod
      value: "1"
    - name: address
      value: "%s"
    - name: prometheus_server
      value: :2112
    image: ghcr.io/kube-vip/kube-vip:%s
    imagePullPolicy: IfNotPresent
    name: kube-vip
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
        - NET_RAW
    volumeMounts:
    - mountPath: /etc/kubernetes/admin.conf
      name: kubeconfig
  hostAliases:
  - hostnames:
    - kubernetes
    ip: 127.0.0.1
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/admin.conf
    name: kubeconfig
`, cfg.Interface, cfg.VIP, version)
}
