// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

// Package verifier provides verification methods for cluster state.
package verifier

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
)

const (
	statusOK       = "ok"
	statusFailed   = "failed"
	statusNotFound = "not found"
)

// Verifier provides verification methods for cluster state.
type Verifier struct {
	ssh *client.SSHClient
}

// New creates a new Verifier with the given SSH client.
func New(ssh *client.SSHClient) *Verifier {
	return &Verifier{ssh: ssh}
}

// Evidence captures verification results for diagnostics.
type Evidence struct {
	Timestamp time.Time
	Node      string
	Check     string
	Passed    bool
	Command   string
	Output    string
	Error     string
	Details   map[string]string
}

// CheckResult holds the result of a verification check.
type CheckResult struct {
	Passed   bool
	Evidence Evidence
	Err      error
}

// CheckSSHReachable verifies SSH connectivity to a node.
func (v *Verifier) CheckSSHReachable(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "ssh_reachable",
		Command:   "ssh true",
	}

	if v.ssh.Check(ctx, ip, "true") {
		ev.Passed = true
		return CheckResult{Passed: true, Evidence: ev}
	}

	ev.Error = "SSH connection failed"
	return CheckResult{Passed: false, Evidence: ev}
}

// CheckOSReady verifies OS prerequisites are configured.
func (v *Verifier) CheckOSReady(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "os_ready",
		Details:   make(map[string]string),
	}

	checks := []struct {
		name    string
		command string
	}{
		{"swap_disabled", "test $(cat /proc/swaps | wc -l) -eq 1"},
		{"br_netfilter_loaded", "lsmod | grep -q br_netfilter"},
		{"overlay_loaded", "lsmod | grep -q overlay"},
		{"ip_forward", "test $(cat /proc/sys/net/ipv4/ip_forward) -eq 1"},
		{"bridge_nf_call_iptables", "test $(cat /proc/sys/net/bridge/bridge-nf-call-iptables) -eq 1"},
	}

	allPassed := true
	for _, check := range checks {
		if v.ssh.Check(ctx, ip, "sudo "+check.command) {
			ev.Details[check.name] = statusOK
		} else {
			ev.Details[check.name] = statusFailed
			allPassed = false
		}
	}

	ev.Passed = allPassed
	if !allPassed {
		ev.Error = "some OS prerequisites not met"
	}
	return CheckResult{Passed: allPassed, Evidence: ev}
}

// CheckRuntimeReady verifies containerd is properly configured and running.
func (v *Verifier) CheckRuntimeReady(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "runtime_ready",
		Details:   make(map[string]string),
	}

	// Check containerd binary exists
	if !v.ssh.Check(ctx, ip, "which containerd") {
		ev.Details["containerd_installed"] = statusFailed
		ev.Error = "containerd not installed"
		return CheckResult{Passed: false, Evidence: ev}
	}
	ev.Details["containerd_installed"] = statusOK

	// Check socket exists
	socketExists := v.ssh.Check(ctx, ip, "sudo test -S /run/containerd/containerd.sock -o -S /var/run/containerd/containerd.sock")
	if !socketExists {
		ev.Details["containerd_socket"] = statusFailed
		ev.Error = "containerd socket not found"
		return CheckResult{Passed: false, Evidence: ev}
	}
	ev.Details["containerd_socket"] = statusOK

	// Check systemctl status
	if v.ssh.Check(ctx, ip, "sudo systemctl is-active --quiet containerd") {
		ev.Details["containerd_active"] = statusOK
	} else {
		ev.Details["containerd_active"] = "warning (socket exists)"
	}

	ev.Passed = true
	return CheckResult{Passed: true, Evidence: ev}
}

// CheckKubeadmReady verifies kubeadm, kubelet, and kubectl are installed.
func (v *Verifier) CheckKubeadmReady(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "kubeadm_ready",
		Details:   make(map[string]string),
	}

	binaries := []string{"kubeadm", "kubelet", "kubectl"}
	allPassed := true

	for _, bin := range binaries {
		out, err := v.ssh.Output(ctx, ip, "command -v "+bin)
		if err != nil || out == "" {
			ev.Details[bin] = statusNotFound
			allPassed = false
		} else {
			ev.Details[bin] = statusOK
		}
	}

	// Check kubelet service is enabled
	if v.ssh.Check(ctx, ip, "sudo systemctl is-enabled --quiet kubelet") {
		ev.Details["kubelet_enabled"] = statusOK
	} else {
		ev.Details["kubelet_enabled"] = "not enabled"
		allPassed = false
	}

	ev.Passed = allPassed
	if !allPassed {
		ev.Error = "kubeadm prerequisites not ready"
	}
	return CheckResult{Passed: allPassed, Evidence: ev}
}

// CheckAdminConf verifies admin.conf exists on a control plane node.
func (v *Verifier) CheckAdminConf(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "admin_conf",
	}

	if v.ssh.Check(ctx, ip, "sudo test -s /etc/kubernetes/admin.conf") {
		ev.Passed = true
		return CheckResult{Passed: true, Evidence: ev}
	}

	ev.Error = "admin.conf not found"
	return CheckResult{Passed: false, Evidence: ev}
}

// CheckKubeVipManifest verifies kube-vip manifest exists.
func (v *Verifier) CheckKubeVipManifest(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "kubevip_manifest",
	}

	if v.ssh.Check(ctx, ip, "sudo test -f /etc/kubernetes/manifests/kube-vip.yaml") {
		ev.Passed = true
		return CheckResult{Passed: true, Evidence: ev}
	}

	ev.Error = "kube-vip manifest not found"
	return CheckResult{Passed: false, Evidence: ev}
}

// CheckClusterNotInitialized verifies kubeadm has not been run on a node.
func (v *Verifier) CheckClusterNotInitialized(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "cluster_not_initialized",
	}

	if v.ssh.Check(ctx, ip, "sudo test -f /etc/kubernetes/kubelet.conf") {
		ev.Error = "cluster appears to be already initialized"
		return CheckResult{Passed: false, Evidence: ev}
	}

	ev.Passed = true
	return CheckResult{Passed: true, Evidence: ev}
}

// CheckNodeJoined verifies a node appears in the cluster.
func (v *Verifier) CheckNodeJoined(ctx context.Context, cpIP, nodeName string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Node:      nodeName,
		Check:     "node_joined",
	}

	cmd := fmt.Sprintf("kubectl --kubeconfig=/etc/kubernetes/admin.conf get node %s -o name 2>/dev/null", nodeName)
	out, err := v.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		ev.Error = "node not found in cluster"
		return CheckResult{Passed: false, Evidence: ev}
	}

	expected := "node/" + nodeName
	if strings.TrimSpace(out) == expected {
		ev.Passed = true
		ev.Output = out
		return CheckResult{Passed: true, Evidence: ev}
	}

	ev.Error = "unexpected output: " + out
	return CheckResult{Passed: false, Evidence: ev}
}

// CheckNodeReady verifies a node has Ready status.
func (v *Verifier) CheckNodeReady(ctx context.Context, cpIP, nodeName string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Node:      nodeName,
		Check:     "node_ready",
	}

	cmd := fmt.Sprintf("kubectl --kubeconfig=/etc/kubernetes/admin.conf get node %s -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' 2>/dev/null", nodeName)
	out, err := v.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		ev.Error = fmt.Sprintf("failed to get node status: %v", err)
		return CheckResult{Passed: false, Evidence: ev}
	}

	if strings.TrimSpace(out) == "True" {
		ev.Passed = true
		ev.Output = "Ready"
		return CheckResult{Passed: true, Evidence: ev}
	}

	ev.Error = "node status: " + out
	return CheckResult{Passed: false, Evidence: ev}
}

// CheckAPIReachable verifies the Kubernetes API is reachable.
func (v *Verifier) CheckAPIReachable(ctx context.Context, ip, endpoint string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "api_reachable",
	}

	cmd := fmt.Sprintf("curl -sk --connect-timeout 5 https://%s/healthz", endpoint)
	out, err := v.ssh.Output(ctx, ip, cmd)
	if err != nil {
		ev.Error = fmt.Sprintf("API not reachable: %v", err)
		return CheckResult{Passed: false, Evidence: ev}
	}

	if strings.TrimSpace(out) == "ok" {
		ev.Passed = true
		ev.Output = out
		return CheckResult{Passed: true, Evidence: ev}
	}

	ev.Error = "unexpected API response: " + out
	return CheckResult{Passed: false, Evidence: ev}
}

// CheckCNIInstalled verifies Cilium is installed and running.
func (v *Verifier) CheckCNIInstalled(ctx context.Context, cpIP string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "cni_installed",
		Details:   make(map[string]string),
	}

	// Check Cilium daemonset
	cmd := "kubectl --kubeconfig=/etc/kubernetes/admin.conf get ds -n kube-system cilium -o jsonpath='{.status.numberReady}' 2>/dev/null"
	out, err := v.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		ev.Details["cilium_ds"] = "not found"
		ev.Error = "Cilium daemonset not found"
		return CheckResult{Passed: false, Evidence: ev}
	}

	ev.Details["cilium_ready_count"] = out

	// Check CoreDNS
	cmd = "kubectl --kubeconfig=/etc/kubernetes/admin.conf get deploy -n kube-system coredns -o jsonpath='{.status.readyReplicas}' 2>/dev/null"
	out, err = v.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		ev.Details["coredns"] = "not found"
		ev.Error = "CoreDNS not found"
		return CheckResult{Passed: false, Evidence: ev}
	}

	ev.Details["coredns_ready"] = out
	ev.Passed = true
	return CheckResult{Passed: true, Evidence: ev}
}

// CheckInfraReady verifies a node is ready for k8s deployment after infra provisioning.
func (v *Verifier) CheckInfraReady(ctx context.Context, ip string) CheckResult {
	ev := Evidence{
		Timestamp: time.Now().UTC(),
		Check:     "infra_ready",
		Details:   make(map[string]string),
	}

	// SSH reachable
	if !v.ssh.Check(ctx, ip, "true") {
		ev.Details["ssh"] = statusFailed
		ev.Error = "SSH not reachable"
		return CheckResult{Passed: false, Evidence: ev}
	}
	ev.Details["ssh"] = statusOK

	// Cloud-init complete
	switch {
	case v.ssh.Check(ctx, ip, "sudo cloud-init status --wait 2>/dev/null | grep -q 'done'"):
		ev.Details["cloud_init"] = "done"
	case v.ssh.Check(ctx, ip, "test -f /var/lib/cloud/instance/boot-finished"):
		ev.Details["cloud_init"] = "done (boot-finished)"
	default:
		ev.Details["cloud_init"] = "running"
		ev.Error = "cloud-init still running"
		return CheckResult{Passed: false, Evidence: ev}
	}

	// apt lock available
	switch {
	case v.ssh.Check(ctx, ip, "sudo fuser /var/lib/dpkg/lock-frontend 2>/dev/null; test $? -eq 1"):
		ev.Details["apt_lock"] = "available"
	case v.ssh.Check(ctx, ip, "! sudo lsof /var/lib/dpkg/lock-frontend 2>/dev/null | grep -q ."):
		ev.Details["apt_lock"] = "available"
	default:
		ev.Details["apt_lock"] = "locked"
		ev.Error = "apt lock held by another process"
		return CheckResult{Passed: false, Evidence: ev}
	}

	// systemd fully booted
	if !v.ssh.Check(ctx, ip, "sudo systemctl is-system-running 2>/dev/null | grep -qE '(running|degraded)'") {
		ev.Details["systemd"] = "not ready"
		ev.Error = "systemd not fully booted"
		return CheckResult{Passed: false, Evidence: ev}
	}
	ev.Details["systemd"] = "ready"

	ev.Passed = true
	return CheckResult{Passed: true, Evidence: ev}
}
