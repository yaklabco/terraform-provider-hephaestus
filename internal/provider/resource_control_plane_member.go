// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
	"github.com/yaklab/terraform-provider-hephaestus/internal/verifier"
)

const defaultIfaceMember = "eth0"

var _ resource.Resource = &ControlPlaneMemberResource{}
var _ resource.ResourceWithImportState = &ControlPlaneMemberResource{}

func NewControlPlaneMemberResource() resource.Resource {
	return &ControlPlaneMemberResource{}
}

type ControlPlaneMemberResource struct {
	ssh      *client.SSHClient
	verifier *verifier.Verifier
	timeouts Timeouts
}

type ControlPlaneMemberResourceModel struct {
	ID              types.String `tfsdk:"id"`
	NodeID          types.String `tfsdk:"node_id"`
	NodeIP          types.String `tfsdk:"node_ip"`
	NodeName        types.String `tfsdk:"node_name"`
	ClusterID       types.String `tfsdk:"cluster_id"`
	JoinEndpoint    types.String `tfsdk:"join_endpoint"`
	JoinToken       types.String `tfsdk:"join_token"`
	CACertHash      types.String `tfsdk:"ca_cert_hash"`
	CertificateKey  types.String `tfsdk:"certificate_key"`
	ControlPlaneVIP types.String `tfsdk:"control_plane_vip"`

	// Computed
	JoinedAt        types.String `tfsdk:"joined_at"`
	KubeVIPDeployed types.Bool   `tfsdk:"kubevip_deployed"`
}

func (r *ControlPlaneMemberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_control_plane_member"
}

func (r *ControlPlaneMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Joins an additional control plane node to an existing Kubernetes cluster for high availability.

This resource uses the join material from ` + "`hephaestus_control_plane`" + ` to join additional 
control plane nodes and deploys kube-vip on each.

## Example Usage

` + "```hcl" + `
resource "hephaestus_control_plane_member" "secondary" {
  for_each = {
    "k8s-cp-2" = hephaestus_node.cp2
    "k8s-cp-3" = hephaestus_node.cp3
  }
  
  node_id          = each.value.id
  node_ip          = each.value.ip
  node_name        = each.key
  cluster_id       = hephaestus_control_plane.primary.id
  join_endpoint    = hephaestus_control_plane.primary.api_endpoint
  join_token       = hephaestus_control_plane.primary.join_token
  ca_cert_hash     = hephaestus_control_plane.primary.ca_cert_hash
  certificate_key  = hephaestus_control_plane.primary.certificate_key
  control_plane_vip = hephaestus_control_plane.primary.control_plane_vip
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Resource identifier",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"node_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the hephaestus_node resource",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"node_ip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "IP address of the node",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"node_name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Hostname of the node",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"cluster_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the hephaestus_control_plane resource",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"join_endpoint": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "API endpoint to join (from control_plane.api_endpoint)",
			},
			"join_token": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Join token (from control_plane.join_token)",
			},
			"ca_cert_hash": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "CA certificate hash (from control_plane.ca_cert_hash)",
			},
			"certificate_key": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Certificate key for control plane join (from control_plane.certificate_key)",
			},
			"control_plane_vip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Control plane VIP for kube-vip deployment",
			},
			// Computed
			"joined_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the node joined the cluster",
			},
			"kubevip_deployed": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether kube-vip is deployed on this node",
			},
		},
	}
}

func (r *ControlPlaneMemberResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ProviderData, got: %T", req.ProviderData),
		)
		return
	}

	r.ssh = providerData.SSHClient
	r.verifier = providerData.Verifier
	r.timeouts = providerData.Timeouts
}

func (r *ControlPlaneMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ControlPlaneMemberResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := plan.NodeIP.ValueString()
	name := plan.NodeName.ValueString()
	endpoint := plan.JoinEndpoint.ValueString()
	vip := plan.ControlPlaneVIP.ValueString()

	tflog.Info(ctx, "Joining control plane member", map[string]interface{}{
		"name":     name,
		"ip":       ip,
		"endpoint": endpoint,
	})

	// Verify node is prepared
	if !r.verifier.CheckKubeadmReady(ctx, ip).Passed {
		resp.Diagnostics.AddError("Node Not Prepared",
			"The referenced node is not prepared. Ensure hephaestus_node resource is created first.")
		return
	}

	// Check if already joined
	// We need to find the first CP to check - extract from endpoint
	endpointIP := strings.Split(endpoint, ":")[0]
	if r.verifier.CheckNodeJoined(ctx, endpointIP, name).Passed {
		tflog.Info(ctx, "Node already joined to cluster")
		plan.ID = types.StringValue(fmt.Sprintf("%s-%s", plan.ClusterID.ValueString(), name))
		plan.JoinedAt = types.StringValue(time.Now().Format(time.RFC3339))
		plan.KubeVIPDeployed = types.BoolValue(r.verifier.CheckKubeVipManifest(ctx, ip).Passed)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	// Join cluster as control plane
	script := fmt.Sprintf(`set -euo pipefail
kubeadm join %s --token %s --discovery-token-ca-cert-hash %s --control-plane --certificate-key %s
`, endpoint, plan.JoinToken.ValueString(), plan.CACertHash.ValueString(), plan.CertificateKey.ValueString())

	_, stderr, err := r.ssh.RunScript(ctx, ip, script)
	if err != nil {
		resp.Diagnostics.AddError("kubeadm join Failed", fmt.Sprintf("%s\n%s", err, stderr))
		return
	}

	// Deploy kube-vip
	tflog.Info(ctx, "Deploying kube-vip on member")
	iface, err := r.ssh.Output(ctx, ip, "ip route show default | head -n 1 | cut -d' ' -f5")
	if err != nil || iface == "" {
		iface = defaultIfaceMember
	}
	if err := r.deployKubeVip(ctx, ip, vip, strings.TrimSpace(iface)); err != nil {
		resp.Diagnostics.AddWarning("kube-vip Deployment Warning", err.Error())
	}

	// Set computed values
	plan.ID = types.StringValue(fmt.Sprintf("%s-%s", plan.ClusterID.ValueString(), name))
	plan.JoinedAt = types.StringValue(time.Now().Format(time.RFC3339))
	plan.KubeVIPDeployed = types.BoolValue(r.verifier.CheckKubeVipManifest(ctx, ip).Passed)

	tflog.Info(ctx, "Control plane member joined successfully")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ControlPlaneMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ControlPlaneMemberResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := state.NodeIP.ValueString()
	name := state.NodeName.ValueString()
	endpoint := state.JoinEndpoint.ValueString()

	// Verify node is reachable
	if !r.verifier.CheckSSHReachable(ctx, ip).Passed {
		resp.Diagnostics.AddWarning("Node Unreachable",
			fmt.Sprintf("Node %s is not reachable via SSH. State may be stale.", name))
		return
	}

	// Check if still joined
	endpointIP := strings.Split(endpoint, ":")[0]
	if !r.verifier.CheckNodeJoined(ctx, endpointIP, name).Passed {
		resp.State.RemoveResource(ctx)
		return
	}

	// Update kube-vip status
	state.KubeVIPDeployed = types.BoolValue(r.verifier.CheckKubeVipManifest(ctx, ip).Passed)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ControlPlaneMemberResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ControlPlaneMemberResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Preserve computed values - most fields require replacement
	plan.ID = state.ID
	plan.JoinedAt = state.JoinedAt
	plan.KubeVIPDeployed = state.KubeVIPDeployed

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ControlPlaneMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ControlPlaneMemberResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := state.NodeIP.ValueString()
	name := state.NodeName.ValueString()

	tflog.Info(ctx, "Removing control plane member", map[string]interface{}{"name": name})

	// Drain and delete node from cluster first
	endpoint := state.JoinEndpoint.ValueString()
	endpointIP := strings.Split(endpoint, ":")[0]

	drainScript := fmt.Sprintf(`
kubectl --kubeconfig=/etc/kubernetes/admin.conf drain %s \
  --ignore-daemonsets --delete-emptydir-data --force 2>/dev/null || true
kubectl --kubeconfig=/etc/kubernetes/admin.conf delete node %s 2>/dev/null || true
`, name, name)
	if _, _, err := r.ssh.RunScript(ctx, endpointIP, drainScript); err != nil {
		tflog.Warn(ctx, "Drain script returned error (may be expected)", map[string]interface{}{"error": err.Error()})
	}

	// Reset the node
	resetScript := `set -euo pipefail
kubeadm reset -f 2>/dev/null || true
rm -rf /etc/cni/net.d/* 2>/dev/null || true
rm -rf /var/lib/etcd/* 2>/dev/null || true
rm -rf /etc/kubernetes/manifests/* 2>/dev/null || true
`
	_, _, err := r.ssh.RunScript(ctx, ip, resetScript)
	if err != nil {
		resp.Diagnostics.AddWarning("Reset Warning",
			fmt.Sprintf("Node reset may have failed: %s", err))
	}

	tflog.Info(ctx, "Control plane member removed")
}

func (r *ControlPlaneMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: node_name:node_ip:cluster_id
	parts := strings.Split(req.ID, ":")
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid Import ID",
			"Import ID must be in format: node_name:node_ip:cluster_id")
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node_name"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node_ip"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("cluster_id"), parts[2])...)
}

func (r *ControlPlaneMemberResource) deployKubeVip(ctx context.Context, ip, vip, iface string) error {
	manifest := fmt.Sprintf(`apiVersion: v1
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
    image: ghcr.io/kube-vip/kube-vip:v0.8.0
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
`, iface, vip)

	return r.ssh.WriteFile(ctx, ip, "/etc/kubernetes/manifests/kube-vip.yaml", manifest)
}
