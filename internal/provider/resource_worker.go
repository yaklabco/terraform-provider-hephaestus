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

var _ resource.Resource = &WorkerResource{}
var _ resource.ResourceWithImportState = &WorkerResource{}

func NewWorkerResource() resource.Resource {
	return &WorkerResource{}
}

type WorkerResource struct {
	ssh      *client.SSHClient
	verifier *verifier.Verifier
	timeouts Timeouts
}

type WorkerResourceModel struct {
	ID           types.String `tfsdk:"id"`
	NodeID       types.String `tfsdk:"node_id"`
	NodeIP       types.String `tfsdk:"node_ip"`
	NodeName     types.String `tfsdk:"node_name"`
	ClusterID    types.String `tfsdk:"cluster_id"`
	JoinEndpoint types.String `tfsdk:"join_endpoint"`
	JoinToken    types.String `tfsdk:"join_token"`
	CACertHash   types.String `tfsdk:"ca_cert_hash"`
	Labels       types.Map    `tfsdk:"labels"`

	// Computed
	JoinedAt types.String `tfsdk:"joined_at"`
	Status   types.String `tfsdk:"status"`
}

func (r *WorkerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_worker"
}

func (r *WorkerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Joins a worker node to an existing Kubernetes cluster.

This resource uses the join material from ` + "`hephaestus_control_plane`" + ` to join worker nodes.
Worker nodes only require the join token and CA hash (not the certificate key).

## Example Usage

` + "```hcl" + `
resource "hephaestus_worker" "nodes" {
  for_each = {
    "k8s-worker-1" = { ip = "10.0.0.204", gpu = false }
    "k8s-worker-2" = { ip = "10.0.0.205", gpu = false }
    "k8s-gpu-1"    = { ip = "10.0.0.206", gpu = true }
  }
  
  node_id       = hephaestus_node.workers[each.key].id
  node_ip       = each.value.ip
  node_name     = each.key
  cluster_id    = hephaestus_control_plane.primary.id
  join_endpoint = hephaestus_control_plane.primary.api_endpoint
  join_token    = hephaestus_control_plane.primary.join_token
  ca_cert_hash  = hephaestus_control_plane.primary.ca_cert_hash
  
  labels = each.value.gpu ? {
    "nvidia.com/gpu"                        = "true"
    "node-role.kubernetes.io/gpu-worker"    = ""
  } : {
    "node-role.kubernetes.io/worker"        = ""
  }
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
			"labels": schema.MapAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Labels to apply to the node after joining",
			},
			// Computed
			"joined_at": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Timestamp when the node joined the cluster",
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current node status (Ready/NotReady)",
			},
		},
	}
}

func (r *WorkerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *WorkerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan WorkerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := plan.NodeIP.ValueString()
	name := plan.NodeName.ValueString()
	endpoint := plan.JoinEndpoint.ValueString()

	tflog.Info(ctx, "Joining worker node", map[string]interface{}{
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
	endpointIP := strings.Split(endpoint, ":")[0]
	if r.verifier.CheckNodeJoined(ctx, endpointIP, name).Passed {
		tflog.Info(ctx, "Node already joined to cluster")
		plan.ID = types.StringValue(fmt.Sprintf("%s-%s", plan.ClusterID.ValueString(), name))
		plan.JoinedAt = types.StringValue(time.Now().Format(time.RFC3339))
		r.updateStatus(ctx, &plan, endpointIP, name)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	// Join cluster as worker
	script := fmt.Sprintf(`set -euo pipefail
kubeadm join %s --token %s --discovery-token-ca-cert-hash %s
`, endpoint, plan.JoinToken.ValueString(), plan.CACertHash.ValueString())

	_, stderr, err := r.ssh.RunScript(ctx, ip, script)
	if err != nil {
		resp.Diagnostics.AddError("kubeadm join Failed", fmt.Sprintf("%s\n%s", err, stderr))
		return
	}

	// Apply labels
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		labels := make(map[string]string)
		resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &labels, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		if len(labels) > 0 {
			if err := r.applyLabels(ctx, endpointIP, name, labels); err != nil {
				resp.Diagnostics.AddWarning("Label Application Warning", err.Error())
			}
		}
	}

	// Set computed values
	plan.ID = types.StringValue(fmt.Sprintf("%s-%s", plan.ClusterID.ValueString(), name))
	plan.JoinedAt = types.StringValue(time.Now().Format(time.RFC3339))
	r.updateStatus(ctx, &plan, endpointIP, name)

	tflog.Info(ctx, "Worker node joined successfully")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *WorkerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state WorkerResourceModel
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

	// Update status
	r.updateStatus(ctx, &state, endpointIP, name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *WorkerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state WorkerResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := plan.NodeName.ValueString()
	endpoint := plan.JoinEndpoint.ValueString()
	endpointIP := strings.Split(endpoint, ":")[0]

	// Handle label changes
	if !plan.Labels.Equal(state.Labels) {
		labels := make(map[string]string)
		if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
			resp.Diagnostics.Append(plan.Labels.ElementsAs(ctx, &labels, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}

		// Remove old labels, apply new ones
		oldLabels := make(map[string]string)
		if !state.Labels.IsNull() && !state.Labels.IsUnknown() {
			_ = state.Labels.ElementsAs(ctx, &oldLabels, false)
		}

		// Remove labels that are in old but not in new
		for k := range oldLabels {
			if _, exists := labels[k]; !exists {
				if err := r.removeLabel(ctx, endpointIP, name, k); err != nil {
					tflog.Warn(ctx, "Failed to remove label", map[string]interface{}{
						"label": k,
						"error": err.Error(),
					})
				}
			}
		}

		// Apply new labels
		if len(labels) > 0 {
			if err := r.applyLabels(ctx, endpointIP, name, labels); err != nil {
				resp.Diagnostics.AddWarning("Label Update Warning", err.Error())
			}
		}
	}

	// Preserve computed values
	plan.ID = state.ID
	plan.JoinedAt = state.JoinedAt
	r.updateStatus(ctx, &plan, endpointIP, name)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *WorkerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state WorkerResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := state.NodeIP.ValueString()
	name := state.NodeName.ValueString()
	endpoint := state.JoinEndpoint.ValueString()

	tflog.Info(ctx, "Removing worker node", map[string]interface{}{"name": name})

	// Drain and delete node from cluster
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
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -X 2>/dev/null || true
`
	_, _, err := r.ssh.RunScript(ctx, ip, resetScript)
	if err != nil {
		resp.Diagnostics.AddWarning("Reset Warning",
			fmt.Sprintf("Node reset may have failed: %s", err))
	}

	tflog.Info(ctx, "Worker node removed")
}

func (r *WorkerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
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

func (r *WorkerResource) applyLabels(ctx context.Context, cpIP, nodeName string, labels map[string]string) error {
	for labelKey, labelVal := range labels {
		var cmd string
		if labelVal == "" {
			cmd = fmt.Sprintf("kubectl --kubeconfig=/etc/kubernetes/admin.conf label node %s %s= --overwrite", nodeName, labelKey)
		} else {
			cmd = fmt.Sprintf("kubectl --kubeconfig=/etc/kubernetes/admin.conf label node %s %s=%s --overwrite", nodeName, labelKey, labelVal)
		}
		if err := r.ssh.RunSudo(ctx, cpIP, cmd); err != nil {
			return fmt.Errorf("failed to apply label %s: %w", labelKey, err)
		}
	}
	return nil
}

func (r *WorkerResource) removeLabel(ctx context.Context, cpIP, nodeName, label string) error {
	cmd := fmt.Sprintf("kubectl --kubeconfig=/etc/kubernetes/admin.conf label node %s %s- 2>/dev/null || true", nodeName, label)
	return r.ssh.RunSudo(ctx, cpIP, cmd)
}

func (r *WorkerResource) updateStatus(ctx context.Context, model *WorkerResourceModel, cpIP, nodeName string) {
	result := r.verifier.CheckNodeReady(ctx, cpIP, nodeName)
	if result.Passed {
		model.Status = types.StringValue("Ready")
	} else {
		model.Status = types.StringValue("NotReady")
	}
}
