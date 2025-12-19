// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
	"github.com/yaklab/terraform-provider-hephaestus/internal/verifier"
)

const defaultNodePrepTimeout = 10 * time.Minute

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &NodeResource{}
var _ resource.ResourceWithImportState = &NodeResource{}

// NewNodeResource creates a new node resource.
func NewNodeResource() resource.Resource {
	return &NodeResource{}
}

// NodeResource defines the resource implementation.
type NodeResource struct {
	ssh      client.SSHRunner
	verifier *verifier.Verifier
	timeouts Timeouts
}

// NodeResourceModel describes the resource data model.
type NodeResourceModel struct {
	ID                types.String `tfsdk:"id"`
	Name              types.String `tfsdk:"name"`
	IP                types.String `tfsdk:"ip"`
	Role              types.String `tfsdk:"role"`
	KubernetesVersion types.String `tfsdk:"kubernetes_version"`
	Phase             types.String `tfsdk:"phase"`
	ContainerdVersion types.String `tfsdk:"containerd_version"`
	KubeadmVersion    types.String `tfsdk:"kubeadm_version"`
}

func (r *NodeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_node"
}

func (r *NodeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Prepares a node for Kubernetes cluster membership by configuring OS prerequisites, 
installing the containerd runtime, and installing kubeadm tools (kubeadm, kubelet, kubectl).

This resource should be created before using ` + "`hephaestus_control_plane`" + `, 
` + "`hephaestus_control_plane_member`" + `, or ` + "`hephaestus_worker`" + ` resources.

## Example Usage

` + "```hcl" + `
resource "hephaestus_node" "cp1" {
  name = "k8s-cp-1"
  ip   = "10.0.0.201"
  role = "control_plane"
}

resource "hephaestus_node" "workers" {
  for_each = {
    "k8s-worker-1" = "10.0.0.204"
    "k8s-worker-2" = "10.0.0.205"
  }
  
  name = each.key
  ip   = each.value
  role = "worker"
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Node identifier (same as name)",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Node hostname. Must match the actual hostname of the node.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Node IP address for SSH access.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Node role: `control_plane`, `worker`, or `gpu_worker`",
				Validators: []validator.String{
					stringvalidator.OneOf("control_plane", "worker", "gpu_worker"),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"kubernetes_version": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("1.31.3"),
				MarkdownDescription: "Kubernetes version to install (without 'v' prefix). Default: `1.31.3`",
			},
			"phase": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current preparation phase: `os_ready`, `runtime_ready`, or `kubeadm_ready`",
			},
			"containerd_version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Installed containerd version",
			},
			"kubeadm_version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Installed kubeadm version",
			},
		},
	}
}

func (r *NodeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *NodeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan NodeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := plan.IP.ValueString()
	name := plan.Name.ValueString()
	version := plan.KubernetesVersion.ValueString()

	tflog.Info(ctx, "Creating node resource", map[string]interface{}{
		"name": name,
		"ip":   ip,
		"role": plan.Role.ValueString(),
	})

	// Wait for SSH to be available
	tflog.Debug(ctx, "Waiting for SSH availability")
	timeout, err := time.ParseDuration(r.timeouts.NodePrep)
	if err != nil {
		timeout = defaultNodePrepTimeout
	}
	if err := r.ssh.WaitForSSH(ctx, ip, timeout); err != nil {
		resp.Diagnostics.AddError("SSH Not Available", fmt.Sprintf("Cannot connect to node %s: %s", name, err))
		return
	}

	// Check if already prepared
	if r.verifier.CheckKubeadmReady(ctx, ip).Passed {
		tflog.Info(ctx, "Node already prepared, skipping")
		plan.ID = plan.Name
		plan.Phase = types.StringValue("kubeadm_ready")
		r.refreshVersions(ctx, &plan, ip)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	// Phase 1: Configure OS
	tflog.Info(ctx, "Configuring OS prerequisites")
	if err := r.configureOS(ctx, ip); err != nil {
		resp.Diagnostics.AddError("OS Configuration Failed", err.Error())
		return
	}

	// Verify OS ready
	if !r.verifier.CheckOSReady(ctx, ip).Passed {
		resp.Diagnostics.AddError("OS Configuration Failed", "OS prerequisites not met after configuration")
		return
	}
	tflog.Debug(ctx, "OS prerequisites configured")

	// Phase 2: Install containerd
	tflog.Info(ctx, "Installing containerd runtime")
	if err := r.installContainerd(ctx, ip); err != nil {
		resp.Diagnostics.AddError("Containerd Installation Failed", err.Error())
		return
	}

	// Verify runtime ready
	if !r.verifier.CheckRuntimeReady(ctx, ip).Passed {
		resp.Diagnostics.AddError("Containerd Installation Failed", "containerd not ready after installation")
		return
	}
	tflog.Debug(ctx, "Containerd installed")

	// Phase 3: Install kubeadm tools
	tflog.Info(ctx, "Installing kubeadm tools", map[string]interface{}{"version": version})
	if err := r.installKubeadm(ctx, ip, version); err != nil {
		resp.Diagnostics.AddError("Kubeadm Installation Failed", err.Error())
		return
	}

	// Verify kubeadm ready
	if !r.verifier.CheckKubeadmReady(ctx, ip).Passed {
		resp.Diagnostics.AddError("Kubeadm Installation Failed", "kubeadm tools not ready after installation")
		return
	}
	tflog.Debug(ctx, "Kubeadm tools installed")

	// Set computed values
	plan.ID = plan.Name
	plan.Phase = types.StringValue("kubeadm_ready")
	r.refreshVersions(ctx, &plan, ip)

	tflog.Info(ctx, "Node preparation complete")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NodeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state NodeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := state.IP.ValueString()
	name := state.Name.ValueString()

	tflog.Debug(ctx, "Reading node state", map[string]interface{}{"name": name, "ip": ip})

	// Verify node is reachable
	if !r.verifier.CheckSSHReachable(ctx, ip).Passed {
		resp.Diagnostics.AddWarning("Node Unreachable",
			fmt.Sprintf("Node %s is not reachable via SSH. State may be stale.", name))
		return
	}

	// Determine current phase
	phase := r.determinePhase(ctx, ip)
	state.Phase = types.StringValue(phase)

	// Refresh versions
	r.refreshVersions(ctx, &state, ip)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *NodeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state NodeResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := plan.IP.ValueString()

	// Only kubernetes_version can be updated in-place
	if !plan.KubernetesVersion.Equal(state.KubernetesVersion) {
		version := plan.KubernetesVersion.ValueString()
		tflog.Info(ctx, "Updating kubeadm tools version", map[string]interface{}{"version": version})

		if err := r.installKubeadm(ctx, ip, version); err != nil {
			resp.Diagnostics.AddError("Kubeadm Update Failed", err.Error())
			return
		}

		r.refreshVersions(ctx, &plan, ip)
	}

	plan.ID = state.ID
	plan.Phase = state.Phase
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *NodeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state NodeResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Node preparation is intentionally not cleaned up on delete.
	// The installed packages are harmless and the real cleanup
	// happens when cluster resources (control_plane, worker) are destroyed.
	tflog.Info(ctx, "Node resource deleted from state", map[string]interface{}{
		"name": state.Name.ValueString(),
	})
}

func (r *NodeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import expects format: name:ip:role
	parts := strings.Split(req.ID, ":")
	if len(parts) != 3 {
		resp.Diagnostics.AddError(
			"Invalid Import ID",
			"Import ID must be in format: name:ip:role (e.g., k8s-cp-1:10.0.0.201:control_plane)",
		)
		return
	}

	name, ip, role := parts[0], parts[1], parts[2]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), name)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("ip"), ip)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role"), role)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("kubernetes_version"), "1.31.3")...)
}

// Helper methods

func (r *NodeResource) configureOS(ctx context.Context, ip string) error {
	script := `set -euo pipefail

# Wait for apt locks
wait_for_apt() {
    local max_wait=120
    local count=0
    while [ $count -lt $max_wait ]; do
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            sleep 1
            count=$((count + 1))
            continue
        fi
        if fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
            sleep 1
            count=$((count + 1))
            continue
        fi
        break
    done
}

wait_for_apt

# Disable swap
swapoff -a || true
sed -i '/swap/d' /etc/fstab || true

# Load required kernel modules
cat > /etc/modules-load.d/k8s.conf <<EOF
overlay
br_netfilter
EOF

modprobe overlay || true
modprobe br_netfilter || true

# Configure sysctl
cat > /etc/sysctl.d/k8s.conf <<EOF
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sysctl --system >/dev/null 2>&1 || true
`
	_, _, err := r.ssh.RunScript(ctx, ip, script)
	return err
}

func (r *NodeResource) installContainerd(ctx context.Context, ip string) error {
	script := `set -euo pipefail

wait_for_apt() {
    local max_wait=120
    local count=0
    while [ $count -lt $max_wait ]; do
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
            sleep 1; count=$((count + 1)); continue
        fi
        if fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
            sleep 1; count=$((count + 1)); continue
        fi
        break
    done
}

wait_for_apt
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq containerd
mkdir -p /etc/containerd

# Handle config version mismatch and generate default config if needed
regex='^[[:space:]]*version[[:space:]]*=[[:space:]]*3[[:space:]]*$'
if [ -f /etc/containerd/config.toml ] && grep -Eq "$regex" /etc/containerd/config.toml 2>/dev/null; then
    mv /etc/containerd/config.toml "/etc/containerd/config.toml.bak.$(date +%s)"
    containerd config default > /etc/containerd/config.toml
elif [ ! -s /etc/containerd/config.toml ]; then
    containerd config default > /etc/containerd/config.toml
fi

# Configure containerd for Kubernetes
python3 << 'PYEOF'
import pathlib, re
p = pathlib.Path('/etc/containerd/config.toml')
c = p.read_text()
c = re.sub(r'(?m)^\s*SystemdCgroup\s*=\s*false\s*$', 'SystemdCgroup = true', c)
t = '  sandbox_image = "registry.k8s.io/pause:3.10"'
c = re.sub(r'(?m)^\s*sandbox_image\s*=.*$', t, c)
if 'sandbox_image' not in c:
    m = '[plugins."io.containerd.grpc.v1.cri"]'
    c = c.replace(m, m + '\n' + t)
p.write_text(c)
PYEOF

# Enable and start containerd
systemctl daemon-reload || true
systemctl enable containerd || true

for attempt in 1 2 3; do
    systemctl restart containerd && break
    sleep 2
done

# Wait for socket
for i in $(seq 1 60); do
    if [ -S /run/containerd/containerd.sock ] || [ -S /var/run/containerd/containerd.sock ]; then
        break
    fi
    sleep 1
done
`
	_, _, err := r.ssh.RunScript(ctx, ip, script)
	return err
}

func (r *NodeResource) installKubeadm(ctx context.Context, ip, version string) error {
	script := fmt.Sprintf(`set -euo pipefail

wait_for_apt() {
    local max_wait=120
    local count=0
    while [ $count -lt $max_wait ]; do
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then sleep 1; count=$((count + 1)); continue; fi
        if fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then sleep 1; count=$((count + 1)); continue; fi
        break
    done
}

wait_for_apt
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apt-transport-https ca-certificates curl gpg

mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg 2>/dev/null || true

cat > /etc/apt/sources.list.d/kubernetes.list <<EOF
deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.31/deb/ /
EOF

wait_for_apt
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq kubelet=%s-* kubeadm=%s-* kubectl=%s-*
apt-mark hold kubelet kubeadm kubectl
systemctl enable kubelet
`, version, version, version)

	_, _, err := r.ssh.RunScript(ctx, ip, script)
	return err
}

func (r *NodeResource) determinePhase(ctx context.Context, ip string) string {
	if r.verifier.CheckKubeadmReady(ctx, ip).Passed {
		return "kubeadm_ready"
	}
	if r.verifier.CheckRuntimeReady(ctx, ip).Passed {
		return "runtime_ready"
	}
	if r.verifier.CheckOSReady(ctx, ip).Passed {
		return "os_ready"
	}
	return "unknown"
}

func (r *NodeResource) refreshVersions(ctx context.Context, model *NodeResourceModel, ip string) {
	// Get containerd version
	if v, err := r.ssh.Output(ctx, ip, "containerd --version 2>/dev/null | awk '{print $3}'"); err == nil && v != "" {
		model.ContainerdVersion = types.StringValue(v)
	}

	// Get kubeadm version
	if v, err := r.ssh.Output(ctx, ip, "kubeadm version -o short 2>/dev/null | sed 's/^v//'"); err == nil && v != "" {
		model.KubeadmVersion = types.StringValue(v)
	}
}
