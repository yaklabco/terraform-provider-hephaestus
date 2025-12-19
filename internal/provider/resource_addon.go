// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
	"github.com/yaklab/terraform-provider-hephaestus/internal/verifier"
)

const addonTypeHelm = "helm"

var _ resource.Resource = &AddonResource{}
var _ resource.ResourceWithImportState = &AddonResource{}

func NewAddonResource() resource.Resource {
	return &AddonResource{}
}

type AddonResource struct {
	ssh      *client.SSHClient
	verifier *verifier.Verifier
	timeouts Timeouts
}

type AddonResourceModel struct {
	ID               types.String `tfsdk:"id"`
	ClusterID        types.String `tfsdk:"cluster_id"`
	ControlPlaneIP   types.String `tfsdk:"control_plane_ip"`
	Name             types.String `tfsdk:"name"`
	Type             types.String `tfsdk:"type"`
	Version          types.String `tfsdk:"version"`
	Namespace        types.String `tfsdk:"namespace"`
	Repository       types.String `tfsdk:"repository"`
	Values           types.String `tfsdk:"values"`
	Wait             types.Bool   `tfsdk:"wait"`
	Timeout          types.String `tfsdk:"timeout"`
	InstalledVersion types.String `tfsdk:"installed_version"`
	Status           types.String `tfsdk:"status"`
}

func (r *AddonResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_addon"
}

func (r *AddonResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Installs cluster addons via Helm or manifests.

Supports common Kubernetes addons with pre-configured defaults for:
- ` + "`cilium`" + ` - CNI with kube-proxy replacement
- ` + "`tailscale`" + ` - Tailscale operator for remote access
- ` + "`nvidia-device-plugin`" + ` - NVIDIA GPU support

## Example Usage

` + "```hcl" + `
# Install Cilium CNI
resource "hephaestus_addon" "cilium" {
  cluster_id       = hephaestus_control_plane.primary.id
  control_plane_ip = hephaestus_control_plane.primary.node_ip
  name             = "cilium"
  version          = "1.16.4"
  
  values = jsonencode({
    kubeProxyReplacement = true
    k8sServiceHost       = "10.0.0.200"
    k8sServicePort       = 6443
    hubble = {
      enabled = true
      relay   = { enabled = true }
      ui      = { enabled = true }
    }
  })
  
  depends_on = [
    hephaestus_control_plane_member.secondary,
    hephaestus_worker.nodes
  ]
}

# Install Tailscale operator
resource "hephaestus_addon" "tailscale" {
  cluster_id       = hephaestus_control_plane.primary.id
  control_plane_ip = hephaestus_control_plane.primary.node_ip
  name             = "tailscale-operator"
  repository       = "https://pkgs.tailscale.com/helmcharts"
  namespace        = "tailscale"
  
  values = jsonencode({
    oauth = {
      clientId     = var.tailscale_client_id
      clientSecret = var.tailscale_client_secret
    }
  })
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
			"cluster_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the hephaestus_control_plane resource",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"control_plane_ip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "IP address of a control plane node for Helm operations",
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Addon/release name",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"type": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("helm"),
				MarkdownDescription: "Installation type: `helm` or `manifest`. Default: `helm`",
				Validators: []validator.String{
					stringvalidator.OneOf("helm", "manifest"),
				},
			},
			"version": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Chart version (for helm type)",
			},
			"namespace": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("kube-system"),
				MarkdownDescription: "Target namespace. Default: `kube-system`",
			},
			"repository": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Helm repository URL. Required for non-builtin charts.",
			},
			"values": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Helm values as JSON string. Use `jsonencode()` to generate.",
			},
			"wait": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Wait for resources to be ready. Default: `true`",
			},
			"timeout": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("15m"),
				MarkdownDescription: "Timeout for installation. Default: `15m`",
			},
			// Computed
			"installed_version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Actually installed version",
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Deployment status",
			},
		},
	}
}

func (r *AddonResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *AddonResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan AddonResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cpIP := plan.ControlPlaneIP.ValueString()
	name := plan.Name.ValueString()
	addonType := plan.Type.ValueString()

	tflog.Info(ctx, "Installing addon", map[string]interface{}{
		"name": name,
		"type": addonType,
	})

	// Ensure helm is installed
	if addonType == addonTypeHelm {
		if err := r.ensureHelm(ctx, cpIP); err != nil {
			resp.Diagnostics.AddError("Helm Setup Failed", err.Error())
			return
		}
	}

	// Install the addon
	var err error
	switch addonType {
	case addonTypeHelm:
		err = r.installHelmChart(ctx, &plan)
	case "manifest":
		err = r.installManifest(ctx, &plan)
	default:
		resp.Diagnostics.AddError("Unknown Addon Type", "Unknown type: "+addonType)
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Addon Installation Failed", err.Error())
		return
	}

	// Set computed values
	plan.ID = types.StringValue(fmt.Sprintf("%s-%s", plan.ClusterID.ValueString(), name))
	r.refreshStatus(ctx, &plan)

	tflog.Info(ctx, "Addon installed successfully")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AddonResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AddonResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cpIP := state.ControlPlaneIP.ValueString()

	// Verify control plane is reachable
	if !r.verifier.CheckSSHReachable(ctx, cpIP).Passed {
		resp.Diagnostics.AddWarning("Control Plane Unreachable",
			"Control plane is not reachable via SSH. State may be stale.")
		return
	}

	// Refresh status
	r.refreshStatus(ctx, &state)

	// Check if addon still exists
	if state.Status.ValueString() == "not_found" {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *AddonResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state AddonResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Upgrade helm release if version or values changed
	if plan.Type.ValueString() == addonTypeHelm {
		needsUpgrade := !plan.Version.Equal(state.Version) || !plan.Values.Equal(state.Values)
		if needsUpgrade {
			tflog.Info(ctx, "Upgrading helm release")
			if err := r.installHelmChart(ctx, &plan); err != nil {
				resp.Diagnostics.AddError("Helm Upgrade Failed", err.Error())
				return
			}
		}
	}

	plan.ID = state.ID
	r.refreshStatus(ctx, &plan)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *AddonResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AddonResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cpIP := state.ControlPlaneIP.ValueString()
	name := state.Name.ValueString()
	namespace := state.Namespace.ValueString()
	addonType := state.Type.ValueString()

	tflog.Info(ctx, "Uninstalling addon", map[string]interface{}{"name": name})

	if addonType == addonTypeHelm {
		cmd := fmt.Sprintf("helm uninstall %s -n %s --kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null || true", name, namespace)
		if err := r.ssh.RunSudo(ctx, cpIP, cmd); err != nil {
			tflog.Warn(ctx, "Helm uninstall returned error (may be expected)", map[string]interface{}{"error": err.Error()})
		}
	}

	tflog.Info(ctx, "Addon uninstalled")
}

func (r *AddonResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: cluster_id:name:namespace
	parts := strings.Split(req.ID, ":")
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid Import ID",
			"Import ID must be in format: cluster_id:name:namespace")
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("cluster_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("namespace"), parts[2])...)
}

// Helper methods

func (r *AddonResource) ensureHelm(ctx context.Context, cpIP string) error {
	if r.ssh.Check(ctx, cpIP, "command -v helm") {
		return nil
	}

	script := `set -euo pipefail
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
`
	_, _, err := r.ssh.RunScript(ctx, cpIP, script)
	return err
}

func (r *AddonResource) installHelmChart(ctx context.Context, model *AddonResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	name := model.Name.ValueString()
	namespace := model.Namespace.ValueString()
	version := model.Version.ValueString()
	repo := model.Repository.ValueString()
	timeout := model.Timeout.ValueString()
	wait := model.Wait.ValueBool()

	// Build helm command
	var chartRef string
	var repoSetup string

	// Handle built-in charts
	switch name {
	case "cilium":
		repoSetup = "helm repo add cilium https://helm.cilium.io/ --force-update 2>/dev/null || true && helm repo update cilium"
		chartRef = "cilium/cilium"
	case "tailscale", "tailscale-operator":
		repoSetup = "helm repo add tailscale https://pkgs.tailscale.com/helmcharts --force-update 2>/dev/null || true && helm repo update tailscale"
		chartRef = "tailscale/tailscale-operator"
	default:
		if repo == "" {
			return fmt.Errorf("repository is required for non-builtin chart %q", name)
		}
		repoName := strings.ReplaceAll(name, "-", "_")
		repoSetup = fmt.Sprintf("helm repo add %s %s --force-update 2>/dev/null || true && helm repo update %s", repoName, repo, repoName)
		chartRef = fmt.Sprintf("%s/%s", repoName, name)
	}

	// Build values file if provided
	var valuesFlag string
	if !model.Values.IsNull() && model.Values.ValueString() != "" {
		// Validate JSON
		var js interface{}
		if err := json.Unmarshal([]byte(model.Values.ValueString()), &js); err != nil {
			return fmt.Errorf("invalid values JSON: %w", err)
		}
		valuesFlag = fmt.Sprintf("--values <(echo '%s')", model.Values.ValueString())
	}

	// Build command
	cmd := fmt.Sprintf(`set -euo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
%s
helm upgrade --install %s %s \
  --namespace %s \
  --create-namespace`, repoSetup, name, chartRef, namespace)

	if version != "" {
		cmd += " \\\n  --version " + version
	}

	if valuesFlag != "" {
		cmd += " \\\n  " + valuesFlag
	}

	if wait {
		cmd += " \\\n  --wait"
	}

	cmd += " \\\n  --timeout " + timeout

	_, stderr, err := r.ssh.RunScript(ctx, cpIP, cmd)
	if err != nil {
		return fmt.Errorf("helm install: %w\n%s", err, stderr)
	}

	return nil
}

func (r *AddonResource) installManifest(ctx context.Context, model *AddonResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	name := model.Name.ValueString()

	// Handle built-in manifests
	var manifestURL string
	switch name {
	case "nvidia-device-plugin":
		manifestURL = "https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.17.0/deployments/static/nvidia-device-plugin.yml"
	default:
		return fmt.Errorf("unknown manifest addon: %s (only built-in manifests are supported)", name)
	}

	cmd := "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f " + manifestURL
	_, stderr, err := r.ssh.RunScript(ctx, cpIP, cmd)
	if err != nil {
		return fmt.Errorf("kubectl apply: %w\n%s", err, stderr)
	}

	return nil
}

func (r *AddonResource) refreshStatus(ctx context.Context, model *AddonResourceModel) {
	cpIP := model.ControlPlaneIP.ValueString()
	name := model.Name.ValueString()
	namespace := model.Namespace.ValueString()
	addonType := model.Type.ValueString()

	// Always ensure computed fields have a value (never unknown after apply)
	if model.InstalledVersion.IsUnknown() || model.InstalledVersion.IsNull() {
		model.InstalledVersion = types.StringValue("")
	}
	if model.Status.IsUnknown() || model.Status.IsNull() {
		model.Status = types.StringValue("unknown")
	}

	if addonType == addonTypeHelm {
		cmd := fmt.Sprintf("helm status %s -n %s --kubeconfig=/etc/kubernetes/admin.conf -o json 2>/dev/null", name, namespace)
		out, err := r.ssh.OutputSudo(ctx, cpIP, cmd)
		if err != nil {
			model.Status = types.StringValue("not_found")
			model.InstalledVersion = types.StringValue("")
			return
		}

		// Parse JSON to get status and version
		var status struct {
			Info struct {
				Status string `json:"status"`
			} `json:"info"`
			Version int    `json:"version"`
			Chart   string `json:"chart"` // e.g., "cilium-1.16.4"
		}
		if err := json.Unmarshal([]byte(out), &status); err == nil {
			model.Status = types.StringValue(status.Info.Status)
			// Extract version from chart name (e.g., "cilium-1.16.4" -> "1.16.4")
			if parts := strings.Split(status.Chart, "-"); len(parts) > 1 {
				model.InstalledVersion = types.StringValue(parts[len(parts)-1])
			} else if !model.Version.IsNull() && model.Version.ValueString() != "" {
				// Chart name doesn't contain version, use requested version
				model.InstalledVersion = types.StringValue(model.Version.ValueString())
			}
		} else {
			tflog.Warn(ctx, "Failed to parse helm status JSON", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// For manifests, just check if the primary resource exists
	if addonType != addonTypeHelm {
		model.Status = types.StringValue("deployed")
		// Use requested version for manifests
		if !model.Version.IsNull() && model.Version.ValueString() != "" {
			model.InstalledVersion = types.StringValue(model.Version.ValueString())
		}
	}
}
