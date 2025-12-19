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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
	"github.com/yaklab/terraform-provider-hephaestus/internal/verifier"
)

// Using constants from constants.go for consistency.

var _ resource.Resource = &ControlPlaneResource{}
var _ resource.ResourceWithImportState = &ControlPlaneResource{}

func NewControlPlaneResource() resource.Resource {
	return &ControlPlaneResource{}
}

type ControlPlaneResource struct {
	ssh      *client.SSHClient
	verifier *verifier.Verifier
	timeouts Timeouts
}

type ControlPlaneResourceModel struct {
	ID               types.String `tfsdk:"id"`
	NodeID           types.String `tfsdk:"node_id"`
	NodeIP           types.String `tfsdk:"node_ip"`
	ControlPlaneVIP  types.String `tfsdk:"control_plane_vip"`
	PodCIDR          types.String `tfsdk:"pod_cidr"`
	ServiceCIDR      types.String `tfsdk:"service_cidr"`
	KubeVIPVersion   types.String `tfsdk:"kubevip_version"`
	KubeVIPInterface types.String `tfsdk:"kubevip_interface"`

	// Computed - join material
	JoinToken      types.String `tfsdk:"join_token"`
	CACertHash     types.String `tfsdk:"ca_cert_hash"`
	CertificateKey types.String `tfsdk:"certificate_key"`
	TokenExpiry    types.String `tfsdk:"token_expiry"`

	// Computed - cluster info
	APIEndpoint types.String `tfsdk:"api_endpoint"`
	Kubeconfig  types.String `tfsdk:"kubeconfig"`
}

func (r *ControlPlaneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_control_plane"
}

func (r *ControlPlaneResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Initializes the first control plane node of a Kubernetes cluster using kubeadm init
and deploys kube-vip for high availability.

This resource must reference a ` + "`hephaestus_node`" + ` resource that has been prepared with the 
` + "`control_plane`" + ` role.

The resource outputs join material (token, CA hash, certificate key) that is used by 
` + "`hephaestus_control_plane_member`" + ` and ` + "`hephaestus_worker`" + ` resources to join the cluster.

## Example Usage

` + "```hcl" + `
resource "hephaestus_node" "cp1" {
  name = "k8s-cp-1"
  ip   = "10.0.0.201"
  role = "control_plane"
}

resource "hephaestus_control_plane" "primary" {
  node_id           = hephaestus_node.cp1.id
  node_ip           = hephaestus_node.cp1.ip
  control_plane_vip = "10.0.0.200"
  pod_cidr          = "10.244.0.0/16"
  service_cidr      = "10.96.0.0/12"
}

output "kubeconfig" {
  value     = hephaestus_control_plane.primary.kubeconfig
  sensitive = true
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Cluster identifier",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"node_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "ID of the hephaestus_node resource for the first control plane",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"node_ip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "IP address of the first control plane node",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"control_plane_vip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Virtual IP for high availability control plane access",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"pod_cidr": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("10.244.0.0/16"),
				MarkdownDescription: "Pod network CIDR. Default: `10.244.0.0/16`",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"service_cidr": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("10.96.0.0/12"),
				MarkdownDescription: "Service network CIDR. Default: `10.96.0.0/12`",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"kubevip_version": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("v0.8.0"),
				MarkdownDescription: "kube-vip version. Default: `v0.8.0`",
			},
			"kubevip_interface": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Network interface for kube-vip. If not set, auto-detected from default route.",
			},
			// Computed outputs
			"join_token": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Bootstrap token for joining nodes (expires after 24h)",
			},
			"ca_cert_hash": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "CA certificate hash for secure joining",
			},
			"certificate_key": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Certificate key for control plane joins",
			},
			"token_expiry": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Token expiration timestamp (RFC3339)",
			},
			"api_endpoint": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Kubernetes API endpoint (VIP:6443)",
			},
			"kubeconfig": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Admin kubeconfig for cluster access",
			},
		},
	}
}

func (r *ControlPlaneResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ControlPlaneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ControlPlaneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := plan.NodeIP.ValueString()
	vip := plan.ControlPlaneVIP.ValueString()

	tflog.Info(ctx, "Creating control plane", map[string]interface{}{
		"node_id": plan.NodeID.ValueString(),
		"ip":      ip,
		"vip":     vip,
	})

	// Verify node is prepared
	if !r.verifier.CheckKubeadmReady(ctx, ip).Passed {
		resp.Diagnostics.AddError("Node Not Prepared",
			"The referenced node is not prepared. Ensure hephaestus_node resource is created first.")
		return
	}

	// Check if already initialized
	if r.verifier.CheckAdminConf(ctx, ip).Passed {
		tflog.Info(ctx, "Control plane already initialized")
		plan.ID = types.StringValue(fmt.Sprintf("cluster-%d", time.Now().Unix()))
		plan.APIEndpoint = types.StringValue(vip + ":6443")
		r.refreshJoinMaterial(ctx, &plan, ip)
		r.refreshKubeconfig(ctx, &plan, ip, vip)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	// Get kubernetes version from node
	kubeVersion, err := r.ssh.Output(ctx, ip, "kubeadm version -o short 2>/dev/null")
	if err != nil {
		kubeVersion = "v1.31.3"
	}
	kubeVersion = strings.TrimSpace(kubeVersion)

	// Step 1: kubeadm init
	tflog.Info(ctx, "Running kubeadm init")
	if err := r.kubeadmInit(ctx, ip, vip, plan.PodCIDR.ValueString(), plan.ServiceCIDR.ValueString(), kubeVersion); err != nil {
		resp.Diagnostics.AddError("kubeadm init Failed", err.Error())
		return
	}

	// Step 2: Deploy kube-vip
	tflog.Info(ctx, "Deploying kube-vip")
	iface := plan.KubeVIPInterface.ValueString()
	if iface == "" {
		// Auto-detect interface
		detectedIface, err := r.ssh.Output(ctx, ip, "ip route show default | head -n 1 | cut -d' ' -f5")
		if err != nil || detectedIface == "" {
			iface = DefaultNetworkInterface
		} else {
			iface = detectedIface
		}
	}
	if err := r.deployKubeVip(ctx, ip, vip, strings.TrimSpace(iface), plan.KubeVIPVersion.ValueString()); err != nil {
		resp.Diagnostics.AddError("kube-vip Deployment Failed", err.Error())
		return
	}

	// Step 3: Wait for VIP to become ready
	tflog.Info(ctx, "Waiting for VIP to become ready")
	if err := r.waitForVIP(ctx, ip, vip); err != nil {
		resp.Diagnostics.AddError("VIP Not Ready", err.Error())
		return
	}

	// Step 4: Update configs to use VIP
	tflog.Info(ctx, "Patching cluster configuration to use VIP")
	if err := r.patchClusterConfig(ctx, ip, vip); err != nil {
		resp.Diagnostics.AddError("Config Patch Failed", err.Error())
		return
	}

	// Set computed values
	plan.ID = types.StringValue(fmt.Sprintf("cluster-%d", time.Now().Unix()))
	plan.APIEndpoint = types.StringValue(vip + ":6443")

	// Extract join material
	r.refreshJoinMaterial(ctx, &plan, ip)
	r.refreshKubeconfig(ctx, &plan, ip, vip)

	tflog.Info(ctx, "Control plane initialization complete")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ControlPlaneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ControlPlaneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := state.NodeIP.ValueString()
	vip := state.ControlPlaneVIP.ValueString()

	// Verify node is reachable
	if !r.verifier.CheckSSHReachable(ctx, ip).Passed {
		resp.Diagnostics.AddWarning("Node Unreachable",
			"Control plane node is not reachable via SSH. State may be stale.")
		return
	}

	// Verify cluster is still initialized
	if !r.verifier.CheckAdminConf(ctx, ip).Passed {
		resp.State.RemoveResource(ctx)
		return
	}

	// Check token expiry and refresh if needed
	if state.TokenExpiry.ValueString() != "" {
		expiry, err := time.Parse(time.RFC3339, state.TokenExpiry.ValueString())
		if err == nil && time.Now().Add(1*time.Hour).After(expiry) {
			tflog.Info(ctx, "Refreshing join token (approaching expiry)")
			r.refreshJoinMaterial(ctx, &state, ip)
		}
	}

	// Refresh kubeconfig (server address might need update)
	r.refreshKubeconfig(ctx, &state, ip, vip)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ControlPlaneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ControlPlaneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := plan.NodeIP.ValueString()

	// Most attributes require replacement, only kubevip_version can be updated
	if !plan.KubeVIPVersion.Equal(state.KubeVIPVersion) {
		tflog.Info(ctx, "Updating kube-vip version")
		iface := plan.KubeVIPInterface.ValueString()
		if iface == "" {
			detectedIface, err := r.ssh.Output(ctx, ip, "ip route show default | head -n 1 | cut -d' ' -f5")
			if err != nil || detectedIface == "" {
				iface = DefaultNetworkInterface
			} else {
				iface = detectedIface
			}
		}
		if err := r.deployKubeVip(ctx, ip, plan.ControlPlaneVIP.ValueString(), strings.TrimSpace(iface), plan.KubeVIPVersion.ValueString()); err != nil {
			resp.Diagnostics.AddError("kube-vip Update Failed", err.Error())
			return
		}
	}

	// Preserve computed values
	plan.ID = state.ID
	plan.JoinToken = state.JoinToken
	plan.CACertHash = state.CACertHash
	plan.CertificateKey = state.CertificateKey
	plan.TokenExpiry = state.TokenExpiry
	plan.APIEndpoint = state.APIEndpoint
	plan.Kubeconfig = state.Kubeconfig

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ControlPlaneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ControlPlaneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ip := state.NodeIP.ValueString()

	tflog.Info(ctx, "Resetting control plane", map[string]interface{}{"ip": ip})

	// Run kubeadm reset
	script := `set -euo pipefail
kubeadm reset -f 2>/dev/null || true
rm -rf /etc/cni/net.d/* 2>/dev/null || true
rm -rf /var/lib/etcd/* 2>/dev/null || true
rm -rf /etc/kubernetes/manifests/* 2>/dev/null || true
iptables -F 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -X 2>/dev/null || true
ipvsadm -C 2>/dev/null || true
`
	_, _, err := r.ssh.RunScript(ctx, ip, script)
	if err != nil {
		resp.Diagnostics.AddWarning("Reset Warning",
			fmt.Sprintf("kubeadm reset may have failed: %s", err))
	}

	tflog.Info(ctx, "Control plane reset complete")
}

func (r *ControlPlaneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import format: node_ip:vip
	parts := strings.Split(req.ID, ":")
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid Import ID",
			"Import ID must be in format: node_ip:control_plane_vip (e.g., 10.0.0.201:10.0.0.200)")
		return
	}

	nodeIP, vip := parts[0], parts[1]

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node_ip"), nodeIP)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("control_plane_vip"), vip)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("api_endpoint"), vip+":6443")...)
}

// Helper methods

func (r *ControlPlaneResource) kubeadmInit(ctx context.Context, ip, vip, podCIDR, serviceCIDR, kubeVersion string) error {
	script := fmt.Sprintf(`set -euo pipefail
kubeadm init \
  --control-plane-endpoint "%s:6443" \
  --upload-certs \
  --apiserver-cert-extra-sans "%s" \
  --pod-network-cidr "%s" \
  --service-cidr "%s" \
  --kubernetes-version "%s"
`, ip, vip, podCIDR, serviceCIDR, kubeVersion)

	_, stderr, err := r.ssh.RunScript(ctx, ip, script)
	if err != nil {
		return fmt.Errorf("kubeadm init: %w\n%s", err, stderr)
	}
	return nil
}

func (r *ControlPlaneResource) deployKubeVip(ctx context.Context, ip, vip, iface, version string) error {
	manifest := GenerateKubeVIPManifest(KubeVIPConfig{
		Interface: iface,
		VIP:       vip,
		Version:   version,
	})
	return r.ssh.WriteFile(ctx, ip, "/etc/kubernetes/manifests/kube-vip.yaml", manifest)
}

func (r *ControlPlaneResource) waitForVIP(ctx context.Context, ip, vip string) error {
	timeout := DefaultVIPWaitTimeout
	checkInterval := DefaultCheckInterval
	deadline := time.Now().Add(timeout)

	cmd := fmt.Sprintf("curl -sk --connect-timeout 3 https://%s:%d/healthz", vip, KubernetesAPIPort)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		out, err := r.ssh.Output(ctx, ip, cmd)
		if err == nil && out == "ok" {
			return nil
		}

		time.Sleep(checkInterval)
	}

	return fmt.Errorf("timeout waiting for VIP %s to respond", vip)
}

func (r *ControlPlaneResource) patchClusterConfig(ctx context.Context, ip, vip string) error {
	// Update admin.conf to use VIP
	script := fmt.Sprintf(`set -euo pipefail
KUBECONFIG=/etc/kubernetes/admin.conf
sed -i 's|server: https://%s:6443|server: https://%s:6443|g' $KUBECONFIG

# Patch kubeadm-config ConfigMap
kubectl --kubeconfig=$KUBECONFIG -n kube-system \
  get cm kubeadm-config -o jsonpath='{.data.ClusterConfiguration}' > /tmp/cluster-config.yaml
sed -i 's|controlPlaneEndpoint:.*|controlPlaneEndpoint: %s:6443|' /tmp/cluster-config.yaml
kubectl --kubeconfig=$KUBECONFIG -n kube-system \
  create cm kubeadm-config --from-file=ClusterConfiguration=/tmp/cluster-config.yaml \
  --dry-run=client -o yaml | kubectl --kubeconfig=$KUBECONFIG apply -f -
rm -f /tmp/cluster-config.yaml

# Patch cluster-info ConfigMap
kubectl --kubeconfig=$KUBECONFIG -n kube-public \
  get cm cluster-info -o jsonpath='{.data.kubeconfig}' > /tmp/cluster-info-kubeconfig.yaml
sed -i 's|server: https://%s:6443|server: https://%s:6443|g' /tmp/cluster-info-kubeconfig.yaml
kubectl --kubeconfig=$KUBECONFIG -n kube-public \
  create cm cluster-info --from-file=kubeconfig=/tmp/cluster-info-kubeconfig.yaml \
  --dry-run=client -o yaml | kubectl --kubeconfig=$KUBECONFIG apply -f -
rm -f /tmp/cluster-info-kubeconfig.yaml
`, ip, vip, vip, ip, vip)

	_, _, err := r.ssh.RunScript(ctx, ip, script)
	return err
}

func (r *ControlPlaneResource) refreshJoinMaterial(ctx context.Context, model *ControlPlaneResourceModel, ip string) {
	// Create new token
	token, err := r.ssh.OutputSudo(ctx, ip, "kubeadm token create")
	if err == nil {
		model.JoinToken = types.StringValue(strings.TrimSpace(token))
		model.TokenExpiry = types.StringValue(time.Now().Add(TokenExpiryHours * time.Hour).Format(time.RFC3339))
	}

	// Get CA hash
	hashCmd := "openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //'"
	hash, err := r.ssh.OutputSudo(ctx, ip, hashCmd)
	if err == nil {
		model.CACertHash = types.StringValue("sha256:" + strings.TrimSpace(hash))
	}

	// Get certificate key
	certKey, err := r.ssh.OutputSudo(ctx, ip, "kubeadm init phase upload-certs --upload-certs 2>/dev/null | tail -1")
	if err == nil {
		model.CertificateKey = types.StringValue(strings.TrimSpace(certKey))
	}
}

func (r *ControlPlaneResource) refreshKubeconfig(ctx context.Context, model *ControlPlaneResourceModel, ip, vip string) {
	kubeconfig, err := r.ssh.OutputSudo(ctx, ip, "cat /etc/kubernetes/admin.conf")
	if err == nil {
		// Replace server address with VIP
		kubeconfig = strings.ReplaceAll(kubeconfig, fmt.Sprintf("server: https://%s:6443", ip), fmt.Sprintf("server: https://%s:6443", vip))
		model.Kubeconfig = types.StringValue(kubeconfig)
	}
}
