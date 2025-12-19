// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
	"github.com/yaklab/terraform-provider-hephaestus/internal/verifier"
)

const (
	defaultHTTPSPort    = 443
	apiWaitTimeout      = 5 * time.Minute
	apiWaitPollInterval = 10 * time.Second
)

var _ resource.Resource = &TailscaleResource{}
var _ resource.ResourceWithImportState = &TailscaleResource{}

func NewTailscaleResource() resource.Resource {
	return &TailscaleResource{}
}

type TailscaleResource struct {
	ssh      *client.SSHClient
	verifier *verifier.Verifier
	timeouts Timeouts
}

type TailscaleResourceModel struct {
	ID                types.String `tfsdk:"id"`
	ClusterID         types.String `tfsdk:"cluster_id"`
	ControlPlaneIP    types.String `tfsdk:"control_plane_ip"`
	OAuthClientID     types.String `tfsdk:"oauth_client_id"`
	OAuthClientSecret types.String `tfsdk:"oauth_client_secret"`
	Namespace         types.String `tfsdk:"namespace"`
	Version           types.String `tfsdk:"version"`
	HostnamePrefix    types.String `tfsdk:"hostname_prefix"`
	Tags              types.List   `tfsdk:"tags"`

	// API Server exposure
	ExposeAPIServer   types.Bool   `tfsdk:"expose_api_server"`
	APIServerHostname types.String `tfsdk:"api_server_hostname"`
	APIServerPort     types.Int64  `tfsdk:"api_server_port"`

	// Subnet router
	EnableSubnetRouter types.Bool   `tfsdk:"enable_subnet_router"`
	SubnetRoutes       types.List   `tfsdk:"subnet_routes"`
	AuthKey            types.String `tfsdk:"auth_key"`

	// Computed outputs
	InstalledVersion     types.String `tfsdk:"installed_version"`
	Status               types.String `tfsdk:"status"`
	TailscaleKubeconfig  types.String `tfsdk:"tailscale_kubeconfig"`
	APIServerTailscaleIP types.String `tfsdk:"api_server_tailscale_ip"`
}

func (r *TailscaleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tailscale"
}

func (r *TailscaleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Installs and configures Tailscale integration for the Kubernetes cluster.

This resource provides:
- **Tailscale Operator**: Manages Tailscale proxies for annotated services
- **K8s API Exposure**: Exposes the Kubernetes API on your tailnet for remote kubectl access
- **Subnet Router**: Optionally exposes pod and service CIDRs to your tailnet
- **Remote Kubeconfig**: Generates a kubeconfig using the Tailscale endpoint

## Prerequisites

1. Create an OAuth client at https://login.tailscale.com/admin/settings/oauth
2. Required scopes: devices:core (write), auth_keys (write)
3. Configure ACL tags in your Tailscale policy

## Example Usage

` + "```hcl" + `
resource "hephaestus_tailscale" "main" {
  cluster_id         = hephaestus_control_plane.primary.id
  control_plane_ip   = hephaestus_control_plane.primary.node_ip
  oauth_client_id    = var.tailscale_oauth_client_id
  oauth_client_secret = var.tailscale_oauth_client_secret
  
  # Expose K8s API on tailnet
  expose_api_server    = true
  api_server_hostname  = "hephaestus-k8s-api"
  
  # Optional: Subnet router for full cluster access
  enable_subnet_router = false
  subnet_routes        = ["10.244.0.0/16", "10.96.0.0/12"]
  
  depends_on = [hephaestus_addon.cilium]
}

output "tailscale_kubeconfig" {
  value     = hephaestus_tailscale.main.tailscale_kubeconfig
  sensitive = true
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
				MarkdownDescription: "Cluster identifier from control_plane resource",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"control_plane_ip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "IP address of a control plane node for kubectl/helm operations",
			},
			"oauth_client_id": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Tailscale OAuth client ID",
			},
			"oauth_client_secret": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Tailscale OAuth client secret",
			},
			"namespace": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("tailscale"),
				MarkdownDescription: "Kubernetes namespace for Tailscale components. Default: `tailscale`",
			},
			"version": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Tailscale operator Helm chart version",
			},
			"hostname_prefix": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("hephaestus-k8s"),
				MarkdownDescription: "Prefix for Tailscale hostnames. Default: `hephaestus-k8s`",
			},
			"tags": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "ACL tags to apply to Tailscale nodes (e.g., [\"tag:k8s\"])",
			},
			// API Server exposure
			"expose_api_server": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
				MarkdownDescription: "Create a service to expose the Kubernetes API on your tailnet. Default: `true`",
			},
			"api_server_hostname": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("hephaestus-k8s-api"),
				MarkdownDescription: "Tailnet hostname for the Kubernetes API. Default: `hephaestus-k8s-api`",
			},
			"api_server_port": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Port for the K8s API service. Default: 443",
			},
			// Subnet router
			"enable_subnet_router": schema.BoolAttribute{
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
				MarkdownDescription: "Deploy a subnet router to expose cluster networks. Default: `false`",
			},
			"subnet_routes": schema.ListAttribute{
				Optional:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "CIDRs to advertise via subnet router. Default: [\"10.244.0.0/16\", \"10.96.0.0/12\"]",
			},
			"auth_key": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "Tailscale auth key for subnet router (required if enable_subnet_router is true)",
			},
			// Computed outputs
			"installed_version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Installed Tailscale operator version",
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Current status of Tailscale integration",
			},
			"tailscale_kubeconfig": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Kubeconfig configured to use Tailscale endpoint for remote access",
			},
			"api_server_tailscale_ip": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Tailscale IP address of the exposed Kubernetes API",
			},
		},
	}
}

func (r *TailscaleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *TailscaleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan TailscaleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cpIP := plan.ControlPlaneIP.ValueString()

	tflog.Info(ctx, "Installing Tailscale integration", map[string]interface{}{
		"control_plane_ip": cpIP,
	})

	// Step 1: Ensure Helm is installed
	if err := r.ensureHelm(ctx, cpIP); err != nil {
		resp.Diagnostics.AddError("Helm Setup Failed", err.Error())
		return
	}

	// Step 2: Install Tailscale operator
	if err := r.installOperator(ctx, &plan); err != nil {
		resp.Diagnostics.AddError("Tailscale Operator Installation Failed", err.Error())
		return
	}

	// Step 3: Create API server service if enabled
	if plan.ExposeAPIServer.ValueBool() {
		if err := r.createAPIServerService(ctx, &plan); err != nil {
			resp.Diagnostics.AddError("API Server Service Creation Failed", err.Error())
			return
		}
	}

	// Step 4: Deploy subnet router if enabled
	if plan.EnableSubnetRouter.ValueBool() {
		if plan.AuthKey.IsNull() || plan.AuthKey.ValueString() == "" {
			resp.Diagnostics.AddError("Subnet Router Configuration Error",
				"auth_key is required when enable_subnet_router is true")
			return
		}
		if err := r.deploySubnetRouter(ctx, &plan); err != nil {
			resp.Diagnostics.AddError("Subnet Router Deployment Failed", err.Error())
			return
		}
	}

	// Step 5: Wait for API server to be accessible and generate kubeconfig
	if plan.ExposeAPIServer.ValueBool() {
		if err := r.waitForAPIServer(ctx, &plan); err != nil {
			tflog.Warn(ctx, "API server not yet accessible via Tailscale", map[string]interface{}{
				"error": err.Error(),
			})
			// Not a fatal error - may need time to propagate
		}
		if err := r.generateTailscaleKubeconfig(ctx, &plan); err != nil {
			tflog.Warn(ctx, "Could not generate Tailscale kubeconfig", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Set computed values
	plan.ID = types.StringValue(plan.ClusterID.ValueString() + "-tailscale")
	r.refreshStatus(ctx, &plan)

	tflog.Info(ctx, "Tailscale integration installed successfully")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TailscaleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state TailscaleResourceModel
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

	// Check if operator still exists
	if state.Status.ValueString() == "not_found" {
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh kubeconfig if API server is exposed
	if state.ExposeAPIServer.ValueBool() {
		if err := r.generateTailscaleKubeconfig(ctx, &state); err != nil {
			tflog.Debug(ctx, "Could not refresh Tailscale kubeconfig", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *TailscaleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan TailscaleResourceModel
	var state TailscaleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cpIP := plan.ControlPlaneIP.ValueString()

	// Check if operator version changed
	if !plan.Version.Equal(state.Version) {
		tflog.Info(ctx, "Upgrading Tailscale operator")
		if err := r.installOperator(ctx, &plan); err != nil {
			resp.Diagnostics.AddError("Tailscale Operator Upgrade Failed", err.Error())
			return
		}
	}

	// Handle API server exposure changes
	if plan.ExposeAPIServer.ValueBool() && !state.ExposeAPIServer.ValueBool() {
		if err := r.createAPIServerService(ctx, &plan); err != nil {
			resp.Diagnostics.AddError("API Server Service Creation Failed", err.Error())
			return
		}
	} else if !plan.ExposeAPIServer.ValueBool() && state.ExposeAPIServer.ValueBool() {
		if err := r.deleteAPIServerService(ctx, cpIP, state.Namespace.ValueString()); err != nil {
			tflog.Warn(ctx, "Failed to delete API server service", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Handle subnet router changes
	if plan.EnableSubnetRouter.ValueBool() && !state.EnableSubnetRouter.ValueBool() {
		if plan.AuthKey.IsNull() || plan.AuthKey.ValueString() == "" {
			resp.Diagnostics.AddError("Subnet Router Configuration Error",
				"auth_key is required when enable_subnet_router is true")
			return
		}
		if err := r.deploySubnetRouter(ctx, &plan); err != nil {
			resp.Diagnostics.AddError("Subnet Router Deployment Failed", err.Error())
			return
		}
	} else if !plan.EnableSubnetRouter.ValueBool() && state.EnableSubnetRouter.ValueBool() {
		if err := r.deleteSubnetRouter(ctx, cpIP, state.Namespace.ValueString()); err != nil {
			tflog.Warn(ctx, "Failed to delete subnet router", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Refresh status and kubeconfig
	r.refreshStatus(ctx, &plan)
	if plan.ExposeAPIServer.ValueBool() {
		if err := r.generateTailscaleKubeconfig(ctx, &plan); err != nil {
			tflog.Debug(ctx, "Could not refresh Tailscale kubeconfig", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *TailscaleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state TailscaleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cpIP := state.ControlPlaneIP.ValueString()
	namespace := state.Namespace.ValueString()

	tflog.Info(ctx, "Removing Tailscale integration")

	// Delete API server service if it exists
	if state.ExposeAPIServer.ValueBool() {
		if err := r.deleteAPIServerService(ctx, cpIP, namespace); err != nil {
			tflog.Warn(ctx, "Failed to delete API server service", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Delete subnet router if deployed
	if state.EnableSubnetRouter.ValueBool() {
		if err := r.deleteSubnetRouter(ctx, cpIP, namespace); err != nil {
			tflog.Warn(ctx, "Failed to delete subnet router", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Uninstall Tailscale operator
	cmd := fmt.Sprintf("helm uninstall tailscale-operator -n %s --kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null || true",
		namespace)
	err := r.ssh.RunSudo(ctx, cpIP, cmd)
	if err != nil {
		tflog.Warn(ctx, "Failed to uninstall Tailscale operator", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Delete namespace (cleanup)
	cmd = fmt.Sprintf("kubectl delete namespace %s --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found=true",
		namespace)
	if err := r.ssh.RunSudo(ctx, cpIP, cmd); err != nil {
		tflog.Warn(ctx, "Failed to delete namespace", map[string]interface{}{
			"error": err.Error(),
		})
	}

	tflog.Info(ctx, "Tailscale integration removed")
}

func (r *TailscaleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ensureHelm ensures helm is installed on the control plane.
func (r *TailscaleResource) ensureHelm(ctx context.Context, cpIP string) error {
	// Check if helm exists
	if _, err := r.ssh.OutputSudo(ctx, cpIP, "which helm"); err == nil {
		return nil
	}

	tflog.Info(ctx, "Installing Helm")

	script := `set -euo pipefail
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash`
	_, stderr, err := r.ssh.RunScript(ctx, cpIP, script)
	if err != nil {
		return fmt.Errorf("helm installation failed: %w\n%s", err, stderr)
	}

	return nil
}

// installOperator installs the Tailscale operator via Helm.
func (r *TailscaleResource) installOperator(ctx context.Context, model *TailscaleResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	namespace := model.Namespace.ValueString()
	clientID := model.OAuthClientID.ValueString()
	clientSecret := model.OAuthClientSecret.ValueString()

	tflog.Info(ctx, "Installing Tailscale operator", map[string]interface{}{
		"namespace": namespace,
	})

	// Get tags (default to tag:k8s if not specified)
	var tags []string
	if !model.Tags.IsNull() && len(model.Tags.Elements()) > 0 {
		model.Tags.ElementsAs(ctx, &tags, false)
	} else {
		tags = []string{"tag:k8s"}
	}

	// Build Helm values
	values := map[string]interface{}{
		"oauth": map[string]interface{}{
			"clientId":     clientID,
			"clientSecret": clientSecret,
		},
		"operatorConfig": map[string]interface{}{
			"hostname": model.HostnamePrefix.ValueString(),
			// Set operator's own tag (defaults to tag:k8s-operator, override to match OAuth client)
			"defaultTags": tags,
		},
		"apiServerProxyConfig": map[string]interface{}{
			"mode": "true",
		},
		// Tags for proxies created by the operator
		"proxyConfig": map[string]interface{}{
			"defaultTags": strings.Join(tags, ","),
		},
	}

	valuesJSON, err := json.Marshal(values)
	if err != nil {
		return fmt.Errorf("failed to marshal values: %w", err)
	}

	// Build install command
	cmd := fmt.Sprintf(`set -euo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
helm repo add tailscale https://pkgs.tailscale.com/helmcharts --force-update 2>/dev/null || true
helm repo update tailscale
helm upgrade --install tailscale-operator tailscale/tailscale-operator \
  --namespace %s \
  --create-namespace \
  --values <(echo '%s') \
  --wait \
  --timeout 10m`, namespace, string(valuesJSON))

	if !model.Version.IsNull() && model.Version.ValueString() != "" {
		cmd = strings.Replace(cmd, "--wait", fmt.Sprintf("--version %s --wait", model.Version.ValueString()), 1)
	}

	_, stderr, err := r.ssh.RunScript(ctx, cpIP, cmd)
	if err != nil {
		return fmt.Errorf("helm install failed: %w\n%s", err, stderr)
	}

	return nil
}

// createAPIServerService creates a service to expose the K8s API on the tailnet.
func (r *TailscaleResource) createAPIServerService(ctx context.Context, model *TailscaleResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	namespace := model.Namespace.ValueString()
	hostname := model.APIServerHostname.ValueString()

	tflog.Info(ctx, "Creating Kubernetes API Tailscale service", map[string]interface{}{
		"hostname": hostname,
	})

	port := int64(defaultHTTPSPort)
	if !model.APIServerPort.IsNull() {
		port = model.APIServerPort.ValueInt64()
	}

	manifest := fmt.Sprintf(`apiVersion: v1
kind: Service
metadata:
  name: kubernetes-api-tailscale
  namespace: %s
  annotations:
    tailscale.com/expose: "true"
    tailscale.com/hostname: "%s"
spec:
  type: ExternalName
  externalName: kubernetes.default.svc.cluster.local
  ports:
    - port: %d
      targetPort: 6443
      protocol: TCP
`, namespace, hostname, port)

	script := fmt.Sprintf("cat <<'EOFMANIFEST' | kubectl apply --kubeconfig=/etc/kubernetes/admin.conf -f -\n%sEOFMANIFEST", manifest)
	_, stderr, err := r.ssh.RunScript(ctx, cpIP, script)
	if err != nil {
		return fmt.Errorf("failed to create API server service: %w\n%s", err, stderr)
	}

	return nil
}

// deleteAPIServerService removes the API server Tailscale service.
func (r *TailscaleResource) deleteAPIServerService(ctx context.Context, cpIP, namespace string) error {
	cmd := fmt.Sprintf("kubectl delete service kubernetes-api-tailscale -n %s --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found=true",
		namespace)
	return r.ssh.RunSudo(ctx, cpIP, cmd)
}

// deploySubnetRouter deploys a Tailscale subnet router.
func (r *TailscaleResource) deploySubnetRouter(ctx context.Context, model *TailscaleResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	namespace := model.Namespace.ValueString()
	authKey := model.AuthKey.ValueString()

	// Get routes
	routes := []string{"10.244.0.0/16", "10.96.0.0/12"} // defaults
	if !model.SubnetRoutes.IsNull() && len(model.SubnetRoutes.Elements()) > 0 {
		model.SubnetRoutes.ElementsAs(ctx, &routes, false)
	}

	tflog.Info(ctx, "Deploying Tailscale subnet router", map[string]interface{}{
		"routes": routes,
	})

	routeStr := strings.Join(routes, ",")
	hostname := model.HostnamePrefix.ValueString() + "-subnet-router"

	manifest := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: tailscale-auth
  namespace: %s
type: Opaque
stringData:
  TS_AUTHKEY: "%s"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: tailscale-subnet-router
  namespace: %s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: tailscale-subnet-router
  namespace: %s
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create", "get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tailscale-subnet-router
  namespace: %s
subjects:
  - kind: ServiceAccount
    name: tailscale-subnet-router
    namespace: %s
roleRef:
  kind: Role
  name: tailscale-subnet-router
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tailscale-subnet-router
  namespace: %s
  labels:
    app: tailscale-subnet-router
spec:
  replicas: 1
  selector:
    matchLabels:
      app: tailscale-subnet-router
  template:
    metadata:
      labels:
        app: tailscale-subnet-router
    spec:
      serviceAccountName: tailscale-subnet-router
      containers:
        - name: tailscale
          image: tailscale/tailscale:latest
          imagePullPolicy: Always
          env:
            - name: TS_AUTHKEY
              valueFrom:
                secretKeyRef:
                  name: tailscale-auth
                  key: TS_AUTHKEY
            - name: TS_KUBE_SECRET
              value: tailscale-subnet-router-state
            - name: TS_USERSPACE
              value: "false"
            - name: TS_ROUTES
              value: "%s"
            - name: TS_EXTRA_ARGS
              value: "--advertise-exit-node=false --accept-routes=false"
            - name: TS_HOSTNAME
              value: "%s"
          securityContext:
            capabilities:
              add:
                - NET_ADMIN
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 256Mi
      nodeSelector:
        kubernetes.io/os: linux
`, namespace, authKey, namespace, namespace, namespace, namespace, namespace, routeStr, hostname)

	script := fmt.Sprintf("cat <<'EOFMANIFEST' | kubectl apply --kubeconfig=/etc/kubernetes/admin.conf -f -\n%sEOFMANIFEST", manifest)
	_, stderr, err := r.ssh.RunScript(ctx, cpIP, script)
	if err != nil {
		return fmt.Errorf("failed to deploy subnet router: %w\n%s", err, stderr)
	}

	return nil
}

// deleteSubnetRouter removes the subnet router deployment.
func (r *TailscaleResource) deleteSubnetRouter(ctx context.Context, cpIP, namespace string) error {
	script := fmt.Sprintf(`set -e
kubectl delete deployment tailscale-subnet-router -n %s --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found=true
kubectl delete rolebinding tailscale-subnet-router -n %s --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found=true
kubectl delete role tailscale-subnet-router -n %s --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found=true
kubectl delete serviceaccount tailscale-subnet-router -n %s --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found=true
kubectl delete secret tailscale-auth -n %s --kubeconfig=/etc/kubernetes/admin.conf --ignore-not-found=true`,
		namespace, namespace, namespace, namespace, namespace)
	_, _, err := r.ssh.RunScript(ctx, cpIP, script)
	return err
}

// waitForAPIServer waits for the Tailscale proxy to be ready for the API server.
func (r *TailscaleResource) waitForAPIServer(ctx context.Context, model *TailscaleResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	namespace := model.Namespace.ValueString()
	hostname := model.APIServerHostname.ValueString()

	tflog.Info(ctx, "Waiting for Tailscale API server proxy")

	// Wait for the tailscale proxy pod to be ready
	deadline := time.Now().Add(apiWaitTimeout)
	for time.Now().Before(deadline) {
		// Check if the proxy is ready by looking for the operator-managed proxy
		cmd := fmt.Sprintf(`kubectl get pods -n %s -l tailscale.com/parent-resource=kubernetes-api-tailscale `+
			`--kubeconfig=/etc/kubernetes/admin.conf -o jsonpath='{.items[0].status.phase}' 2>/dev/null || echo 'NotFound'`,
			namespace)
		out, err := r.ssh.OutputSudo(ctx, cpIP, cmd)
		if err != nil {
			tflog.Debug(ctx, "Could not query pod status", map[string]interface{}{"error": err.Error()})
		}
		out = strings.Trim(out, "'\" \n")

		if out == "Running" {
			tflog.Info(ctx, "Tailscale API server proxy is ready")
			// Try to get the Tailscale IP
			if err := r.refreshTailscaleIP(ctx, model); err == nil {
				return nil
			}
		}

		tflog.Debug(ctx, "Waiting for Tailscale proxy", map[string]interface{}{
			"status":   out,
			"hostname": hostname,
		})
		time.Sleep(apiWaitPollInterval)
	}

	return errors.New("timeout waiting for Tailscale API server proxy")
}

// refreshTailscaleIP attempts to get the Tailscale IP for the API server.
func (r *TailscaleResource) refreshTailscaleIP(ctx context.Context, model *TailscaleResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	namespace := model.Namespace.ValueString()

	// Get the IP from the tailscale state secret
	cmd := fmt.Sprintf(`kubectl get secret -n %s -l tailscale.com/parent-resource=kubernetes-api-tailscale `+
		`-o jsonpath='{.items[0].data.device_ips}' --kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null | base64 -d 2>/dev/null || echo ''`,
		namespace)
	out, err := r.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil || out == "" {
		// Try alternative method - get from pod annotations
		cmd = fmt.Sprintf(`kubectl get pods -n %s -l tailscale.com/parent-resource=kubernetes-api-tailscale `+
			`-o jsonpath='{.items[0].metadata.annotations.tailscale\.com/ts-ips}' --kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null || echo ''`,
			namespace)
		out, err = r.ssh.OutputSudo(ctx, cpIP, cmd)
		if err != nil {
			return fmt.Errorf("could not get Tailscale IP: %w", err)
		}
	}

	out = strings.Trim(out, "'\" \n[]")
	if out != "" {
		// Parse JSON array if present
		ips := strings.Split(out, ",")
		if len(ips) > 0 {
			ip := strings.Trim(ips[0], "\" ")
			model.APIServerTailscaleIP = types.StringValue(ip)
			return nil
		}
	}

	return errors.New("tailscale IP not yet available")
}

// generateTailscaleKubeconfig generates a kubeconfig using the Tailscale endpoint.
func (r *TailscaleResource) generateTailscaleKubeconfig(ctx context.Context, model *TailscaleResourceModel) error {
	cpIP := model.ControlPlaneIP.ValueString()
	hostname := model.APIServerHostname.ValueString()

	// First try to refresh the Tailscale IP
	if err := r.refreshTailscaleIP(ctx, model); err != nil {
		tflog.Debug(ctx, "Could not refresh Tailscale IP for kubeconfig", map[string]interface{}{"error": err.Error()})
	}

	// Get the cluster CA certificate
	cmd := "kubectl get cm kube-root-ca.crt -n default -o jsonpath='{.data.ca\\.crt}' --kubeconfig=/etc/kubernetes/admin.conf"
	caCert, err := r.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		return fmt.Errorf("failed to get CA certificate: %w", err)
	}
	caCert = strings.Trim(caCert, "'\" \n")

	// Get admin credentials from existing kubeconfig
	cmd = "cat /etc/kubernetes/admin.conf"
	adminConf, err := r.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		return fmt.Errorf("failed to read admin.conf: %w", err)
	}

	// Parse admin.conf to extract client certificate and key
	var clientCert, clientKey string

	// Extract client-certificate-data
	for _, line := range strings.Split(adminConf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "client-certificate-data:") {
			clientCert = strings.TrimSpace(strings.TrimPrefix(line, "client-certificate-data:"))
		}
		if strings.HasPrefix(line, "client-key-data:") {
			clientKey = strings.TrimSpace(strings.TrimPrefix(line, "client-key-data:"))
		}
	}

	if clientCert == "" || clientKey == "" {
		return errors.New("could not extract client credentials from admin.conf")
	}

	// Build server URL - use Tailscale hostname or IP
	serverURL := "https://" + net.JoinHostPort(hostname, "443")
	if !model.APIServerTailscaleIP.IsNull() && model.APIServerTailscaleIP.ValueString() != "" {
		// Also have the IP available but prefer hostname
		tflog.Debug(ctx, "Tailscale IP available", map[string]interface{}{
			"ip": model.APIServerTailscaleIP.ValueString(),
		})
	}

	// Generate kubeconfig
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: hephaestus-tailscale
contexts:
- context:
    cluster: hephaestus-tailscale
    user: kubernetes-admin
  name: hephaestus-tailscale
current-context: hephaestus-tailscale
users:
- name: kubernetes-admin
  user:
    client-certificate-data: %s
    client-key-data: %s
`, base64.StdEncoding.EncodeToString([]byte(caCert)), serverURL, clientCert, clientKey)

	model.TailscaleKubeconfig = types.StringValue(kubeconfig)
	return nil
}

// refreshStatus refreshes the status of the Tailscale integration.
func (r *TailscaleResource) refreshStatus(ctx context.Context, model *TailscaleResourceModel) {
	cpIP := model.ControlPlaneIP.ValueString()
	namespace := model.Namespace.ValueString()

	// Initialize computed fields to ensure they're never unknown
	if model.InstalledVersion.IsUnknown() || model.InstalledVersion.IsNull() {
		model.InstalledVersion = types.StringValue("")
	}
	if model.Status.IsUnknown() || model.Status.IsNull() {
		model.Status = types.StringValue("unknown")
	}
	if model.TailscaleKubeconfig.IsUnknown() || model.TailscaleKubeconfig.IsNull() {
		model.TailscaleKubeconfig = types.StringValue("")
	}
	if model.APIServerTailscaleIP.IsUnknown() || model.APIServerTailscaleIP.IsNull() {
		model.APIServerTailscaleIP = types.StringValue("")
	}

	// Check Helm release status
	cmd := fmt.Sprintf("helm status tailscale-operator -n %s --kubeconfig=/etc/kubernetes/admin.conf -o json 2>/dev/null", namespace)
	out, err := r.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		model.Status = types.StringValue("not_found")
		return
	}

	// Parse JSON to get status and version
	var status struct {
		Info struct {
			Status string `json:"status"`
		} `json:"info"`
		Chart string `json:"chart"`
	}
	if err := json.Unmarshal([]byte(out), &status); err == nil {
		model.Status = types.StringValue(status.Info.Status)
		// Extract version from chart name (e.g., "tailscale-operator-1.76.1")
		if parts := strings.Split(status.Chart, "-"); len(parts) > 2 {
			model.InstalledVersion = types.StringValue(parts[len(parts)-1])
		}
	}

	// Refresh Tailscale IP if API server is exposed
	if model.ExposeAPIServer.ValueBool() {
		if err := r.refreshTailscaleIP(ctx, model); err != nil {
			tflog.Debug(ctx, "Could not refresh Tailscale IP during status refresh", map[string]interface{}{"error": err.Error()})
		}
	}
}
