// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
)

const (
	statusRunning        = "Running"
	operatorPodPartCount = 4
)

var _ datasource.DataSource = &TailscaleStatusDataSource{}

func NewTailscaleStatusDataSource() datasource.DataSource {
	return &TailscaleStatusDataSource{}
}

type TailscaleStatusDataSource struct {
	ssh *client.SSHClient
}

type TailscaleStatusDataSourceModel struct {
	ID               types.String `tfsdk:"id"`
	ControlPlaneIP   types.String `tfsdk:"control_plane_ip"`
	Namespace        types.String `tfsdk:"namespace"`
	OperatorReady    types.Bool   `tfsdk:"operator_ready"`
	OperatorPodName  types.String `tfsdk:"operator_pod_name"`
	OperatorPodIP    types.String `tfsdk:"operator_pod_ip"`
	OperatorVersion  types.String `tfsdk:"operator_version"`
	HelmStatus       types.String `tfsdk:"helm_status"`
	HelmRevision     types.Int64  `tfsdk:"helm_revision"`
	APIServiceExists types.Bool   `tfsdk:"api_service_exists"`
	APIServiceIP     types.String `tfsdk:"api_service_tailscale_ip"`
	ProxyPods        types.List   `tfsdk:"proxy_pods"`
	Devices          types.List   `tfsdk:"devices"`
}

type ProxyPodInfo struct {
	Name      string `tfsdk:"name"`
	Ready     bool   `tfsdk:"ready"`
	IP        string `tfsdk:"ip"`
	Node      string `tfsdk:"node"`
	ParentSvc string `tfsdk:"parent_service"`
}

type DeviceInfo struct {
	Hostname    string `tfsdk:"hostname"`
	TailscaleIP string `tfsdk:"tailscale_ip"`
	Tags        string `tfsdk:"tags"`
}

func (d *TailscaleStatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tailscale_status"
}

func (d *TailscaleStatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `Retrieves the current status of Tailscale integration in the cluster.

Use this data source to verify Tailscale is properly configured and to get
information about the operator, API service exposure, and proxy pods.

## Example Usage

` + "```hcl" + `
data "hephaestus_tailscale_status" "current" {
  control_plane_ip = hephaestus_control_plane.primary.node_ip
  namespace        = "tailscale"

  depends_on = [hephaestus_tailscale.main]
}

# Assert operator is ready
check "tailscale_healthy" {
  assert {
    condition     = data.hephaestus_tailscale_status.current.operator_ready
    error_message = "Tailscale operator is not ready"
  }
}

output "tailscale_api_ip" {
  value = data.hephaestus_tailscale_status.current.api_service_tailscale_ip
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Data source identifier",
			},
			"control_plane_ip": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "IP address of a control plane node",
			},
			"namespace": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Tailscale namespace. Default: `tailscale`",
			},
			// Operator status
			"operator_ready": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the Tailscale operator pod is ready",
			},
			"operator_pod_name": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Name of the operator pod",
			},
			"operator_pod_ip": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "IP address of the operator pod",
			},
			"operator_version": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Installed operator version (from Helm)",
			},
			// Helm status
			"helm_status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Helm release status (deployed, failed, etc.)",
			},
			"helm_revision": schema.Int64Attribute{
				Computed:            true,
				MarkdownDescription: "Helm release revision number",
			},
			// API service
			"api_service_exists": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the kubernetes-api-tailscale service exists",
			},
			"api_service_tailscale_ip": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Tailscale IP of the API service proxy (if available)",
			},
			// Proxy pods
			"proxy_pods": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "List of Tailscale proxy pods managed by the operator",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Pod name",
						},
						"ready": schema.BoolAttribute{
							Computed:            true,
							MarkdownDescription: "Whether the pod is ready",
						},
						"ip": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Pod IP address",
						},
						"node": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Node the pod is running on",
						},
						"parent_service": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Parent service this proxy is for",
						},
					},
				},
			},
			// Devices
			"devices": schema.ListNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Tailscale devices registered by the operator",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"hostname": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Tailscale hostname",
						},
						"tailscale_ip": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Tailscale IP address",
						},
						"tags": schema.StringAttribute{
							Computed:            true,
							MarkdownDescription: "Applied tags",
						},
					},
				},
			},
		},
	}
}

func (d *TailscaleStatusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *ProviderData, got: %T", req.ProviderData),
		)
		return
	}

	d.ssh = providerData.SSHClient
}

func (d *TailscaleStatusDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config TailscaleStatusDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cpIP := config.ControlPlaneIP.ValueString()
	namespace := config.Namespace.ValueString()
	if namespace == "" {
		namespace = "tailscale"
	}

	tflog.Info(ctx, "Reading Tailscale status", map[string]interface{}{
		"control_plane_ip": cpIP,
		"namespace":        namespace,
	})

	// Set ID
	config.ID = types.StringValue("tailscale-status-" + namespace)
	config.Namespace = types.StringValue(namespace)

	// Initialize defaults
	config.OperatorReady = types.BoolValue(false)
	config.OperatorPodName = types.StringValue("")
	config.OperatorPodIP = types.StringValue("")
	config.OperatorVersion = types.StringValue("")
	config.HelmStatus = types.StringValue("not_found")
	config.HelmRevision = types.Int64Value(0)
	config.APIServiceExists = types.BoolValue(false)
	config.APIServiceIP = types.StringValue("")

	// Check Helm release status
	d.checkHelmStatus(ctx, cpIP, namespace, &config)

	// Check operator pod status
	d.checkOperatorPod(ctx, cpIP, namespace, &config)

	// Check API service
	d.checkAPIService(ctx, cpIP, namespace, &config)

	// Get proxy pods
	d.populateProxyPods(ctx, cpIP, namespace, &config)

	// Get device info from secrets
	d.populateDevices(ctx, cpIP, namespace, &config)

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func (d *TailscaleStatusDataSource) checkHelmStatus(ctx context.Context, cpIP, namespace string, config *TailscaleStatusDataSourceModel) {
	cmd := fmt.Sprintf("helm status tailscale-operator -n %s --kubeconfig=/etc/kubernetes/admin.conf -o json 2>/dev/null", namespace)
	out, err := d.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		return
	}

	var status struct {
		Info struct {
			Status string `json:"status"`
		} `json:"info"`
		Version int    `json:"version"`
		Chart   string `json:"chart"`
	}
	if err := json.Unmarshal([]byte(out), &status); err == nil {
		config.HelmStatus = types.StringValue(status.Info.Status)
		config.HelmRevision = types.Int64Value(int64(status.Version))
		// Extract version from chart name
		if parts := strings.Split(status.Chart, "-"); len(parts) > 2 {
			config.OperatorVersion = types.StringValue(parts[len(parts)-1])
		}
	}
}

func (d *TailscaleStatusDataSource) checkOperatorPod(ctx context.Context, cpIP, namespace string, config *TailscaleStatusDataSourceModel) {
	cmd := fmt.Sprintf(`kubectl get pods -n %s -l app.kubernetes.io/name=operator `+
		`-o jsonpath='{.items[0].metadata.name}:{.items[0].status.phase}:{.items[0].status.podIP}:{.items[0].status.containerStatuses[0].ready}' `+
		`--kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null`, namespace)
	out, err := d.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		return
	}

	out = strings.Trim(out, "'\" \n")
	parts := strings.Split(out, ":")
	if len(parts) >= operatorPodPartCount {
		config.OperatorPodName = types.StringValue(parts[0])
		config.OperatorPodIP = types.StringValue(parts[2])
		config.OperatorReady = types.BoolValue(parts[1] == statusRunning && parts[3] == "true")
	}
}

func (d *TailscaleStatusDataSource) checkAPIService(ctx context.Context, cpIP, namespace string, config *TailscaleStatusDataSourceModel) {
	// Check if service exists
	cmd := fmt.Sprintf(`kubectl get svc kubernetes-api-tailscale -n %s --kubeconfig=/etc/kubernetes/admin.conf -o jsonpath='{.metadata.name}' 2>/dev/null`, namespace)
	out, err := d.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil || strings.Trim(out, "'\" \n") == "" {
		return
	}

	config.APIServiceExists = types.BoolValue(true)

	// Try to get the Tailscale IP from the proxy pod's secret
	cmd = fmt.Sprintf(`kubectl get secret -n %s -l tailscale.com/parent-resource=kubernetes-api-tailscale `+
		`-o jsonpath='{.items[0].data.device_ips}' --kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null | base64 -d 2>/dev/null`, namespace)
	out, err = d.ssh.OutputSudo(ctx, cpIP, cmd)
	if err == nil && out != "" {
		out = strings.Trim(out, "'\" \n[]")
		ips := strings.Split(out, ",")
		if len(ips) > 0 {
			ip := strings.Trim(ips[0], "\" ")
			if ip != "" {
				config.APIServiceIP = types.StringValue(ip)
			}
		}
	}
}

func (d *TailscaleStatusDataSource) populateProxyPods(ctx context.Context, cpIP, namespace string, config *TailscaleStatusDataSourceModel) {
	cmd := fmt.Sprintf(`kubectl get pods -n %s -l tailscale.com/managed=true -o json --kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null`, namespace)
	out, err := d.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		config.ProxyPods = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{}})
		return
	}

	var podList struct {
		Items []struct {
			Metadata struct {
				Name   string            `json:"name"`
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
			Spec struct {
				NodeName string `json:"nodeName"`
			} `json:"spec"`
			Status struct {
				Phase             string `json:"phase"`
				PodIP             string `json:"podIP"`
				ContainerStatuses []struct {
					Ready bool `json:"ready"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(out), &podList); err != nil {
		config.ProxyPods = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{}})
		return
	}

	proxyPods := make([]ProxyPodInfo, 0, len(podList.Items))
	for _, pod := range podList.Items {
		ready := false
		if len(pod.Status.ContainerStatuses) > 0 {
			ready = pod.Status.ContainerStatuses[0].Ready
		}
		proxyPods = append(proxyPods, ProxyPodInfo{
			Name:      pod.Metadata.Name,
			Ready:     pod.Status.Phase == statusRunning && ready,
			IP:        pod.Status.PodIP,
			Node:      pod.Spec.NodeName,
			ParentSvc: pod.Metadata.Labels["tailscale.com/parent-resource"],
		})
	}

	// Convert to types.List
	proxyPodsValue, diags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"name":           types.StringType,
			"ready":          types.BoolType,
			"ip":             types.StringType,
			"node":           types.StringType,
			"parent_service": types.StringType,
		},
	}, proxyPods)
	if diags.HasError() {
		config.ProxyPods = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{}})
		return
	}
	config.ProxyPods = proxyPodsValue
}

func (d *TailscaleStatusDataSource) populateDevices(ctx context.Context, cpIP, namespace string, config *TailscaleStatusDataSourceModel) {
	// Get device info from tailscale state secrets
	cmd := fmt.Sprintf(`kubectl get secrets -n %s -l tailscale.com/managed=true -o json --kubeconfig=/etc/kubernetes/admin.conf 2>/dev/null`, namespace)
	out, err := d.ssh.OutputSudo(ctx, cpIP, cmd)
	if err != nil {
		config.Devices = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{}})
		return
	}

	var secretList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Data map[string]string `json:"data"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(out), &secretList); err != nil {
		config.Devices = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{}})
		return
	}

	devices := make([]DeviceInfo, 0)
	for _, secret := range secretList.Items {
		// Only process state secrets
		if !strings.HasSuffix(secret.Metadata.Name, "-0") {
			continue
		}

		device := DeviceInfo{}

		// Decode device_fqdn for hostname
		if fqdnB64, ok := secret.Data["device_fqdn"]; ok {
			if decoded, err := base64Decode(fqdnB64); err == nil {
				device.Hostname = decoded
			}
		}

		// Decode device_ips for Tailscale IP
		if ipsB64, ok := secret.Data["device_ips"]; ok {
			if decoded, err := base64Decode(ipsB64); err == nil {
				decoded = strings.Trim(decoded, "[]\"")
				ips := strings.Split(decoded, ",")
				if len(ips) > 0 {
					device.TailscaleIP = strings.Trim(ips[0], "\" ")
				}
			}
		}

		if device.Hostname != "" || device.TailscaleIP != "" {
			devices = append(devices, device)
		}
	}

	// Convert to types.List
	devicesValue, diags := types.ListValueFrom(ctx, types.ObjectType{
		AttrTypes: map[string]attr.Type{
			"hostname":     types.StringType,
			"tailscale_ip": types.StringType,
			"tags":         types.StringType,
		},
	}, devices)
	if diags.HasError() {
		config.Devices = types.ListNull(types.ObjectType{AttrTypes: map[string]attr.Type{}})
		return
	}
	config.Devices = devicesValue
}

func base64Decode(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
