// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

// Package provider implements the Hephaestus Terraform/OpenTofu provider.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/yaklab/terraform-provider-hephaestus/internal/client"
	"github.com/yaklab/terraform-provider-hephaestus/internal/verifier"
)

// Ensure HephaestusProvider satisfies various provider interfaces.
var _ provider.Provider = &HephaestusProvider{}

// HephaestusProvider defines the provider implementation.
type HephaestusProvider struct {
	version string
}

// HephaestusProviderModel describes the provider data model.
type HephaestusProviderModel struct {
	SSHUser               types.String `tfsdk:"ssh_user"`
	SSHPrivateKey         types.String `tfsdk:"ssh_private_key"`
	SSHPrivateKeyFile     types.String `tfsdk:"ssh_private_key_file"`
	SSHTimeout            types.String `tfsdk:"ssh_timeout"`
	SSHConnectionAttempts types.Int64  `tfsdk:"ssh_connection_attempts"`
	SSHUseMultiplexing    types.Bool   `tfsdk:"ssh_use_multiplexing"`
	NodePrepTimeout       types.String `tfsdk:"node_prep_timeout"`
	KubeadmInitTimeout    types.String `tfsdk:"kubeadm_init_timeout"`
	KubeadmJoinTimeout    types.String `tfsdk:"kubeadm_join_timeout"`
	AddonTimeout          types.String `tfsdk:"addon_timeout"`
}

// New creates a new provider factory function.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &HephaestusProvider{
			version: version,
		}
	}
}

// Metadata returns the provider type name.
func (p *HephaestusProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "hephaestus"
	resp.Version = p.version
}

// Schema defines the provider-level configuration schema.
func (p *HephaestusProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `The Hephaestus provider enables declarative Kubernetes cluster lifecycle 
management using kubeadm. It provides resources for bootstrapping HA clusters 
with proper state management and drift detection.

This provider is compatible with both Terraform and OpenTofu.

## Authentication

The provider requires SSH access to cluster nodes. Configure authentication using 
either ` + "`ssh_private_key`" + ` (key content) or ` + "`ssh_private_key_file`" + ` (path to key file).

## Example Usage

` + "```hcl" + `
provider "hephaestus" {
  ssh_user             = "ubuntu"
  ssh_private_key_file = "~/.ssh/id_ed25519"
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"ssh_user": schema.StringAttribute{
				MarkdownDescription: "SSH user for connecting to nodes. Can also be set via `HEPHAESTUS_SSH_USER` environment variable. Default: `ubuntu`",
				Optional:            true,
			},
			"ssh_private_key": schema.StringAttribute{
				MarkdownDescription: "SSH private key content for authentication. " +
					"Either `ssh_private_key` or `ssh_private_key_file` must be set. " +
					"Can also be set via `HEPHAESTUS_SSH_PRIVATE_KEY` environment variable.",
				Optional:  true,
				Sensitive: true,
			},
			"ssh_private_key_file": schema.StringAttribute{
				MarkdownDescription: "Path to SSH private key file. " +
					"Either `ssh_private_key` or `ssh_private_key_file` must be set. " +
					"Can also be set via `HEPHAESTUS_SSH_PRIVATE_KEY_FILE` environment variable.",
				Optional: true,
			},
			"ssh_timeout": schema.StringAttribute{
				MarkdownDescription: "SSH connection timeout as a duration string (e.g., `30s`, `1m`). Default: `30s`",
				Optional:            true,
			},
			"ssh_connection_attempts": schema.Int64Attribute{
				MarkdownDescription: "Number of SSH connection attempts before failing. Default: `3`",
				Optional:            true,
			},
			"ssh_use_multiplexing": schema.BoolAttribute{
				MarkdownDescription: "Enable SSH connection multiplexing for improved performance. Default: `true`",
				Optional:            true,
			},
			"node_prep_timeout": schema.StringAttribute{
				MarkdownDescription: "Timeout for node preparation operations. Default: `10m`",
				Optional:            true,
			},
			"kubeadm_init_timeout": schema.StringAttribute{
				MarkdownDescription: "Timeout for kubeadm init operation. Default: `10m`",
				Optional:            true,
			},
			"kubeadm_join_timeout": schema.StringAttribute{
				MarkdownDescription: "Timeout for kubeadm join operations. Default: `5m`",
				Optional:            true,
			},
			"addon_timeout": schema.StringAttribute{
				MarkdownDescription: "Timeout for addon installation. Default: `15m`",
				Optional:            true,
			},
		},
	}
}

// Configure prepares the provider for data sources and resources.
func (p *HephaestusProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Info(ctx, "Configuring Hephaestus provider")

	var config HephaestusProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build SSH client configuration with environment variable fallbacks
	sshConfig := client.SSHConfig{
		User:            "ubuntu",
		Timeout:         "30s",
		ConnAttempts:    3,
		UseMultiplexing: true,
	}

	// SSH User
	if !config.SSHUser.IsNull() {
		sshConfig.User = config.SSHUser.ValueString()
	} else if v := os.Getenv("HEPHAESTUS_SSH_USER"); v != "" {
		sshConfig.User = v
	}

	// SSH Key - check config first, then environment
	if !config.SSHPrivateKey.IsNull() {
		sshConfig.PrivateKey = config.SSHPrivateKey.ValueString()
	} else if v := os.Getenv("HEPHAESTUS_SSH_PRIVATE_KEY"); v != "" {
		sshConfig.PrivateKey = v
	} else if !config.SSHPrivateKeyFile.IsNull() {
		sshConfig.PrivateKeyFile = config.SSHPrivateKeyFile.ValueString()
	} else if v := os.Getenv("HEPHAESTUS_SSH_PRIVATE_KEY_FILE"); v != "" {
		sshConfig.PrivateKeyFile = v
	} else {
		resp.Diagnostics.AddError(
			"Missing SSH Key Configuration",
			"Either ssh_private_key or ssh_private_key_file must be configured, "+
				"or set HEPHAESTUS_SSH_PRIVATE_KEY or HEPHAESTUS_SSH_PRIVATE_KEY_FILE environment variable",
		)
		return
	}

	// SSH Timeout
	if !config.SSHTimeout.IsNull() {
		sshConfig.Timeout = config.SSHTimeout.ValueString()
	}

	// SSH Connection Attempts
	if !config.SSHConnectionAttempts.IsNull() {
		sshConfig.ConnAttempts = int(config.SSHConnectionAttempts.ValueInt64())
	}

	// SSH Multiplexing
	if !config.SSHUseMultiplexing.IsNull() {
		sshConfig.UseMultiplexing = config.SSHUseMultiplexing.ValueBool()
	}

	// Create shared SSH client
	sshClient, err := client.NewSSHClient(sshConfig)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Create SSH Client",
			"Unable to create SSH client: "+err.Error(),
		)
		return
	}

	// Create verifier
	verify := verifier.New(sshClient)

	// Build provider data to pass to resources
	providerData := &ProviderData{
		SSHClient: sshClient,
		Verifier:  verify,
		Timeouts: Timeouts{
			NodePrep:    getStringOrDefault(config.NodePrepTimeout, "10m"),
			KubeadmInit: getStringOrDefault(config.KubeadmInitTimeout, "10m"),
			KubeadmJoin: getStringOrDefault(config.KubeadmJoinTimeout, "5m"),
			Addon:       getStringOrDefault(config.AddonTimeout, "15m"),
		},
	}

	tflog.Debug(ctx, "Hephaestus provider configured", map[string]interface{}{
		"ssh_user":         sshConfig.User,
		"ssh_multiplexing": sshConfig.UseMultiplexing,
	})

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

// Resources returns the list of resources implemented by this provider.
func (p *HephaestusProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewNodeResource,
		NewControlPlaneResource,
		NewControlPlaneMemberResource,
		NewWorkerResource,
		NewAddonResource,
		NewTailscaleResource,
	}
}

// DataSources returns the list of data sources implemented by this provider.
func (p *HephaestusProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewTailscaleStatusDataSource,
	}
}

// ProviderData holds the configured provider data passed to resources.
type ProviderData struct {
	SSHClient client.SSHRunner
	Verifier  *verifier.Verifier
	Timeouts  Timeouts
}

// Timeouts holds configured timeout values.
type Timeouts struct {
	NodePrep    string
	KubeadmInit string
	KubeadmJoin string
	Addon       string
}

// getStringOrDefault returns the string value or a default if null/unknown.
func getStringOrDefault(value types.String, defaultValue string) string {
	if value.IsNull() || value.IsUnknown() {
		return defaultValue
	}
	return value.ValueString()
}
