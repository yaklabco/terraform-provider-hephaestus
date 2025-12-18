# Hephaestus Terraform Provider

The Hephaestus provider enables declarative Kubernetes cluster lifecycle management using kubeadm. It provides resources for bootstrapping HA clusters with proper state management and drift detection.

**Compatible with both Terraform and OpenTofu.**

## Features

- Declarative Kubernetes cluster management via IaC
- High availability with kube-vip integration
- Support for control plane and worker nodes
- GPU worker node support with automatic labeling
- Built-in addon support (Cilium, Tailscale, NVIDIA device plugin)
- Native drift detection via resource Read() functions
- Sensitive data (tokens, kubeconfig) stored securely in Terraform state

## Requirements

- Terraform >= 1.0 or OpenTofu >= 1.6
- Go >= 1.23 (for building from source)
- SSH access to target nodes (Ubuntu recommended)
- Nodes with static IPs on the same network

## Installation

### From OpenTofu/Terraform Registry

```hcl
terraform {
  required_providers {
    hephaestus = {
      source  = "yaklab/hephaestus"
      version = "~> 1.0"
    }
  }
}
```

### Building from Source

```bash
git clone https://github.com/yaklab/terraform-provider-hephaestus
cd terraform-provider-hephaestus
go build -o terraform-provider-hephaestus
```

For local development, create `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "yaklab/hephaestus" = "/path/to/terraform-provider-hephaestus"
  }
  direct {}
}
```

## Quick Start

```hcl
provider "hephaestus" {
  ssh_user             = "ubuntu"
  ssh_private_key_file = "~/.ssh/id_ed25519"
}

# Prepare node
resource "hephaestus_node" "cp1" {
  name = "k8s-cp-1"
  ip   = "10.0.0.201"
  role = "control_plane"
}

# Initialize control plane
resource "hephaestus_control_plane" "primary" {
  node_id           = hephaestus_node.cp1.id
  node_ip           = hephaestus_node.cp1.ip
  control_plane_vip = "10.0.0.200"
}

# Install CNI
resource "hephaestus_addon" "cilium" {
  cluster_id       = hephaestus_control_plane.primary.id
  control_plane_ip = hephaestus_control_plane.primary.node_ip
  name             = "cilium"
  version          = "1.16.4"
}

output "kubeconfig" {
  value     = hephaestus_control_plane.primary.kubeconfig
  sensitive = true
}
```

## Resources

| Resource | Description |
|----------|-------------|
| `hephaestus_node` | Prepares a node (OS, containerd, kubeadm) |
| `hephaestus_control_plane` | Initializes first control plane with kube-vip |
| `hephaestus_control_plane_member` | Joins additional control planes |
| `hephaestus_worker` | Joins worker nodes |
| `hephaestus_addon` | Installs cluster addons (Helm/manifests) |

## Provider Configuration

| Attribute | Description | Default |
|-----------|-------------|---------|
| `ssh_user` | SSH user for node access | `ubuntu` |
| `ssh_private_key` | SSH private key content | - |
| `ssh_private_key_file` | Path to SSH private key | - |
| `ssh_timeout` | SSH connection timeout | `30s` |
| `ssh_connection_attempts` | SSH retry attempts | `3` |
| `ssh_use_multiplexing` | Enable SSH multiplexing | `true` |

## Examples

See the [examples](./examples) directory:

- [basic](./examples/basic) - Single control plane cluster
- [ha-cluster](./examples/ha-cluster) - 3 CP + workers + GPU nodes

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed design documentation.

## Development

```bash
# Build
go build -o terraform-provider-hephaestus

# Run tests
go test ./...

# Run acceptance tests (requires VMs)
TF_ACC=1 go test ./internal/provider/... -v
```

## License

MPL-2.0
