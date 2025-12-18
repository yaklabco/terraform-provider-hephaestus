# High Availability Kubernetes cluster with GPU support
#
# This example creates a production-ready cluster with:
# - 3 control plane nodes (HA with kube-vip)
# - 2 regular worker nodes
# - 2 GPU worker nodes
# - Cilium CNI
# - NVIDIA device plugin

terraform {
  required_providers {
    hephaestus = {
      source  = "yaklab/hephaestus"
      version = "~> 1.0"
    }
  }
}

provider "hephaestus" {
  ssh_user             = var.ssh_user
  ssh_private_key_file = var.ssh_private_key_file
}

locals {
  # Merge all worker nodes
  all_workers = merge(
    { for name, ip in var.worker_nodes : name => { ip = ip, gpu = false } },
    { for name, ip in var.gpu_nodes : name => { ip = ip, gpu = true } }
  )
}

# =============================================================================
# Control Plane Nodes
# =============================================================================

# Prepare all control plane nodes
resource "hephaestus_node" "control_planes" {
  for_each = var.control_plane_nodes

  name              = each.key
  ip                = each.value
  role              = "control_plane"
  kubernetes_version = var.kubernetes_version
}

# Initialize first control plane
resource "hephaestus_control_plane" "primary" {
  node_id           = hephaestus_node.control_planes[var.first_control_plane].id
  node_ip           = hephaestus_node.control_planes[var.first_control_plane].ip
  control_plane_vip = var.control_plane_vip
  pod_cidr          = var.pod_cidr
  service_cidr      = var.service_cidr
}

# Join additional control planes
resource "hephaestus_control_plane_member" "secondary" {
  for_each = {
    for name, ip in var.control_plane_nodes : name => ip
    if name != var.first_control_plane
  }

  node_id           = hephaestus_node.control_planes[each.key].id
  node_ip           = each.value
  node_name         = each.key
  cluster_id        = hephaestus_control_plane.primary.id
  join_endpoint     = hephaestus_control_plane.primary.api_endpoint
  join_token        = hephaestus_control_plane.primary.join_token
  ca_cert_hash      = hephaestus_control_plane.primary.ca_cert_hash
  certificate_key   = hephaestus_control_plane.primary.certificate_key
  control_plane_vip = var.control_plane_vip
}

# =============================================================================
# Worker Nodes
# =============================================================================

# Prepare all worker nodes
resource "hephaestus_node" "workers" {
  for_each = local.all_workers

  name              = each.key
  ip                = each.value.ip
  role              = each.value.gpu ? "gpu_worker" : "worker"
  kubernetes_version = var.kubernetes_version
}

# Join workers
resource "hephaestus_worker" "nodes" {
  for_each = local.all_workers

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

  depends_on = [hephaestus_control_plane_member.secondary]
}

# =============================================================================
# Cluster Addons
# =============================================================================

# Install Cilium CNI
resource "hephaestus_addon" "cilium" {
  cluster_id       = hephaestus_control_plane.primary.id
  control_plane_ip = hephaestus_control_plane.primary.node_ip
  name             = "cilium"
  version          = var.cilium_version

  values = jsonencode({
    kubeProxyReplacement = true
    k8sServiceHost       = var.control_plane_vip
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

# Install NVIDIA device plugin (for GPU nodes)
resource "hephaestus_addon" "nvidia" {
  count = length(var.gpu_nodes) > 0 ? 1 : 0

  cluster_id       = hephaestus_control_plane.primary.id
  control_plane_ip = hephaestus_control_plane.primary.node_ip
  name             = "nvidia-device-plugin"
  type             = "manifest"

  depends_on = [hephaestus_addon.cilium]
}

# Optional: Install Tailscale operator
resource "hephaestus_addon" "tailscale" {
  count = var.tailscale_client_id != "" ? 1 : 0

  cluster_id       = hephaestus_control_plane.primary.id
  control_plane_ip = hephaestus_control_plane.primary.node_ip
  name             = "tailscale-operator"
  namespace        = "tailscale"

  values = jsonencode({
    oauth = {
      clientId     = var.tailscale_client_id
      clientSecret = var.tailscale_client_secret
    }
    operatorConfig = {
      defaultTags = "tag:k8s"
    }
  })

  depends_on = [hephaestus_addon.cilium]
}

# =============================================================================
# Outputs
# =============================================================================

output "kubeconfig" {
  description = "Kubeconfig for cluster access"
  value       = hephaestus_control_plane.primary.kubeconfig
  sensitive   = true
}

output "api_endpoint" {
  description = "Kubernetes API endpoint"
  value       = hephaestus_control_plane.primary.api_endpoint
}

output "control_plane_nodes" {
  description = "Control plane node names"
  value       = keys(var.control_plane_nodes)
}

output "worker_nodes" {
  description = "Worker node names"
  value       = keys(var.worker_nodes)
}

output "gpu_nodes" {
  description = "GPU node names"
  value       = keys(var.gpu_nodes)
}
