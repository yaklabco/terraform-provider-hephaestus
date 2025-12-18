# Basic single control plane Kubernetes cluster
#
# This example creates a minimal cluster with:
# - 1 control plane node
# - 2 worker nodes
# - Cilium CNI

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

# Prepare control plane node
resource "hephaestus_node" "cp" {
  name               = "k8s-cp-1"
  ip                 = var.control_plane_ip
  role               = "control_plane"
  kubernetes_version = var.kubernetes_version
}

# Initialize control plane
resource "hephaestus_control_plane" "primary" {
  node_id           = hephaestus_node.cp.id
  node_ip           = hephaestus_node.cp.ip
  control_plane_vip = var.control_plane_vip
  pod_cidr          = var.pod_cidr
  service_cidr      = var.service_cidr
}

# Prepare worker nodes
resource "hephaestus_node" "workers" {
  for_each = var.worker_nodes

  name               = each.key
  ip                 = each.value
  role               = "worker"
  kubernetes_version = var.kubernetes_version
}

# Join workers
resource "hephaestus_worker" "nodes" {
  for_each = hephaestus_node.workers

  node_id       = each.value.id
  node_ip       = each.value.ip
  node_name     = each.key
  cluster_id    = hephaestus_control_plane.primary.id
  join_endpoint = hephaestus_control_plane.primary.api_endpoint
  join_token    = hephaestus_control_plane.primary.join_token
  ca_cert_hash  = hephaestus_control_plane.primary.ca_cert_hash

  labels = {
    "node-role.kubernetes.io/worker" = ""
  }
}

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

  depends_on = [hephaestus_worker.nodes]
}

# Outputs
output "kubeconfig" {
  description = "Kubeconfig for cluster access"
  value       = hephaestus_control_plane.primary.kubeconfig
  sensitive   = true
}

output "api_endpoint" {
  description = "Kubernetes API endpoint"
  value       = hephaestus_control_plane.primary.api_endpoint
}
