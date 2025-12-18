variable "ssh_user" {
  description = "SSH user for node access"
  type        = string
  default     = "ubuntu"
}

variable "ssh_private_key_file" {
  description = "Path to SSH private key"
  type        = string
  default     = "~/.ssh/id_ed25519"
}

variable "control_plane_nodes" {
  description = "Map of control plane node names to IPs"
  type        = map(string)
  default = {
    "k8s-cp-1" = "10.0.0.201"
    "k8s-cp-2" = "10.0.0.202"
    "k8s-cp-3" = "10.0.0.203"
  }
}

variable "first_control_plane" {
  description = "Name of the first control plane node (for initial cluster bootstrap)"
  type        = string
  default     = "k8s-cp-1"
}

variable "control_plane_vip" {
  description = "Virtual IP for HA control plane access"
  type        = string
  default     = "10.0.0.200"
}

variable "worker_nodes" {
  description = "Map of worker node names to IPs"
  type        = map(string)
  default = {
    "k8s-worker-1" = "10.0.0.204"
    "k8s-worker-2" = "10.0.0.205"
  }
}

variable "gpu_nodes" {
  description = "Map of GPU worker node names to IPs"
  type        = map(string)
  default = {
    "k8s-gpu-1" = "10.0.0.206"
    "k8s-gpu-2" = "10.0.0.207"
  }
}

variable "kubernetes_version" {
  description = "Kubernetes version to install"
  type        = string
  default     = "1.31.3"
}

variable "pod_cidr" {
  description = "Pod network CIDR"
  type        = string
  default     = "10.244.0.0/16"
}

variable "service_cidr" {
  description = "Service network CIDR"
  type        = string
  default     = "10.96.0.0/12"
}

variable "cilium_version" {
  description = "Cilium version"
  type        = string
  default     = "1.16.4"
}

variable "tailscale_client_id" {
  description = "Tailscale OAuth client ID (optional)"
  type        = string
  default     = ""
}

variable "tailscale_client_secret" {
  description = "Tailscale OAuth client secret (optional)"
  type        = string
  default     = ""
  sensitive   = true
}
