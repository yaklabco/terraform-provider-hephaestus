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

variable "control_plane_ip" {
  description = "IP address of the control plane node"
  type        = string
}

variable "control_plane_vip" {
  description = "Virtual IP for HA control plane access"
  type        = string
}

variable "worker_nodes" {
  description = "Map of worker node names to IPs"
  type        = map(string)
  default = {
    "k8s-worker-1" = "10.0.0.204"
    "k8s-worker-2" = "10.0.0.205"
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
