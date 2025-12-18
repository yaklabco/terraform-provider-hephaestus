# Configure the Hephaestus provider
# This provider works with both Terraform and OpenTofu

terraform {
  required_providers {
    hephaestus = {
      source  = "yaklab/hephaestus"
      version = "~> 1.0"
    }
  }
}

provider "hephaestus" {
  # SSH user for connecting to nodes
  ssh_user = "ubuntu"

  # SSH private key - use one of these options:
  # Option 1: Path to key file
  ssh_private_key_file = "~/.ssh/id_ed25519"

  # Option 2: Key content (useful with secrets managers)
  # ssh_private_key = var.ssh_private_key

  # Optional: SSH connection settings
  # ssh_timeout             = "30s"
  # ssh_connection_attempts = 3
  # ssh_use_multiplexing    = true

  # Optional: Operation timeouts
  # node_prep_timeout    = "10m"
  # kubeadm_init_timeout = "10m"
  # kubeadm_join_timeout = "5m"
  # addon_timeout        = "15m"
}
