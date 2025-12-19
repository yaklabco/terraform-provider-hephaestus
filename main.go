// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/yaklab/terraform-provider-hephaestus/internal/provider"
)

// version is set by goreleaser at build time.
var version = "dev"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		// Address is the provider address for the Terraform/OpenTofu registry.
		// For OpenTofu, this works the same way as Terraform.
		Address: "registry.terraform.io/yaklab/hephaestus",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
