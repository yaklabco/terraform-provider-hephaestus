// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories is used to instantiate a provider during acceptance testing.
//
//nolint:unused // Used by acceptance tests
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"hephaestus": providerserver.NewProtocol6WithError(New("test")()),
}

//nolint:unused // Used by acceptance tests
func testAccPreCheck(t *testing.T) {
	t.Helper()
	// Add pre-check logic here, e.g., verify SSH key exists
}
