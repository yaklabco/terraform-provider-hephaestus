// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// IPAddressValidator validates that a string is a valid IP address.
type IPAddressValidator struct{}

// Description returns a plain text description of the validator's behavior.
func (v IPAddressValidator) Description(_ context.Context) string {
	return "value must be a valid IP address"
}

// MarkdownDescription returns a markdown description of the validator's behavior.
func (v IPAddressValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v IPAddressValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if ip := net.ParseIP(value); ip == nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid IP Address",
			fmt.Sprintf("Value %q is not a valid IP address", value),
		)
	}
}

// ValidIPAddress returns a validator that checks if a string is a valid IP address.
func ValidIPAddress() validator.String {
	return IPAddressValidator{}
}

// DurationValidator validates that a string is a valid Go duration.
type DurationValidator struct{}

// Description returns a plain text description of the validator's behavior.
func (v DurationValidator) Description(_ context.Context) string {
	return "value must be a valid duration string (e.g., '30s', '5m', '1h')"
}

// MarkdownDescription returns a markdown description of the validator's behavior.
func (v DurationValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v DurationValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if _, err := time.ParseDuration(value); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Duration",
			fmt.Sprintf("Value %q is not a valid duration: %s", value, err),
		)
	}
}

// ValidDuration returns a validator that checks if a string is a valid duration.
func ValidDuration() validator.String {
	return DurationValidator{}
}

// CIDRValidator validates that a string is a valid CIDR notation.
type CIDRValidator struct{}

// Description returns a plain text description of the validator's behavior.
func (v CIDRValidator) Description(_ context.Context) string {
	return "value must be a valid CIDR notation (e.g., '10.0.0.0/8')"
}

// MarkdownDescription returns a markdown description of the validator's behavior.
func (v CIDRValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

// ValidateString performs the validation.
func (v CIDRValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}

	value := req.ConfigValue.ValueString()
	if _, _, err := net.ParseCIDR(value); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid CIDR",
			fmt.Sprintf("Value %q is not a valid CIDR notation: %s", value, err),
		)
	}
}

// ValidCIDR returns a validator that checks if a string is a valid CIDR notation.
func ValidCIDR() validator.String {
	return CIDRValidator{}
}
