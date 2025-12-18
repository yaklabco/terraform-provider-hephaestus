package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/yaklabco/stave/pkg/st"
)

// Provider groups provider development targets.
type Provider st.Namespace

// binaryName is the output binary name.
const binaryName = "terraform-provider-hephaestus"

// getProviderDir returns the provider root directory.
func getProviderDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}

	// Walk up to find go.mod with the provider module.
	for dir := wd; ; {
		gomod := filepath.Join(dir, "go.mod")
		if _, err := os.Stat(gomod); err == nil {
			content, err := os.ReadFile(gomod)
			if err == nil && strings.Contains(string(content), "terraform-provider-hephaestus") {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("provider root not found (no go.mod with terraform-provider-hephaestus)")
}

// runIn executes a command in a specific directory.
func runIn(ctx context.Context, dir string, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Build compiles the provider binary.
func (Provider) Build(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Building Provider ===")
	return runIn(ctx, dir, "go", "build", "-o", binaryName, ".")
}

// BuildAll builds the provider for multiple platforms.
func (Provider) BuildAll(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	platforms := []struct {
		goos   string
		goarch string
	}{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
	}

	fmt.Println("=== Building Provider (All Platforms) ===")

	distDir := filepath.Join(dir, "dist")
	if err := os.MkdirAll(distDir, 0755); err != nil {
		return fmt.Errorf("create dist dir: %w", err)
	}

	for _, p := range platforms {
		outName := fmt.Sprintf("%s_%s_%s", binaryName, p.goos, p.goarch)
		outPath := filepath.Join(distDir, outName)

		fmt.Printf("  Building %s/%s...\n", p.goos, p.goarch)

		cmd := exec.CommandContext(ctx, "go", "build", "-o", outPath, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GOOS="+p.goos,
			"GOARCH="+p.goarch,
			"CGO_ENABLED=0",
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("build %s/%s: %w", p.goos, p.goarch, err)
		}
	}

	fmt.Printf("\nBinaries written to: %s\n", distDir)
	return nil
}

// Test runs all tests.
func (Provider) Test(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Running Tests ===")
	return runIn(ctx, dir, "go", "test", "-v", "./...")
}

// TestUnit runs unit tests only (no acceptance tests).
func (Provider) TestUnit(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Running Unit Tests ===")
	return runIn(ctx, dir, "go", "test", "-v", "-short", "./...")
}

// TestAcc runs acceptance tests (requires TF_ACC=1).
func (Provider) TestAcc(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Running Acceptance Tests ===")
	fmt.Println("Note: Requires actual infrastructure")

	cmd := exec.CommandContext(ctx, "go", "test", "-v", "./internal/provider/...")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TF_ACC=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Lint runs golangci-lint.
func (Provider) Lint(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Running Linter ===")
	return runIn(ctx, dir, "golangci-lint", "run", "./...")
}

// Fmt formats all Go files.
func (Provider) Fmt(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Formatting Code ===")
	return runIn(ctx, dir, "gofmt", "-w", ".")
}

// FmtCheck checks if code is formatted.
func (Provider) FmtCheck(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Checking Format ===")

	cmd := exec.CommandContext(ctx, "gofmt", "-l", ".")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("gofmt: %w", err)
	}

	if len(out) > 0 {
		fmt.Println("The following files need formatting:")
		fmt.Print(string(out))
		return fmt.Errorf("code not formatted")
	}

	fmt.Println("All files formatted correctly")
	return nil
}

// Vet runs go vet.
func (Provider) Vet(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Running go vet ===")
	return runIn(ctx, dir, "go", "vet", "./...")
}

// Tidy runs go mod tidy.
func (Provider) Tidy(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Running go mod tidy ===")
	return runIn(ctx, dir, "go", "mod", "tidy")
}

// Install builds and installs the provider for local development.
// Creates ~/.terraformrc with dev_overrides if it doesn't exist.
func (Provider) Install(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Installing Provider for Local Development ===")

	// Build first
	if err := runIn(ctx, dir, "go", "build", "-o", binaryName, "."); err != nil {
		return err
	}

	// Get binary path
	binaryPath := filepath.Join(dir, binaryName)

	// Check/create terraformrc
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	terraformrc := filepath.Join(home, ".terraformrc")
	expectedContent := fmt.Sprintf(`provider_installation {
  dev_overrides {
    "yaklab/hephaestus" = "%s"
  }
  direct {}
}
`, dir)

	// Check if file exists and has correct content
	existing, err := os.ReadFile(terraformrc)
	if err != nil || !strings.Contains(string(existing), "yaklab/hephaestus") {
		fmt.Printf("\nCreating %s with dev_overrides...\n", terraformrc)
		if err := os.WriteFile(terraformrc, []byte(expectedContent), 0644); err != nil {
			return fmt.Errorf("write terraformrc: %w", err)
		}
	}

	fmt.Println()
	fmt.Printf("Provider installed: %s\n", binaryPath)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cd ../cluster && tofu apply  # Uses local provider")
	fmt.Println()
	fmt.Println("Note: With dev_overrides, 'tofu init' is not required.")

	return nil
}

// Clean removes build artifacts.
func (Provider) Clean(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Cleaning Build Artifacts ===")

	// Remove binary
	binary := filepath.Join(dir, binaryName)
	if err := os.Remove(binary); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove binary: %w", err)
	}
	fmt.Printf("  Removed %s\n", binary)

	// Remove dist directory
	dist := filepath.Join(dir, "dist")
	if err := os.RemoveAll(dist); err != nil {
		return fmt.Errorf("remove dist: %w", err)
	}
	fmt.Printf("  Removed %s/\n", dist)

	return nil
}

// Ci runs all CI checks (fmt, vet, lint, test).
func (Provider) Ci(ctx context.Context) error {
	fmt.Println("=== Running CI Checks ===")
	fmt.Println()

	checks := []struct {
		name string
		fn   func(context.Context) error
	}{
		{"Format Check", (Provider{}).FmtCheck},
		{"Go Vet", (Provider{}).Vet},
		{"Lint", (Provider{}).Lint},
		{"Unit Tests", (Provider{}).TestUnit},
	}

	for _, check := range checks {
		fmt.Printf("--- %s ---\n", check.name)
		if err := check.fn(ctx); err != nil {
			return fmt.Errorf("%s failed: %w", check.name, err)
		}
		fmt.Println()
	}

	fmt.Println("=== All CI Checks Passed ===")
	return nil
}

// Docs generates provider documentation using tfplugindocs.
func (Provider) Docs(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Generating Documentation ===")

	// Check if tfplugindocs is installed
	if _, err := exec.LookPath("tfplugindocs"); err != nil {
		fmt.Println("tfplugindocs not found. Installing...")
		cmd := exec.CommandContext(ctx, "go", "install", "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@latest")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("install tfplugindocs: %w", err)
		}
	}

	return runIn(ctx, dir, "tfplugindocs", "generate")
}

// Release builds release artifacts using goreleaser (dry-run).
func (Provider) Release(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Building Release (Dry Run) ===")

	// Check if goreleaser is installed
	if _, err := exec.LookPath("goreleaser"); err != nil {
		return fmt.Errorf("goreleaser not found - install with: brew install goreleaser")
	}

	return runIn(ctx, dir, "goreleaser", "release", "--snapshot", "--clean")
}

// Version prints the current version from git.
func (Provider) Version(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "git", "describe", "--tags", "--always", "--dirty")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		fmt.Println("Version: dev (no git tags)")
		return nil
	}

	fmt.Printf("Version: %s", string(out))
	return nil
}

// Info prints provider and environment information.
func (Provider) Info(ctx context.Context) error {
	dir, err := getProviderDir()
	if err != nil {
		return err
	}

	fmt.Println("=== Provider Info ===")
	fmt.Printf("Directory: %s\n", dir)
	fmt.Printf("Binary: %s\n", binaryName)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	// Check if binary exists
	binary := filepath.Join(dir, binaryName)
	if info, err := os.Stat(binary); err == nil {
		fmt.Printf("Binary Size: %.2f MB\n", float64(info.Size())/(1024*1024))
		fmt.Printf("Binary Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("Binary: not built")
	}

	return nil
}
