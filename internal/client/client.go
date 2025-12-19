// Copyright (c) 2025 Yaklab Co.
// SPDX-License-Identifier: MIT

// Package client provides SSH client functionality for remote node operations.
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SSHConfig holds configuration for SSH connections.
type SSHConfig struct {
	User            string
	PrivateKey      string // Key content
	PrivateKeyFile  string // Path to key file
	Timeout         string
	ConnAttempts    int
	UseMultiplexing bool
}

// SSHClient handles SSH execution to cluster nodes.
type SSHClient struct {
	user           string
	privateKeyFile string
	timeout        time.Duration
	connAttempts   int
	useMux         bool
	controlDir     string
}

const (
	defaultSSHTimeout   = 30 * time.Second
	defaultConnAttempts = 3
	sshControlPersist   = "60"
	sshControlDir       = "/tmp/hephaestus-ssh-mux"
	keyFilePermissions  = 0o600
	controlDirPerms     = 0o700
)

// NewSSHClient creates a new SSH client from configuration.
func NewSSHClient(cfg SSHConfig) (*SSHClient, error) {
	// Parse timeout
	timeout := defaultSSHTimeout
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid timeout %q: %w", cfg.Timeout, err)
		}
		timeout = d
	}

	connAttempts := defaultConnAttempts
	if cfg.ConnAttempts > 0 {
		connAttempts = cfg.ConnAttempts
	}

	// Handle private key - write to temp file if provided as content
	var keyFile string
	if cfg.PrivateKey != "" {
		tmpFile, err := os.CreateTemp("", "hephaestus-ssh-key-*")
		if err != nil {
			return nil, fmt.Errorf("create temp key file: %w", err)
		}
		if _, err := tmpFile.WriteString(cfg.PrivateKey); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("write temp key file: %w", err)
		}
		if err := tmpFile.Chmod(keyFilePermissions); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
			return nil, fmt.Errorf("chmod temp key file: %w", err)
		}
		_ = tmpFile.Close()
		keyFile = tmpFile.Name()
	} else if cfg.PrivateKeyFile != "" {
		keyFile = expandHomePath(cfg.PrivateKeyFile)
	}

	client := &SSHClient{
		user:           cfg.User,
		privateKeyFile: keyFile,
		timeout:        timeout,
		connAttempts:   connAttempts,
		useMux:         cfg.UseMultiplexing,
		controlDir:     sshControlDir,
	}

	if client.useMux {
		if err := os.MkdirAll(client.controlDir, controlDirPerms); err != nil {
			return nil, fmt.Errorf("create control directory: %w", err)
		}
	}

	return client, nil
}

// expandHomePath expands ~ to the user's home directory.
func expandHomePath(path string) string {
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return strings.Replace(path, "~", home, 1)
		}
	}
	return path
}

// sshArgs returns common SSH arguments.
func (c *SSHClient) sshArgs() []string {
	args := []string{
		"-o", fmt.Sprintf("ConnectTimeout=%d", int(c.timeout.Seconds())),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", fmt.Sprintf("ConnectionAttempts=%d", c.connAttempts),
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
	}

	if c.privateKeyFile != "" {
		args = append(args, "-i", c.privateKeyFile, "-o", "IdentitiesOnly=yes")
	}

	if c.useMux {
		controlPath := filepath.Join(c.controlDir, "%h")
		args = append(args,
			"-o", "ControlMaster=auto",
			"-o", "ControlPath="+controlPath,
			"-o", "ControlPersist="+sshControlPersist,
		)
	}

	return args
}

// buildSSHArgs creates a new slice with SSH args for a specific host and command.
// This safely copies the base args to avoid slice mutation issues.
func (c *SSHClient) buildSSHArgs(ip, cmd string) []string {
	baseArgs := c.sshArgs()
	args := make([]string, 0, len(baseArgs)+2)
	args = append(args, baseArgs...)
	args = append(args, fmt.Sprintf("%s@%s", c.user, ip), cmd)
	return args
}

// buildSCPArgs creates a new slice with SCP args for file transfer.
// This safely copies the base args to avoid slice mutation issues.
func (c *SSHClient) buildSCPArgs(localPath, ip, remotePath string) []string {
	baseArgs := c.sshArgs()
	args := make([]string, 0, len(baseArgs)+2)
	args = append(args, baseArgs...)
	args = append(args, localPath, fmt.Sprintf("%s@%s:%s", c.user, ip, remotePath))
	return args
}

// Check runs a command and returns true if it succeeds (exit 0).
func (c *SSHClient) Check(ctx context.Context, ip, cmd string) bool {
	args := c.buildSSHArgs(ip, cmd)
	execCmd := exec.CommandContext(ctx, "ssh", args...)
	execCmd.Stdout = io.Discard
	execCmd.Stderr = io.Discard
	return execCmd.Run() == nil
}

// Run executes a command on a remote node.
func (c *SSHClient) Run(ctx context.Context, ip, cmd string) error {
	return c.RunWithOutput(ctx, ip, cmd, io.Discard, io.Discard)
}

// RunWithOutput executes a command with custom output writers.
func (c *SSHClient) RunWithOutput(ctx context.Context, ip, cmd string, stdout, stderr io.Writer) error {
	args := c.buildSSHArgs(ip, cmd)
	execCmd := exec.CommandContext(ctx, "ssh", args...)
	execCmd.Stdout = stdout
	execCmd.Stderr = stderr

	if err := execCmd.Run(); err != nil {
		return &RemoteError{
			IP:       ip,
			Command:  cmd,
			ExitCode: exitCode(err),
			Err:      err,
		}
	}
	return nil
}

// Output runs a command and captures stdout.
func (c *SSHClient) Output(ctx context.Context, ip, cmd string) (string, error) {
	var stdout, stderr bytes.Buffer
	args := c.buildSSHArgs(ip, cmd)
	execCmd := exec.CommandContext(ctx, "ssh", args...)
	execCmd.Stdout = &stdout
	execCmd.Stderr = &stderr

	if err := execCmd.Run(); err != nil {
		return "", &RemoteError{
			IP:       ip,
			Command:  cmd,
			ExitCode: exitCode(err),
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			Err:      err,
		}
	}
	return strings.TrimSpace(stdout.String()), nil
}

// RunSudo executes a command with sudo.
func (c *SSHClient) RunSudo(ctx context.Context, ip, cmd string) error {
	return c.Run(ctx, ip, "sudo "+cmd)
}

// OutputSudo runs a command with sudo and captures stdout.
func (c *SSHClient) OutputSudo(ctx context.Context, ip, cmd string) (string, error) {
	return c.Output(ctx, ip, "sudo "+cmd)
}

// RunScript streams a script to bash -s via stdin.
func (c *SSHClient) RunScript(ctx context.Context, ip, script string) (string, string, error) {
	args := c.buildSSHArgs(ip, "sudo bash -s")

	var stdoutBuf, stderrBuf bytes.Buffer
	execCmd := exec.CommandContext(ctx, "ssh", args...)
	execCmd.Stdin = strings.NewReader(script)
	execCmd.Stdout = &stdoutBuf
	execCmd.Stderr = &stderrBuf

	if runErr := execCmd.Run(); runErr != nil {
		return stdoutBuf.String(), stderrBuf.String(), &RemoteError{
			IP:       ip,
			Command:  "bash -s (script)",
			ExitCode: exitCode(runErr),
			Stdout:   stdoutBuf.String(),
			Stderr:   stderrBuf.String(),
			Err:      runErr,
		}
	}
	return stdoutBuf.String(), stderrBuf.String(), nil
}

// WriteFile writes content to a remote file via temp upload + sudo mv.
func (c *SSHClient) WriteFile(ctx context.Context, ip, remotePath, content string) error {
	tmpFile, err := os.CreateTemp("", "hephaestus-remote-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	_ = tmpFile.Close()

	tmpRemote := "/tmp/" + filepath.Base(tmpFile.Name())
	if err := c.Upload(ctx, ip, tmpFile.Name(), tmpRemote); err != nil {
		return err
	}

	mvCmd := fmt.Sprintf("mv %s %s", tmpRemote, remotePath)
	return c.RunSudo(ctx, ip, mvCmd)
}

// Upload copies a local file to a remote path using scp.
func (c *SSHClient) Upload(ctx context.Context, ip, localPath, remotePath string) error {
	args := c.buildSCPArgs(localPath, ip, remotePath)
	execCmd := exec.CommandContext(ctx, "scp", args...)
	execCmd.Stdout = io.Discard
	execCmd.Stderr = io.Discard

	if err := execCmd.Run(); err != nil {
		return &RemoteError{
			IP:       ip,
			Command:  fmt.Sprintf("scp %s -> %s", localPath, remotePath),
			ExitCode: exitCode(err),
			Err:      err,
		}
	}
	return nil
}

// ReadFile fetches a remote file's content.
func (c *SSHClient) ReadFile(ctx context.Context, ip, remotePath string) (string, error) {
	return c.OutputSudo(ctx, ip, "cat "+remotePath)
}

// WaitForSSH waits until SSH is available on a node.
func (c *SSHClient) WaitForSSH(ctx context.Context, ip string, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if c.Check(ctx, ip, "true") {
				return nil
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("SSH not available on %s after %v", ip, maxWait)
			}
		}
	}
}

// Close terminates the SSH control master for a specific host.
// Returns any error from the SSH exit command.
func (c *SSHClient) Close(ctx context.Context, ip string) error {
	if !c.useMux {
		return nil
	}
	controlPath := filepath.Join(c.controlDir, ip)
	args := []string{"-O", "exit", "-o", "ControlPath=" + controlPath, fmt.Sprintf("%s@%s", c.user, ip)}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	return cmd.Run()
}

// CloseAll terminates all SSH control masters.
// Errors from individual close operations are collected but do not stop cleanup.
func (c *SSHClient) CloseAll(ctx context.Context) error {
	if !c.useMux || c.controlDir == "" {
		return nil
	}
	entries, err := os.ReadDir(c.controlDir)
	if err != nil {
		return fmt.Errorf("read control directory: %w", err)
	}
	var errs []error
	for _, entry := range entries {
		if !entry.IsDir() {
			socketPath := filepath.Join(c.controlDir, entry.Name())
			args := []string{"-O", "exit", "-o", "ControlPath=" + socketPath, "dummy"}
			cmd := exec.CommandContext(ctx, "ssh", args...)
			if err := cmd.Run(); err != nil {
				errs = append(errs, fmt.Errorf("close %s: %w", entry.Name(), err))
			}
			if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("remove socket %s: %w", socketPath, err))
			}
		}
	}
	return errors.Join(errs...)
}

// RemoteError provides structured error information for SSH failures.
type RemoteError struct {
	IP       string
	Command  string
	ExitCode int
	Stdout   string
	Stderr   string
	Err      error
}

func (e *RemoteError) Error() string {
	if e.ExitCode != 0 {
		return fmt.Sprintf("remote command on %s failed with exit code %d: %s", e.IP, e.ExitCode, e.Stderr)
	}
	return fmt.Sprintf("remote command on %s failed: %v", e.IP, e.Err)
}

func (e *RemoteError) Unwrap() error {
	return e.Err
}

// exitCode extracts the exit code from an exec error.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	exitErr := &exec.ExitError{}
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
