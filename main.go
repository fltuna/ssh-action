package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	os.Exit(run())
}

func run() int {
	host := getInput("HOST")
	user := getInput("USER")
	key := getInput("KEY")
	portStr := getInput("PORT")
	knownHostsStr := getInput("KNOWN_HOSTS")
	script := getInput("SCRIPT")
	timeoutStr := getInput("TIMEOUT")

	// Validate required inputs
	if host == "" {
		actionError("input 'host' is required")
		return 1
	}
	if user == "" {
		actionError("input 'user' is required")
		return 1
	}
	if key == "" {
		actionError("input 'key' is required")
		return 1
	}
	if script == "" {
		actionError("input 'script' is required")
		return 1
	}

	// Parse port
	port := 22
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			actionError("invalid port: %s", portStr)
			return 1
		}
		port = p
	}

	// Parse timeout
	timeout := 30
	if timeoutStr != "" {
		t, err := strconv.Atoi(timeoutStr)
		if err != nil || t < 1 {
			actionError("invalid timeout: %s", timeoutStr)
			return 1
		}
		timeout = t
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		actionError("failed to parse private key: %v", err)
		return 1
	}

	// Host key callback
	hostKeyCallback, err := buildHostKeyCallback(knownHostsStr)
	if err != nil {
		actionError("failed to parse known_hosts: %v", err)
		return 1
	}

	// SSH client config
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         time.Duration(timeout) * time.Second,
	}

	// Connect
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		if isTimeout(err) {
			actionError("connection timed out")
		} else if isConnectionRefused(err) {
			actionError("connection refused")
		} else if strings.Contains(err.Error(), "host key") {
			actionError("host key verification failed: %v", err)
		} else {
			actionError("failed to connect: %v", err)
		}
		return 1
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		actionError("failed to create session: %v", err)
		return 1
	}
	defer session.Close()

	// Capture stdout for GitHub Actions output, while also streaming to runner stdout
	var stdoutBuf strings.Builder
	stdoutWriter := io.MultiWriter(os.Stdout, &stdoutBuf)

	session.Stdout = stdoutWriter
	session.Stderr = os.Stderr

	// Execute script
	exitCode := 0
	if err := session.Run(script); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitStatus()
		} else {
			actionError("failed to execute script: %v", err)
			return 1
		}
	}

	// Set GitHub Actions outputs
	setOutput("stdout", stdoutBuf.String())
	setOutput("exit_code", strconv.Itoa(exitCode))

	return exitCode
}

func getInput(name string) string {
	return strings.TrimSpace(os.Getenv("INPUT_" + name))
}

func actionError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "::error::"+format+"\n", args...)
}

func actionWarning(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "::warning::"+format+"\n", args...)
}

func setOutput(name, value string) {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		return
	}
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	delimiter := "ghadelimiter_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fmt.Fprintf(f, "%s<<%s\n%s\n%s\n", name, delimiter, value, delimiter)
}

func buildHostKeyCallback(knownHostsStr string) (ssh.HostKeyCallback, error) {
	if knownHostsStr == "" {
		// TOFU: accept any host key with a warning
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			actionWarning("host key verification skipped (TOFU): %s key %s from %s",
				key.Type(),
				ssh.FingerprintSHA256(key),
				hostname,
			)
			return nil
		}, nil
	}

	// Write known_hosts to a temp file for knownhosts.New
	tmpFile, err := os.CreateTemp("", "known_hosts")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.WriteString(knownHostsStr); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("failed to write known_hosts: %w", err)
	}
	tmpFile.Close()

	callback, err := knownhosts.New(tmpPath)
	os.Remove(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse known_hosts: %w", err)
	}

	return callback, nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return strings.Contains(err.Error(), "timed out") ||
		strings.Contains(err.Error(), "timeout")
}

func isConnectionRefused(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			return strings.Contains(sysErr.Err.Error(), "connection refused")
		}
	}
	return strings.Contains(err.Error(), "connection refused")
}
