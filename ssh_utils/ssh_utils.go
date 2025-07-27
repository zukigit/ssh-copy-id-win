package sshutils

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func HostKeyCallbackFunc(knownHostsPath string) ssh.HostKeyCallback {
	knownHostsCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse known_hosts: %v\n", err)
		os.Exit(1)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := knownHostsCallback(hostname, remote, key)
		if err == nil {
			// Host already known and key matches
			return nil
		}

		keyErr, ok := err.(*knownhosts.KeyError)
		if !ok {
			// Unexpected error (e.g. file read issue)
			return err
		}

		if len(keyErr.Want) > 0 {
			// Host is known but key mismatch — potential MITM attack
			return fmt.Errorf("WARNING: remote host key mismatch for %s", hostname)
		}

		// Host not found — ask user if they want to trust and add it
		fingerprint := base64.StdEncoding.EncodeToString(sha256.New().Sum(key.Marshal()))
		fmt.Printf("The authenticity of host '%s (%s)' can't be established.\n", hostname, remote)
		fmt.Printf("%s key fingerprint is SHA256:%s.\n", key.Type(), fingerprint)
		fmt.Print("Are you sure you want to continue connecting (yes/no)? ")

		var response string
		fmt.Scanln(&response)

		if strings.ToLower(strings.TrimSpace(response)) != "yes" {
			return fmt.Errorf("user rejected unknown host: %s", hostname)
		}

		// Append to known_hosts
		f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("failed to open known_hosts: %w", err)
		}
		defer f.Close()

		hostLine := knownhosts.Line([]string{hostname}, key)
		if _, err := f.WriteString(hostLine + "\n"); err != nil {
			return fmt.Errorf("failed to write to known_hosts: %w", err)
		}

		fmt.Println("Host key added to known_hosts.")
		return nil
	}
}

func GetClientWithKey(hostIP string, port int, username string, privateKeyfilepath string, knownHostsPath string) (*ssh.Client, error) {
	// Load the private key
	key, err := os.ReadFile(privateKeyfilepath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key, Error: %s", err.Error())
	}

	// Create the signer for the private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key, Error: %s", err.Error())
	}

	clientConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: HostKeyCallbackFunc(knownHostsPath),
	}

	address := fmt.Sprintf("%s:%d", hostIP, port)

	client, err := ssh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed in getting ssh client, Error: %s", err.Error())
	}

	return client, err
}

func GetClient(hostIP string, port int, username string, password string, knownHostsPath string) (*ssh.Client, error) {
	clientConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: HostKeyCallbackFunc(knownHostsPath),
	}

	address := fmt.Sprintf("%s:%d", hostIP, port)

	client, err := ssh.Dial("tcp", address, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed in getting ssh client, Error: %s", err.Error())
	}

	return client, err
}
