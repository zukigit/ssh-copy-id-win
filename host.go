package main

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

type Host struct {
	SshClient *ssh.Client
}

func (host *Host) Run_cmd(cmd string) ([]byte, error) {
	if host.SshClient == nil {
		return nil, fmt.Errorf("err: ssh client is nil")
	}

	session, err := host.SshClient.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

	byteData, err := session.CombinedOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("stderr: %s, err: %s", string(byteData), err.Error())
	}

	return byteData, err
}
