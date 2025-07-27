package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func getPublicKey(filePath string) (string, error) {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("No identities found(%s)\n", filePath)
		}

		return "", fmt.Errorf("os.Stat(%s) failed. err: %s\n", filePath, err.Error())
	}

	byteData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("os.ReadFile(%s) failed. err: %s\n", filePath, err.Error())
	}

	return string(byteData), nil
}

func askPasswd(message_to_show string) string {
	fmt.Printf("%s: ", message_to_show)
	bytepw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Println("Failed in getting password, Error:", err.Error())
		os.Exit(1)
	}

	return string(bytepw)
}

func getUserNHostname(argString string) (user string, host string) {
	parts := strings.Split(argString, "@")
	if len(parts) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	user = parts[0]
	host = parts[1]

	return
}

func main() {
	// get default identity filepath
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic("Unable to get user home directory: " + err.Error())
	}
	deafultIdentityFile := filepath.Join(homeDir, ".ssh", "id_rsa.pub")

	// flags
	port := flag.Int("p", 22, "port")
	identityFile := flag.String("i", deafultIdentityFile, "identity_file")
	targetPath := flag.String("t", `%programdata%/ssh/administrators_authorized_keys`, "target_path")
	force := flag.Bool("f", false, "force mode -- copy keys without trying to check if they are already installed")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s: [user@]hostname\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Printf("INFO: Source of key(s) to be installed: %s\n", *identityFile)

	publicKey, err := getPublicKey(*identityFile)
	if err != nil {
		fmt.Println("ERROR: ", err.Error())
	}

	user, hostname := getUserNHostname(flag.Arg(0))

	privateKeyFilepath := strings.TrimSuffix(*identityFile, ".pub")
	knownHostsPath := filepath.Join(homeDir, ".ssh", "known_hosts")

	var client *ssh.Client

	if !*force {
		_, err = GetClientWithKey(hostname, *port, user, privateKeyFilepath, knownHostsPath)
		if err != nil {
			fmt.Println("INFO: attempting to log in with the new key(s), to filter out any that are already installed")
			fmt.Println("INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys")
		} else {
			fmt.Println("WARNING: All keys were skipped because they already exist on the remote system.")
			fmt.Println("(if you think this is a mistake, you may want to use -f option")
			os.Exit(0)
		}
	}

	passwd := askPasswd(fmt.Sprintf("%s's password", flag.Arg(0)))
	client, err = GetClient(hostname, *port, user, passwd, knownHostsPath)
	if err != nil {
		fmt.Printf("Permission denied. err: %s\n", err.Error())
		os.Exit(1)
	}

	host := &Host{
		SshClient: client,
	}

	publicKey = strings.ReplaceAll(publicKey, "\n", "")
	cmd := fmt.Sprintf(`powershell -Command "[IO.File]::AppendAllText('%s', '%s' + [Environment]::NewLine)"`,
		*targetPath, publicKey)

	_, err = host.Run_cmd(cmd)
	if err != nil {
		fmt.Printf("ERROR: could not add public key. err: %s\n", err.Error())
		os.Exit(1)
	}

	cmd = fmt.Sprintf(`icacls %s /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"`, *targetPath)
	_, err = host.Run_cmd(cmd)
	if err != nil {
		fmt.Printf("ERROR: could not grant required permissions. err: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println("Number of key(s) added: 1")
	fmt.Println()
	fmt.Printf("Now try logging into the machine, with: 'ssh '%s''", flag.Arg(0))
	fmt.Println("and check to make sure that only the key(s) you wanted were added.")
}
