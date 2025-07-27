package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	sshutils "github.com/zukigit/ssh-copy-id-win/ssh_utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func checkIdentityFile(filePath string) {
	_, err := os.Stat(filePath)
	if err == nil {
		return
	}

	if os.IsNotExist(err) {
		fmt.Printf("ERROR: No identities found(%s)\n", filePath)
		os.Exit(1)
	}

	panic(err)
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
	checkIdentityFile(*identityFile)

	user, host := getUserNHostname(flag.Arg(0))

	privateKeyFilepath := strings.TrimSuffix(*identityFile, ".pub")
	knownHostsPath := filepath.Join(homeDir, ".ssh", "known_hosts")

	var client *ssh.Client

	if !*force {
		fmt.Println("INFO: attempting to log in with the new key(s), to filter out any that are already installed")

		_, err = sshutils.GetClientWithKey(host, *port, user, privateKeyFilepath, knownHostsPath)
		if err != nil {
			fmt.Println("INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys")
		} else {
			fmt.Println("WARNING: All keys were skipped because they already exist on the remote system.")
			fmt.Println("(if you think this is a mistake, you may want to use -f option")
			os.Exit(0)
		}
	}

	passwd := askPasswd(fmt.Sprintf("%s's password", flag.Arg(0)))
	client, err = sshutils.GetClient(host, *port, user, passwd, knownHostsPath)
	if err != nil {
		fmt.Printf("Permission denied. err: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println("port", *port)
	fmt.Println("identityFile", identityFile)
	fmt.Println(user, host)
	fmt.Println("*client", client)
}
