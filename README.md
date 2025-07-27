# ssh-copy-id-win

Similar to `ssh-copy-id` but for Windows environments.

## Installation

Build from source:

```sh
go build github.com/zukigit/ssh-copy-id-win
```

## Usage
```sh
./ssh-copy-id-win [options] user@hostname
```

## Options

| Flag              | Description                                                                                      |
|-------------------|--------------------------------------------------------------------------------------------------|
| `-p <port>`       | SSH port to connect to (default: `22`)                                                           |
| `-i <file>`       | Path to your public key file (default: `~/.ssh/id_rsa.pub`)                                      |
| `-t <path>`       | Target path on the remote Windows host (default: `%programdata%/ssh/administrators_authorized_keys`) |
| `-f`              | Force mode — skip key existence check and copy the key regardless                                |

