package util

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
)

func HomeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	usr, _ := user.Current()
	if usr != nil {
		return usr.HomeDir
	}
	return "."
}

func EnsureDir(path string, mode os.FileMode) error {
	return os.MkdirAll(path, mode)
}

func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil { return err }
	return os.WriteFile(path, b, 0o600)
}

func MarshalAuthorizedKey(pub ed25519.PublicKey, comment string) ([]byte, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil { return nil, err }
	line := ssh.MarshalAuthorizedKey(sshPub)
	if comment != "" {
		line = append(bytes.TrimSpace(line), ' ')
		line = append(line, []byte(comment)...)
		line = append(line, '\n')
	}
	return line, nil
}

func WriteOpenSSHPublicKey(path string, pub ed25519.PublicKey, comment string) error {
	line, err := MarshalAuthorizedKey(pub, comment)
	if err != nil { return err }
	return os.WriteFile(path, line, 0o644)
}

func WriteOpenSSHPrivateKey(path string, priv ed25519.PrivateKey) error {
	// OpenSSH-compatible PEM using mikesmitty/edkey
	raw := edkey.MarshalED25519PrivateKey(priv)
	block := &pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: raw}
	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return errors.New("pem encode failed")
	}
	return os.WriteFile(path, pemBytes, 0o600)
}

func NewEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func DefaultSSHPaths(base string) (priv, pub string) {
	if base == "" {
		base = filepath.Join(HomeDir(), ".ssh", "id_ed25519")
	}
	return base, base + ".pub"
}

func PrintNextSteps(pubPath string) {
	fmt.Printf("\nAdd this public key to ~/.ssh/authorized_keys on your target host:\n  %s\n\n", pubPath)
	fmt.Println("It must begin with 'ssh-ed25519 ...'. If you see that prefix, you're good.")
}
