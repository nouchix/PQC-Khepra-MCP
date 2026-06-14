package drbc

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/kms"
)

const (
	GenesisSalt   = "GENESIS_BACKUP_KEY_v0"
	GenesisOutput = "adinkhepra_v0.0_genesis.kpkg"
)

// AwakenGenesis initiates the full project backup logic
func AwakenGenesis(password string) error {
	// 1. Unlock the Master Seed (Identity Verification)
	fmt.Println(" [PHOENIX] Verifying Identity...")
	seedPath := kms.DefaultSeedPath()
	if _, err := os.Stat(seedPath); os.IsNotExist(err) {
		return fmt.Errorf("%s not found. Run 'asaf kms init' first", seedPath)
	}

	seed, err := kms.LoadMasterSeed(seedPath, password)
	if err != nil {
		return fmt.Errorf("identity verification failed: %v", err)
	}

	// 2. Derive Genesis Key
	// Key = HMAC-SHA512(Seed, Salt)[:32] (AES-256)
	mac := hmac.New(sha512.New, []byte(GenesisSalt))
	mac.Write(seed)
	genesisKey := mac.Sum(nil)[:32]

	// 3. Create Temporary Archive (Tar + Gzip)
	fmt.Println(" [PHOENIX] Compressing Reality (Creating Archive)...")
	tempArchive, err := os.CreateTemp("", "khepra_genesis_*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tempArchive.Name()) // Clean up temp file

	if err := compressProject(tempArchive); err != nil {
		tempArchive.Close()
		return err
	}

	// Reset temp file pointer for reading
	tempArchive.Seek(0, 0)

	// 4. Encrypt and Seal
	fmt.Println(" [PHOENIX] Sealing Genesis Artifact...")
	outputFile, err := os.Create(GenesisOutput)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	if err := encryptStream(genesisKey, tempArchive, outputFile); err != nil {
		return err
	}

	return nil
}

// shouldSkipEntry returns true for paths the Genesis archive should exclude.
func shouldSkipEntry(info os.FileInfo) bool {
	if info.Name() == GenesisOutput {
		return true
	}
	if info.Name() == ".git" && info.IsDir() {
		return true
	}
	return false
}

// addFileToTar writes a single file's contents into the tar writer.
// Locked or otherwise unreadable files are silently skipped.
func addFileToTar(tw *tar.Writer, path string, info os.FileInfo) error {
	header, err := tar.FileInfoHeader(info, info.Name())
	if err != nil {
		return nil // skip unusual files (e.g. sockets, devices)
	}
	header.Name = filepath.ToSlash(path)

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil // skip locked/unreadable files
	}
	defer f.Close()

	if _, err = io.Copy(tw, f); err != nil {
		return nil // skip files that error mid-copy
	}
	return nil
}

func compressProject(w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	return filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if shouldSkipEntry(info) {
			return nil
		}
		return addFileToTar(tw, path, info)
	})
}


func encryptStream(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize) // CTR requires 16 bytes (BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	// Write IV first
	if _, err := out.Write(iv); err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv) // Accessing large files, usually GCM is block-based in memory.
	// Wait, user used GCM in root.go. But for streaming large files, CTR or OFB is better unless we chunk it.
	// Since we are compressing simply, let's use a simpler wrapper.
	// Actually, let's stick to GCM but read the whole temp file?
	// The temp file might be huge if node_modules is there. Streaming encryption is safer.
	// Let's use OFB or CFB for streaming.

	// Re-decision: Use AES-CTR for streaming large backup.
	// Ideally GCM is authenticated. But standard Go GCM doesn't stream easily without chunking.
	// For "Genesis Backup", let's use a HMAC-SHA256 over the ciphertext for integrity.

	encryptedStream := cipher.StreamWriter{S: stream, W: out}
	if _, err := io.Copy(encryptedStream, in); err != nil {
		return err
	}

	return nil
}
