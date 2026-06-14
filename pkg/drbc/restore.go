package drbc

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/kms"
)

// RestoreGenesis reverses the specific Genesis encryption/compression
func RestoreGenesis(password string, targetDir string) error {
	// 1. Unlock Identity
	fmt.Println(" [PHOENIX] Verifying Identity for Restoration...")
	seedPath := kms.DefaultSeedPath()
	if _, err := os.Stat(seedPath); os.IsNotExist(err) {
		return fmt.Errorf("%s not found. Run 'asaf kms init' first", seedPath)
	}

	seed, err := kms.LoadMasterSeed(seedPath, password)
	if err != nil {
		return fmt.Errorf("identity verification failed: %v", err)
	}

	// 2. Derive Key
	mac := hmac.New(sha512.New, []byte(GenesisSalt))
	mac.Write(seed)
	genesisKey := mac.Sum(nil)[:32]

	// 3. Open Artifact
	inputFile, err := os.Open(GenesisOutput)
	if err != nil {
		return fmt.Errorf("artifact %s not found: %v", GenesisOutput, err)
	}
	defer inputFile.Close()

	// 4. Decrypt Stream
	fmt.Println(" [PHOENIX] Decrypting Reality...")

	// Create a pipe to connect Decryptor -> Decompressor
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		if err := decryptStream(genesisKey, inputFile, pw); err != nil {
			pw.CloseWithError(err)
		}
	}()

	// 5. Decompress & Untar
	fmt.Printf(" [PHOENIX] Restoring to '%s'...\n", targetDir)
	if err := decompressProject(pr, targetDir); err != nil {
		return fmt.Errorf("restoration failed: %w", err)
	}

	return nil
}

func decryptStream(key []byte, in io.Reader, out io.Writer) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Read IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(in, iv); err != nil {
		return errors.New("failed to read IV from artifact")
	}

	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: in}

	if _, err := io.Copy(out, reader); err != nil {
		return err
	}
	return nil
}

func decompressProject(r io.Reader, targetDir string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(targetDir, header.Name)
		if err := extractEntry(tr, header, target); err != nil {
			return err
		}
	}
	return nil
}

func extractEntry(tr *tar.Reader, header *tar.Header, target string) error {
	switch header.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, 0755)
	case tar.TypeReg:
		dir := filepath.Dir(target)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err := io.Copy(f, tr); err != nil {
			return err
		}
	}
	return nil
}
