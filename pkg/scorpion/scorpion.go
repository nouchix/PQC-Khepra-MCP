package scorpion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
)

const (
	MaxAttempts = 3
	HeaderSize  = 128
	MagicBytes  = "SCORPION_v1"
	SaltSize    = 16
	NonceSize   = 12
	KeySize     = 32
)

// ScorpionHeader is the vessel's mark
type ScorpionHeader struct {
	Magic    [11]byte
	Version  uint8
	Salt     [SaltSize]byte
	Nonce    [NonceSize]byte
	Attempts uint8
	Checksum [32]byte
}

// Mpatapo binds the spirit to the vessel.
// Only the true Name can release it.
func Mpatapo(path string, data []byte, password string) error {
	salt := make([]byte, SaltSize)
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	key := ngyinado(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	header := ScorpionHeader{
		Version:  1,
		Attempts: 0,
	}
	copy(header.Magic[:], MagicBytes)
	copy(header.Salt[:], salt)
	copy(header.Nonce[:], nonce)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := binary.Write(f, binary.LittleEndian, &header); err != nil {
		return err
	}
	if _, err := f.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

// Sane seeks the truth.
// If the heart is heavy, the feather rejects.
// If the path is false thrice, the cycle ends (Hye).
func Sane(path string, password string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var header ScorpionHeader
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, errors.New("vessel corrupted")
	}

	if string(header.Magic[:]) != MagicBytes {
		return nil, errors.New("unrecognized vessel")
	}

	if header.Attempts >= MaxAttempts {
		_ = hye(f)
		return nil, errors.New("VESSEL CONSUMED")
	}

	key := ngyinado(password, header.Salt[:])
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	stat, _ := f.Stat()
	ciphertextFunc := make([]byte, stat.Size()-int64(binary.Size(header)))
	if _, err := f.ReadAt(ciphertextFunc, int64(binary.Size(header))); err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, header.Nonce[:], ciphertextFunc, nil)
	if err != nil {
		header.Attempts++

		if header.Attempts >= MaxAttempts {
			fmt.Println(" [SCORPION] JUDGMENT: Unworthy. INITIATING HYE.")
			if nukeErr := hye(f); nukeErr != nil {
				return nil, fmt.Errorf("cleansing failed: %v", nukeErr)
			}
			return nil, errors.New("VESSEL CONSUMED BY FLAME")
		}

		if _, seekErr := f.Seek(0, 0); seekErr == nil {
			binary.Write(f, binary.LittleEndian, &header)
		}

		return nil, fmt.Errorf("voice unrecognized. Attempts: %d/%d", header.Attempts, MaxAttempts)
	}

	return plaintext, nil
}

// hye returns the vessel to the void.
// Random chaos overwrites order.
func hye(f *os.File) error {
	info, _ := f.Stat()
	size := info.Size()

	noise := make([]byte, 1024)
	for i := int64(0); i < size; i += 1024 {
		rand.Read(noise)
		f.WriteAt(noise, i)
	}

	f.Sync()
	f.Truncate(0)
	return nil
}

// ngyinado establishes the foundation.
func ngyinado(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}
