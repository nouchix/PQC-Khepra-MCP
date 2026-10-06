package scorpion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/nouchix/khepra-pqc/kdf"
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

// Version is the vessel format: PBKDF2-HMAC-SHA-384 key, AES-256-GCM with a
// module-generated nonce, and magic, version and salt as associated data.
const Version = 2

// Mpatapo binds the spirit to the vessel.
// Only the true Name can release it.
func Mpatapo(path string, data []byte, password string) error {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}

	header := ScorpionHeader{
		Version:  Version,
		Attempts: 0,
	}
	copy(header.Magic[:], MagicBytes)
	copy(header.Salt[:], salt)

	gcm, err := vesselAEAD(password, salt)
	if err != nil {
		return err
	}
	sealed := gcm.Seal(nil, nil, data, headerAAD(&header))
	copy(header.Nonce[:], sealed[:NonceSize])
	ciphertext := sealed[NonceSize:]

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	// Explicit close with error capture to prevent silent data loss (Go WARNING).
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("[WARN] file close error: %v", cerr)
		}
	}()

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
	// Explicit close with error capture to prevent silent data loss (Go WARNING).
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("[WARN] file close error: %v", cerr)
		}
	}()

	var header ScorpionHeader
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return nil, errors.New("vessel corrupted")
	}

	if string(header.Magic[:]) != MagicBytes {
		return nil, errors.New("unrecognized vessel")
	}
	if header.Version != Version {
		return nil, fmt.Errorf("vessel format %d is not supported", header.Version)
	}

	if header.Attempts >= MaxAttempts {
		_ = hye(f)
		return nil, errors.New("VESSEL CONSUMED")
	}

	gcm, err := vesselAEAD(password, header.Salt[:])
	if err != nil {
		return nil, err
	}

	stat, _ := f.Stat()
	ciphertextFunc := make([]byte, stat.Size()-int64(binary.Size(header)))
	if _, err := f.ReadAt(ciphertextFunc, int64(binary.Size(header))); err != nil {
		return nil, err
	}

	sealed := append(append([]byte{}, header.Nonce[:]...), ciphertextFunc...)
	plaintext, err := gcm.Open(nil, nil, sealed, headerAAD(&header))
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

// vesselAEAD derives the vessel key with PBKDF2-HMAC-SHA-384 (ngyinado:
// establishing the foundation) and returns AES-256-GCM with module-generated
// nonces.
func vesselAEAD(password string, salt []byte) (cipher.AEAD, error) {
	key, err := kdf.PassphraseKey(password, salt, KeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// headerAAD authenticates the fields of the header that never change. The
// attempt counter is excluded because Sane rewrites it.
func headerAAD(h *ScorpionHeader) []byte {
	aad := make([]byte, 0, len(h.Magic)+1+len(h.Salt))
	aad = append(aad, h.Magic[:]...)
	aad = append(aad, h.Version)
	aad = append(aad, h.Salt[:]...)
	return aad
}
