package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

func main() {
	fmt.Println("Generating Dilithium3 Offline Root Key Pair...")

	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		fmt.Printf("Error generating key: %v\n", err)
		os.Exit(1)
	}

	pkHex := hex.EncodeToString(pk)
	skHex := hex.EncodeToString(sk)

	fmt.Printf("Public Key:  %s\n", pkHex)
	fmt.Printf("Private Key: %s\n", skHex)

	if err := os.WriteFile("offline_root.pub", []byte(pkHex), 0644); err != nil {
		panic(err)
	}
	if err := os.WriteFile("OFFLINE_ROOT_KEY.secret", []byte(skHex), 0600); err != nil {
		panic(err)
	}

	fmt.Println("\nKeys saved to 'offline_root.pub' and 'OFFLINE_ROOT_KEY.secret'")
	fmt.Println("WARNING: Move 'OFFLINE_ROOT_KEY.secret' to a secure air-gapped location immediately!")
}
